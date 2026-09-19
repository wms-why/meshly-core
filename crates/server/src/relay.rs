//! Relay protocol handler (ALPN `meshly-core/data`).
//!
//! Wire format on this ALPN:
//!
//! 1. Consumer opens a bi-stream.
//! 2. Consumer writes a single `Frame::DataOpen { target_service,
//!    target_provider, consumer_node_id, proof: [0u8; 32] }`.
//!    (proof is unused in v1.)
//! 3. Server checks:
//!    - target_service is registered and target_provider matches.
//!    - `consumer_node_id` parses to an EndpointID and matches
//!      `Connection::remote_id()`. A mismatch is treated as a protocol
//!      violation (likely a buggy or malicious client trying to claim
//!      someone else's NodeID to inherit their rate-override bucket).
//! 4. Server looks the consumer up in
//!    [`ServerState::lookup_relay_rate_override`]. The hit (or the
//!    configured default) becomes the initial cap for this connection.
//! 5. Server dials the provider on ALPN `meshly-core/<target_service>` and
//!    opens a bi-stream.
//! 6. Server performs a bidirectional byte relay between the two
//!    bi-streams, throttling the **reply** direction
//!    (provider → consumer) according to
//!    [`crate::ratelimit::RateLimitHandle`].

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Context;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use meshly_core_common::alpn::alpn_for_service;
use meshly_core_common::parse_endpoint_id;
use meshly_core_common::protocol::Frame;

use crate::ratelimit::{self, RateLimitHandle};
use crate::registry::ServerState;

/// Protocol handler for the data-plane relay.
#[derive(Debug, Clone)]
pub struct RelayHandler {
    pub endpoint: Endpoint,
    pub state: Arc<ServerState>,
    /// Default reply-bandwidth cap applied to every new relay
    /// connection. Each spawned relay task clones this into its own
    /// per-connection `RateLimitHandle`, which the writer reads on
    /// every refill — so flipping this at runtime affects only
    /// connections that haven't started yet; use
    /// [`ServerState::update_relay_rate`] to retarget an in-flight one.
    ///
    /// `None` means rate limiting is **off** at the master-switch level
    /// (the `relay.enabled` config knob is `false`). In that state the
    /// relay forwards all reply bytes as fast as QUIC allows and the
    /// per-connection rate handle is never allocated.
    pub default_reply_bps: Option<RateLimitHandle>,
}

impl ProtocolHandler for RelayHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        let remote_str = remote.fmt_short().to_string();
        debug!(remote = %remote_str, "data relay: connection accepted");

        match self.accept_loop(conn, remote).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                Err(AcceptError::from_boxed(boxed))
            }
        }
    }

    async fn shutdown(&self) {}
}

impl RelayHandler {
    async fn accept_loop(&self, conn: Connection, remote: EndpointId) -> anyhow::Result<()> {
        let remote_str = remote.fmt_short().to_string();
        loop {
            let (mut consumer_send, mut consumer_recv) = match conn.accept_bi().await {
                Ok(p) => p,
                Err(e) => {
                    debug!(remote = %remote_str, err = %e,
                        "relay accept_bi ended; closing relay loop");
                    return Ok(());
                }
            };

            let frame = match Frame::read_from(&mut consumer_recv).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(remote = %remote_str, err = %e,
                        "relay: failed to read DataOpen");
                    let _ = consumer_send.shutdown().await;
                    continue;
                }
            };

            let (target_service, target_provider_str, consumer_node_id_str) = match frame {
                Frame::DataOpen {
                    target_service,
                    target_provider,
                    consumer_node_id,
                    ..
                } => (target_service, target_provider, consumer_node_id),
                other => {
                    warn!(remote = %remote_str, got = ?other,
                        "relay: expected DataOpen, got something else");
                    let _ = consumer_send.shutdown().await;
                    continue;
                }
            };

            let target_provider = match parse_endpoint_id(&target_provider_str) {
                Some(id) => id,
                None => {
                    warn!(remote = %remote_str, target = %target_provider_str,
                        "relay: malformed target provider id");
                    let _ = consumer_send.shutdown().await;
                    continue;
                }
            };

            // The consumer MUST declare itself, and the declared NodeID
            // MUST match the QUIC connection peer. A mismatch is the
            // strongest signal we have that someone is trying to ride
            // another consumer's rate bucket (or the client is buggy).
            let consumer_node_id = match parse_endpoint_id(&consumer_node_id_str) {
                Some(id) => id,
                None => {
                    warn!(remote = %remote_str, claimed = %consumer_node_id_str,
                        "relay: malformed consumer_node_id in DataOpen");
                    let _ = consumer_send.shutdown().await;
                    continue;
                }
            };
            if consumer_node_id != remote {
                warn!(
                    remote = %remote_str,
                    claimed = %consumer_node_id.fmt_short(),
                    "relay: consumer_node_id does not match connection peer; \
                     refusing to attribute this stream to the claimed NodeID"
                );
                let _ = consumer_send.shutdown().await;
                continue;
            }

            let provider = self.lookup_service_any_group(&target_service);
            let provider = match provider {
                Some(p) if p == target_provider => p,
                Some(p) => {
                    warn!(
                        remote = %remote_str, requested = %target_provider.fmt_short(),
                        actual = %p.fmt_short(), service = %target_service,
                        "relay: target provider does not match registered provider"
                    );
                    let _ = consumer_send.shutdown().await;
                    continue;
                }
                None => {
                    warn!(remote = %remote_str, service = %target_service,
                        "relay: service not registered");
                    let _ = consumer_send.shutdown().await;
                    continue;
                }
            };

            // Initial reply rate for this connection: prefer the
            // per-consumer override, fall back to the server default.
            // When the master switch is off (`default_reply_bps ==
            // None`), pass `None` through so `run_relay` skips the
            // rate-handle allocation entirely.
            let initial_reply_bps = self.default_reply_bps.as_ref().map(|handle| {
                self.state
                    .lookup_relay_rate_override(consumer_node_id)
                    .unwrap_or_else(|| handle.load(std::sync::atomic::Ordering::Relaxed))
            });
            if let Some(bps) = initial_reply_bps {
                debug!(
                    consumer = %consumer_node_id.fmt_short(),
                    initial_reply_bps = bps,
                    "relay: picked initial rate for consumer"
                );
            } else {
                debug!(
                    consumer = %consumer_node_id.fmt_short(),
                    "relay: rate limiting disabled at master switch; forwarding unthrottled"
                );
            }

            let endpoint = self.endpoint.clone();
            let state = self.state.clone();
            let svc = target_service.clone();
            let remote_str2 = remote_str.clone();
            tokio::spawn(async move {
                if let Err(e) = run_relay(
                    endpoint,
                    state,
                    initial_reply_bps,
                    provider,
                    svc,
                    consumer_send,
                    consumer_recv,
                )
                .await
                {
                    warn!(remote = %remote_str2, err = %e, "relay task ended with error");
                } else {
                    debug!(remote = %remote_str2, "relay task ended cleanly");
                }
            });
        }
    }

    fn lookup_service_any_group(&self, service: &str) -> Option<EndpointId> {
        for entry in self.state.dump_services() {
            if entry.1 == service {
                return Some(entry.2);
            }
        }
        None
    }
}

async fn run_relay(
    endpoint: Endpoint,
    state: Arc<ServerState>,
    initial_reply_bps: Option<u64>,
    provider: EndpointId,
    target_service: String,
    consumer_send: iroh::endpoint::SendStream,
    consumer_recv: iroh::endpoint::RecvStream,
) -> anyhow::Result<()> {
    let alpn = alpn_for_service(&target_service)?;
    let addr = EndpointAddr::new(provider);
    let provider_conn = endpoint
        .connect(addr, &alpn)
        .await
        .context("relay: connect to provider")?;

    let (prov_send, prov_recv) = provider_conn
        .open_bi()
        .await
        .context("relay: open_bi to provider")?;

    // Per-connection rate handle. Only allocated when the master
    // switch is on; `None` means the relay will byte-bridge both
    // directions as fast as QUIC allows.
    let stream_id = state.alloc_stream_id();
    let reply_bps = match initial_reply_bps {
        Some(bps) => {
            let handle = Arc::new(AtomicU64::new(bps));
            state.register_relay_rate(stream_id, handle.clone());
            Some(handle)
        }
        None => None,
    };

    info!(
        provider = %provider.fmt_short(), service = %target_service,
        stream_id, reply_bps = ?reply_bps.as_ref().map(|h| h.load(std::sync::atomic::Ordering::Relaxed)),
        "relay: tunnel established"
    );

    let copied = match copy_bidirectional(
        (consumer_recv, consumer_send),
        (prov_recv, prov_send),
        reply_bps,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            state.unregister_relay_rate(stream_id);
            return Err(e);
        }
    };

    state.unregister_relay_rate(stream_id);
    info!(
        provider = %provider.fmt_short(), service = %target_service,
        stream_id, request_bytes = copied.0, reply_bytes = copied.1,
        "relay: tunnel closed"
    );

    Ok(())
}

/// Bidirectional copy between two pairs of (recv, send). The
/// `provider → consumer` direction (`b_to_a`) is throttled by
/// `reply_bps` when present; the `consumer → provider` direction is
/// always passed through unthrottled. `reply_bps = None` means the
/// master switch is off and **both** directions use plain
/// `tokio::io::copy`.
///
/// Returns `(request_bytes, reply_bytes)`.
async fn copy_bidirectional(
    a: (iroh::endpoint::RecvStream, iroh::endpoint::SendStream),
    b: (iroh::endpoint::RecvStream, iroh::endpoint::SendStream),
    reply_bps: Option<RateLimitHandle>,
) -> anyhow::Result<(u64, u64)> {
    let (mut ar, mut as_) = (a.0, a.1);
    let (mut br, mut bs) = (b.0, b.1);

    // Request: consumer → provider, never throttled.
    let a_to_b = async {
        tokio::io::copy(&mut ar, &mut bs)
            .await
            .context("relay: request copy (consumer->provider)")
    };

    // Reply: provider → consumer. Pick the right flavor based on
    // whether the master switch is on. Both branches borrow `br`/`as_`
    // rather than moving them so the shutdown calls below still work.
    let (r1, r2) = match reply_bps {
        Some(handle) => {
            let throttled = async {
                ratelimit::copy_throttled(&mut br, &mut as_, &handle)
                    .await
                    .context("relay: throttled reply copy (provider->consumer)")
            };
            tokio::join!(a_to_b, throttled)
        }
        None => {
            let unthrottled = async {
                tokio::io::copy(&mut br, &mut as_)
                    .await
                    .context("relay: unthrottled reply copy (provider->consumer)")
            };
            tokio::join!(a_to_b, unthrottled)
        }
    };

    let request_bytes = r1?;
    let reply_bytes = r2?;
    let _ = as_.shutdown().await;
    let _ = bs.shutdown().await;
    Ok((request_bytes, reply_bytes))
}