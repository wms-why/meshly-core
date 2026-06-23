//! Relay protocol handler (ALPN `frp2p/data`).
//!
//! Wire format on this ALPN:
//!
//! 1. Consumer opens a bi-stream.
//! 2. Consumer writes a single `Frame::DataOpen { target_service,
//!    target_provider, proof: [0u8; 32] }`. (proof is unused in v1.)
//! 3. Server checks: target_service is registered and target_provider matches.
//! 4. Server dials the provider on ALPN `frp2p/<target_service>` and opens a
//!    bi-stream.
//! 5. Server performs a dumb byte relay between the two bi-streams.

use std::sync::Arc;

use anyhow::Context;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use frp2p_common::alpn::alpn_for_service;
use frp2p_common::protocol::Frame;

use crate::registry::ServerState;

/// Protocol handler for the data-plane relay.
#[derive(Debug, Clone)]
pub struct RelayHandler {
    pub endpoint: Endpoint,
    pub state: Arc<ServerState>,
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

            let (target_service, target_provider_str) = match frame {
                Frame::DataOpen { target_service, target_provider, .. } => {
                    (target_service, target_provider)
                }
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

            let endpoint = self.endpoint.clone();
            let svc = target_service.clone();
            let remote_str2 = remote_str.clone();
            tokio::spawn(async move {
                if let Err(e) = run_relay(endpoint, provider, svc, consumer_send, consumer_recv).await {
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

fn parse_endpoint_id(s: &str) -> Option<EndpointId> {
    if let Ok(id) = s.parse::<EndpointId>() {
        return Some(id);
    }
    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return iroh::PublicKey::from_bytes(&arr).ok();
        }
    }
    None
}

async fn run_relay(
    endpoint: Endpoint,
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

    info!(provider = %provider.fmt_short(), service = %target_service,
        "relay: tunnel established");

    let copied = copy_bidirectional(
        (consumer_recv, consumer_send),
        (prov_recv, prov_send),
    )
    .await?;
    info!(provider = %provider.fmt_short(), service = %target_service,
        bytes = copied, "relay: tunnel closed");

    Ok(())
}

/// Bidirectional copy between two pairs of (recv, send).
async fn copy_bidirectional(
    a: (iroh::endpoint::RecvStream, iroh::endpoint::SendStream),
    b: (iroh::endpoint::RecvStream, iroh::endpoint::SendStream),
) -> anyhow::Result<u64> {
    let (mut ar, mut as_) = (a.0, a.1);
    let (mut br, mut bs) = (b.0, b.1);
    let a_to_b = tokio::io::copy(&mut ar, &mut bs);
    let b_to_a = tokio::io::copy(&mut br, &mut as_);
    let (r1, r2) = tokio::join!(a_to_b, b_to_a);
    let total = r1? + r2?;
    let _ = as_.shutdown().await;
    let _ = bs.shutdown().await;
    Ok(total)
}