//! Consume mode: subscribe to a remote service and expose it on a local port.
//!
//! Flow on startup:
//!
//! 1. Connect to server's control plane, send `Hello`, then `Subscribe`.
//! 2. Read `SubscribeOk` to learn the provider's NodeID.
//! 3. Dial the provider directly on ALPN `frp2p/<service>` (P2P path).
//!    On failure, fall back to server relay on ALPN `frp2p/data`.
//! 4. Open a local TCP listener; for each accepted connection, open a
//!    new bi-stream on the (possibly relayed) provider connection and
//!    bridge bytes both ways.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use frp2p_common::alpn::alpn_for_service;
use frp2p_common::protocol::{
    AuthNonce, AuthOk, AuthProof, AuthErr, Frame, Hello, HelloOk, Subscribe, SubscribeOk,
    AUTH_ERR_BAD_PROOF,
};
use frp2p_common::tunnel::{bridge, BiStream};

use crate::expose::make_proof;

/// Description of one remote service to consume.
#[derive(Debug, Clone)]
pub struct ConsumeSpec {
    pub name: String,
    pub local_bind: SocketAddr,
    pub shared_secret: Vec<u8>,
}

/// Shared state for a consume service: holds the lazy / cached
/// connection to the provider.
pub struct ConsumeState {
    pub spec: ConsumeSpec,
    pub server_node_id: EndpointId,
    pub group_token: String,
    pub endpoint: Endpoint,
    pub conn: Mutex<Option<Connection>>,
    pub reconnect: ReconnectConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct ReconnectConfig {
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub prefer_direct: bool,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_backoff_ms: 50,
            max_backoff_ms: 5000,
            prefer_direct: true,
        }
    }
}

/// Subscribe to `service` and return the provider's NodeID.
pub async fn subscribe(
    endpoint: &Endpoint,
    server_node_id: EndpointId,
    group_token: &str,
    service: &str,
) -> Result<EndpointId> {
    let conn = endpoint
        .connect(EndpointAddr::new(server_node_id), b"frp2p/control")
        .await
        .context("connect to server control plane")?;

    let (mut send, mut recv) = conn.open_bi().await?;
    Frame::Hello(Hello {
        group_token: group_token.to_string(),
        client_info: format!("frp2p-client/{}", env!("CARGO_PKG_VERSION")),
    })
    .write_to(&mut send)
    .await?;
    match Frame::read_from(&mut recv).await? {
        Frame::HelloOk(HelloOk { session_id }) => {
            info!(session_id, "server hello-ok received (subscribe)");
        }
        Frame::ControlError { code, reason } => {
            anyhow::bail!("server rejected hello: code={code} reason={reason}");
        }
        other => anyhow::bail!("unexpected frame after hello: {other:?}"),
    }

    // Open a second stream for the Subscribe request.
    drop(send);
    drop(recv);
    let (mut s, mut r) = conn.open_bi().await?;
    Frame::Subscribe(Subscribe { service: service.to_string() })
        .write_to(&mut s)
        .await?;
    let resp = Frame::read_from(&mut r).await?;
    let provider_id = match resp {
        Frame::SubscribeOk(SubscribeOk {
            provider_node_id: Some(id),
            ..
        }) => id,
        Frame::SubscribeOk(SubscribeOk {
            provider_node_id: None,
            ..
        }) => anyhow::bail!("server has no provider for service {service:?}"),
        Frame::ControlError { code, reason } => {
            anyhow::bail!("subscribe rejected: code={code} reason={reason}");
        }
        other => anyhow::bail!("unexpected frame after subscribe: {other:?}"),
    };
    let _ = s.shutdown().await;

    let provider: EndpointId = provider_id
        .parse()
        .with_context(|| format!("invalid provider id {provider_id:?}"))?;
    Ok(provider)
}

/// Run the consumer service: bind local listener, accept TCP, forward to provider.
pub async fn run(state: Arc<ConsumeState>) -> Result<()> {
    let listener = TcpListener::bind(state.spec.local_bind)
        .await
        .with_context(|| format!("bind local {}", state.spec.local_bind))?;
    let local_addr = listener.local_addr()?;
    info!(
        service = %state.spec.name,
        local = %local_addr,
        provider = %state.server_node_id.fmt_short(),
        "consumer service ready"
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(t) => t,
            Err(e) => {
                warn!(err = %e, "accept failed");
                continue;
            }
        };
        let service_name = state.spec.name.clone();
        debug!(service = %service_name, ?peer, "local TCP accepted");
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_one(state, tcp).await {
                warn!(service = %service_name, err = %e, "forward ended");
            }
        });
    }
}

async fn forward_one(state: Arc<ConsumeState>, tcp: tokio::net::TcpStream) -> Result<()> {
    let conn = acquire_or_dial(&state).await?;
    let (send, recv) = conn.open_bi().await?;
    let service_name = state.spec.name.clone();
    let copied = bridge(tcp, BiStream::new(recv, send)).await?;
    debug!(
        service = %service_name,
        bytes = copied.a_to_b + copied.b_to_a,
        "forward complete"
    );
    Ok(())
}

async fn acquire_or_dial(state: &Arc<ConsumeState>) -> Result<Connection> {
    {
        let guard = state.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
    }
    // Dial with retry + backoff. We resolve the provider id lazily on
    // first dial so the user's Subscribe call is the source of truth.
    let mut backoff_ms = state.reconnect.initial_backoff_ms;
    loop {
        match dial_provider(state).await {
            Ok(c) => {
                let mut guard = state.conn.lock().await;
                *guard = Some(c.clone());
                return Ok(c);
            }
            Err(e) => {
                warn!(service = %state.spec.name, err = %e,
                    backoff_ms, "dial provider failed; retrying");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(state.reconnect.max_backoff_ms);
            }
        }
    }
}

async fn dial_provider(state: &Arc<ConsumeState>) -> Result<Connection> {
    // Resolve provider id (cached via subscribe? For v1 we re-subscribe
    // each time after a dial failure to refresh the id in case the
    // provider restarted).
    let provider_id = subscribe(
        &state.endpoint,
        state.server_node_id,
        &state.group_token,
        &state.spec.name,
    )
    .await?;

    let alpn = alpn_for_service(&state.spec.name)?;
    // Try direct first if prefer_direct.
    let direct_result = if state.reconnect.prefer_direct {
        let service_name = state.spec.name.clone();
        let shared_secret = state.spec.shared_secret.clone();
        let r: Result<Connection> = async {
            let conn = state
                .endpoint
                .connect(EndpointAddr::new(provider_id), &alpn)
                .await?;
            // Authenticate.
            let (mut send, mut recv) = conn.open_bi().await?;
            let nonce_frame = Frame::read_from(&mut recv).await?;
            let nonce = match nonce_frame {
                Frame::AuthNonce(AuthNonce { nonce }) => nonce,
                Frame::AuthErr(AuthErr { code, reason }) => {
                    return Err(anyhow!("provider auth err code={code} reason={reason}"));
                }
                _ => return Err(anyhow!("expected AuthNonce, got {nonce_frame:?}")),
            };
            let proof = make_proof(&shared_secret, &service_name, &nonce);
            Frame::AuthProof(AuthProof { mac: proof })
                .write_to(&mut send)
                .await?;
            let auth_resp = Frame::read_from(&mut recv).await?;
            match auth_resp {
                Frame::AuthOk(AuthOk) => {
                    debug!(service = %service_name, "direct auth ok");
                    drop(send);
                    drop(recv);
                    Ok(conn)
                }
                Frame::AuthErr(AuthErr { code, reason }) => {
                    Err(anyhow!("provider rejected proof: code={code} reason={reason}"))
                }
                _ => Err(anyhow!("expected AuthOk, got {auth_resp:?}")),
            }
        }
        .await;
        Some(r)
    } else {
        None
    };

    match direct_result {
        Some(Ok(c)) => Ok(c),
        Some(Err(e)) => {
            warn!(service = %state.spec.name, err = %e,
                "direct P2P failed; falling back to server relay");
            dial_via_relay(state, provider_id).await
        }
        None => dial_via_relay(state, provider_id).await,
    }
}

async fn dial_via_relay(state: &Arc<ConsumeState>, provider_id: EndpointId) -> Result<Connection> {
    // Connect to server on frp2p/data ALPN. We open a fresh connection per
    // forwarded stream (the server's relay handler expects this).
    let conn = state
        .endpoint
        .connect(EndpointAddr::new(state.server_node_id), b"frp2p/data")
        .await?;
    let (mut send, recv) = conn.open_bi().await?;
    let svc = state.spec.name.clone();
    Frame::DataOpen {
        target_service: svc,
        target_provider: provider_id.to_string(),
        proof: [0u8; 32],
    }
    .write_to(&mut send)
    .await?;
    // Drop our local handle on the negotiation stream; the relay task will
    // open its own provider-side stream.
    drop(send);
    drop(recv);
    Ok(conn)
}

// Suppress dead-code warning for the imported proof helper used above.
#[allow(dead_code)]
fn _unused() -> Result<()> {
    let _ = AUTH_ERR_BAD_PROOF;
    Ok(())
}