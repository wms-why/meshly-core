//! Expose mode: publish a local TCP service to the group.
//!
//! Flow on startup:
//!
//! 1. Open a control connection to the server (`meshly-core/control`).
//! 2. Send `Hello { group_token, client_info }`, wait for `HelloOk`.
//! 3. For each [[expose]] entry, register the service:
//!    - send `Register { service }`; receive `RegisterOk`.
//! 4. Register a per-service `ProtocolHandler` on the local Router that
//!    accepts P2P connections on ALPN `meshly-core/<service>`, runs the HMAC
//!    handshake with the consumer, then bridges to the local backend.
//!
//! The control connection also serves as a keep-alive: if it dies the
//! client tears down and reconnects.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use meshly_core_common::protocol::{
    compute_proof, verify_proof, AuthNonce, AuthOk, AuthProof, Frame, Hello, HelloOk, Register,
    RegisterOk,
};
use meshly_core_common::tunnel::{bridge, BiStream};

/// Description of one service to expose.
#[derive(Debug, Clone)]
pub struct ExposeSpec {
    pub name: String,
    pub local_addr: SocketAddr,
    pub shared_secret: Vec<u8>,
}

/// Per-service ProtocolHandler for the data ALPN.
#[derive(Debug, Clone)]
pub struct ExposeHandler {
    pub spec: Arc<ExposeSpec>,
}

impl ProtocolHandler for ExposeHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        match self.handle(conn).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(service = %self.spec.name, err = %e, "expose: session ended with error");
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                Err(AcceptError::from_boxed(boxed))
            }
        }
    }
}

impl ExposeHandler {
    async fn handle(&self, conn: Connection) -> anyhow::Result<()> {
        info!(service = %self.spec.name, remote = %conn.remote_id().fmt_short(),
            "expose: incoming connection");

        // We accept the first bi-stream and run the auth handshake.
        let (mut send, mut recv) = conn.accept_bi().await?;
        // Send nonce.
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::rngs::OsRng, &mut nonce[..]);
        Frame::AuthNonce(AuthNonce { nonce }).write_to(&mut send).await?;

        // Receive proof.
        let proof_frame = Frame::read_from(&mut recv).await?;
        let proof = match proof_frame {
            Frame::AuthProof(AuthProof { mac }) => mac,
            _ => {
                warn!(service = %self.spec.name, got = ?proof_frame,
                    "expose: expected AuthProof");
                return Ok(());
            }
        };
        if !verify_proof(&self.spec.shared_secret, &self.spec.name, &nonce, &proof) {
            warn!(service = %self.spec.name, "expose: bad HMAC proof");
            // Send AuthErr so the peer can distinguish bad auth from EOF.
            let _ = Frame::AuthErr(meshly_core_common::protocol::AuthErr {
                code: meshly_core_common::protocol::AUTH_ERR_BAD_PROOF,
                reason: "bad HMAC proof".into(),
            })
            .write_to(&mut send)
            .await;
            let _ = send.shutdown().await;
            return Ok(());
        }
        Frame::AuthOk(AuthOk).write_to(&mut send).await?;
        debug!(service = %self.spec.name, "expose: auth ok, bridging to backend");

        // Dial local backend with a timeout.
        let backend = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(self.spec.local_addr),
        )
        .await
        .map_err(|_| anyhow::anyhow!("backend connect timed out"))?
        .with_context(|| format!("connect backend {}", self.spec.local_addr))?;

        let _stats = bridge(backend, BiStream::new(recv, send)).await?;
        info!(service = %self.spec.name, "expose: tunnel closed");
        Ok(())
    }
}

/// Helper: compute a proof client-side. Exposed for tests + reuse.
pub fn make_proof(secret: &[u8], service: &str, nonce: &[u8; 32]) -> [u8; 32] {
    compute_proof(secret, service, nonce)
}

/// Protocol handler for incoming control connections on the client side.
///
/// The server sends periodic Heartbeat frames over the control connection;
/// we accept those bi-streams, read the heartbeat, and reply with a
/// heartbeat of our own. The connection is otherwise idle.
#[derive(Debug, Default)]
pub struct ControlResponseHandler;

impl ProtocolHandler for ControlResponseHandler {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        // We don't initiate anything; we just consume server-pushed frames.
        let remote = conn.remote_id().fmt_short().to_string();
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            let frame = match Frame::read_from(&mut recv).await {
                Ok(f) => f,
                Err(_) => break,
            };
            if let Frame::Heartbeat = frame {
                tracing::debug!(remote = %remote, "client: heartbeat received");
                let _ = Frame::Heartbeat.write_to(&mut send).await;
            }
            let _ = send.shutdown().await;
        }
        Ok(())
    }
}

/// Open a control connection to the server, send Hello, register all
/// services. Returns the live `Connection` (for keep-alive) and the
/// list of (service_name, alpn) tuples to register on the local Router.
///
/// This function is invoked once on client startup and again on
/// reconnect.
pub async fn register_with_server(
    endpoint: &Endpoint,
    server_node_id: iroh::EndpointId,
    group_token: &str,
    client_info: &str,
    services: &[ExposeSpec],
    static_services: &[super::static_http::StaticSpec],
) -> Result<Connection> {
    let conn = endpoint
        .connect(EndpointAddr::new(server_node_id), b"meshly-core/control")
        .await
        .context("connect to server control plane")?;

    // 1. Hello.
    let (mut send, mut recv) = conn.open_bi().await?;
    Frame::Hello(Hello {
        group_token: group_token.to_string(),
        client_info: client_info.to_string(),
    })
    .write_to(&mut send)
    .await?;
    let hello_ok = Frame::read_from(&mut recv).await?;
    match hello_ok {
        Frame::HelloOk(HelloOk { session_id }) => {
            info!(session_id, "server hello-ok received");
        }
        Frame::ControlError { code, reason } => {
            anyhow::bail!("server rejected hello: code={code} reason={reason}");
        }
        other => anyhow::bail!("unexpected frame after hello: {other:?}"),
    }
    let _ = send.shutdown().await;
    drop(recv);

    // 2. Register each TCP-exposed service on a fresh bi-stream.
    for svc in services {
        let (mut s, mut r) = conn.open_bi().await?;
        Frame::Register(Register { service: svc.name.clone() })
            .write_to(&mut s)
            .await?;
        let resp = Frame::read_from(&mut r).await?;
        match resp {
            Frame::RegisterOk(RegisterOk { service }) => {
                info!(service = %service, "server registered expose service");
            }
            Frame::ControlError { code, reason } => {
                anyhow::bail!("server rejected register({}): code={code} reason={reason}", svc.name);
            }
            other => anyhow::bail!("unexpected frame after register: {other:?}"),
        }
        let _ = s.shutdown().await;
        drop(r);
    }

    // 3. Register each static (HTTP) service the same way. The server side
    //    treats them identically; consumers pick up the name and the kind
    //    is surfaced to consumers as a regular service row (the `kind`
    //    field distinguishes HTTP from TCP).
    for s in static_services {
        let (mut stream, mut r) = conn.open_bi().await?;
        Frame::Register(Register { service: s.name.clone() })
            .write_to(&mut stream)
            .await?;
        let resp = Frame::read_from(&mut r).await?;
        match resp {
            Frame::RegisterOk(RegisterOk { service }) => {
                info!(service = %service, "server registered static service");
            }
            Frame::ControlError { code, reason } => {
                anyhow::bail!(
                    "server rejected register({} static): code={code} reason={reason}",
                    s.name
                );
            }
            other => anyhow::bail!("unexpected frame after register: {other:?}"),
        }
        let _ = stream.shutdown().await;
        drop(r);
    }

    Ok(conn)
}

/// Identity bootstrap helper for the client (same pattern as server).
pub fn load_identity_for_client(
    identity_path: Option<&std::path::Path>,
) -> anyhow::Result<(iroh::SecretKey, String)> {
    let (key, paths) = match identity_path {
        Some(p) => meshly_core_common::load_or_generate_at(p)?,
        None => meshly_core_common::load_or_generate()?,
    };
    let node_id = key.public().to_string();
    tracing::info!(node_id = %node_id, identity = %paths.key_file.display(),
        "client identity ready");
    Ok((key, node_id))
}