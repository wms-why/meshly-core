//! Control-plane protocol handler (ALPN `meshly-core/control`).
//!
//! Each accepted Connection runs the following sequence:
//!
//! 1. Read `Hello { group_token, client_info }`. Verify the token.
//! 2. Reply `HelloOk { session_id }`.
//! 3. Loop on inbound frames until the client disconnects:
//!    - `Register { service }`  -> reply `RegisterOk` or `ControlError`
//!    - `Subscribe { service }` -> reply `SubscribeOk { provider, relay_required }`
//!    - `Heartbeat`             -> update last_heartbeat

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use meshly_core_common::protocol::{Frame, Register, Subscribe};

use crate::registry::{Group, ServerState};

/// Server-side configuration knobs.
#[derive(Debug, Clone, Copy)]
pub struct ControlConfig {
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
}

/// Protocol handler for the control plane.
#[derive(Debug)]
pub struct ControlHandler {
    pub state: Arc<ServerState>,
    pub config: ControlConfig,
}

impl ProtocolHandler for ControlHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        let remote_str = remote.fmt_short().to_string();
        debug!(remote = %remote_str, "control connection accepted");

        match self.run_session(conn, remote).await {
            Ok(()) => {
                debug!(remote = %remote_str, "control session ended cleanly");
                Ok(())
            }
            Err(e) => {
                warn!(remote = %remote_str, error = %e, "control session ended with error");
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                Err(AcceptError::from_boxed(boxed))
            }
        }
    }

    async fn shutdown(&self) {}
}

impl ControlHandler {
    async fn run_session(&self, conn: Connection, remote: EndpointId) -> anyhow::Result<()> {
        // 1. Wait for Hello on the first bi-stream.
        let (mut send, mut recv) = conn.accept_bi().await?;
        let hello_frame = Frame::read_from(&mut recv).await?;
        let hello = match hello_frame {
            Frame::Hello(h) => h,
            other => {
                warn!(remote = %remote.fmt_short(), got = ?other,
                    "expected Hello as first frame");
                return Ok(());
            }
        };

        // group_token doubles as group identifier in v1.
        let group = match self.state.authenticate(&hello.group_token) {
            Some(g) => g,
            None => {
                warn!(remote = %remote.fmt_short(), token = %hello.group_token,
                    "control hello: unknown group");
                let _ = Frame::ControlError {
                    code: 1,
                    reason: "unknown group".into(),
                }
                .write_to(&mut send)
                .await;
                let _ = send.shutdown().await;
                return Ok(());
            }
        };

        group.touch_session(remote);
        info!(remote = %remote.fmt_short(), group = %group.name, info = %hello.client_info,
            "client hello accepted");

        // 2. Send HelloOk.
        let session_id: u64 = rand::random();
        Frame::HelloOk(meshly_core_common::protocol::HelloOk { session_id })
            .write_to(&mut send)
            .await?;
        let _ = send.shutdown().await;
        drop(recv);

        // 3. Heartbeat writer task.
        let hb_send = conn.clone();
        let hb_interval = self.config.heartbeat_interval;
        let hb_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(hb_interval).await;
                let (mut s, _r) = match hb_send.open_bi().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                if Frame::Heartbeat.write_to(&mut s).await.is_err() {
                    break;
                }
                let _ = s.shutdown().await;
            }
        });

        // 4. Main loop: accept new bi-streams for each command.
        loop {
            let (mut s, mut r) = match conn.accept_bi().await {
                Ok(p) => p,
                Err(e) => {
                    debug!(remote = %remote.fmt_short(), err = %e,
                        "control accept_bi ended");
                    break;
                }
            };

            let frame = match Frame::read_from(&mut r).await {
                Ok(f) => f,
                Err(e) => {
                    debug!(remote = %remote.fmt_short(), err = %e,
                        "control read frame failed");
                    break;
                }
            };

            match frame {
                Frame::Register(reg) => {
                    Self::handle_register(&group, remote, &reg, &mut s).await?;
                }
                Frame::Subscribe(sub) => {
                    Self::handle_subscribe(&self.state, &group, &sub, &mut s).await?;
                }
                Frame::Heartbeat => {
                    group.touch_session(remote);
                }
                Frame::Hello(_) => {
                    let _ = Frame::ControlError {
                        code: 2,
                        reason: "Hello already received".into(),
                    }
                    .write_to(&mut s)
                    .await;
                }
                other => {
                    warn!(remote = %remote.fmt_short(), got = ?other,
                        "control: unexpected frame");
                }
            }

            let _ = s.shutdown().await;
        }

        hb_task.abort();
        group.drop_session(remote);
        info!(remote = %remote.fmt_short(), group = %group.name,
            "control session closed");
        Ok(())
    }

    async fn handle_register(
        group: &Arc<Group>,
        remote: EndpointId,
        reg: &Register,
        send: &mut iroh::endpoint::SendStream,
    ) -> anyhow::Result<()> {
        match group.register_service(&reg.service, remote) {
            Ok(prev) => {
                if let Some(prev_id) = prev {
                    warn!(service = %reg.service, prev = %prev_id.fmt_short(),
                        new = %remote.fmt_short(),
                        "service registration replaced previous provider");
                }
                info!(service = %reg.service, provider = %remote.fmt_short(),
                    "service registered");
                Frame::RegisterOk(meshly_core_common::protocol::RegisterOk {
                    service: reg.service.clone(),
                })
                .write_to(send)
                .await?;
            }
            Err(e) => {
                let _ = Frame::ControlError {
                    code: 3,
                    reason: format!("register failed: {e}"),
                }
                .write_to(send)
                .await;
            }
        }
        Ok(())
    }

    async fn handle_subscribe(
        state: &Arc<ServerState>,
        group: &Arc<Group>,
        sub: &Subscribe,
        send: &mut iroh::endpoint::SendStream,
    ) -> anyhow::Result<()> {
        match state.lookup_service(&group.name, &sub.service) {
            Some(provider) => {
                let provider_str = provider.to_string();
                info!(service = %sub.service, provider = %provider_str,
                    "subscription resolved");
                Frame::SubscribeOk(meshly_core_common::protocol::SubscribeOk {
                    service: sub.service.clone(),
                    provider_node_id: Some(provider_str),
                    relay_required: false,
                })
                .write_to(send)
                .await?;
            }
            None => {
                warn!(service = %sub.service, "subscription: service not found");
                Frame::SubscribeOk(meshly_core_common::protocol::SubscribeOk {
                    service: sub.service.clone(),
                    provider_node_id: None,
                    relay_required: false,
                })
                .write_to(send)
                .await?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tag constants are defined in `meshly_core_common::protocol` and used by both
// the client and server through `Frame::tag()`. No re-exports needed here.
// ---------------------------------------------------------------------------