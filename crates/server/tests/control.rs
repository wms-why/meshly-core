//! Phase 2 — control plane integration tests.
//!
//! These tests exercise the production `ControlHandler` (the
//! `ProtocolHandler` registered on ALPN `meshly-core/control`) end-to-end
//! over a real Iroh transport. The handler's private modules are re-
//! included via `#[path]` so the tests can construct it directly
//! without exposing a library crate (the production binary's `Cargo.toml`
//! has no `[lib]` section).

mod common;

// Re-include the server's private modules so we can construct
// `ControlHandler` and `ServerState` from the test binary.
#[path = "../src/registry.rs"]
mod registry;
#[path = "../src/control.rs"]
mod control;

use std::sync::Arc;
use std::time::Duration;

use iroh::EndpointId;
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;

use meshly_core_common::config::GroupConfig;
use meshly_core_common::protocol::{
    Frame, Hello, HelloOk, Register, RegisterOk, Subscribe, SubscribeOk,
};

use crate::control::{ControlConfig, ControlHandler};
use crate::registry::ServerState;

const TEST_GROUP_TOKEN: &str = "test-group-token";
const TEST_GROUP_NAME: &str = "default";

/// Build a `ServerState` with a single group that accepts `TEST_GROUP_TOKEN`.
fn make_state() -> Arc<ServerState> {
    ServerState::new(
        &[GroupConfig {
            name: TEST_GROUP_NAME.into(),
            group_token: TEST_GROUP_TOKEN.into(),
        }],
        &[],
    )
}

/// Build a `ControlHandler` with stable heartbeat config so the test
/// doesn't sit in the writer loop.
fn make_handler(state: Arc<ServerState>) -> Arc<ControlHandler> {
    Arc::new(ControlHandler {
        state,
        config: ControlConfig {
            heartbeat_interval: Duration::from_secs(3600),
            heartbeat_timeout: Duration::from_secs(1800),
        },
    })
}

/// Open the server's control plane as a real Iroh endpoint + Router
/// and return the address + router handle. The caller must keep the
/// router alive for the duration of the test.
async fn spawn_control_provider(
    state: Arc<ServerState>,
) -> (iroh::EndpointId, iroh::protocol::Router) {
    let dir = tempdir().unwrap();
    let (server_ep, _router) = common::test_provider(
        dir.path(),
        meshly_core_common::alpn::alpn_control(),
        make_handler(state),
    )
    .await
    .unwrap();
    let server_id = server_ep.secret_key().public();
    // test_provider returns (endpoint, router); we re-bind below to
    // surface both. This works because router is held by the inner
    // tuple.
    (server_id, _router)
}

/// Read a single frame from `r`, but treat a `ConnectionLost` IO error
/// as a valid signal that the server tore the connection down before
/// delivering — the test caller will decide whether that's the
/// expected outcome (e.g. server rejected hello and closed).
async fn read_frame_or_lost<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Frame, tokio::io::Error> {
    match Frame::read_from(r).await {
        Ok(f) => Ok(f),
        Err(e) => match e {
            meshly_core_common::protocol::FrameError::Io(io) => Err(io),
            other => panic!("read frame failed: {other:?}"),
        },
    }
}

/// Read a single frame; panics on any error.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Frame {
    match read_frame_or_lost(r).await {
        Ok(f) => f,
        Err(e) => panic!("read frame from server: {e}"),
    }
}

// ----------------------------------------------------------------------
// Test 1: hello → register happy path
// ----------------------------------------------------------------------
#[tokio::test]
async fn server_handles_hello_then_register() {
    let state = make_state();
    let dir = tempdir().unwrap();
    let (server_ep, router) = common::test_provider(
        dir.path(),
        meshly_core_common::alpn::alpn_control(),
        make_handler(state.clone()),
    )
    .await
    .unwrap();
    let server_addr = server_ep.addr();

    let client_dir = tempdir().unwrap();
    let (client_ep, _key) = common::test_endpoint(client_dir.path()).await.unwrap();

    let conn = client_ep
        .connect(server_addr, b"meshly-core/control")
        .await
        .expect("connect to server control plane");

    // Stream 1: Hello -> HelloOk
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi for hello");
    Frame::Hello(Hello {
        group_token: TEST_GROUP_TOKEN.into(),
        client_info: "test/0.1".into(),
    })
    .write_to(&mut send)
    .await
    .expect("write hello");
    let resp = read_frame(&mut recv).await;
    match resp {
        Frame::HelloOk(HelloOk { session_id }) => {
            assert_ne!(session_id, 0, "session_id should be non-zero");
        }
        other => panic!("expected HelloOk, got {other:?}"),
    }
    send.shutdown().await.ok();

    // Stream 2: Register -> RegisterOk
    let (mut s, mut r) = conn.open_bi().await.expect("open bi for register");
    Frame::Register(Register {
        service: "ssh".into(),
    })
    .write_to(&mut s)
    .await
    .expect("write register");
    let resp = read_frame(&mut r).await;
    match resp {
        Frame::RegisterOk(RegisterOk { service }) => {
            assert_eq!(service, "ssh");
        }
        other => panic!("expected RegisterOk, got {other:?}"),
    }
    s.shutdown().await.ok();

    // Verify the service was registered.
    let provider_id = state
        .lookup_service(TEST_GROUP_NAME, "ssh")
        .expect("service ssh should be registered");
    assert_eq!(provider_id, client_ep.secret_key().public());

    drop(conn);
    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 2: wrong group_token -> ControlError
// ----------------------------------------------------------------------
#[tokio::test]
async fn server_rejects_hello_with_wrong_group_token() {
    let state = make_state();
    let dir = tempdir().unwrap();
    let (server_ep, router) = common::test_provider(
        dir.path(),
        meshly_core_common::alpn::alpn_control(),
        make_handler(state.clone()),
    )
    .await
    .unwrap();
    let server_addr = server_ep.addr();

    let client_dir = tempdir().unwrap();
    let (client_ep, _key) = common::test_endpoint(client_dir.path()).await.unwrap();

    let conn = client_ep
        .connect(server_addr, b"meshly-core/control")
        .await
        .expect("connect to server control plane");

    let (mut send, mut recv) = conn.open_bi().await.expect("open bi for hello");
    Frame::Hello(Hello {
        group_token: "wrong-token".into(),
        client_info: "test/0.1".into(),
    })
    .write_to(&mut send)
    .await
    .expect("write hello");
    send.shutdown().await.ok();
    // The server returns from its handler right after writing the
    // error, which causes iroh to close the whole QUIC connection.
    // Either outcome is valid: we read the ControlError before the
    // close, or the close arrives first. Both signal rejection.
    let resp = read_frame_or_lost(&mut recv).await;
    match resp {
        Ok(Frame::ControlError { code, reason }) => {
            assert_eq!(code, 1, "AUTH/UNKNOWN_GROUP code = 1");
            assert!(
                reason.contains("unknown group"),
                "reason should explain: {reason}"
            );
        }
        Ok(other) => panic!("expected ControlError, got {other:?}"),
        Err(e) => {
            // ConnectionLost is acceptable — the server rejected the
            // hello and tore down the connection before we could read
            // the error frame.
            assert!(
                matches!(
                    e.kind(),
                    tokio::io::ErrorKind::NotConnected
                        | tokio::io::ErrorKind::UnexpectedEof
                ),
                "unexpected io error: {e:?}"
            );
        }
    }

    drop(conn);
    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 3: provider registers, consumer subscribes -> gets provider id
// ----------------------------------------------------------------------
#[tokio::test]
async fn server_returns_subscribe_ok_with_provider_node_id() {
    let state = make_state();
    let dir = tempdir().unwrap();
    let (server_ep, router) = common::test_provider(
        dir.path(),
        meshly_core_common::alpn::alpn_control(),
        make_handler(state.clone()),
    )
    .await
    .unwrap();
    let server_addr = server_ep.addr();

    // Provider endpoint: registers the service "web".
    let provider_dir = tempdir().unwrap();
    let (provider_ep, _pkey) = common::test_endpoint(provider_dir.path()).await.unwrap();
    let provider_id = provider_ep.secret_key().public();

    let provider_conn = provider_ep
        .connect(server_addr.clone(), b"meshly-core/control")
        .await
        .expect("provider connects");
    let (mut ps, mut pr) = provider_conn.open_bi().await.expect("provider open bi");
    Frame::Hello(Hello {
        group_token: TEST_GROUP_TOKEN.into(),
        client_info: "provider/0.1".into(),
    })
    .write_to(&mut ps)
    .await
    .expect("provider hello");
    let resp = read_frame(&mut pr).await;
    assert!(matches!(resp, Frame::HelloOk(_)), "got {resp:?}");
    ps.shutdown().await.ok();
    drop(provider_conn);

    // Server registry reflects the registered provider.
    // (Note: drop_session was not called, so the provider's session is
    // still alive in the registry. We directly insert the service
    // record since the test focuses on subscribe lookup semantics; the
    // full register+session lifecycle is covered by Test 1.)
    state
        .group(TEST_GROUP_NAME)
        .unwrap()
        .register_service("web", provider_id)
        .expect("register service web");

    // Consumer endpoint: subscribes to "web".
    let consumer_dir = tempdir().unwrap();
    let (consumer_ep, _ckey) = common::test_endpoint(consumer_dir.path()).await.unwrap();

    let consumer_conn = consumer_ep
        .connect(server_addr, b"meshly-core/control")
        .await
        .expect("consumer connects");
    let (mut cs, mut cr) = consumer_conn.open_bi().await.expect("consumer open bi hello");
    Frame::Hello(Hello {
        group_token: TEST_GROUP_TOKEN.into(),
        client_info: "consumer/0.1".into(),
    })
    .write_to(&mut cs)
    .await
    .expect("consumer hello");
    let resp = read_frame(&mut cr).await;
    assert!(matches!(resp, Frame::HelloOk(_)), "got {resp:?}");
    cs.shutdown().await.ok();
    drop(cr);

    let (mut cs2, mut cr2) = consumer_conn
        .open_bi()
        .await
        .expect("consumer open bi subscribe");
    Frame::Subscribe(Subscribe {
        service: "web".into(),
    })
    .write_to(&mut cs2)
    .await
    .expect("consumer subscribe");
    let resp = read_frame(&mut cr2).await;
    match resp {
        Frame::SubscribeOk(SubscribeOk {
            service,
            provider_node_id: Some(id),
            relay_required,
        }) => {
            assert_eq!(service, "web");
            assert_eq!(id, provider_id.to_string(), "id mismatch");
            assert!(!relay_required, "relay_required should be false in v1");
        }
        other => panic!("expected SubscribeOk with provider id, got {other:?}"),
    }
    cs2.shutdown().await.ok();

    drop(consumer_conn);
    drop(consumer_ep);
    drop(provider_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 4: subscribe for unknown service -> SubscribeOk { provider: None }
// ----------------------------------------------------------------------
#[tokio::test]
async fn server_returns_subscribe_err_when_service_unknown() {
    let state = make_state();
    let dir = tempdir().unwrap();
    let (server_ep, router) = common::test_provider(
        dir.path(),
        meshly_core_common::alpn::alpn_control(),
        make_handler(state.clone()),
    )
    .await
    .unwrap();
    let server_addr = server_ep.addr();

    let client_dir = tempdir().unwrap();
    let (client_ep, _key) = common::test_endpoint(client_dir.path()).await.unwrap();

    let conn = client_ep
        .connect(server_addr, b"meshly-core/control")
        .await
        .expect("connect");
    let (mut s, mut r) = conn.open_bi().await.expect("open bi hello");
    Frame::Hello(Hello {
        group_token: TEST_GROUP_TOKEN.into(),
        client_info: "test/0.1".into(),
    })
    .write_to(&mut s)
    .await
    .expect("hello");
    let resp = read_frame(&mut r).await;
    assert!(matches!(resp, Frame::HelloOk(_)), "got {resp:?}");
    s.shutdown().await.ok();
    drop(r);

    let (mut s, mut r) = conn.open_bi().await.expect("open bi subscribe");
    Frame::Subscribe(Subscribe {
        service: "no-such-service".into(),
    })
    .write_to(&mut s)
    .await
    .expect("subscribe");
    let resp = read_frame(&mut r).await;
    // The server replies with SubscribeOk { provider_node_id: None }
    // for an unknown service (it does NOT reply ControlError). This is
    // the contract the client consumes.
    match resp {
        Frame::SubscribeOk(SubscribeOk {
            service,
            provider_node_id,
            relay_required: _,
        }) => {
            assert_eq!(service, "no-such-service");
            assert!(
                provider_node_id.is_none(),
                "expected provider_node_id None, got {provider_node_id:?}"
            );
        }
        other => panic!("expected SubscribeOk with None provider, got {other:?}"),
    }

    drop(conn);
    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 5: heartbeat timeout reaps the session
// ----------------------------------------------------------------------
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn server_reaps_expired_session_on_heartbeat_timeout() {
    use std::time::Instant;

    // Build a state whose group will record sessions.
    let state = make_state();
    let group = state.group(TEST_GROUP_NAME).expect("group present");

    // Synthetic provider id (no Iroh endpoint needed for this test;
    // we only care about the registry's session bookkeeping).
    let fake_provider: EndpointId =
        iroh::SecretKey::generate().public();

    // Insert a session + service record as if the provider had
    // registered earlier, but with an OLD last_heartbeat (older than
    // the production `heartbeat.timeout_secs`) so the sweeper can
    // classify it as expired deterministically. `Instant` is not
    // mockable by tokio's paused clock, so we set the value directly.
    group.touch_session(fake_provider);
    {
        let old = Instant::now() - Duration::from_secs(120);
        let mut entry = group.sessions.get_mut(&fake_provider).expect("session present");
        entry.last_heartbeat = old;
    }
    group
        .register_service("ssh", fake_provider)
        .expect("register service");
    assert_eq!(state.session_count(), 1);
    assert!(state.lookup_service(TEST_GROUP_NAME, "ssh").is_some());

    // The heartbeat timeout used in production (`heartbeat.timeout_secs`).
    let timeout = Duration::from_secs(60);

    // Run the same sweep the server's sweeper runs after the timer
    // fires. With the session's last_heartbeat already 120 s in the
    // past, the cutoff (now - 60 s) is greater than last_heartbeat
    // and the session is reaped.
    sweep_dead_sessions(&state, timeout);

    assert_eq!(
        state.session_count(),
        0,
        "session should be reaped after timeout"
    );
    assert!(
        state.lookup_service(TEST_GROUP_NAME, "ssh").is_none(),
        "service should be reaped alongside session"
    );
}

/// Drop sessions whose last heartbeat is older than `timeout`.
/// Mirror of `sweep_dead_sessions` in `server/src/main.rs`.
fn sweep_dead_sessions(state: &Arc<ServerState>, timeout: Duration) {
    let cutoff = std::time::Instant::now() - timeout;
    for entry in state.dump_services() {
        let group_name = &entry.0;
        if let Some(g) = state.group(group_name) {
            let dead: Vec<_> = g
                .sessions
                .iter()
                .filter(|s| s.last_heartbeat < cutoff)
                .map(|s| *s.key())
                .collect();
            for id in dead {
                g.drop_session(id);
            }
        }
    }
    // Silence unused-import warning if VecDeque is removed.
    let _ = std::collections::VecDeque::<u8>::new();
}

// Tiny compile-time sanity check: confirm our module references line up.
#[allow(dead_code)]
fn _module_link_check(_f: Frame) -> EndpointId {
    // This function exists solely so the compiler will fail loudly if
    // any of the `use` paths above drift out of sync with the source.
    iroh::SecretKey::generate().public()
}