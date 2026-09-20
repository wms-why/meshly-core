//! Phase 2 — control plane integration tests (client side).
//!
//! Exercises `consume::subscribe` and `expose::register_with_server`
//! against a scripted fake server. The client crate is a binary, so
//! its private modules are re-included via `#[path]` so we can call
//! the production code under test.

mod common;

// Re-include the client crate's private modules so the tests can call
// `subscribe` and `register_with_server` from the test binary.
#[path = "../src/status.rs"]
mod status;
#[path = "../src/static_http.rs"]
mod static_http;
#[path = "../src/expose.rs"]
mod expose;
#[path = "../src/consume.rs"]
mod consume;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;

use meshly_core_common::protocol::{
    Frame, HelloOk, RegisterOk, SubscribeOk,
};

use crate::consume::subscribe;
use crate::expose::{register_with_server, ExposeSpec};

const TEST_GROUP_TOKEN: &str = "test-token";

// ----------------------------------------------------------------------
// Fake server: scripted ProtocolHandler that replays a pre-recorded
// sequence of frames back to the client.
// ----------------------------------------------------------------------

#[derive(Debug, Clone)]
enum FakeStep {
    /// Read any incoming frame, then send the supplied response.
    ExpectAnyThenRespond(Frame),
    /// Expect `Hello`, then respond with `HelloOk { session_id: 42 }`.
    ExpectHelloThenHelloOk,
    /// Expect `Hello`, then respond with `ControlError`.
    ExpectHelloThenError { code: u16, reason: String },
    /// Expect `Register`, then echo back `RegisterOk { service }`.
    ExpectRegisterThenRegisterOk { service: String },
    /// Expect `Register`, then respond with `ControlError`.
    ExpectRegisterThenError { code: u16, reason: String },
    /// Expect `Subscribe`, then respond with `SubscribeOk`.
    ExpectSubscribeThenSubscribeOk {
        service: String,
        provider_node_id: Option<String>,
    },
}

#[derive(Debug)]
struct FakeControlHandler {
    steps: Mutex<VecDeque<FakeStep>>,
    captured: Mutex<Vec<Frame>>,
}

impl FakeControlHandler {
    fn new(steps: Vec<FakeStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn captured(&self) -> Vec<Frame> {
        self.captured.lock().unwrap().clone()
    }
}

impl ProtocolHandler for FakeControlHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // Keep accepting bi-streams until the peer disconnects. Only
        // returning from `accept` after `accept_bi` fails preserves the
        // QUIC connection long enough for the client to read the
        // response we wrote on the previous stream — returning Ok(())
        // eagerly triggers a graceful CONNECTION_CLOSE that surfaces
        // to the client as "closed by peer" before its read completes.
        loop {
            let (mut s, mut r) = match conn.accept_bi().await {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };

            let frame = match Frame::read_from(&mut r).await {
                Ok(f) => f,
                Err(_) => {
                    let _ = s.shutdown().await;
                    continue;
                }
            };

            // Pop the step AFTER reading the frame so the right step
            // matches the right incoming frame, and so an exhausted
            // step queue just means we silently drain further streams
            // (instead of prematurely closing the connection).
            let step = self.steps.lock().unwrap().pop_front();
            self.captured.lock().unwrap().push(frame);

            let response = match step {
                Some(FakeStep::ExpectAnyThenRespond(f)) => Some(f),
                Some(FakeStep::ExpectHelloThenHelloOk) => Some(Frame::HelloOk(HelloOk {
                    session_id: 42,
                })),
                Some(FakeStep::ExpectHelloThenError { code, reason }) => {
                    Some(Frame::ControlError { code, reason })
                }
                Some(FakeStep::ExpectRegisterThenRegisterOk { service }) => {
                    Some(Frame::RegisterOk(RegisterOk { service }))
                }
                Some(FakeStep::ExpectRegisterThenError { code, reason }) => {
                    Some(Frame::ControlError { code, reason })
                }
                Some(FakeStep::ExpectSubscribeThenSubscribeOk {
                    service,
                    provider_node_id,
                }) => Some(Frame::SubscribeOk(SubscribeOk {
                    service,
                    provider_node_id,
                    relay_required: false,
                })),
                None => None,
            };
            if let Some(resp) = response {
                let _ = resp.write_to(&mut s).await;
            }
            let _ = s.shutdown().await;
        }
    }
}

// ----------------------------------------------------------------------
// Spawn a fake server endpoint on the control ALPN. Returns the
// (endpoint, router, handler, shared_lookup) so the caller can build a
// client endpoint that sees the same address lookup.
// ----------------------------------------------------------------------
async fn spawn_fake_server(
    steps: Vec<FakeStep>,
    lookup: Arc<MemoryLookup>,
) -> (iroh::Endpoint, iroh::protocol::Router, Arc<FakeControlHandler>) {
    let handler = Arc::new(FakeControlHandler::new(steps));
    let dir = tempdir().unwrap();
    let (ep, router) = common::test_provider_in_lookup(
        dir.path(),
        meshly_core_common::alpn::alpn_control(),
        handler.clone(),
        lookup,
    )
    .await
    .unwrap();
    (ep, router, handler)
}

/// A valid EndpointId string for tests — parseable by
/// `EndpointId::from_str`. We use the public key of a fresh secret.
fn fake_provider_id_string() -> String {
    iroh::SecretKey::generate().public().to_string()
}

/// Build a client endpoint that uses the same `MemoryLookup` as the
/// fake server so it can resolve the server's EndpointId to a
/// dialable address.
async fn make_client(lookup: Arc<MemoryLookup>) -> (iroh::Endpoint, iroh::SecretKey) {
    let dir = tempdir().unwrap();
    common::test_endpoint_in_lookup(dir.path(), lookup)
        .await
        .unwrap()
}

// ----------------------------------------------------------------------
// Test 1: happy path — subscribe returns the provider id
// ----------------------------------------------------------------------
#[tokio::test]
async fn subscribe_parses_hello_ok_then_subscribe_ok_with_provider() {
    let lookup = Arc::new(MemoryLookup::new());
    let provider_str = fake_provider_id_string();
    let expected_provider_id: iroh::EndpointId = provider_str.parse().unwrap();

    let (server_ep, router, _handler) = spawn_fake_server(
        vec![
            FakeStep::ExpectHelloThenHelloOk,
            FakeStep::ExpectSubscribeThenSubscribeOk {
                service: "web".into(),
                provider_node_id: Some(provider_str.clone()),
            },
        ],
        lookup.clone(),
    )
    .await;
    let server_id = server_ep.secret_key().public();

    let (client_ep, _key) = make_client(lookup).await;

    let provider = subscribe(&client_ep, server_id, TEST_GROUP_TOKEN, "web")
        .await
        .expect("subscribe should succeed");

    assert_eq!(
        provider, expected_provider_id,
        "returned provider id must match SubscribeOk payload"
    );

    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 2: server rejects hello with ControlError
// ----------------------------------------------------------------------
#[tokio::test]
async fn subscribe_errors_on_server_control_error() {
    let lookup = Arc::new(MemoryLookup::new());
    let (server_ep, router, _handler) = spawn_fake_server(
        vec![FakeStep::ExpectHelloThenError {
            code: 1,
            reason: "unknown group".into(),
        }],
        lookup.clone(),
    )
    .await;
    let server_id = server_ep.secret_key().public();

    let (client_ep, _key) = make_client(lookup).await;

    let err = subscribe(&client_ep, server_id, TEST_GROUP_TOKEN, "web")
        .await
        .expect_err("subscribe should fail when server rejects hello");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("server rejected hello"),
        "error should mention rejected hello; got {msg}"
    );

    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 3: server returns SubscribeOk with provider_node_id: None
// ----------------------------------------------------------------------
#[tokio::test]
async fn subscribe_errors_when_provider_node_id_missing() {
    let lookup = Arc::new(MemoryLookup::new());
    let (server_ep, router, _handler) = spawn_fake_server(
        vec![
            FakeStep::ExpectHelloThenHelloOk,
            FakeStep::ExpectSubscribeThenSubscribeOk {
                service: "web".into(),
                provider_node_id: None,
            },
        ],
        lookup.clone(),
    )
    .await;
    let server_id = server_ep.secret_key().public();

    let (client_ep, _key) = make_client(lookup).await;

    let err = subscribe(&client_ep, server_id, TEST_GROUP_TOKEN, "web")
        .await
        .expect_err("subscribe should fail when server has no provider");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("server has no provider"),
        "error should mention missing provider; got {msg}"
    );

    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 4: server sends the wrong frame after Subscribe (RegisterOk)
// ----------------------------------------------------------------------
#[tokio::test]
async fn subscribe_errors_on_unexpected_frame() {
    let lookup = Arc::new(MemoryLookup::new());
    let (server_ep, router, _handler) = spawn_fake_server(
        vec![
            FakeStep::ExpectHelloThenHelloOk,
            FakeStep::ExpectAnyThenRespond(Frame::RegisterOk(RegisterOk {
                service: "web".into(),
            })),
        ],
        lookup.clone(),
    )
    .await;
    let server_id = server_ep.secret_key().public();

    let (client_ep, _key) = make_client(lookup).await;

    let err = subscribe(&client_ep, server_id, TEST_GROUP_TOKEN, "web")
        .await
        .expect_err("subscribe should fail on wrong frame after Subscribe");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unexpected frame after subscribe"),
        "error should mention unexpected frame; got {msg}"
    );

    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 5: register_with_server registers two services in order
// ----------------------------------------------------------------------
#[tokio::test]
async fn register_with_server_registers_multiple_services_in_order() {
    let lookup = Arc::new(MemoryLookup::new());
    let (server_ep, router, handler) = spawn_fake_server(
        vec![
            FakeStep::ExpectHelloThenHelloOk,
            FakeStep::ExpectRegisterThenRegisterOk {
                service: "ssh".into(),
            },
            FakeStep::ExpectRegisterThenRegisterOk {
                service: "web".into(),
            },
        ],
        lookup.clone(),
    )
    .await;
    let server_id = server_ep.secret_key().public();

    let (client_ep, _key) = make_client(lookup).await;

    // Pick arbitrary localhost-ish ports; the values don't matter
    // because the fake server never dials back.
    let services = vec![
        ExposeSpec {
            name: "ssh".into(),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            shared_secret: b"ssh-secret".to_vec(),
        },
        ExposeSpec {
            name: "web".into(),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            shared_secret: b"web-secret".to_vec(),
        },
    ];

    let _conn = register_with_server(
        &client_ep,
        server_id,
        TEST_GROUP_TOKEN,
        "test/0.1",
        &services,
        &[],
    )
    .await
    .expect("register_with_server should succeed");

    // Verify the order of Register frames captured by the fake server.
    let captured = handler.captured();
    assert_eq!(captured.len(), 3, "expected Hello + 2 Registers");
    assert!(
        matches!(&captured[0], Frame::Hello(_)),
        "first frame must be Hello, got {:?}",
        captured[0]
    );
    match &captured[1] {
        Frame::Register(r) => assert_eq!(r.service, "ssh"),
        other => panic!("expected Register(ssh), got {other:?}"),
    }
    match &captured[2] {
        Frame::Register(r) => assert_eq!(r.service, "web"),
        other => panic!("expected Register(web), got {other:?}"),
    }

    drop(client_ep);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 6: register_with_server errors when second Register is rejected
// ----------------------------------------------------------------------
#[tokio::test]
async fn register_with_server_errors_on_server_rejecting_one_service() {
    let lookup = Arc::new(MemoryLookup::new());
    let (server_ep, router, _handler) = spawn_fake_server(
        vec![
            FakeStep::ExpectHelloThenHelloOk,
            FakeStep::ExpectRegisterThenRegisterOk {
                service: "ssh".into(),
            },
            FakeStep::ExpectRegisterThenError {
                code: 3,
                reason: "register failed: bad name".into(),
            },
        ],
        lookup.clone(),
    )
    .await;
    let server_id = server_ep.secret_key().public();

    let (client_ep, _key) = make_client(lookup).await;

    let services = vec![
        ExposeSpec {
            name: "ssh".into(),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            shared_secret: b"ssh-secret".to_vec(),
        },
        ExposeSpec {
            name: "BAD!".into(), // intentionally not a valid service name
            local_addr: "127.0.0.1:0".parse().unwrap(),
            shared_secret: b"bad-secret".to_vec(),
        },
    ];

    let err = register_with_server(
        &client_ep,
        server_id,
        TEST_GROUP_TOKEN,
        "test/0.1",
        &services,
        &[],
    )
    .await
    .expect_err("register_with_server should fail when one service is rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("server rejected register") && msg.contains("BAD!"),
        "error should mention rejected service name; got {msg}"
    );

    drop(client_ep);
    router.shutdown().await.ok();
}