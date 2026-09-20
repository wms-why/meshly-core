//! Phase 3 — data plane HMAC handshake integration tests (client side).
//!
//! Exercises `consume::dial_direct`, `consume::dial_relay`, and
//! `consume::dial_stream` end-to-end over real Iroh endpoints. The
//! client crate is a binary, so its private modules are re-included
//! via `#[path]` so the tests can construct a `ConsumeState` and call
//! the dial helpers directly.
//!
//! Protocol summary: see `crates/common/src/protocol.rs`. The
//! `dial_direct` / `dial_relay` paths use the production handshake —
//! the only thing inlined here is the test scaffolding for spinning
//! up an ExposeHandler that mirrors what a real meshly-core-client's
//! expose side would do, plus a tiny in-memory relay for tests that
//! need to exercise the relay path.

mod common;

// Re-include the client crate's private modules so the tests can
// construct a ConsumeState and call dial_direct / dial_relay / dial_stream.
#[path = "../src/status.rs"]
mod status;
#[path = "../src/static_http.rs"]
mod static_http;
#[path = "../src/expose.rs"]
mod expose;
#[path = "../src/consume.rs"]
mod consume;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow as anyhow_macro;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointId};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::debug;

use meshly_core_common::alpn::alpn_for_service;
use meshly_core_common::protocol::Frame;
use meshly_core_common::tunnel::{bridge, BiStream};

use crate::consume::{
    dial_direct, dial_relay, dial_stream, ConsumeSpec, ConsumeState, ReconnectConfig,
};
use crate::expose::{ExposeHandler, ExposeSpec};
use crate::status::RuntimeStatus;

const TEST_SERVICE: &str = "ssh";
const TEST_SECRET: &[u8] = b"client-auth-secret";
const TEST_GROUP: &str = "test-token";

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// Spawn a tiny TCP echo backend bound to a fresh port. The backend
/// closes its write side after the client closes its read side, so the
/// echo terminates cleanly.
async fn spawn_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match tcp.read(&mut buf).await {
                        Ok(0) => {
                            // Client half-closed → close our writer so the
                            // consumer's read sees EOF after the echo.
                            let _ = tcp.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if tcp.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    addr
}

/// Spin up a provider endpoint with `ExposeHandler` on ALPN
/// `meshly-core/<service>` backed by `backend_addr`, registered in
/// the shared `MemoryLookup`.
async fn spawn_expose_provider(
    service: &str,
    secret: &[u8],
    backend_addr: SocketAddr,
    lookup: Arc<MemoryLookup>,
) -> (Endpoint, Router) {
    let handler = Arc::new(ExposeHandler {
        spec: Arc::new(ExposeSpec {
            name: service.to_string(),
            local_addr: backend_addr,
            shared_secret: secret.to_vec(),
        }),
    });
    let dir = tempdir().unwrap();
    let (ep, router) = common::test_provider_in_lookup(
        dir.path(),
        alpn_for_service(service).unwrap(),
        handler,
        lookup,
    )
    .await
    .unwrap();
    (ep, router)
}

/// Build a consumer endpoint that uses the shared `MemoryLookup`.
async fn make_consumer(lookup: Arc<MemoryLookup>) -> Endpoint {
    let dir = tempdir().unwrap();
    common::test_endpoint_in_lookup(dir.path(), lookup)
        .await
        .unwrap()
        .0
}

/// Build a fresh ConsumeState pointing at the supplied endpoint /
/// provider id, with the provider already cached so `dial_stream`
/// skips `subscribe()`.
async fn make_consume_state(
    endpoint: Endpoint,
    server_node_id: EndpointId,
    provider_id: EndpointId,
    service: &str,
    secret: &[u8],
    local_bind: SocketAddr,
) -> Arc<ConsumeState> {
    let spec = ConsumeSpec {
        name: service.to_string(),
        local_bind,
        shared_secret: secret.to_vec(),
    };
    let status = RuntimeStatus::new(vec![service.to_string()]);
    let state = Arc::new(ConsumeState {
        spec,
        server_node_id,
        group_token: TEST_GROUP.to_string(),
        endpoint,
        cached_provider: tokio::sync::Mutex::new(Some(provider_id)),
        reconnect: ReconnectConfig {
            initial_backoff_ms: 10,
            max_backoff_ms: 50,
            prefer_direct: true,
        },
        status,
    });
    state
}

// ----------------------------------------------------------------------
// Test 1: dial_direct_happy_path
// ----------------------------------------------------------------------
#[tokio::test]
async fn dial_direct_happy_path() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) =
        spawn_expose_provider(TEST_SERVICE, TEST_SECRET, backend_addr, lookup.clone()).await;
    let provider_id = provider_ep.id();

    let consumer = make_consumer(lookup).await;
    let state = make_consume_state(
        consumer.clone(),
        provider_id, // server == provider for direct-only test
        provider_id,
        TEST_SERVICE,
        TEST_SECRET,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;

    let (conn, mut send, mut recv) = dial_direct(&state, provider_id)
        .await
        .expect("dial_direct should succeed with correct proof");

    // Push a payload and verify the echo round-trip through the bridge.
    let payload = b"hello-from-client";
    send.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut got))
        .await
        .expect("read_exact timed out")
        .expect("read_exact failed");
    assert_eq!(got, payload, "echo must round-trip through tunnel");

    drop(conn);
    drop(state);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 2: dial_direct_bad_proof_returns_auth_err
// ----------------------------------------------------------------------
#[tokio::test]
async fn dial_direct_bad_proof_returns_auth_err() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) =
        spawn_expose_provider(TEST_SERVICE, TEST_SECRET, backend_addr, lookup.clone()).await;
    let provider_id = provider_ep.id();

    // Build a consumer whose `shared_secret` differs from the
    // provider's. The HMAC will not verify and the provider will
    // respond with AuthErr + close.
    let wrong_secret = b"WRONG-secret";
    let consumer = make_consumer(lookup).await;
    let state = make_consume_state(
        consumer.clone(),
        provider_id,
        provider_id,
        TEST_SERVICE,
        wrong_secret,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;

    let err = dial_direct(&state, provider_id)
        .await
        .expect_err("dial_direct with wrong secret must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("provider rejected proof"),
        "error message must mention 'provider rejected proof' so the cache-invalidation classifier picks it up; got: {msg:?}"
    );

    drop(state);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 3: dial_stream_invalidates_cache_on_auth_error
// ----------------------------------------------------------------------
//
// dial_direct with a wrong secret triggers `is_auth_error` →
// `invalidate_provider_cache`. We assert that the cached provider id
// is cleared after a dial_stream call whose direct path auth-fails.
#[tokio::test]
async fn dial_stream_invalidates_cache_on_auth_error() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) = spawn_expose_provider(
        TEST_SERVICE,
        b"WRONG-secret-on-provider",
        backend_addr,
        lookup.clone(),
    )
    .await;
    let provider_id = provider_ep.id();

    let consumer = make_consumer(lookup).await;
    // Use a non-existent server id so dial_relay fails fast (transport
    // error) instead of running the full handshake with the wrong
    // secret. The direct path is what we want to exercise here.
    let unreachable_server: EndpointId = iroh::SecretKey::generate().public();
    let state = make_consume_state(
        consumer.clone(),
        unreachable_server,
        provider_id,
        TEST_SERVICE,
        TEST_SECRET,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;

    // Sanity: cache is populated.
    assert!(state.cached_provider.lock().await.is_some());

    // dial_stream with bad secret — direct will fail with auth err,
    // which must clear the cache.
    let _ = tokio::time::timeout(Duration::from_secs(10), dial_stream(&state))
        .await
        .expect("dial_stream timed out");

    // Cache must be None now (dial_stream's auth-err branch called
    // invalidate_provider_cache).
    let cache_after = *state.cached_provider.lock().await;
    assert!(
        cache_after.is_none(),
        "cached provider id must be cleared after auth error, got: {cache_after:?}"
    );

    drop(state);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 4: dial_stream_falls_back_to_relay_after_direct_fails
// ----------------------------------------------------------------------
//
// Force `dial_direct` to fail with a TRANSPORT error (provider id is
// not registered in the consumer's lookup, so the consumer can't
// reach it), then verify that `dial_stream` falls back to `dial_relay`.
// The "relay" is a tiny in-process handler that accepts DataOpen +
// bridges the consumer's stream to a fresh bi-stream on the real
// provider.
//
// Setup: the provider + relay-server share one lookup (so the relay
// can find the provider). The consumer uses a SECOND lookup that only
// has the relay-server registered — the provider's EndpointId isn't
// resolvable from there, so `dial_direct` fails with a transport
// error (no addresses to dial).
#[tokio::test]
async fn dial_stream_falls_back_to_relay_after_direct_fails() {
    // Shared lookup for provider + relay-server.
    let server_lookup = Arc::new(MemoryLookup::new());
    // Separate lookup for consumer (only has relay-server registered).
    let consumer_lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;

    let (provider_ep, provider_router) = spawn_expose_provider(
        TEST_SERVICE,
        TEST_SECRET,
        backend_addr,
        server_lookup.clone(),
    )
    .await;
    let provider_id = provider_ep.id();

    // "Server" endpoint on the server_lookup.
    let relay_handler = Arc::new(TestRelay::new());
    let dir = tempdir().unwrap();
    let (server_ep, server_router) = common::test_provider_in_lookup(
        dir.path(),
        b"meshly-core/data".to_vec(),
        relay_handler.clone(),
        server_lookup.clone(),
    )
    .await
    .unwrap();
    let server_id = server_ep.id();
    relay_handler.set_endpoint(server_ep.clone()).await;
    // Cross-register server in the consumer's lookup too.
    consumer_lookup.add_endpoint_info(server_ep.addr());

    // Consumer endpoint on the consumer_lookup (which has the server
    // but NOT the provider — so dial_direct will fail transport).
    let consumer = make_consumer(consumer_lookup).await;

    // Use the REAL provider_id. dial_direct fails because the lookup
    // can't resolve it; dial_relay succeeds because the server can
    // resolve it via server_lookup and bridge to the provider.
    let state = make_consume_state(
        consumer.clone(),
        server_id,
        provider_id,
        TEST_SERVICE,
        TEST_SECRET,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;

    let (conn, mut send, mut recv) =
        tokio::time::timeout(Duration::from_secs(15), dial_stream(&state))
            .await
            .expect("dial_stream timed out")
            .expect("dial_stream should fall back to relay after direct fails");

    let payload = b"via-relay";
    send.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut got))
        .await
        .expect("read_exact timed out")
        .expect("read_exact failed");
    assert_eq!(got, payload);

    // The status should be Live(relay) — not Live(direct).
    let snap = state.status.snapshot().await;
    let svc_status = snap.consumers.get(TEST_SERVICE).expect("consumer status");
    assert_eq!(svc_status.mode.as_deref(), Some("relay"));

    drop(conn);
    drop(state);
    drop(consumer);
    server_router.shutdown().await.ok();
    provider_router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 5: dial_relay_happy_path
// ----------------------------------------------------------------------
//
// Direct test of `dial_relay`: the in-process relay handler accepts
// the consumer's stream, reads DataOpen, opens a bi-stream on the
// provider, runs the HMAC handshake (forwarded transparently), and
// then bridges bytes. The test verifies the consumer can push and
// pull through the relay.
#[tokio::test]
async fn dial_relay_happy_path() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;

    let (provider_ep, provider_router) =
        spawn_expose_provider(TEST_SERVICE, TEST_SECRET, backend_addr, lookup.clone()).await;
    let provider_id = provider_ep.id();

    let relay_handler = Arc::new(TestRelay::new());
    let dir = tempdir().unwrap();
    let (server_ep, server_router) = common::test_provider_in_lookup(
        dir.path(),
        b"meshly-core/data".to_vec(),
        relay_handler.clone(),
        lookup.clone(),
    )
    .await
    .unwrap();
    let server_id = server_ep.id();
    relay_handler.set_endpoint(server_ep.clone()).await;

    let consumer = make_consumer(lookup).await;
    let state = make_consume_state(
        consumer.clone(),
        server_id,
        provider_id,
        TEST_SERVICE,
        TEST_SECRET,
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;

    let (conn, mut send, mut recv) = dial_relay(&state, provider_id)
        .await
        .expect("dial_relay must succeed when relay + provider handshake work");

    let payload = b"hello-via-relay";
    send.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut got))
        .await
        .expect("read_exact timed out")
        .expect("read_exact failed");
    assert_eq!(got, payload);

    drop(conn);
    drop(state);
    drop(consumer);
    provider_router.shutdown().await.ok();
    server_router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 6: consume_bridge_round_trip
// ----------------------------------------------------------------------
//
// Stand up a local TCP echo backend, point `consume::run` at a
// provider with the same echo backend, connect to the consumer's
// local port, write "hello", and verify the round-trip echo from
// the provider's backend.
#[tokio::test]
async fn consume_bridge_round_trip() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, provider_router) =
        spawn_expose_provider(TEST_SERVICE, TEST_SECRET, backend_addr, lookup.clone()).await;
    let provider_id = provider_ep.id();

    // Pick a free port for the consumer's TCP listener.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    drop(listener); // free the port; `run` will rebind it.

    let consumer = make_consumer(lookup).await;
    let state = make_consume_state(
        consumer.clone(),
        provider_id,
        provider_id,
        TEST_SERVICE,
        TEST_SECRET,
        local_addr,
    )
    .await;

    let run_state = state.clone();
    let run_task = tokio::spawn(async move {
        let _ = crate::consume::run(run_state).await;
    });

    // Give the listener a moment to come up.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut local = tokio::net::TcpStream::connect(local_addr)
        .await
        .expect("connect to consumer local port");
    let payload = b"hello-tunnel-roundtrip";
    local.write_all(payload).await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), local.read_exact(&mut buf))
        .await
        .expect("read_exact timed out")
        .expect("read_exact failed");
    assert_eq!(buf, payload);

    run_task.abort();
    drop(state);
    drop(consumer);
    provider_router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// TestRelay — a tiny in-process relay for tests that need the relay
// path. Mirrors the production server relay in `crates/server/src/relay.rs`
// but stripped of rate limiting, registry lookup, and group-token
// validation.
// ----------------------------------------------------------------------

#[derive(Debug)]
struct TestRelay {
    endpoint: tokio::sync::Mutex<Option<Endpoint>>,
}

impl TestRelay {
    fn new() -> Self {
        Self {
            endpoint: tokio::sync::Mutex::new(None),
        }
    }
    async fn set_endpoint(&self, ep: Endpoint) {
        *self.endpoint.lock().await = Some(ep);
    }
}

impl ProtocolHandler for TestRelay {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let ep = self
            .endpoint
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow_macro!("TestRelay: endpoint not set"))
            .map_err(|e| {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                AcceptError::from_boxed(boxed)
            })?;
        let (mut cs, mut cr) = match conn.accept_bi().await {
            Ok(p) => p,
            Err(e) => {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                return Err(AcceptError::from_boxed(boxed));
            }
        };
        // Read DataOpen.
        let frame = match Frame::read_from(&mut cr).await {
            Ok(f) => f,
            Err(e) => {
                debug!(err = %e, "TestRelay: read DataOpen");
                return Ok(());
            }
        };
        let (target_service, target_provider_str) = match frame {
            Frame::DataOpen {
                target_service,
                target_provider,
                ..
            } => (target_service, target_provider),
            other => {
                debug!(got = ?other, "TestRelay: expected DataOpen");
                return Ok(());
            }
        };
        let target_provider: EndpointId = match target_provider_str.parse() {
            Ok(id) => id,
            Err(_) => return Ok(()),
        };
        let alpn = match alpn_for_service(&target_service) {
            Ok(a) => a,
            Err(_) => return Ok(()),
        };
        let provider_conn = match ep
            .connect(iroh::EndpointAddr::new(target_provider), &alpn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                debug!(err = %e, "TestRelay: connect to provider");
                return Ok(());
            }
        };
        let (mut ps, mut pr) = match provider_conn.open_bi().await {
            Ok(p) => p,
            Err(e) => {
                debug!(err = %e, "TestRelay: open_bi to provider");
                return Ok(());
            }
        };
        // The provider's ExposeHandler will receive AuthHello, send
        // AuthNonce, etc. We bridge both halves. The AuthHello /
        // AuthNonce / AuthProof / AuthOk bytes flow transparently.
        //
        // Byte routing:
        //   consumer.write → consumer.send → arrives at server.cr →
        //     bridge reads from stream_a.reader (cr), writes to
        //     stream_b.writer (ps) → arrives at provider.recv.
        //   provider.write → provider.send → arrives at server.pr →
        //     bridge reads from stream_b.reader (pr), writes to
        //     stream_a.writer (cs) → arrives at consumer.recv.
        let stats = bridge(BiStream::new(cr, cs), BiStream::new(pr, ps)).await;
        debug!(?stats, "TestRelay: bridge returned");
        Ok(())
    }
}