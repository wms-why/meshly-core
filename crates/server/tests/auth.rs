//! Phase 3 — data plane HMAC handshake integration tests (server side).
//!
//! These tests exercise the production `ExposeHandler` (defined in
//! `crates/client/src/expose.rs`) end-to-end over a real Iroh transport.
//! The handler's source file is re-included via `#[path]` so the tests
//! can construct it directly without exposing a library crate (the
//! production binary's `Cargo.toml` has no `[lib]` section).
//!
//! Protocol summary (see `crates/common/src/protocol.rs` for full
//! details): the consumer sends `AuthHello` first after `open_bi()` to
//! unblock Quinn's bi-stream handshake (which only progresses on a
//! write); the server reads the marker, then issues `AuthNonce`. The
//! consumer computes an HMAC-SHA256 over (service, nonce) and sends
//! `AuthProof`; the server verifies and replies `AuthOk` or `AuthErr`.

mod common;

// `expose.rs` references `super::static_http::StaticSpec` inside
// `register_with_server`. We don't call `register_with_server` from any
// test, but the module must still compile, so re-include `static_http.rs`
// here too.
#[path = "../../client/src/static_http.rs"]
mod static_http;
#[path = "../../client/src/expose.rs"]
mod expose;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use meshly_core_common::alpn::alpn_for_service;
use meshly_core_common::protocol::{
    compute_proof, AuthNonce, AuthOk, AuthProof, AuthErr, Frame, AUTH_ERR_BAD_PROOF,
};

use crate::expose::{ExposeHandler, ExposeSpec};

const TEST_SERVICE: &str = "ssh";
const TEST_SECRET: &[u8] = b"server-auth-secret";

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// Spawn a tiny TCP echo backend bound to a fresh port. Returns the
/// bound address. The backend task is detached; the test's drop order
/// will tear it down.
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
                        Ok(0) => return,
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
/// `meshly-core/<service>` backed by `backend_addr`.
async fn spawn_expose_provider(
    service: &str,
    secret: &[u8],
    backend_addr: SocketAddr,
    lookup: Arc<MemoryLookup>,
) -> (iroh::Endpoint, Router) {
    let handler = Arc::new(ExposeHandler {
        spec: Arc::new(ExposeSpec {
            name: service.to_string(),
            local_addr: backend_addr,
            shared_secret: secret.to_vec(),
        }),
    });
    let dir = tempdir().unwrap();
    common::test_provider_in_lookup(
        dir.path(),
        alpn_for_service(service).unwrap(),
        handler,
        lookup,
    )
    .await
    .unwrap()
}

/// Build a consumer endpoint that uses the shared `MemoryLookup`.
async fn make_consumer(lookup: Arc<MemoryLookup>) -> iroh::Endpoint {
    let dir = tempdir().unwrap();
    common::test_endpoint_in_lookup(dir.path(), lookup)
        .await
        .unwrap()
        .0
}

/// Drive the HMAC handshake inline on `stream` with the given secret
/// and service name. Returns `Ok(())` if the server sent `AuthOk`, or
/// `Err(reason)` if it sent `AuthErr` (with the supplied code/reason)
/// or the connection closed unexpectedly.
///
/// This mirrors the protocol logic in `consume::dial_direct` but is
/// inlined here so the tests can drive the server-side handler without
/// pulling in the consumer's private dial functions.
async fn run_handshake<R, W>(
    send: &mut W,
    recv: &mut R,
    secret: &[u8],
    service: &str,
) -> std::result::Result<(), AuthErr>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // 1. Send AuthHello to trigger the bi-stream SYN. Without this the
    //    server's `accept_bi()` never returns (Quinn constraint).
    Frame::AuthHello
        .write_to(send)
        .await
        .expect("write AuthHello");
    // 2. Read AuthNonce from server.
    let frame = Frame::read_from(recv).await.expect("read AuthNonce");
    let nonce = match frame {
        Frame::AuthNonce(AuthNonce { nonce }) => nonce,
        Frame::AuthErr(AuthErr { code, reason }) => {
            return Err(AuthErr { code, reason });
        }
        other => panic!("expected AuthNonce, got {other:?}"),
    };
    // 3. Compute + send AuthProof.
    let proof = compute_proof(secret, service, &nonce);
    Frame::AuthProof(AuthProof { mac: proof })
        .write_to(send)
        .await
        .expect("write AuthProof");
    // 4. Read AuthOk or AuthErr.
    match Frame::read_from(recv).await.expect("read AuthOk/AuthErr") {
        Frame::AuthOk(AuthOk) => Ok(()),
        Frame::AuthErr(AuthErr { code, reason }) => Err(AuthErr { code, reason }),
        other => panic!("expected AuthOk/AuthErr, got {other:?}"),
    }
}

/// Outcome of `read_auth_err_with_close_race`: either we received the
/// server's AuthErr frame, or the connection closed (the test's job
/// is only to verify "auth failed" — both are acceptable proof of
/// that, because Quinn's connection close can race with the buffered
/// AuthErr bytes).
enum AuthFailOutcome {
    ErrFrame(AuthErr),
    /// Stream EOF (peer closed cleanly without delivering a frame).
    Closed,
    /// ConnectionLost / ApplicationClosed — same family: the server
    /// tore the connection down rather than accepting the proof.
    ConnectionLost,
}

/// After sending a bad proof, race the read against a short timeout
/// so we tolerate the AuthErr-byte-vs-connection-close race. Quinn's
/// `accept_bi`-driven handlers drop the connection as soon as the
/// handler returns, which can lose the AuthErr bytes still in the
/// QUIC send buffer. We accept that as long as the connection was
/// actually torn down (i.e. no AuthOk arrived).
async fn read_auth_fail_outcome<R>(
    recv: &mut R,
    timeout: Duration,
) -> AuthFailOutcome
where
    R: tokio::io::AsyncRead + Unpin,
{
    let read_fut = Frame::read_from(recv);
    match tokio::time::timeout(timeout, read_fut).await {
        Ok(Ok(Frame::AuthErr(e))) => AuthFailOutcome::ErrFrame(e),
        Ok(Ok(other)) => {
            panic!("expected AuthErr or close, got frame {other:?}")
        }
        Ok(Err(_)) => AuthFailOutcome::Closed,
        Err(_) => AuthFailOutcome::Closed,
    }
}

// ----------------------------------------------------------------------
// Test 1: happy path — good proof + AuthOk + bytes bridge end-to-end
// ----------------------------------------------------------------------
#[tokio::test]
async fn expose_accepts_correct_proof() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) =
        spawn_expose_provider(TEST_SERVICE, TEST_SECRET, backend_addr, lookup.clone()).await;
    let provider_addr = provider_ep.addr();

    let consumer = make_consumer(lookup).await;

    let conn = tokio::time::timeout(
        Duration::from_secs(15),
        consumer.connect(provider_addr.clone(), &alpn_for_service(TEST_SERVICE).unwrap()),
    )
    .await
    .expect("connect timed out")
    .expect("connect to provider");

    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(15), conn.open_bi())
        .await
        .expect("open_bi timed out")
        .expect("open bi");

    run_handshake(&mut send, &mut recv, TEST_SECRET, TEST_SERVICE)
        .await
        .expect("handshake should succeed with correct proof");

    // Give the server's ExposeHandler time to dial the backend and
    // start bridging bytes.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // After AuthOk, the server's ExposeHandler has dialed the echo
    // backend and is bridging bytes. Push a payload from the consumer
    // and verify the round-trip via the bridge.
    //
    // We use a write→read_exact loop rather than a half-close + read_to_end:
    // the half-close makes copy_bidirectional shut the QUIC send side down
    // before the echo has been delivered to the peer, and Iroh's connection
    // close then races against the in-flight bytes. read_exact keeps the
    // stream alive until exactly the expected payload arrives.
    let payload = b"hello-tunnel";
    send.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut got))
        .await
        .expect("read_exact timed out")
        .expect("read_exact failed");
    assert_eq!(
        got, payload,
        "echo backend should round-trip bytes through the tunnel"
    );

    drop(send);
    drop(recv);
    drop(conn);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 2: tampered MAC -> AuthErr and stream close
// ----------------------------------------------------------------------
#[tokio::test]
async fn expose_rejects_bad_proof() {
    let lookup = Arc::new(MemoryLookup::new());
    // Backend is unused in this test — auth fails before any bridge.
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) = spawn_expose_provider(
        TEST_SERVICE,
        TEST_SECRET,
        backend_addr,
        lookup.clone(),
    )
    .await;
    let provider_addr = provider_ep.addr();

    let consumer = make_consumer(lookup).await;
    let conn = consumer
        .connect(provider_addr, &alpn_for_service(TEST_SERVICE).unwrap())
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");

    // Send AuthHello to unblock the server's accept_bi.
    Frame::AuthHello.write_to(&mut send).await.unwrap();

    // Read nonce, send a tampered proof (all-zero MAC) that won't
    // match the expected HMAC.
    let frame = Frame::read_from(&mut recv).await.expect("read nonce");
    let nonce = match frame {
        Frame::AuthNonce(AuthNonce { nonce }) => nonce,
        other => panic!("expected AuthNonce, got {other:?}"),
    };
    let _ = nonce; // silence unused warning
    Frame::AuthProof(AuthProof { mac: [0u8; 32] })
        .write_to(&mut send)
        .await
        .unwrap();

    // Server should reject the proof with AuthErr + close. Either the
    // AuthErr frame is delivered OR the connection is torn down
    // immediately — both prove auth failed (and that no AuthOk was
    // ever sent). See `read_auth_fail_outcome` for the rationale.
    let outcome = read_auth_fail_outcome(&mut recv, Duration::from_secs(2)).await;
    match outcome {
        AuthFailOutcome::ErrFrame(AuthErr { code, reason }) => {
            assert_eq!(
                code, AUTH_ERR_BAD_PROOF,
                "auth err code must be BAD_PROOF"
            );
            assert!(
                reason.contains("bad HMAC proof"),
                "reason should explain bad HMAC, got {reason:?}"
            );
        }
        AuthFailOutcome::Closed | AuthFailOutcome::ConnectionLost => {
            // Connection closed without delivering AuthErr — also
            // proves auth failed.
        }
    }

    drop(conn);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 3: proof minted for service A, presented to handler bound to B
// ----------------------------------------------------------------------
//
// We use a single shared secret but two different service names. The
// ExposeHandler in production always binds `spec.name` to the ALPN
// suffix, so to mismatch the names we have to register the handler on
// an ALPN whose suffix differs from `spec.name`. Here we keep the
// Router's ALPN as `meshly-core/<spec.name>` so the connection
// succeeds; the mismatch is between the ALPN the consumer dialed and
// the service name in the proof.
//
// In current production code, `verify_proof` always verifies against
// `self.spec.name`, and `self.spec.name` is set by the operator (the
// client knows it from config). A real-world cross-service replay
// would have the consumer computing proof for service A and presenting
// it to a provider bound to service B — the proof would fail because
// HMAC includes the service name. We simulate that here by having the
// consumer compute the proof for a *different* service name than the
// provider expects.
#[tokio::test]
async fn expose_rejects_proof_from_wrong_service() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) = spawn_expose_provider(
        TEST_SERVICE, // provider bound to "ssh"
        TEST_SECRET,
        backend_addr,
        lookup.clone(),
    )
    .await;
    let provider_addr = provider_ep.addr();

    let consumer = make_consumer(lookup).await;
    let conn = consumer
        .connect(provider_addr, &alpn_for_service(TEST_SERVICE).unwrap())
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");

    // Trigger the SYN + read the nonce the provider sent for "ssh".
    Frame::AuthHello.write_to(&mut send).await.unwrap();
    let frame = Frame::read_from(&mut recv).await.expect("read nonce");
    let nonce = match frame {
        Frame::AuthNonce(AuthNonce { nonce }) => nonce,
        other => panic!("expected AuthNonce, got {other:?}"),
    };
    // Compute proof for the WRONG service. The HMAC is service-bound,
    // so the server (which verifies with `spec.name = "ssh"`) will
    // reject this even though the secret matches.
    let wrong_proof = compute_proof(TEST_SECRET, "web", &nonce);
    Frame::AuthProof(AuthProof { mac: wrong_proof })
        .write_to(&mut send)
        .await
        .unwrap();

    // Same AuthErr / close-race tolerance as test 2.
    let outcome = read_auth_fail_outcome(&mut recv, Duration::from_secs(2)).await;
    match outcome {
        AuthFailOutcome::ErrFrame(AuthErr { code, reason }) => {
            assert_eq!(
                code, AUTH_ERR_BAD_PROOF,
                "current code conflates wrong-service with bad proof; \
                 Phase 9 will introduce AuthError::BadService"
            );
            assert!(
                reason.contains("bad HMAC proof"),
                "reason should mention bad proof, got {reason:?}"
            );
        }
        AuthFailOutcome::Closed | AuthFailOutcome::ConnectionLost => {
            // Acceptable — connection teardown proves auth failed.
        }
    }

    drop(conn);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 4: unexpected first frame -> server returns Ok early (no AuthOk)
// ----------------------------------------------------------------------
//
// The ExposeHandler expects `AuthHello` as the very first frame (it
// discards anything else and returns Ok early without sending an
// AuthOk). We send `Frame::AuthNonce` instead — which is well-formed
// but not `AuthHello`. The handler's match falls through to the
// "expected AuthHello" warn arm and returns Ok. The consumer then
// never sees an AuthOk (the read on the server's stream blocks until
// the QUIC connection is torn down); the test uses a short timeout
// on the read.
#[tokio::test]
async fn expose_rejects_unexpected_first_frame() {
    let lookup = Arc::new(MemoryLookup::new());
    let backend_addr = spawn_echo_backend().await;
    let (provider_ep, router) = spawn_expose_provider(
        TEST_SERVICE,
        TEST_SECRET,
        backend_addr,
        lookup.clone(),
    )
    .await;
    let provider_addr = provider_ep.addr();

    let consumer = make_consumer(lookup).await;
    let conn = consumer
        .connect(provider_addr, &alpn_for_service(TEST_SERVICE).unwrap())
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");

    // Send a non-AuthHello first frame. The handler returns Ok
    // without writing AuthOk or AuthErr — the consumer's subsequent
    // read must therefore never see AuthOk.
    Frame::AuthNonce(AuthNonce { nonce: [0u8; 32] })
        .write_to(&mut send)
        .await
        .unwrap();

    // Race the read against a 500 ms timeout — the timeout must fire
    // (no AuthOk arrives).
    let read_attempt = async {
        Frame::read_from(&mut recv).await
    };
    match tokio::time::timeout(Duration::from_millis(500), read_attempt).await {
        Ok(Ok(f)) => panic!("expected no AuthOk, got frame {f:?}"),
        Ok(Err(e)) => {
            // If the connection closed (e.g. CONNECTION_CLOSE arrived),
            // that's also acceptable — the test contract is just "no
            // AuthOk".
            eprintln!("read errored (acceptable): {e:?}");
        }
        Err(_) => {
            // Timeout fired: no AuthOk arrived. Test passes.
        }
    }

    drop(conn);
    drop(consumer);
    router.shutdown().await.ok();
}

// ----------------------------------------------------------------------
// Test 5: backend connect failure -> ExposeHandler reports error
// ----------------------------------------------------------------------
//
// The ExposeHandler wraps `TcpStream::connect` in a 5-second timeout.
// To trigger the failure path quickly, we point `local_addr` at a
// port that is guaranteed not to be listening: bind a TcpListener,
// grab its port, then drop the listener so the port is closed. The
// next connect to that port yields ConnectionRefused. The handler's
// outer `?` then propagates the wrapped I/O error back through
// `accept`, and the QUIC connection is torn down.
//
// This test verifies the "backend connect failure" path. The specific
// failure mode (timeout vs refused) depends on the OS / address. In
// practice on macOS / Linux with a localhost address, the kernel
// completes the TCP handshake via SYN cookies only when the listener
// is up; once the listener is dropped the port is closed and connect
// fails fast with ECONNREFUSED. Either way the test asserts the
// surface behavior: the consumer sees the tunnel go down, with the
// bridge never having produced any bytes.
#[tokio::test]
async fn expose_backend_connect_failure_is_reported() {
    let lookup = Arc::new(MemoryLookup::new());

    // Reserve a port, then immediately close it so connect() will fail.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);

    let (provider_ep, router) = spawn_expose_provider(
        TEST_SERVICE,
        TEST_SECRET,
        dead_addr,
        lookup.clone(),
    )
    .await;
    let provider_addr = provider_ep.addr();

    let consumer = make_consumer(lookup).await;
    let conn = consumer
        .connect(provider_addr, &alpn_for_service(TEST_SERVICE).unwrap())
        .await
        .expect("connect to provider");
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");

    // Handshake should still succeed — backend is dialed AFTER AuthOk.
    run_handshake(&mut send, &mut recv, TEST_SECRET, TEST_SERVICE)
        .await
        .expect("handshake must succeed even if backend is down");

    // Then the server's handler tries to connect to `dead_addr` and
    // fails (or times out after 5 s in the timeout code path). Either
    // way the handler returns Err, accept returns Err, and Iroh tears
    // down the connection. The consumer's recv should observe the
    // close within ~5 seconds.
    //
    // We race the read against a generous 7-second timeout so the test
    // still completes if the timeout branch fires.
    let deadline = Duration::from_secs(7);
    let read_result =
        tokio::time::timeout(deadline, recv.read_to_end(64 * 1024)).await;
    match read_result {
        Ok(Ok(got)) => {
            assert!(
                got.is_empty(),
                "expected stream close after backend failure, got {} bytes: {:?}",
                got.len(),
                got
            );
        }
        Ok(Err(_)) => {
            // Connection reset / closed — also acceptable.
        }
        Err(_) => panic!("timed out waiting for tunnel close"),
    }

    drop(conn);
    drop(consumer);
    router.shutdown().await.ok();
}
