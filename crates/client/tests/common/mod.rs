//! Shared test infrastructure for integration tests.
//!
//! IMPORTANT: every test that creates an Endpoint must go through
//! `test_endpoint` with an explicit `identity_path` inside a
//! `tempfile::tempdir()`. Never call `meshly_core_common::load_or_generate()`
//! (the no-arg variant) — that touches the developer's real
//! `<config_dir>/meshly-core/identity.key`.

use anyhow::Result;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::{ProtocolHandler, Router};
use iroh::{Endpoint, SecretKey};
use std::path::Path;
use std::sync::Arc;

/// Bind a fresh Endpoint with a new in-memory SecretKey.
///
/// The `identity_path` parameter is taken as documentation; the
/// endpoint uses the SecretKey directly (memory-only transport).
/// Passing a path inside a `tempfile::tempdir()` is the canonical
/// signal that this test is not touching the developer's real
/// `<config_dir>/meshly-core/identity.key`.
pub async fn test_endpoint(identity_path: &Path) -> Result<(Endpoint, SecretKey)> {
    let _ = identity_path; // reserved for future identity-persistence tests
    let key = SecretKey::generate();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(key.clone())
        .bind()
        .await?;
    Ok((endpoint, key))
}

/// Spin up a provider Endpoint with a Router accepting `alpn` and
/// `handler`. Returns (provider_endpoint, router_handle).
///
/// Caller is responsible for keeping `router_handle` alive for the
/// duration of the test; dropping it cancels the handler.
///
/// `handler` is a concrete `Arc<T>` (where `T: ProtocolHandler`)
/// rather than `Arc<dyn ProtocolHandler>` because `ProtocolHandler`
/// is not dyn-compatible in iroh 1.0 (its methods return
/// `impl Future<...>`). The blanket impl `ProtocolHandler for Arc<T>`
/// in iroh means `Arc<T>: Into<Box<dyn DynProtocolHandler>>`, which
/// is what `RouterBuilder::accept` requires.
pub async fn test_provider<T>(
    identity_path: &Path,
    alpn: Vec<u8>,
    handler: Arc<T>,
) -> Result<(Endpoint, Router)>
where
    T: ProtocolHandler + 'static,
{
    let (ep, _key) = test_endpoint(identity_path).await?;
    let router = Router::builder(ep.clone())
        .accept(alpn, handler)
        .spawn();
    Ok((ep, router))
}

// ----------------------------------------------------------------------
// Phase 2 — control-plane helpers
// ----------------------------------------------------------------------
//
// The Phase 1 helpers above bind an endpoint with the default address
// lookup (pkarr + DNS). Tests that resolve a remote EndpointId through
// those discovery services need network access and therefore fail in a
// sandboxed CI runner. `consume::subscribe` and
// `expose::register_with_server` construct
// `EndpointAddr::new(node_id)` internally, which has no direct
// addresses — they rely on the address lookup to discover the peer.
//
// The helpers below create an in-memory shared `MemoryLookup`, register
// every endpoint bound through them, and attach the same lookup to
// every endpoint so lookups succeed without any network I/O.

/// Build an endpoint that uses a shared in-memory `MemoryLookup` for
/// peer discovery. The endpoint's `EndpointAddr` is registered in the
/// lookup so other endpoints sharing the same lookup can find it by
/// `EndpointId` alone.
pub async fn test_endpoint_in_lookup(
    identity_path: &Path,
    lookup: Arc<MemoryLookup>,
) -> Result<(Endpoint, SecretKey)> {
    let _ = identity_path;
    let key = SecretKey::generate();
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .address_lookup(lookup.clone())
        .secret_key(key.clone())
        .bind()
        .await?;
    // Register the endpoint's full addr (with direct IP addresses) so
    // the lookup can resolve EndpointId-only queries to a dialable
    // address.
    lookup.add_endpoint_info(endpoint.addr());
    Ok((endpoint, key))
}

/// Spin up a provider endpoint using a shared `MemoryLookup`.
pub async fn test_provider_in_lookup<T>(
    identity_path: &Path,
    alpn: Vec<u8>,
    handler: Arc<T>,
    lookup: Arc<MemoryLookup>,
) -> Result<(Endpoint, Router)>
where
    T: ProtocolHandler + 'static,
{
    let (ep, _key) = test_endpoint_in_lookup(identity_path, lookup).await?;
    let router = Router::builder(ep.clone())
        .accept(alpn, handler)
        .spawn();
    Ok((ep, router))
}