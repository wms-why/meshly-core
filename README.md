# meshly-core

A P2P frp-like reverse-proxy / port-forwarding tool written in Rust, using
[Iroh](https://github.com/n0-computer/iroh) for QUIC connections, automatic
NAT traversal, and end-to-end encryption.

meshly-core replaces the classic `frpc ↔ frps ↔ visitor` model with a simpler one:

- A central **server** owns the control plane (service registry) and a
  fallback data-plane relay for clients that cannot establish direct P2P.
- Each **client** can both **expose** a local TCP service (publish to the
  group) and **consume** a peer-exposed service (listen locally and tunnel
  inbound TCP to that peer over Iroh).

Built without TUN/TAP — runs without root or admin privileges.

## Workspace layout

```
meshly-core/
├── crates/
│   ├── common/      shared library (identity, ALPN, protocol, tunnel, config)
│   ├── server/      meshly-core-server binary
│   ├── client/      meshly-core-client binary (with `id` subcommand)
│   └── client-gui/  placeholder for the future GUI frontend
└── examples/        sample TOML configs
```

## Build

```bash
cargo build --release
```

Binaries land in `target/release/`:
- `meshly-core-server` (or `meshly-core-server.exe` on Windows)
- `meshly-core-client` (or `meshly-core-client.exe`)

## Quick start

1. **Print the server's NodeID** (run on the host where `meshly-core-server` will run):

   ```bash
   ./target/release/meshly-core-client id
   # -> meshly-core node id: <64 hex chars>
   ```

2. **Start the server**:

   ```bash
   ./target/release/meshly-core-server -c ./examples/server.toml
   ```

3. **Start a client** on a host that has the actual service to expose:

   ```bash
   # Edit client-A.toml: paste the server's NodeID into server_node_id,
   # and confirm [common].identity_path points to a file distinct from
   # the server's. Default in the example is "./keys/provider.key".
   ./target/release/meshly-core-client -c ./examples/client-A.toml
   ```

4. **Start a consumer client** that wants to reach the exposed service:

   ```bash
   # Edit client-B.toml similarly.
   ./target/release/meshly-core-client -c ./examples/client-B.toml
   ```

5. **Verify**:

   ```bash
   curl http://127.0.0.1:19090/    # Should hit host-A's local 18081
   ```

## Tests

```bash
cargo test  --workspace
```

Unit tests cover the common crate (ALPN derivation, frame encoding,
HMAC proofs, tunnel bridging, config validation).

## Known issues

These are tracked from the v1 end-to-end smoke test on Windows
(Rust 1.96, iroh 1.0.0, public DERP relay `relay.n0.iroh.link`):

1. **iroh 1.0 + Windows + public DERP multipath bug.** Direct P2P
   connections sometimes fail at the QUIC layer with
   `PATH_CIDS_BLOCKED next sequence number larger than in local state`
   during stream open. Symptom: the provider logs
   `expose: session ended with error ... PATH_CIDS_BLOCKED ...` and the
   consumer falls back to the server relay. Workarounds:

   - Pin the relay URL to a known-good region via `Endpoint::builder`
     instead of the default `presets::N0`.
   - Run the test on Linux where this path is more reliable.
   - Track iroh releases; this looks like an upstream QUIC-multipath
     edge case on Windows.

2. **Heartbeat-driven session expiry.** The provider's service
   registration lives only as long as its control-plane connection
   is alive. If the provider's relay changes mid-session, the
   server-side heartbeat sweep drops the session and the service is
   garbage-collected. Recommended for v1:

   - Keep `heartbeat.timeout_secs` high (≥ 600s) until the reconnect
     logic is more robust.
   - Have the client proactively re-register services on relay
     change events from Iroh.

3. **Hand-rolled control session on the client.** *(Fixed: v0.1.0+
   proactive heartbeat.)* The client now runs a periodic `Heartbeat`
   writer on the control connection (default 60s), analogous to the
   server's writer. If the connection dies, the writer exits and the
   outer loop reconnects.

4. **Same-machine testing requires explicit `identity_path`.** Without
   distinct identity files in the TOML config, server and clients
   share the default `<config_dir>/meshly-core/identity.key` and end up
   with identical NodeIDs, which causes confusing `subscription:
   service not found` errors. Always set
   `[common].identity_path = "/path/to/distinct/key"` per process.

5. **TOML field ordering matters with `[common]` subtables.** Keys
   placed after `[common.logging]` belong to that subtable. Keep
   top-level fields (`server_node_id`, `group_token`, `[[expose]]`,
   `[[consume]]`) before any `[common.*]` block, or use explicit
   `[common]` blocks to reset context.

## v1 scope

- TCP only.
- Auth: Iroh NodeID identity + per-service shared secret via
  HMAC-SHA256 nonce handshake on the first bi-stream of a connection.
- One Iroh Connection per service (ALPN `meshly-core/<name>`).
- Group token required to register or subscribe.

Not in v1: UDP, HTTP virtual hosting, TUN/TAP, per-stream auth,
hot reload, ACLs, Prometheus metrics, GUI.

## License

MIT OR Apache-2.0