# frp2p

A P2P frp-like reverse-proxy / port-forwarding tool written in Rust, using
[Iroh](https://github.com/n0-computer/iroh) for QUIC connections, automatic
NAT traversal, and end-to-end encryption.

frp2p replaces the classic `frpc ↔ frps ↔ visitor` model with a simpler one:

- A central **server** owns the control plane (service registry) and a
  fallback data-plane relay for clients that cannot establish direct P2P.
- Each **client** can both **expose** a local TCP service (publish to the
  group) and **consume** a peer-exposed service (listen locally and tunnel
  inbound TCP to that peer over Iroh).

Built without TUN/TAP — runs without root or admin privileges.

## Workspace layout

```
frp2p/
├── crates/
│   ├── common/      shared library (identity, ALPN, protocol, tunnel, config)
│   ├── server/      frp2p-server binary
│   ├── client/      frp2p-client + frp2p-id binaries
│   └── client-gui/  placeholder for the future GUI frontend
└── examples/        sample TOML configs
```

## Build

```bash
cargo build --release
```

Binaries land in `target/release/`:
- `frp2p-server` (or `frp2p-server.exe` on Windows)
- `frp2p-client` (or `frp2p-client.exe`)
- `frp2p-id`

## Quick start

1. **Print the server's NodeID** (run on the host where `frp2p-server` will run):

   ```bash
   ./target/release/frp2p-id
   # -> frp2p node id: <64 hex chars>
   ```

2. **Start the server**:

   ```bash
   ./target/release/frp2p-server -c ./examples/server.toml
   ```

3. **Start a client** on a host that has the actual service to expose:

   ```bash
   # Edit client-A.toml: set [common].identity_path and server_node_id
   ./target/release/frp2p-client -c ./examples/client-A.toml
   ```

4. **Start a consumer client** that wants to reach the exposed service:

   ```bash
   # Edit client-B.toml similarly.
   ./target/release/frp2p-client -c ./examples/client-B.toml
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

3. **Hand-rolled control session on the client.** The client currently
   registers once on startup and then parks the connection with
   `std::future::pending()`. If the connection dies the client
   reconnects every 5s, but there's no proactive ping. Add a
   periodic `Heartbeat` writer on the client side analogous to the
   server's writer to keep the session alive through relay hops.

4. **Same-machine testing requires explicit `identity_path`.** Without
   distinct identity files in the TOML config, server and clients
   share the default `<config_dir>/frp2p/identity.key` and end up
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
- One Iroh Connection per service (ALPN `frp2p/<name>`).
- Group token required to register or subscribe.

Not in v1: UDP, HTTP virtual hosting, TUN/TAP, per-stream auth,
hot reload, ACLs, Prometheus metrics, GUI.

## License

MIT OR Apache-2.0