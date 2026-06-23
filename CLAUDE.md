# CLAUDE.md — frp2p

Guidance for Claude (or any agent) working in this repo.

## What this project is

A P2P frp-like tunnel tool written in Rust, built on top of
[Iroh](https://github.com/n0-computer/iroh) for QUIC + NAT traversal.

Three binaries from a Cargo workspace:
- `frp2p-server` — control plane (registry) + data-plane relay fallback.
- `frp2p-client` — single binary with two modes (`[[expose]]` and
  `[[consume]]`) that can coexist in one process.
- `frp2p-id` — print or generate the local Iroh NodeID.

Plus `frp2p-client-gui`, a placeholder library for a future GUI
frontend (v1 ships an empty lib.rs).

## Workspace layout

```
frp2p/
├── Cargo.toml                  # [workspace] + [workspace.dependencies]
├── crates/
│   ├── common/                 # shared library (no main)
│   │   └── src/
│   │       ├── lib.rs          # module aggregator + re-exports
│   │       ├── identity.rs     # SecretKey load/generate (chmod 0600 on Unix)
│   │       ├── alpn.rs         # ALPN byte constants + service_name validation
│   │       ├── protocol.rs     # frame types (tag+len+payload), HMAC-SHA256 proof
│   │       ├── tunnel.rs       # bridge() + BiStream wrapper (AsyncRead+AsyncWrite)
│   │       └── config.rs       # serde RootConfig + validate()
│   ├── server/                 # frp2p-server
│   │   └── src/
│   │       ├── main.rs         # CLI + Endpoint bind + Router + heartbeat sweep
│   │       ├── registry.rs     # ServerState / Group / Session / ServiceRecord
│   │       ├── control.rs      # frp2p/control ProtocolHandler
│   │       └── relay.rs        # frp2p/data ProtocolHandler (dumb byte relay)
│   ├── client/                 # frp2p-client + frp2p-id
│   │   └── src/
│   │       ├── main.rs         # CLI + dual expose/consume setup
│   │       ├── expose.rs       # register + ProtocolHandler per service + ControlResponseHandler
│   │       ├── consume.rs      # subscribe + local TCP listener + dial-with-fallback
│   │       └── bin/id.rs       # frp2p-id binary
│   └── client-gui/             # placeholder lib for future GUI
└── examples/                   # sample TOML configs (server, client-A, client-B, etc.)
```

## Build and test

```bash
cargo build --workspace              # debug
cargo build --release --workspace    # release
cargo test  --workspace              # run all unit tests
cargo clippy --workspace -- -D warnings   # lint
```

Pre-built release binaries in `target/release/`:
- `frp2p-server.exe` / `frp2p-server`
- `frp2p-client.exe` / `frp2p-client`
- `frp2p-id.exe` / `frp2p-id`

## Architecture in 60 seconds

```
                 ┌─────────────────────────────┐
                 │   Server (frp2p-server)     │
                 │  - control plane registry   │
                 │  - data plane relay         │
                 │  ALPN: frp2p/control        │
                 │        frp2p/data           │
                 └──────────┬──────────────────┘
                            │ register / subscribe
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
       ┌──────────┐   ┌──────────┐   ┌──────────┐
       │ Client A │   │ Client B │   │ Client C │
       │ expose[] │   │ expose[] │   │ consume[]│
       │ consume[]│   │          │   │          │
       └────┬─────┘   └────┬─────┘   └────┬─────┘
            │  frp2p/<svc> (direct P2P)   │
            └─────────────────────────────┘
```

- **Direct path**: Consumer dials Provider on ALPN `frp2p/<service>`,
  runs an HMAC nonce handshake on the first bi-stream, then bridges
  raw bytes between a local TCP listener and the QUIC stream.
- **Relay path**: Consumer dials Server on ALPN `frp2p/data`, sends
  `DataOpen { target_service, target_provider }`, Server dials
  Provider on `frp2p/<service>` and `copy_bidirectional`s between
  the two bi-streams.
- **Service discovery**: Client → Server (Hello + Subscribe) →
  Server replies with provider's NodeID.

## Key conventions

### Protocol framing
All framed messages use `[tag: u8][len: u16 LE][payload]` with
`MAX_FRAME_PAYLOAD = 32 KiB`. After `AuthOk` on the data plane,
streams carry raw bytes (no framing).

Tag ranges:
- `0x01..=0x0F` — data plane auth (AuthNonce / AuthProof / AuthOk / AuthErr)
- `0x05`        — DataOpen (relay handshake)
- `0x10..=0x1F` — control plane (Hello / HelloOk / Register /
                  RegisterOk / Subscribe / SubscribeOk / Heartbeat / Error)

### ALPN scheme
- `frp2p/control` — control plane (client → server)
- `frp2p/data` — relay (client → server)
- `frp2p/<svc>` — direct P2P data (client ↔ client); `<svc>` must
  match `[a-z0-9-]{1,32}` and not be in the reserved list
  (`control`, `data`, `status`, `reload`, `admin`, `metrics`, `ping`).

### HMAC proof
`HMAC_SHA256(key=shared_secret, msg=service_name || nonce)`.
Always service-bound so a proof for service A can't be replayed
against service B. Comparison is constant-time via `subtle::ConstantTimeEq`.

### One Iroh connection per service
Each `[[expose]]` gets one `Router::accept(frp2p/<name>, handler)`.
Each `[[consume]]` lazily dials one connection to the provider
on that ALPN. Reconnect logic in `client::consume::acquire_or_dial`.

## Iroh 1.0 API notes (notable quirks)

- `Endpoint::builder(presets::N0).secret_key(k).bind().await?` —
  builder takes a `Preset`, not zero args.
- `SecretKey::generate()` — no arguments (returns a new key from OsRng).
- `SecretKey::to_bytes() -> [u8; 32]` /
  `SecretKey::from_bytes(&[u8; 32]) -> Self`.
- `Endpoint::connect(addr, &alpn) -> Connection`.
- `Connection::open_bi() -> (SendStream, RecvStream)` and
  `accept_bi()` symmetrically.
- `SendStream` / `RecvStream` live at `iroh::endpoint::{SendStream, RecvStream}`.
  They implement `AsyncWrite` / `AsyncRead` respectively but **not**
  both — use the `BiStream` wrapper in `common::tunnel` when you need
  a value satisfying `AsyncRead + AsyncWrite` (e.g. for `bridge()`).
- `ProtocolHandler::accept` returns `Result<(), AcceptError>`,
  where `AcceptError::from_err<T: std::error::Error>(t)` is what you
  want. **`anyhow::Error` does NOT implement `std::error::Error`**;
  use `AcceptError::from_boxed(e.into())` via
  `let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();`.
- `EndpointId = PublicKey` (type alias). Display already returns
  the canonical z-base32 string; `FromStr` parses it.
- `iroh` crate re-exports `Connection`, `SendStream`, `RecvStream`
  via `iroh::endpoint::*`. `Endpoint` itself is at `iroh::Endpoint`.

## Configuration file gotchas

- The TOML schema lives in `common::config::RootConfig`. Top-level
  client fields (`server_node_id`, `group_token`, `[[expose]]`,
  `[[consume]]`) sit **outside** `[common]`. `[common.identity_path]`
  and `[common.logging]` are nested.
- TOML table scope: any key after `[common.logging]` belongs to
  `common.logging` until another table header. Always put the
  top-level keys **before** `[common.*]`, or use an explicit
  `[common]` block to reset scope.
- `service_name` must satisfy `validate_service_name` in `common::alpn`
  (lowercase, digits, hyphens; 1..=32 chars; no leading/trailing
  hyphen; no `--`; not reserved).

## Known issues (Windows + iroh 1.0.0 + public DERP)

From the v1 end-to-end smoke test — see README "Known issues":

1. **QUIC multipath bug**: `PATH_CIDS_BLOCKED next sequence number
   larger than in local state` when direct P2P streams open during
   relay migration. Falls back to relay. Likely upstream; track
   iroh releases.
2. **Heartbeat sweep is aggressive**: provider sessions expire when
   the relay rotates and the connection drops. Set
   `heartbeat.timeout_secs ≥ 600` for testing.
3. **Client doesn't ping**: the client registers once and parks the
   control connection. No proactive heartbeat writer on the client.
4. **Same-identity collision**: server and clients share the default
   `<config_dir>/frp2p/identity.key` if `[common].identity_path` is
   unset. Always set distinct identity paths per process.

## Common tasks

### Add a new protocol frame
1. Add the tag constant in `common/src/protocol.rs`.
2. Add a variant to the `Frame` enum.
3. Implement encode in `encode_payload` and decode in `decode`.
4. Update `lib.rs` re-exports if callers need the type.

### Add a new ALPN
1. Define the constant in `common/src/alpn.rs` and a helper if needed.
2. Register in the `Router::builder(...).accept(alpn, handler)`
   call in `server/src/main.rs` and/or `client/src/main.rs`.
3. Implement a `ProtocolHandler` struct (Debug + Clone + Send + Sync).

### Debug "service not found" on the server
Check in order:
- Did the provider client's control session expire? Look for
  `session expired (no heartbeat)` and `garbage-collected service`
  in the server log.
- Does the consumer's `subscribe` reach the same group as the
  provider's `register`? Both must present the same `group_token`.
- Is the consumer's `server_node_id` the server's actual NodeID?
  Re-run `frp2p-id` on the server host.

## Plan file

Project plan lives at `~/.claude/plans/gleaming-meandering-cosmos.md`
(read-only reference). Update it only when restructuring scope;
in-flight tasks are tracked via TaskCreate / TaskUpdate instead.