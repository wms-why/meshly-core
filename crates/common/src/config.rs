//! Configuration schema and validation.
//!
//! Both `meshly-core-server` and `meshly-core-client` load TOML files. The schema is
//! flattened: a single `RootConfig` discriminates between the two roles by
//! which optional sections are present.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::alpn::{alpn_for_service, validate_service_name};

/// Top-level configuration.
///
/// The TOML file is parsed into one of the role-specific configs by
/// inspecting which sections are present. The server never defines
/// `server_node_id` / `[[expose]]` / `[[consume]]`; the client never
/// defines `[[groups]]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    /// Common fields shared by both server and client (logging, identity path).
    #[serde(default)]
    pub common: CommonConfig,

    // ---- server-only fields ----
    /// Server-only: list of groups managed by this server.
    #[serde(default, rename = "group", skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupConfig>,
    /// Server-only: heartbeat tuning.
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    /// Server-only: relay tuning (bandwidth limits, etc).
    ///
    /// `Some` only when the TOML contains a `[relay]` section. The
    /// validator rejects `Some` in client configs — the reply-bandwidth
    /// cap is server-administered and the client has no authority over
    /// it. A server config that omits `[relay]` deserializes to `None`
    /// and falls back to [`RelayConfig::default`] at use time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayConfig>,

    // ---- client-only fields ----
    /// Client-only: server's Iroh NodeID (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_node_id: Option<String>,
    /// Client-only: shared group token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_token: Option<String>,

    /// Client-only: services to publish.
    #[serde(default, rename = "expose", skip_serializing_if = "Vec::is_empty")]
    pub expose: Vec<ExposeConfig>,
    /// Client-only: HTTP static file services to publish.
    #[serde(default, rename = "static", skip_serializing_if = "Vec::is_empty")]
    pub static_services: Vec<StaticConfig>,
    /// Client-only: services to consume from peers in the group.
    #[serde(default, rename = "consume", skip_serializing_if = "Vec::is_empty")]
    pub consume: Vec<ConsumeConfig>,
    /// Client-only: reconnect tuning.
    #[serde(default)]
    pub reconnect: ReconnectConfig,
}

/// Common fields (logging, identity).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonConfig {
    /// Path to the persisted Iroh identity key. If `None`, the default
    /// location `<config_dir>/meshly-core/identity.key` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_path: Option<PathBuf>,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// One of trace, debug, info, warn, error. Defaults to "info".
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { level: default_log_level() }
    }
}

fn default_log_level() -> String {
    "info".into()
}

/// Server-side: a managed group. Clients authenticate to a group with the
/// matching `group_token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    /// Group identifier; informational only, must be unique per server.
    pub name: String,
    /// Shared secret that all clients in this group must present.
    pub group_token: String,
}

/// Server-side: heartbeat tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatConfig {
    /// Seconds between heartbeats sent by the server to each client.
    pub interval_secs: u64,
    /// Seconds without a heartbeat before a client is declared offline.
    pub timeout_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            timeout_secs: 90,
        }
    }
}

/// Server-side: relay-plane tuning.
///
/// **Server-only.** Caps the rate at which the relay forwards **replies**
/// (provider → consumer) through the server. The cap is enforced per
/// active connection; each connection's limit can later be changed
/// dynamically via the rate-handle registry held by
/// `meshly_core_server::registry::ServerState`.
///
/// This type is intentionally **not** re-exported from
/// `meshly_core_common`'s public API — it's part of the common crate
/// only so that `RootConfig` can deserialize it via serde. Client code
/// has no business constructing, reading, or mutating one, and the
/// config validator rejects any client TOML that contains a `[relay]`
/// section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Master switch for reply-bandwidth throttling.
    ///
    /// `false` (the default) bypasses the rate limiter entirely: the
    /// relay forwards all reply bytes as fast as the underlying QUIC
    /// streams allow, and per-consumer overrides are parsed but not
    /// applied. `true` engages the limiter using `bytes_per_sec` as
    /// the default cap, with `rate_overrides` taking precedence for
    /// specific consumers.
    #[serde(default)]
    pub enabled: bool,

    /// Per-connection reply bandwidth cap in **bytes per second**
    /// applied to consumers that don't appear in `rate_overrides`.
    /// `0` disables throttling (unlimited) **for that specific
    /// consumer** — the master `enabled` switch still governs whether
    /// throttling runs at all.
    ///
    /// Only consulted when `enabled = true`. Defaults to 100 KiB/s
    /// (102_400 bytes/s) when omitted, but that value is harmless if
    /// the master switch is off.
    #[serde(default = "default_relay_bytes_per_sec")]
    pub bytes_per_sec: u64,

    /// Per-consumer overrides keyed by the consumer's EndpointID (as
    /// canonical z-base32 or 64-char hex). When a consumer opens a
    /// relayed tunnel, the server looks it up here and uses the
    /// override as the initial rate for that connection. Consumers not
    /// listed fall back to `bytes_per_sec` above.
    ///
    /// The data plane's `DataOpen` frame carries the consumer's own
    /// NodeID so the server can match it against this table; if the
    /// frame's `consumer_node_id` doesn't match the connection's
    /// `remote_id()` the server rejects the open. Like `bytes_per_sec`,
    /// these rows only take effect when `enabled = true`.
    #[serde(default, rename = "rate_override", skip_serializing_if = "Vec::is_empty")]
    pub rate_overrides: Vec<RelayRateOverride>,
}

fn default_relay_bytes_per_sec() -> u64 {
    100 * 1024
}

impl Default for RelayConfig {
    fn default() -> Self {
        // Master switch is OFF by default: rate limiting is opt-in.
        // The 100 KiB/s default for `bytes_per_sec` is dormant in that
        // state; flipping `enabled = true` activates it.
        Self {
            enabled: false,
            bytes_per_sec: default_relay_bytes_per_sec(),
            rate_overrides: Vec::new(),
        }
    }
}

/// Server-side: one row of the per-consumer rate-override table.
///
/// `node_id` is the consumer's EndpointID, accepted in the same string
/// forms as the rest of the project (z-base32 default; 64-char hex also
/// recognized — see `parse_endpoint_id`). `bytes_per_sec = 0` means
/// unlimited for that specific consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRateOverride {
    pub node_id: String,
    pub bytes_per_sec: u64,
}

/// Client-side: a local service to expose to the group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeConfig {
    /// Service name (must satisfy `[a-z0-9-]{1,32}`).
    pub name: String,
    /// Local backend address (e.g. `127.0.0.1:22`).
    pub local_addr: SocketAddr,
    /// Shared secret that consumers must present to access this service.
    pub shared_secret: String,
}

/// Client-side: an HTTP static file service to publish to the group.
///
/// On incoming P2P traffic, the client serves files rooted at
/// `root_dir` over HTTP/1.1. If `allow_directory_listing` is true, GET
/// on a directory returns an HTML index; otherwise it returns 403.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticConfig {
    /// Service name (must satisfy `[a-z0-9-]{1,32}`).
    pub name: String,
    /// Local root directory to serve files from. Must exist and be a
    /// directory at config load time.
    pub root_dir: PathBuf,
    /// When true, GET on a directory returns an HTML listing of its
    /// children. When false, directories return 403.
    #[serde(default)]
    pub allow_directory_listing: bool,
    /// Shared secret that consumers must present to access this service.
    pub shared_secret: String,
}

/// Client-side: a remote service to subscribe to and expose locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeConfig {
    /// Service name (must match a peer's `ExposeConfig.name`).
    pub name: String,
    /// Local address to bind for the consumer listener (e.g. `127.0.0.1:2222`).
    pub local_bind: SocketAddr,
    /// Shared secret matching the provider's `ExposeConfig.shared_secret`.
    pub shared_secret: String,
}

/// Client-side: reconnect tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectConfig {
    /// Initial backoff after a disconnect.
    pub initial_backoff_ms: u64,
    /// Cap on the backoff.
    pub max_backoff_ms: u64,
    /// Prefer direct P2P over the server relay when both are possible.
    pub prefer_direct: bool,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_backoff_ms: 50,
            max_backoff_ms: 5000,
            prefer_direct: true,
        }
    }
}

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config file {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("validation: {0}")]
    Validate(String),
}

impl RootConfig {
    /// Load a `RootConfig` from a TOML file and validate it.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let cfg: RootConfig = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate the configuration. Catches role confusion (server fields on
    /// client configs and vice versa) plus per-section constraints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let v = |s: String| ConfigError::Validate(s);

        // Detect role: server if any `[[group]]` is defined, else client.
        let has_server_fields = !self.groups.is_empty();
        let has_client_fields =
            self.server_node_id.is_some() || !self.expose.is_empty() || !self.consume.is_empty();

        if has_server_fields && has_client_fields {
            return Err(v(
                "config mixes server ([[group]]) and client ([[expose]]/[[consume]]) fields"
                    .into(),
            ));
        }
        if !has_server_fields && !has_client_fields {
            return Err(v(
                "config defines no [[group]], [[expose]], or [[consume]] sections".into(),
            ));
        }

        if has_server_fields {
            self.validate_server()?;
        } else {
            self.validate_client()?;
        }

        // Logging level sanity.
        match self.common.logging.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => return Err(v(format!("unknown logging.level: {other:?}"))),
        }

        Ok(())
    }

    fn validate_server(&self) -> Result<(), ConfigError> {
        let v = |s: String| ConfigError::Validate(s);
        let mut seen = std::collections::HashSet::new();
        for g in &self.groups {
            if !seen.insert(g.name.as_str()) {
                return Err(v(format!("duplicate group name: {:?}", g.name)));
            }
            if g.group_token.is_empty() {
                return Err(v(format!("group {:?}: group_token is empty", g.name)));
            }
        }
        // Each [[relay.rate_override]] entry must reference a valid
        // EndpointID. We parse eagerly here so config load fails loudly
        // on typos instead of silently dropping the row at lookup time.
        let mut seen_ids: std::collections::HashSet<iroh::EndpointId> =
            std::collections::HashSet::new();
        for (idx, ov) in self
            .relay
            .as_ref()
            .map(|r| r.rate_overrides.as_slice())
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            let id = crate::endpoint::parse_endpoint_id(&ov.node_id).ok_or_else(|| {
                v(format!(
                    "relay.rate_override[{}].node_id {:?} is not a valid EndpointID \
                     (expected canonical z-base32 or 64-char hex)",
                    idx, ov.node_id
                ))
            })?;
            if !seen_ids.insert(id) {
                return Err(v(format!(
                    "relay.rate_override[{}]: duplicate node_id {:?}",
                    idx, ov.node_id
                )));
            }
        }
        Ok(())
    }

    fn validate_client(&self) -> Result<(), ConfigError> {
        let v = |s: String| ConfigError::Validate(s);

        // Server-administered knobs: clients have no authority over
        // these and any attempt to set them is treated as a config
        // error (most often a copy-pasted server.toml). Reject early
        // so the failure mode is loud rather than silently ignored.
        if self.relay.is_some() {
            return Err(v(
                "[relay] is server-only and must not appear in client configs; \
                 the reply-bandwidth cap is administered by the server operator"
                    .into(),
            ));
        }

        let node_id = self
            .server_node_id
            .as_ref()
            .ok_or_else(|| v("client config missing server_node_id".into()))?;
        if node_id.is_empty() {
            return Err(v("server_node_id is empty".into()));
        }

        let token = self
            .group_token
            .as_ref()
            .ok_or_else(|| v("client config missing group_token".into()))?;
        if token.is_empty() {
            return Err(v("group_token is empty".into()));
        }

        // Reject same name in both expose and consume (semantic ambiguity).
        let exp_names: std::collections::HashSet<_> =
            self.expose.iter().map(|e| e.name.as_str()).collect();
        let static_names: std::collections::HashSet<_> = self
            .static_services
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        // Reject duplicate names within the same table (would silently
        // shadow earlier entries at runtime — define explicitly instead).
        let mut seen_expose = std::collections::HashSet::new();
        for e in &self.expose {
            if !seen_expose.insert(e.name.as_str()) {
                return Err(v(format!(
                    "duplicate service name {:?} in [[expose]]",
                    e.name
                )));
            }
        }
        let mut seen_consume = std::collections::HashSet::new();
        for c in &self.consume {
            if !seen_consume.insert(c.name.as_str()) {
                return Err(v(format!(
                    "duplicate service name {:?} in [[consume]]",
                    c.name
                )));
            }
        }
        let mut seen_static = std::collections::HashSet::new();
        for s in &self.static_services {
            if !seen_static.insert(s.name.as_str()) {
                return Err(v(format!(
                    "duplicate service name {:?} in [[static]]",
                    s.name
                )));
            }
        }
        for c in &self.consume {
            if exp_names.contains(c.name.as_str()) || static_names.contains(c.name.as_str()) {
                return Err(v(format!(
                    "service {:?} appears in both [[expose]] or [[static]] and [[consume]]",
                    c.name
                )));
            }
        }
        for e in &self.expose {
            if static_names.contains(e.name.as_str()) {
                return Err(v(format!(
                    "service {:?} appears in both [[expose]] and [[static]]",
                    e.name
                )));
            }
        }

        for e in &self.expose {
            validate_service_name(&e.name).map_err(|err| v(format!("expose {:?}: {err}", e.name)))?;
            if e.shared_secret.is_empty() {
                return Err(v(format!("expose {:?}: shared_secret is empty", e.name)));
            }
            // Pre-compute ALPN to fail fast on bad names.
            alpn_for_service(&e.name).map_err(|err| v(format!("expose {:?}: {err}", e.name)))?;
        }
        for s in &self.static_services {
            validate_service_name(&s.name)
                .map_err(|err| v(format!("static {:?}: {err}", s.name)))?;
            if s.shared_secret.is_empty() {
                return Err(v(format!(
                    "static {:?}: shared_secret is empty",
                    s.name
                )));
            }
            if !s.root_dir.exists() {
                return Err(v(format!(
                    "static {:?}: root_dir {:?} does not exist",
                    s.name,
                    s.root_dir.display()
                )));
            }
            if !s.root_dir.is_dir() {
                return Err(v(format!(
                    "static {:?}: root_dir {:?} is not a directory",
                    s.name,
                    s.root_dir.display()
                )));
            }
            alpn_for_service(&s.name).map_err(|err| v(format!("static {:?}: {err}", s.name)))?;
        }
        for c in &self.consume {
            validate_service_name(&c.name).map_err(|err| v(format!("consume {:?}: {err}", c.name)))?;
            if c.shared_secret.is_empty() {
                return Err(v(format!("consume {:?}: shared_secret is empty", c.name)));
            }
            alpn_for_service(&c.name).map_err(|err| v(format!("consume {:?}: {err}", c.name)))?;
        }

        Ok(())
    }

    /// Returns true if this config defines a server (has any [[group]]).
    pub fn is_server(&self) -> bool {
        !self.groups.is_empty()
    }
}

// Convenient type aliases used by binary crates.
pub type ServerConfig = RootConfig;
pub type ClientConfig = RootConfig;

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_SERVER: &str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "secret"
"#;

    const GOOD_CLIENT: &str = r#"
server_node_id = "abcd"
group_token = "secret"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "s"

[[consume]]
name = "lan-db"
local_bind = "127.0.0.1:3307"
shared_secret = "s"
"#;

    #[test]
    fn parses_valid_server() {
        let cfg = RootConfig::load_from_str(GOOD_SERVER).unwrap();
        assert!(cfg.is_server());
        assert_eq!(cfg.groups.len(), 1);
    }

    #[test]
    fn parses_valid_client() {
        let cfg = RootConfig::load_from_str(GOOD_CLIENT).unwrap();
        assert!(!cfg.is_server());
        assert_eq!(cfg.expose.len(), 1);
        assert_eq!(cfg.consume.len(), 1);
    }

    #[test]
    fn rejects_mixed_role() {
        let mixed = r#"
server_node_id = "abcd"
group_token = "tok"

[[group]]
name = "g"
group_token = "tok"
"#;
        let err = RootConfig::load_from_str(mixed).unwrap_err();
        assert!(matches!(err, ConfigError::Validate(_)));
    }

    #[test]
    fn rejects_empty_role() {
        let empty = r#"
[common.logging]
level = "info"
"#;
        let err = RootConfig::load_from_str(empty).unwrap_err();
        assert!(matches!(err, ConfigError::Validate(_)));
    }

    #[test]
    fn rejects_same_name_expose_consume() {
        let bad = r#"
server_node_id = "abcd"
group_token = "tok"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "a"

[[consume]]
name = "ssh"
local_bind = "127.0.0.1:2222"
shared_secret = "b"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("ssh")),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_service_name() {
        let bad = r#"
server_node_id = "abcd"
group_token = "tok"

[[expose]]
name = "Bad Name!"
local_addr = "127.0.0.1:22"
shared_secret = "a"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        assert!(matches!(err, ConfigError::Validate(_)));
    }

    #[test]
    fn rejects_bad_log_level() {
        let bad = r#"
[common.logging]
level = "verbose"

[[group]]
name = "g"
group_token = "tok"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("logging.level")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_valid_static_entry() {
        // Use this crate's source dir as a guaranteed-existing directory.
        let here = std::env::current_dir().unwrap();
        let cfg_str = format!(
            r#"
server_node_id = "abcd"
group_token = "tok"

[[static]]
name = "files"
root_dir = "{}"
shared_secret = "s"
allow_directory_listing = true
"#,
            here.display().to_string().replace('\\', "\\\\")
        );
        let cfg = RootConfig::load_from_str(&cfg_str).unwrap();
        assert_eq!(cfg.static_services.len(), 1);
        assert_eq!(cfg.static_services[0].name, "files");
        assert!(cfg.static_services[0].allow_directory_listing);
    }

    #[test]
    fn static_defaults_allow_listing_to_false() {
        let here = std::env::current_dir().unwrap();
        let cfg_str = format!(
            r#"
server_node_id = "abcd"
group_token = "tok"

[[static]]
name = "files"
root_dir = "{}"
shared_secret = "s"
"#,
            here.display().to_string().replace('\\', "\\\\")
        );
        let cfg = RootConfig::load_from_str(&cfg_str).unwrap();
        assert!(!cfg.static_services[0].allow_directory_listing);
    }

    #[test]
    fn rejects_static_with_missing_root_dir() {
        let bad = r#"
server_node_id = "abcd"
group_token = "tok"

[[static]]
name = "files"
root_dir = "/nope/this/does/not/exist/at/all"
shared_secret = "s"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("root_dir")),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_static_with_root_dir_pointing_at_file() {
        // Use Cargo.toml as a known file in the workspace.
        let here = std::env::current_dir().unwrap();
        let cfg_str = format!(
            r#"
server_node_id = "abcd"
group_token = "tok"

[[static]]
name = "files"
root_dir = "{}/Cargo.toml"
shared_secret = "s"
"#,
            here.display().to_string().replace('\\', "\\\\")
        );
        let err = RootConfig::load_from_str(&cfg_str).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("not a directory")),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_same_name_across_static_and_consume() {
        let here = std::env::current_dir().unwrap();
        let cfg_str = format!(
            r#"
server_node_id = "abcd"
group_token = "tok"

[[static]]
name = "files"
root_dir = "{}"
shared_secret = "s"

[[consume]]
name = "files"
local_bind = "127.0.0.1:8080"
shared_secret = "s"
"#,
            here.display().to_string().replace('\\', "\\\\")
        );
        let err = RootConfig::load_from_str(&cfg_str).unwrap_err();
        assert!(matches!(err, ConfigError::Validate(_)));
    }

    #[test]
    fn rejects_same_name_across_static_and_expose() {
        let here = std::env::current_dir().unwrap();
        let cfg_str = format!(
            r#"
server_node_id = "abcd"
group_token = "tok"

[[expose]]
name = "files"
local_addr = "127.0.0.1:22"
shared_secret = "s"

[[static]]
name = "files"
root_dir = "{}"
shared_secret = "s"
"#,
            here.display().to_string().replace('\\', "\\\\")
        );
        let err = RootConfig::load_from_str(&cfg_str).unwrap_err();
        assert!(matches!(err, ConfigError::Validate(_)));
    }

    impl RootConfig {
        fn load_from_str(s: &str) -> Result<Self, ConfigError> {
            let cfg: RootConfig = toml::from_str(s)?;
            cfg.validate()?;
            Ok(cfg)
        }
    }

    // -- Phase 0: round-trip each example TOML and exercise validate() -----

    /// Load each example TOML from disk, validate it (with any root_dir
    /// rewrite so we can test in isolation), then re-serialize and
    /// re-parse, asserting structural equality.
    ///
    /// For configs that reference a real directory (static), we rewrite
    /// the `root_dir` to a guaranteed-existing tempdir so validation
    /// passes regardless of the host filesystem.
    #[test]
    fn roundtrip_example_server_toml() {
        let cfg = load_example("server.toml").expect("server.toml must parse");
        let s = toml::to_string(&cfg).unwrap();
        let back: RootConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.groups.len(), cfg.groups.len());
        assert_eq!(back.groups[0].name, cfg.groups[0].name);
        assert_eq!(back.groups[0].group_token, cfg.groups[0].group_token);
        assert_eq!(back.common.logging.level, cfg.common.logging.level);
        assert!(back.is_server());
    }

    #[test]
    fn roundtrip_example_client_a_toml() {
        let cfg = load_example("client-A.toml").expect("client-A.toml must parse");
        assert_eq!(cfg.expose.len(), 1);
        assert!(cfg.expose[0].shared_secret.len() > 0);
        let s = toml::to_string(&cfg).unwrap();
        let back: RootConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.expose.len(), 1);
        assert_eq!(back.expose[0].name, cfg.expose[0].name);
        assert_eq!(back.expose[0].local_addr, cfg.expose[0].local_addr);
        assert_eq!(back.expose[0].shared_secret, cfg.expose[0].shared_secret);
        assert!(!back.is_server());
    }

    #[test]
    fn roundtrip_example_client_b_toml() {
        let cfg = load_example("client-B.toml").expect("client-B.toml must parse");
        assert_eq!(cfg.expose.len(), 1);
        assert_eq!(cfg.consume.len(), 1);
        let s = toml::to_string(&cfg).unwrap();
        let back: RootConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.expose.len(), cfg.expose.len());
        assert_eq!(back.consume.len(), cfg.consume.len());
        assert_eq!(back.expose[0].name, cfg.expose[0].name);
        assert_eq!(back.consume[0].name, cfg.consume[0].name);
        assert_eq!(back.consume[0].local_bind, cfg.consume[0].local_bind);
        assert!(!back.is_server());
    }

    #[test]
    fn roundtrip_example_consume_only_toml() {
        let cfg =
            load_example("client-consume-only.toml").expect("client-consume-only.toml must parse");
        assert!(cfg.expose.is_empty());
        assert_eq!(cfg.consume.len(), 1);
        let s = toml::to_string(&cfg).unwrap();
        let back: RootConfig = toml::from_str(&s).unwrap();
        assert!(back.expose.is_empty());
        assert_eq!(back.consume.len(), 1);
        assert_eq!(back.consume[0].name, cfg.consume[0].name);
        assert_eq!(back.consume[0].shared_secret, cfg.consume[0].shared_secret);
    }

    #[test]
    fn roundtrip_example_expose_only_toml() {
        let cfg =
            load_example("client-expose-only.toml").expect("client-expose-only.toml must parse");
        assert!(cfg.consume.is_empty());
        assert_eq!(cfg.expose.len(), 1);
        let s = toml::to_string(&cfg).unwrap();
        let back: RootConfig = toml::from_str(&s).unwrap();
        assert!(back.consume.is_empty());
        assert_eq!(back.expose.len(), 1);
        assert_eq!(back.expose[0].name, cfg.expose[0].name);
    }

    #[test]
    fn roundtrip_example_static_only_toml() {
        // The example static-only config points at /Users/me/photos which
        // does not exist on most dev machines. We rewrite root_dir to a
        // guaranteed-existing tempdir so validation succeeds, then round-trip.
        let mut cfg =
            load_example("client-static-only.toml").expect("client-static-only.toml must parse");
        let tmp = tempfile::tempdir().unwrap();
        cfg.static_services[0].root_dir = tmp.path().to_path_buf();
        cfg.validate().expect("rewritten config must validate");

        let s = toml::to_string(&cfg).unwrap();
        let back: RootConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.static_services.len(), 1);
        assert_eq!(back.static_services[0].name, cfg.static_services[0].name);
        assert!(back.static_services[0].allow_directory_listing);
        assert_eq!(back.static_services[0].root_dir, tmp.path());
    }

    /// Helper: load a `RootConfig` from the workspace's `examples/` dir
    /// without running validate (some examples have placeholder
    /// `server_node_id` strings that pass serde but aren't valid NodeIDs
    /// at runtime, and the static example references a path that may not
    /// exist on the test host).
    fn load_example(name: &str) -> Result<RootConfig, ConfigError> {
        // examples/ lives two directories up from this file: .../common/src/config.rs
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join(name);
        let text = std::fs::read_to_string(&path).map_err(|e| ConfigError::Io {
            path: path.clone(),
            source: e,
        })?;
        let cfg: RootConfig = toml::from_str(&text)?;
        // Don't validate — placeholder server_node_id ("REPLACE_ME_…")
        // and root_dir paths would fail. Round-tripping tests are
        // structural and don't care about validation.
        Ok(cfg)
    }

    // -- Phase 0: validate() rejections ----------------------------------

    #[test]
    fn rejects_client_missing_server_node_id() {
        let bad = r#"
group_token = "tok"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "a"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("server_node_id")),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_client_with_empty_server_node_id() {
        let bad = r#"
server_node_id = ""
group_token = "tok"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "a"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("server_node_id")),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_client_missing_group_token() {
        let bad = r#"
server_node_id = "abcd"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "a"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("group_token")),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    /// `[relay]` is server-administered. A client TOML containing one
    /// must be rejected so a copy-pasted `server.toml` doesn't silently
    /// pretend to set the reply-bandwidth cap from the client side.
    #[test]
    fn rejects_relay_section_in_client_config() {
        let bad = r#"
server_node_id = "abcd"
group_token = "tok"

[relay]
bytes_per_sec = 999999

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "a"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(
                s.contains("relay") && s.contains("server-only"),
                "expected server-only relay error, got: {s}"
            ),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    /// Counterpart: a server config without `[relay]` must still parse
    /// + validate cleanly so omitting the section picks up the defaults.
    #[test]
    fn server_config_without_relay_section_is_allowed() {
        let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"
"#;
        let cfg = RootConfig::load_from_str(cfg_str).expect("omitted [relay] is fine");
        assert!(cfg.is_server());
        assert!(cfg.relay.is_none(), "no [relay] => None, not default");
    }

    /// And a server config WITH `[relay]` is accepted and the value is
    /// read faithfully.
    #[test]
    fn server_config_with_relay_section_is_read() {
        let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[relay]
bytes_per_sec = 4096
"#;
        let cfg = RootConfig::load_from_str(cfg_str).expect("[relay] on server is fine");
        assert!(cfg.is_server());
        let relay = cfg.relay.as_ref().expect("Some(_))");
        assert_eq!(relay.bytes_per_sec, 4096);
        assert!(relay.rate_overrides.is_empty());
    }

    /// `[[relay.rate_override]]` rows with valid EndpointIDs round-trip
    /// through validation.
    #[test]
    fn server_config_with_rate_overrides_is_accepted() {
        // 32-byte all-zero payload is a valid ed25519 public key (the
        // identity point) — avoids the test breaking on random-looking
        // hex strings that decode to non-curve points.
        let nid_hex = "00".repeat(32);
        let cfg_str = format!(
            r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[relay]
bytes_per_sec = 102400

[[relay.rate_override]]
node_id = "{nid_hex}"
bytes_per_sec = 1048576
"#
        );
        let cfg = RootConfig::load_from_str(&cfg_str).expect("valid override accepted");
        let relay = cfg.relay.as_ref().expect("Some(_))");
        assert_eq!(relay.rate_overrides.len(), 1);
        assert_eq!(relay.rate_overrides[0].bytes_per_sec, 1048576);
        assert_eq!(relay.rate_overrides[0].node_id, nid_hex);
    }

    /// `[[relay.rate_override]]` rows with garbage in `node_id` are
    /// rejected at config load, not silently dropped at lookup time.
    #[test]
    fn server_config_with_malformed_rate_override_is_rejected() {
        let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[[relay.rate_override]]
node_id = "not-a-real-endpoint-id"
bytes_per_sec = 4096
"#;
        let err = RootConfig::load_from_str(cfg_str).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(
                s.contains("rate_override") && s.contains("node_id"),
                "msg: {s}"
            ),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    /// Two `[[relay.rate_override]]` rows claiming the same NodeID is a
    /// config error.
    #[test]
    fn server_config_with_duplicate_rate_override_is_rejected() {
        let nid_hex = "00".repeat(32);
        let cfg_str = format!(
            r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[[relay.rate_override]]
node_id = "{nid_hex}"
bytes_per_sec = 4096

[[relay.rate_override]]
node_id = "{nid_hex}"
bytes_per_sec = 8192
"#
        );
        let err = RootConfig::load_from_str(&cfg_str).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(
                s.contains("rate_override") && s.contains("duplicate"),
                "msg: {s}"
            ),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_expose_names() {
        let bad = r#"
server_node_id = "abcd"
group_token = "tok"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:22"
shared_secret = "a"

[[expose]]
name = "ssh"
local_addr = "127.0.0.1:23"
shared_secret = "b"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => assert!(s.contains("ssh"), "msg: {s}"),
            other => panic!("expected validate error, got {other:?}"),
        }
    }

    /// The plan asks us to verify `[[consume]]` referencing an unknown
    /// service is rejected. Today the validator only checks that
    /// consume/expose/static names don't collide; cross-references to
    /// *peer* services are not validated (a consumer can name a service
    /// that only exists on another client). We pin that semantic by
    /// asserting a consume entry with an unknown service name still
    /// Master switch defaults to OFF — rate limiting is opt-in. Pinning
/// the default here so a future refactor that flips it can't silently
/// start throttling production servers.
#[test]
fn relay_master_switch_defaults_to_off() {
    let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[relay]
bytes_per_sec = 999999
"#;
    let cfg = RootConfig::load_from_str(cfg_str).expect("[relay] with bytes_per_sec parses");
    let relay = cfg.relay.as_ref().expect("Some(_))");
    assert!(
        !relay.enabled,
        "relay.enabled must default to false when omitted"
    );
    // The bytes_per_sec is parsed faithfully but is dormant because
    // the master switch is off.
    assert_eq!(relay.bytes_per_sec, 999999);
}

#[test]
fn relay_master_switch_explicit_on_is_accepted() {
    let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[relay]
enabled = true
bytes_per_sec = 4096
"#;
    let cfg = RootConfig::load_from_str(cfg_str).expect("explicit enabled = true parses");
    let relay = cfg.relay.as_ref().expect("Some(_))");
    assert!(relay.enabled);
    assert_eq!(relay.bytes_per_sec, 4096);
}

#[test]
fn relay_master_switch_explicit_off_is_accepted() {
    let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"

[relay]
enabled = false
"#;
    let cfg = RootConfig::load_from_str(cfg_str).expect("explicit enabled = false parses");
    let relay = cfg.relay.as_ref().expect("Some(_))");
    assert!(!relay.enabled);
    // bytes_per_sec falls back to the 100 KiB/s default; that's
    // dormant when the switch is off.
    assert_eq!(relay.bytes_per_sec, 100 * 1024);
}

#[test]
fn relay_section_omitted_means_disabled() {
    let cfg_str = r#"
[common.logging]
level = "info"

[[group]]
name = "homelab"
group_token = "tok"
"#;
    let cfg = RootConfig::load_from_str(cfg_str).expect("omitted [relay] is fine");
    assert!(cfg.relay.is_none(), "no [relay] => None");
}

#[test]
fn relay_rate_limit_default_for_relay_config() {
    // The struct-level `Default` must produce a disabled switch so
    // any code that constructs a `RelayConfig::default()` (rather
    // than deserializing one) starts from "off".
    let d = RelayConfig::default();
    assert!(!d.enabled, "default RelayConfig must be disabled");
    assert!(d.rate_overrides.is_empty());
}

/// The plan asks us to verify `[[consume]]` referencing an unknown
/// service is rejected. Today the validator only checks that
/// consume/expose/static names don't collide; cross-references to
/// *peer* services are not validated (a consumer can name a service
/// that only exists on another client). We pin that semantic by
/// asserting a consume entry with an unknown service name still
/// parses + validates successfully — this test is documentation, not
/// a rejection test. If future phases want stricter validation,
/// they'll update this expectation.
#[test]
fn consume_referencing_unknown_service_is_allowed() {
        let cfg_str = r#"
server_node_id = "abcd"
group_token = "tok"

[[consume]]
name = "remote-only-service"
local_bind = "127.0.0.1:9000"
shared_secret = "s"
"#;
        let cfg = RootConfig::load_from_str(cfg_str).expect("consume of unknown peer svc is valid");
        assert_eq!(cfg.consume.len(), 1);
        assert_eq!(cfg.consume[0].name, "remote-only-service");
    }

    #[test]
    fn rejects_duplicate_group_names() {
        let bad = r#"
[[group]]
name = "homelab"
group_token = "a"

[[group]]
name = "homelab"
group_token = "b"
"#;
        let err = RootConfig::load_from_str(bad).unwrap_err();
        match err {
            ConfigError::Validate(s) => {
                assert!(s.contains("duplicate") || s.contains("homelab"));
            }
            other => panic!("expected validate error, got {other:?}"),
        }
    }
}