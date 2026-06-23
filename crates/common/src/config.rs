//! Configuration schema and validation.
//!
//! Both `frp2p-server` and `frp2p-client` load TOML files. The schema is
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
    /// location `<config_dir>/frp2p/identity.key` is used.
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
        Ok(())
    }

    fn validate_client(&self) -> Result<(), ConfigError> {
        let v = |s: String| ConfigError::Validate(s);

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
        for c in &self.consume {
            if exp_names.contains(c.name.as_str()) {
                return Err(v(format!(
                    "service {:?} appears in both [[expose]] and [[consume]]",
                    c.name
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

    impl RootConfig {
        fn load_from_str(s: &str) -> Result<Self, ConfigError> {
            let cfg: RootConfig = toml::from_str(s)?;
            cfg.validate()?;
            Ok(cfg)
        }
    }
}