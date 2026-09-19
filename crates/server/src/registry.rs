//! In-memory registry of groups, sessions, and services.
//!
//! Concurrency model: one `std::sync::RwLock<ServerStateInner>` guards the
//! group map. Inside each group we use `DashMap` for `sessions` and
//! `services` so that per-group lookups can proceed in parallel without
//! blocking the global lock. The lock is only held for HashMap lookups
//! and DashMap references; once handed out, no global lock is involved.
//!
//! Active relay streams register their rate-limit handles in the
//! `relay_rates` DashMap under a unique `stream_id`. This is the hook
//! future control-plane handlers will use to adjust the bandwidth cap
//! of an individual connection without restarting it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dashmap::DashMap;
use iroh::{EndpointId, SecretKey};

/// Top-level server state.
#[derive(Debug)]
pub struct ServerState {
    inner: RwLock<ServerStateInner>,
    /// Monotonic counter for relay stream ids. Stable for the lifetime
    /// of the server process; never reused.
    next_stream_id: AtomicU64,
    /// Active relay streams, keyed by `stream_id`. The value is the
    /// `Arc<AtomicU64>` rate handle the writer reads each refill.
    relay_rates: DashMap<u64, Arc<AtomicU64>>,
    /// Per-consumer reply-rate overrides from the server config. Looked
    /// up by the consumer's EndpointID when a new relay tunnel opens;
    /// consumers not listed fall back to the global default. `0` in
    /// the value means "unlimited for this consumer".
    relay_rate_overrides: HashMap<EndpointId, u64>,
}

struct ServerStateInner {
    groups: HashMap<String, Arc<Group>>,
}

// Manual Debug impl because the contents are mostly DashMap internals.
impl std::fmt::Debug for ServerStateInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerStateInner")
            .field("groups", &self.groups.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug)]
pub struct Group {
    pub name: String,
    pub token: String,
    pub sessions: DashMap<EndpointId, Session>,
    pub services: DashMap<String, ServiceRecord>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub last_heartbeat: Instant,
}

#[derive(Debug, Clone)]
pub struct ServiceRecord {
    pub provider_id: EndpointId,
}

impl ServerState {
    /// Build a fresh registry from the configured group definitions
    /// and the per-consumer rate overrides parsed out of the relay
    /// config. `rate_overrides` is a list of
    /// `(EndpointId, bytes_per_sec)`; entries with an unparseable
    /// `node_id` are skipped (the config validator should have caught
    /// those at load time).
    pub fn new(
        groups: &[meshly_core_common::config::GroupConfig],
        rate_overrides: &[(EndpointId, u64)],
    ) -> Arc<Self> {
        let mut map = HashMap::with_capacity(groups.len());
        for g in groups {
            map.insert(
                g.name.clone(),
                Arc::new(Group {
                    name: g.name.clone(),
                    token: g.group_token.clone(),
                    sessions: DashMap::new(),
                    services: DashMap::new(),
                }),
            );
        }
        assert!(
            !map.is_empty(),
            "server must have at least one group configured"
        );
        let mut overrides = HashMap::with_capacity(rate_overrides.len());
        for (id, bps) in rate_overrides {
            overrides.insert(*id, *bps);
        }
        Arc::new(Self {
            inner: RwLock::new(ServerStateInner { groups: map }),
            next_stream_id: AtomicU64::new(1),
            relay_rates: DashMap::new(),
            relay_rate_overrides: overrides,
        })
    }

    /// Look up a group by name. Returns `None` if unknown.
    pub fn group(&self, name: &str) -> Option<Arc<Group>> {
        self.inner.read().ok()?.groups.get(name).cloned()
    }

    /// Authenticate by group_token. In v1 the group_token doubles as the
    /// group identifier (groups are named by their token). Returns the
    /// matching group on success.
    pub fn authenticate(&self, token: &str) -> Option<Arc<Group>> {
        let inner = self.inner.read().ok()?;
        inner.groups.values().find(|g| g.token == token).cloned()
    }

    /// Resolve a service name within a group, returning the provider's
    /// endpoint id (None if the service is not currently registered).
    pub fn lookup_service(&self, group_name: &str, service: &str) -> Option<EndpointId> {
        self.group(group_name)?.services.get(service).map(|r| r.provider_id)
    }

    /// List of (group_name, service_name, provider_id) tuples.
    pub fn dump_services(&self) -> Vec<(String, String, EndpointId)> {
        let mut out = Vec::new();
        let inner = match self.inner.read() {
            Ok(i) => i,
            Err(_) => return out,
        };
        for (gname, group) in inner.groups.iter() {
            for entry in group.services.iter() {
                out.push((gname.clone(), entry.key().clone(), entry.value().provider_id));
            }
        }
        out
    }

    /// Number of active sessions across all groups.
    pub fn session_count(&self) -> usize {
        self.inner
            .read()
            .map(|i| i.groups.values().map(|g| g.sessions.len()).sum())
            .unwrap_or(0)
    }

    /// Per-consumer reply-rate override, if one was configured for
    /// this consumer's NodeID. Returns `None` if no override is set;
    /// the caller should fall back to its default.
    ///
    /// The returned `u64` is bytes per second. `0` means unlimited
    /// for this specific consumer.
    pub fn lookup_relay_rate_override(&self, consumer: EndpointId) -> Option<u64> {
        self.relay_rate_overrides.get(&consumer).copied()
    }

    /// Snapshot of every per-consumer rate override, as
    /// `(EndpointId, bytes_per_sec)`. Useful for `--status`.
    pub fn relay_rate_overrides_snapshot(&self) -> Vec<(EndpointId, u64)> {
        self.relay_rate_overrides
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    // -------------------------------------------------------------------
    // Relay-stream bookkeeping (the "dynamic per-connection rate" hook)
    // -------------------------------------------------------------------

    /// Allocate a fresh `stream_id` for a new relay task. Ids are
    /// monotonic and never reused within a process lifetime.
    pub fn alloc_stream_id(&self) -> u64 {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a relay task's rate handle under `stream_id`. The
    /// handle is what a future control-plane message will mutate to
    /// adjust this connection's bandwidth cap at runtime.
    pub fn register_relay_rate(&self, stream_id: u64, handle: Arc<AtomicU64>) {
        self.relay_rates.insert(stream_id, handle);
    }

    /// Remove a relay's rate handle when the task ends. Idempotent.
    pub fn unregister_relay_rate(&self, stream_id: u64) {
        self.relay_rates.remove(&stream_id);
    }

    /// Dynamically update the reply bandwidth cap of a single relay
    /// connection. Returns `true` if `stream_id` was found and updated.
    ///
    /// This is the hook future admin / control-plane messages will use.
    /// `0` disables throttling for that connection; any positive value
    /// caps the reply stream at that many bytes per second.
    #[allow(dead_code)] // exposed for the forthcoming control-plane admin path
    pub fn update_relay_rate(&self, stream_id: u64, bytes_per_sec: u64) -> bool {
        if let Some(h) = self.relay_rates.get(&stream_id) {
            h.store(bytes_per_sec, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Snapshot of `(stream_id, current_bps)` for every active relay.
    /// Useful for `--status` style introspection.
    pub fn relay_rates_snapshot(&self) -> Vec<(u64, u64)> {
        self.relay_rates
            .iter()
            .map(|e| (*e.key(), e.value().load(Ordering::Relaxed)))
            .collect()
    }
}

impl Group {
    /// Register a service. If the service was already registered by another
    /// client, returns the previous provider id so the caller can log the
    /// conflict.
    pub fn register_service(
        &self,
        service: &str,
        provider: EndpointId,
    ) -> Result<Option<EndpointId>, RegisterError> {
        if service.len() > 32 {
            return Err(RegisterError::BadName);
        }
        let prev = self.services.insert(
            service.to_string(),
            ServiceRecord {
                provider_id: provider,
            },
        );
        Ok(prev.map(|r| r.provider_id))
    }

    /// Insert or update a session for `client`.
    pub fn touch_session(&self, client_id: EndpointId) {
        let mut entry = self.sessions.entry(client_id).or_insert_with(|| Session {
            last_heartbeat: Instant::now(),
        });
        entry.last_heartbeat = Instant::now();
    }

    /// Drop a session (and any services registered by it).
    pub fn drop_session(&self, client_id: EndpointId) {
        self.sessions.remove(&client_id);
        let to_remove: Vec<String> = self
            .services
            .iter()
            .filter(|e| e.value().provider_id == client_id)
            .map(|e| e.key().clone())
            .collect();
        for svc in to_remove {
            self.services.remove(&svc);
            tracing::info!(service = %svc, provider = %client_id.fmt_short(),
                "garbage-collected service from dropped session");
        }
    }
}

/// Reasons a service registration can be rejected.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("invalid service name")]
    BadName,
}

/// Identity bootstrap helper: load or generate the server's secret key.
pub fn load_identity(identity_path: Option<&std::path::Path>) -> anyhow::Result<(SecretKey, String)> {
    let (key, paths) = match identity_path {
        Some(p) => meshly_core_common::load_or_generate_at(p)?,
        None => meshly_core_common::load_or_generate()?,
    };
    let node_id = key.public().to_string();
    tracing::info!(node_id = %node_id, identity = %paths.key_file.display(),
        "server identity ready");
    Ok((key, node_id))
}