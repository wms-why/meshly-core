//! In-memory registry of groups, sessions, and services.
//!
//! Concurrency model: one `std::sync::RwLock<ServerStateInner>` guards the
//! group map. Inside each group we use `DashMap` for `sessions` and
//! `services` so that per-group lookups can proceed in parallel without
//! blocking the global lock. The lock is only held for HashMap lookups
//! and DashMap references; once handed out, no global lock is involved.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dashmap::DashMap;
use iroh::{EndpointId, SecretKey};

/// Top-level server state.
#[derive(Debug)]
pub struct ServerState {
    inner: RwLock<ServerStateInner>,
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
    pub client_id: EndpointId,
    pub group: String,
    pub registered_services: Vec<String>,
    pub last_heartbeat: Instant,
}

#[derive(Debug, Clone)]
pub struct ServiceRecord {
    pub name: String,
    pub provider_id: EndpointId,
}

impl ServerState {
    /// Build a fresh registry from the configured group definitions.
    pub fn new(groups: &[frp2p_common::config::GroupConfig]) -> Arc<Self> {
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
        let state = Arc::new(Self {
            inner: RwLock::new(ServerStateInner { groups: map }),
        });
        state
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
                name: service.to_string(),
                provider_id: provider,
            },
        );
        Ok(prev.map(|r| r.provider_id))
    }

    /// Unregister a service previously registered by `provider`.
    pub fn unregister_service(&self, service: &str, provider: EndpointId) -> bool {
        if let Some(entry) = self.services.get(service) {
            if entry.provider_id == provider {
                drop(entry);
                self.services.remove(service);
                return true;
            }
        }
        false
    }

    /// Insert or update a session for `client`.
    pub fn touch_session(&self, client_id: EndpointId) {
        let mut entry = self.sessions.entry(client_id).or_insert_with(|| Session {
            client_id,
            group: self.name.clone(),
            registered_services: Vec::new(),
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
        Some(p) => frp2p_common::load_or_generate_at(p)?,
        None => frp2p_common::load_or_generate()?,
    };
    let node_id = key.public().to_string();
    tracing::info!(node_id = %node_id, identity = %paths.key_file.display(),
        "server identity ready");
    Ok((key, node_id))
}