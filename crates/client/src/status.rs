//! Shared runtime status for `--status` and future observability.
//!
//! The control-plane registration task and each `consume` service push
//! state transitions into this struct through an `Arc`. A snapshot is
//! taken by `print_status` and (eventually) by an HTTP / IPC endpoint.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::RwLock;

/// State of the control-plane session.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlState {
    #[default]
    Unregistered,
    Registering,
    Registered,
    Reconnecting,
}

/// State of a single `consume` service.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerState {
    #[default]
    Idle,
    Dialing,
    Live,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ControlStatus {
    pub state: ControlState,
    pub last_registered_at_ms: Option<i64>,
    pub last_heartbeat_at_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConsumerStatus {
    pub state: ConsumerState,
    /// `"direct"` or `"relay"`, set on the most recent successful dial.
    pub mode: Option<String>,
    pub last_attempt_at_ms: Option<i64>,
    pub last_success_at_ms: Option<i64>,
    pub last_error: Option<String>,
    pub forwarded_streams: u64,
}

pub struct RuntimeStatus {
    control: RwLock<ControlStatus>,
    consumers: RwLock<BTreeMap<String, ConsumerStatus>>,
}

impl RuntimeStatus {
    /// Pre-populate the consumer map so `--status` can list every
    /// configured service even before the first dial.
    pub fn new(consumer_names: impl IntoIterator<Item = String>) -> Arc<Self> {
        let consumers = consumer_names
            .into_iter()
            .map(|n| (n, ConsumerStatus::default()))
            .collect();
        Arc::new(Self {
            control: RwLock::new(ControlStatus::default()),
            consumers: RwLock::new(consumers),
        })
    }

    pub async fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            control: self.control.read().await.clone(),
            consumers: self.consumers.read().await.clone(),
        }
    }

    pub async fn set_control_state(&self, state: ControlState, err: Option<&str>) {
        let mut g = self.control.write().await;
        g.state = state;
        if let Some(e) = err {
            g.last_error = Some(e.to_string());
        } else {
            g.last_error = None;
        }
        if matches!(state, ControlState::Registered) {
            g.last_registered_at_ms = Some(now_ms());
        }
    }

    pub async fn record_heartbeat(&self) {
        self.control.write().await.last_heartbeat_at_ms = Some(now_ms());
    }

    pub async fn set_consumer_state(
        &self,
        name: &str,
        state: ConsumerState,
        mode: Option<&str>,
        err: Option<&str>,
    ) {
        let mut g = self.consumers.write().await;
        let entry = g.entry(name.to_string()).or_default();
        entry.state = state;
        entry.mode = mode.map(String::from);
        entry.last_attempt_at_ms = Some(now_ms());
        if let Some(e) = err {
            entry.last_error = Some(e.to_string());
        } else if matches!(state, ConsumerState::Live) {
            entry.last_error = None;
        }
        if matches!(state, ConsumerState::Live) {
            entry.last_success_at_ms = Some(now_ms());
            entry.forwarded_streams = entry.forwarded_streams.saturating_add(1);
        }
    }
}

#[derive(Serialize)]
pub struct RuntimeSnapshot {
    pub control: ControlStatus,
    pub consumers: BTreeMap<String, ConsumerStatus>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_includes_preconfigured_consumers() {
        let rt = RuntimeStatus::new(vec!["ssh".to_string(), "web".to_string()]);
        let snap = rt.snapshot().await;
        assert_eq!(snap.control.state, ControlState::Unregistered);
        assert_eq!(snap.consumers.len(), 2);
        assert!(snap.consumers.contains_key("ssh"));
        assert!(snap.consumers.contains_key("web"));
        for s in snap.consumers.values() {
            assert_eq!(s.state, ConsumerState::Idle);
        }
    }

    #[tokio::test]
    async fn control_state_transitions_record_timestamps() {
        let rt = RuntimeStatus::new(std::iter::empty());
        rt.set_control_state(ControlState::Registering, None).await;
        rt.set_control_state(ControlState::Registered, None).await;
        assert!(rt.snapshot().await.control.last_registered_at_ms.is_some());
        rt.record_heartbeat().await;
        assert!(rt.snapshot().await.control.last_heartbeat_at_ms.is_some());
    }

    #[tokio::test]
    async fn consumer_live_increments_counter_and_clears_error() {
        let rt = RuntimeStatus::new(vec!["svc".to_string()]);
        rt.set_consumer_state("svc", ConsumerState::Failed, None, Some("boom"))
            .await;
        rt.set_consumer_state("svc", ConsumerState::Live, Some("direct"), None)
            .await;
        let s = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s.state, ConsumerState::Live);
        assert_eq!(s.mode.as_deref(), Some("direct"));
        assert_eq!(s.forwarded_streams, 1);
        assert!(s.last_error.is_none());
    }

    // -- Phase 0: snapshot transition paths -------------------------------

    #[tokio::test]
    async fn consumer_transitions_idle_to_dialing_to_live_direct() {
        let rt = RuntimeStatus::new(vec!["svc".to_string()]);
        // Start: Idle (default after new()).
        let s0 = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s0.state, ConsumerState::Idle);
        assert!(s0.last_error.is_none());
        assert_eq!(s0.forwarded_streams, 0);

        // Dialing with no mode, no error.
        rt.set_consumer_state("svc", ConsumerState::Dialing, None, None)
            .await;
        let s1 = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s1.state, ConsumerState::Dialing);
        assert!(s1.last_attempt_at_ms.is_some());

        // Live on the direct path.
        rt.set_consumer_state("svc", ConsumerState::Live, Some("direct"), None)
            .await;
        let s2 = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s2.state, ConsumerState::Live);
        assert_eq!(s2.mode.as_deref(), Some("direct"));
        assert!(s2.last_success_at_ms.is_some());
        assert_eq!(s2.forwarded_streams, 1);
    }

    #[tokio::test]
    async fn consumer_transitions_idle_to_dialing_to_live_relay() {
        let rt = RuntimeStatus::new(vec!["svc".to_string()]);
        rt.set_consumer_state("svc", ConsumerState::Dialing, None, None)
            .await;
        rt.set_consumer_state("svc", ConsumerState::Live, Some("relay"), None)
            .await;
        let s = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s.state, ConsumerState::Live);
        assert_eq!(s.mode.as_deref(), Some("relay"));
        assert_eq!(s.forwarded_streams, 1);
        assert!(s.last_error.is_none());
    }

    #[tokio::test]
    async fn consumer_failed_records_last_error_then_back_to_live_clears() {
        let rt = RuntimeStatus::new(vec!["svc".to_string()]);
        rt.set_consumer_state("svc", ConsumerState::Dialing, None, None)
            .await;
        rt.set_consumer_state(
            "svc",
            ConsumerState::Failed,
            None,
            Some("relay dial failed: timeout"),
        )
        .await;

        let s_failed = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s_failed.state, ConsumerState::Failed);
        assert!(
            s_failed
                .last_error
                .as_deref()
                .unwrap_or("")
                .contains("timeout"),
            "last_error should contain 'timeout', got {:?}",
            s_failed.last_error
        );
        // Forwarded streams must NOT have incremented on Failed.
        assert_eq!(s_failed.forwarded_streams, 0);

        // Recovery: back to Live clears the error and increments counter.
        rt.set_consumer_state("svc", ConsumerState::Live, Some("relay"), None)
            .await;
        let s_live = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s_live.state, ConsumerState::Live);
        assert!(
            s_live.last_error.is_none(),
            "transition to Live must clear last_error, got {:?}",
            s_live.last_error
        );
        assert_eq!(s_live.forwarded_streams, 1);
    }

    #[tokio::test]
    async fn consumer_multiple_failed_to_live_cycles_increment() {
        // Each successful Live transition increments the counter;
        // intermediate Failed states do not.
        let rt = RuntimeStatus::new(vec!["svc".to_string()]);

        for i in 0..3 {
            rt.set_consumer_state("svc", ConsumerState::Dialing, None, None)
                .await;
            rt.set_consumer_state(
                "svc",
                ConsumerState::Failed,
                None,
                Some(&format!("err {i}")),
            )
            .await;
            rt.set_consumer_state("svc", ConsumerState::Live, Some("direct"), None)
                .await;
        }

        let s = &rt.snapshot().await.consumers["svc"];
        assert_eq!(s.state, ConsumerState::Live);
        assert_eq!(s.forwarded_streams, 3);
        assert!(s.last_error.is_none());
    }
}
