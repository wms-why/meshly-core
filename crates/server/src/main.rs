//! frp2p-server entry point.

mod control;
mod relay;
mod registry;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use iroh::{endpoint::presets, protocol::Router, Endpoint};
use tracing::info;
use tracing_subscriber::EnvFilter;

use frp2p_common::alpn::{alpn_control, alpn_data};

#[derive(Parser, Debug)]
#[command(name = "frp2p-server", about = "frp2p server: control plane + data relay", version)]
struct Cli {
    /// Path to TOML config file.
    #[arg(short, long, default_value = "server.toml")]
    config: PathBuf,

    /// Print server status as JSON and exit.
    #[arg(long)]
    status: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match real_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("frp2p-server: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();

    // Load config first so we can configure logging + identity in one place.
    let cfg = frp2p_common::config::RootConfig::load(&cli.config)
        .with_context(|| format!("load config {}", cli.config.display()))?;
    if !cfg.is_server() {
        anyhow::bail!(
            "config {} does not define any [[group]]; refusing to start as server",
            cli.config.display()
        );
    }

    // Logging.
    let log_level = &cfg.common.logging.level;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Identity.
    let (secret_key, node_id) =
        registry::load_identity(cfg.common.identity_path.as_deref())?;

    // Server state.
    let state = registry::ServerState::new(&cfg.groups);

    if cli.status {
        print_status(&state, &node_id);
        return Ok(());
    }

    // Bind endpoint.
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .bind()
        .await
        .context("bind Iroh endpoint")?;

    let control_cfg = control::ControlConfig {
        heartbeat_interval: Duration::from_secs(cfg.heartbeat.interval_secs.max(1)),
        heartbeat_timeout: Duration::from_secs(cfg.heartbeat.timeout_secs.max(1)),
    };

    let router = Router::builder(endpoint.clone())
        .accept(alpn_control(), control::ControlHandler {
            state: state.clone(),
            config: control_cfg.clone(),
        })
        .accept(alpn_data(), relay::RelayHandler {
            endpoint: endpoint.clone(),
            state: state.clone(),
        })
        .spawn();

    info!(
        node_id = %node_id,
        groups = cfg.groups.len(),
        alpn_control = %String::from_utf8_lossy(&alpn_control()),
        alpn_data = %String::from_utf8_lossy(&alpn_data()),
        "frp2p-server ready"
    );
    eprintln!("frp2p-server node id: {node_id}");
    eprintln!("frp2p-server: ctrl-c to stop");

    // Heartbeat-timeout sweeper task.
    {
        let state = state.clone();
        let timeout = control_cfg.heartbeat_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(timeout).await;
                sweep_dead_sessions(&state, timeout);
            }
        });
    }

    tokio::signal::ctrl_c().await.ok();
    info!("ctrl-c received; shutting down router");
    router.shutdown().await.ok();
    Ok(())
}

/// Drop sessions whose last heartbeat is older than `timeout`.
fn sweep_dead_sessions(state: &Arc<registry::ServerState>, timeout: Duration) {
    let cutoff = std::time::Instant::now() - timeout;
    // Walk groups.
    for entry in state.dump_services() {
        let group_name = &entry.0;
        if let Some(g) = state.group(group_name) {
            let dead: Vec<_> = g
                .sessions
                .iter()
                .filter(|s| s.last_heartbeat < cutoff)
                .map(|s| *s.key())
                .collect();
            for id in dead {
                tracing::warn!(client = %id.fmt_short(), group = %group_name,
                    "session expired (no heartbeat); dropping");
                g.drop_session(id);
            }
        }
    }
}

fn print_status(state: &registry::ServerState, node_id: &str) {
    let mut out = serde_json::json!({
        "node_id": node_id,
        "session_count": state.session_count(),
        "services": state.dump_services().into_iter()
            .map(|(g, s, p)| serde_json::json!({
                "group": g,
                "service": s,
                "provider": p.to_string(),
            }))
            .collect::<Vec<_>>(),
    });
    let s = serde_json::to_string_pretty(&mut out).unwrap_or_else(|_| "{}".into());
    println!("{s}");
}