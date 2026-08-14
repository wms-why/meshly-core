//! meshly-core-client entry point.

mod consume;
mod expose;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointId};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use meshly_core_common::alpn::alpn_control;
use meshly_core_common::config::RootConfig;
use meshly_core_common::protocol::Frame;
use meshly_core_common::{load_or_generate, load_or_generate_at};

/// How often the client sends a control-plane heartbeat.
///
/// Should be strictly less than the server's `heartbeat.timeout_secs`
/// (default 90s) so the session never times out. 60s leaves comfortable
/// margin against the default and matches what server.toml ships.
const CLIENT_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(name = "meshly-core-client", about = "meshly-core client: expose local + consume remote services", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the local Iroh NodeID (loads or generates the identity key).
    Id(IdArgs),
    /// Run the client (default if no subcommand is given).
    Run(RunArgs),
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Path to TOML config file.
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,

    /// Print client status as JSON and exit.
    #[arg(long)]
    status: bool,
}

#[derive(clap::Args, Debug)]
struct IdArgs {
    /// Path to identity key file. If omitted, uses `<config_dir>/meshly-core/identity.key`.
    #[arg(short, long)]
    identity: Option<PathBuf>,

    /// Print NodeID in base32 instead of hex.
    #[arg(long)]
    base32: bool,

    /// Print only the NodeID without labels (useful for piping).
    #[arg(long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match real_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("meshly-core-client: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();

    // Dispatch to subcommand, or default to `run` when none is given.
    match cli.command.unwrap_or(Command::Run(RunArgs {
        config: PathBuf::from("client.toml"),
        status: false,
    })) {
        Command::Id(args) => {
            return run_id(args).await;
        }
        Command::Run(args) => {
            run_client(args).await?;
        }
    }

    Ok(())
}

/// `meshly-core-client id [--identity PATH] [--base32] [--quiet]`
///
/// Loads (or generates) the persistent identity key and prints the
/// public NodeID. Replaces the old standalone `meshly-core-id` binary.
async fn run_id(args: IdArgs) -> Result<()> {
    let (key, paths) = match &args.identity {
        Some(p) => load_or_generate_at(p).context("load identity at explicit path")?,
        None => load_or_generate().context("load or generate identity")?,
    };
    let node_id = key.public();
    let s = if args.base32 {
        // iroh PublicKey's Display already returns the canonical z-base-32.
        node_id.to_string()
    } else {
        hex::encode(node_id.as_bytes())
    };
    if args.quiet {
        println!("{s}");
    } else {
        println!("meshly-core node id: {s}");
        println!("identity file: {}", paths.key_file.display());
    }
    Ok(())
}

async fn run_client(cli: RunArgs) -> Result<()> {
    let cfg = RootConfig::load(&cli.config)
        .with_context(|| format!("load config {}", cli.config.display()))?;
    if cfg.is_server() {
        anyhow::bail!(
            "config {} defines [[group]]; refusing to start as client",
            cli.config.display()
        );
    }

    let log_level = cfg.common.logging.level.clone();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    let (secret_key, node_id) = expose::load_identity_for_client(cfg.common.identity_path.as_deref())?;

    let server_node_id: EndpointId = cfg
        .server_node_id
        .as_ref()
        .context("client config missing server_node_id")?
        .parse()
        .context("parse server_node_id")?;

    if cli.status {
        print_status(&cfg, &node_id);
        return Ok(());
    }

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .bind()
        .await
        .context("bind Iroh endpoint")?;

    // Build router with per-expose handlers (registered up front).
    let mut router_builder = Router::builder(endpoint.clone());
    // Register a handler for the control ALPN so the server's heartbeats
    // don't get rejected (which would tear down our connection).
    router_builder = router_builder.accept(
        alpn_control(),
        expose::ControlResponseHandler,
    );
    for e in &cfg.expose {
        let spec = Arc::new(expose::ExposeSpec {
            name: e.name.clone(),
            local_addr: e.local_addr,
            shared_secret: e.shared_secret.as_bytes().to_vec(),
        });
        let alpn = meshly_core_common::alpn::alpn_for_service(&e.name)?;
        router_builder = router_builder.accept(alpn, expose::ExposeHandler { spec });
        info!(service = %e.name, local_addr = %e.local_addr, "expose handler registered");
    }
    let _router = router_builder.spawn();

    info!(
        node_id = %node_id,
        server = %server_node_id.fmt_short(),
        exposes = cfg.expose.len(),
        consumes = cfg.consume.len(),
        "meshly-core-client ready"
    );
    eprintln!("meshly-core-client node id: {}", node_id);
    eprintln!("meshly-core-client: ctrl-c to stop");

    // Register with server (control plane). For v1 we do this once; on
    // failure we keep retrying with backoff. The resulting Connection is
    // kept alive for the lifetime of the process.
    let client_info = format!("meshly-core-client/{}", env!("CARGO_PKG_VERSION"));
    let group_token = cfg.group_token.clone().unwrap_or_default();
    let expose_specs: Vec<_> = cfg
        .expose
        .iter()
        .map(|e| expose::ExposeSpec {
            name: e.name.clone(),
            local_addr: e.local_addr,
            shared_secret: e.shared_secret.as_bytes().to_vec(),
        })
        .collect();

    {
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            loop {
                match expose::register_with_server(
                    &endpoint,
                    server_node_id,
                    &group_token,
                    &client_info,
                    &expose_specs,
                )
                .await
                {
                    Ok(conn) => {
                        info!("registered with server");
                        // Keep the session alive: periodically open a
                        // bi-stream and write a Heartbeat frame. Mirrors
                        // the server's hb_task in server/src/control.rs.
                        // If the conn dies, the writer breaks and the
                        // outer loop reconnects (after dropping the conn,
                        // which signals the server).
                        let conn = conn;
                        loop {
                            tokio::time::sleep(CLIENT_HEARTBEAT_INTERVAL).await;
                            let (mut s, _r) = match conn.open_bi().await {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!("control connection closed; will reconnect");
                                    break;
                                }
                            };
                            if Frame::Heartbeat.write_to(&mut s).await.is_err() {
                                debug!("heartbeat write failed; will reconnect");
                                break;
                            }
                            let _ = s.shutdown().await;
                        }
                    }
                    Err(e) => {
                        warn!(err = %e, "register with server failed; retry in 5s");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    // Spawn a task for each consume service.
    let reconnect = consume::ReconnectConfig {
        initial_backoff_ms: cfg.reconnect.initial_backoff_ms.max(10),
        max_backoff_ms: cfg.reconnect.max_backoff_ms.max(100),
        prefer_direct: cfg.reconnect.prefer_direct,
    };
    for c in &cfg.consume {
        let state = Arc::new(consume::ConsumeState {
            spec: consume::ConsumeSpec {
                name: c.name.clone(),
                local_bind: c.local_bind,
                shared_secret: c.shared_secret.as_bytes().to_vec(),
            },
            server_node_id,
            group_token: cfg.group_token.clone().unwrap_or_default(),
            endpoint: endpoint.clone(),
            conn: tokio::sync::Mutex::new(None),
            reconnect,
        });
        let state2 = state.clone();
        tokio::spawn(async move {
            if let Err(e) = consume::run(state2).await {
                warn!(service = %state.spec.name, err = %e, "consumer task ended");
            }
        });
    }

    tokio::signal::ctrl_c().await.ok();
    info!("ctrl-c received; shutting down");
    Ok(())
}

fn print_status(cfg: &RootConfig, node_id: &str) {
    let out = serde_json::json!({
        "node_id": node_id,
        "server_node_id": cfg.server_node_id,
        "expose": cfg.expose.iter().map(|e| serde_json::json!({
            "name": e.name,
            "local_addr": e.local_addr.to_string(),
        })).collect::<Vec<_>>(),
        "consume": cfg.consume.iter().map(|c| serde_json::json!({
            "name": c.name,
            "local_bind": c.local_bind.to_string(),
        })).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()));
}