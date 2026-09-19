//! meshly-core-client entry point.

mod consume;
mod expose;
mod status;
mod static_http;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
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
    ///
    /// The client is started normally (endpoint bound, registration
    /// spawned) and we wait up to `--status-timeout` seconds for the
    /// control plane to reach a settled state (Registered or
    /// Reconnecting) before printing and exiting. Exits 0 on
    /// Registered, 1 otherwise.
    #[arg(long)]
    status: bool,

    /// How long `--status` waits for the first control-plane state
    /// change before giving up and printing whatever we have.
    #[arg(long, default_value_t = 10)]
    status_timeout_secs: u64,
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
        status_timeout_secs: 10,
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

    // Shared runtime status. Constructed before `--status` so the dump
    // can include the default runtime entries; cloned into the
    // registration and consume tasks so live state shows up in later
    // snapshots (e.g. an HTTP status endpoint we may add later).
    let status = status::RuntimeStatus::new(
        cfg.consume.iter().map(|c| c.name.clone()),
    );

    let server_node_id: EndpointId = cfg
        .server_node_id
        .as_ref()
        .context("client config missing server_node_id")?
        .parse()
        .context("parse server_node_id")?;

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
    for s in &cfg.static_services {
        let spec = Arc::new(static_http::StaticSpec {
            name: s.name.clone(),
            root_dir: s.root_dir.clone(),
            allow_directory_listing: s.allow_directory_listing,
            shared_secret: s.shared_secret.as_bytes().to_vec(),
        });
        let alpn = meshly_core_common::alpn::alpn_for_service(&s.name)?;
        router_builder = router_builder.accept(alpn, static_http::StaticHandler { spec });
        info!(
            service = %s.name,
            root_dir = %s.root_dir.display(),
            allow_directory_listing = s.allow_directory_listing,
            "static handler registered"
        );
    }
    let _router = router_builder.spawn();

    info!(
        node_id = %node_id,
        server = %server_node_id.fmt_short(),
        exposes = cfg.expose.len(),
        static_services = cfg.static_services.len(),
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
    let static_specs: Vec<_> = cfg
        .static_services
        .iter()
        .map(|s| static_http::StaticSpec {
            name: s.name.clone(),
            root_dir: s.root_dir.clone(),
            allow_directory_listing: s.allow_directory_listing,
            shared_secret: s.shared_secret.as_bytes().to_vec(),
        })
        .collect();

    {
        let endpoint = endpoint.clone();
        let status = status.clone();
        tokio::spawn(async move {
            loop {
                status
                    .set_control_state(status::ControlState::Registering, None)
                    .await;
                match expose::register_with_server(
                    &endpoint,
                    server_node_id,
                    &group_token,
                    &client_info,
                    &expose_specs,
                    &static_specs,
                )
                .await
                {
                    Ok(conn) => {
                        info!("registered with server");
                        status
                            .set_control_state(status::ControlState::Registered, None)
                            .await;
                        // Keep the session alive: periodically open a
                        // bi-stream and write a Heartbeat frame. Mirrors
                        // the server's hb_task in server/src/control.rs.
                        // If the conn dies, the writer breaks and the
                        // outer loop reconnects (after dropping the conn,
                        // which signals the server).
                        let conn = conn;
                        // The server pushes periodic Heartbeats to us on
                        // the SAME control connection by calling
                        // `conn.open_bi()` from its heartbeat task. iroh
                        // does not auto-drain those streams, so we must
                        // keep accepting bi-streams here or the server's
                        // heartbeat writer eventually deadlocks on flow
                        // control. Read the incoming frame and let the
                        // stream close naturally (the server shuts its
                        // send side down after writing).
                        let drain_conn = conn.clone();
                        tokio::spawn(async move {
                            loop {
                                let (_send, mut recv) = match drain_conn.accept_bi().await {
                                    Ok(p) => p,
                                    Err(_) => return,
                                };
                                let _ = Frame::read_from(&mut recv).await;
                            }
                        });
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
                            status.record_heartbeat().await;
                        }
                    }
                    Err(e) => {
                        warn!(err = %e, "register with server failed; retry in 5s");
                        let msg = format!("{e:#}");
                        status
                            .set_control_state(status::ControlState::Reconnecting, Some(&msg))
                            .await;
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    // Spawn a task for each consume service.
    // Clamp user-provided backoff to sane lower bounds. Without this a
    // typo like `initial_backoff_ms = 0` would hot-loop the consume
    // task on a missing provider.
    let reconnect = consume::ReconnectConfig {
        initial_backoff_ms: clamp_backoff(
            "reconnect.initial_backoff_ms",
            cfg.reconnect.initial_backoff_ms,
            10,
        ),
        max_backoff_ms: clamp_backoff(
            "reconnect.max_backoff_ms",
            cfg.reconnect.max_backoff_ms,
            100,
        ),
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
            cached_provider: tokio::sync::Mutex::new(None),
            reconnect,
            status: status.clone(),
        });
        let state2 = state.clone();
        tokio::spawn(async move {
            if let Err(e) = consume::run(state2).await {
                warn!(service = %state.spec.name, err = %e, "consumer task ended");
            }
        });
    }

    if cli.status {
        let exit = status_query(&cfg, &node_id, &status, cli.status_timeout_secs).await;
        endpoint.close().await;
        return exit;
    }

    tokio::signal::ctrl_c().await.ok();
    info!("ctrl-c received; shutting down");
    Ok(())
}

/// Wait for the first settled control-plane state, dump the runtime
/// snapshot, and return Ok(()) only when the state is `Registered`.
/// Used by `--status`.
async fn status_query(
    cfg: &RootConfig,
    node_id: &str,
    status: &status::RuntimeStatus,
    timeout_secs: u64,
) -> Result<()> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let snap = status.snapshot().await;
        if matches!(
            snap.control.state,
            status::ControlState::Registered | status::ControlState::Reconnecting
        ) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    print_status(cfg, node_id, status).await;
    let snap = status.snapshot().await;
    if matches!(snap.control.state, status::ControlState::Registered) {
        Ok(())
    } else {
        Err(anyhow!(
            "control plane did not reach Registered within {}s (state={:?})",
            timeout_secs,
            snap.control.state
        ))
    }
}

fn clamp_backoff(field: &'static str, configured: u64, floor: u64) -> u64 {
    if configured < floor {
        warn!(
            field,
            configured,
            floor,
            "{field} below sane minimum; clamping to {floor}ms",
        );
        floor
    } else {
        configured
    }
}

async fn print_status(cfg: &RootConfig, node_id: &str, status: &status::RuntimeStatus) {
    let snapshot = status.snapshot().await;
    let out = serde_json::json!({
        "node_id": node_id,
        "server_node_id": cfg.server_node_id,
        "expose": cfg.expose.iter().map(|e| serde_json::json!({
            "name": e.name,
            "local_addr": e.local_addr.to_string(),
        })).collect::<Vec<_>>(),
        "static": cfg.static_services.iter().map(|s| serde_json::json!({
            "name": s.name,
            "root_dir": s.root_dir.display().to_string(),
            "allow_directory_listing": s.allow_directory_listing,
        })).collect::<Vec<_>>(),
        "consume": cfg.consume.iter().map(|c| serde_json::json!({
            "name": c.name,
            "local_bind": c.local_bind.to_string(),
        })).collect::<Vec<_>>(),
        "runtime": snapshot,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()));
}
