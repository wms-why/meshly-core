//! frp2p-id: print the local Iroh NodeID.
//!
//! Loads (or generates) the persistent identity key from the default
//! location (`<config_dir>/frp2p/identity.key`) and prints the public
//! NodeID in the requested encoding.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use frp2p_common::load_or_generate;

#[derive(Parser, Debug)]
#[command(name = "frp2p-id", about = "Print the local frp2p Iroh NodeID", version)]
struct Args {
    /// Path to identity key file. If omitted, uses `<config_dir>/frp2p/identity.key`.
    #[arg(short, long)]
    identity: Option<PathBuf>,

    /// Print NodeID in base32 instead of hex.
    #[arg(long)]
    base32: bool,

    /// Print only the NodeID without labels (useful for piping).
    #[arg(long)]
    quiet: bool,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("frp2p-id: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<()> {
    let args = Args::parse();
    let (key, paths) = match &args.identity {
        Some(p) => frp2p_common::load_or_generate_at(p).context("load identity at explicit path")?,
        None => load_or_generate().context("load or generate identity")?,
    };
    let node_id = key.public();
    let s = if args.base32 {
        // iroh PublicKey encodes to base32 via the standard z-base-32.
        format_node_id_b32(&node_id)
    } else {
        hex::encode(node_id.as_bytes())
    };
    if args.quiet {
        println!("{s}");
    } else {
        println!("frp2p node id: {s}");
        println!("identity file: {}", paths.key_file.display());
    }
    Ok(())
}

fn format_node_id_b32(pk: &iroh::PublicKey) -> String {
    // iroh PublicKey exposes a z-base-32 string via to_string(); default
    // Display impl already returns the canonical encoding. We only need
    // this helper if --base32 is explicitly requested, but the default
    // Display already is base32, so we just round-trip through Display.
    pk.to_string()
}