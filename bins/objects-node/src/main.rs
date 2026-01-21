//! Node daemon for OBJECTS Protocol.

pub mod config;

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting OBJECTS node...");

    // TODO: Initialize node
    // 1. Load or generate node keypair
    // 2. Create Iroh endpoint with ALPN /objects/0.1
    // 3. Connect to relay
    // 4. Join discovery topic
    // 5. Start sync service
    // 6. Handle incoming connections

    info!("Node running. Press Ctrl+C to stop.");

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    Ok(())
}
