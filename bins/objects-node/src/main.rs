//! Node daemon for OBJECTS Protocol.

use objects_node::service::NodeService;
use objects_node::{NodeConfig, NodeState};
use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "objects_node=debug,info".to_string()),
        )
        .init();

    info!("Starting OBJECTS node...");

    // Determine config path
    let config_path = std::env::var("OBJECTS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".objects")
                .join("config.toml")
        });

    // Load or create config
    let config = match NodeConfig::load_or_create(&config_path) {
        Ok(cfg) => {
            info!("Loaded config from: {}", config_path.display());
            cfg
        }
        Err(e) => {
            error!("Failed to load config: {}", e);
            return Err(e.into());
        }
    };

    // Ensure data directory exists
    std::fs::create_dir_all(&config.node.data_dir)?;

    // Load or create state
    let state_path = Path::new(&config.node.data_dir).join("node.key");
    let state = match NodeState::load_or_create(&state_path) {
        Ok(s) => {
            info!("Node ID: {}", s.node_key().public());
            s
        }
        Err(e) => {
            error!("Failed to load state: {}", e);
            return Err(e.into());
        }
    };

    // Log identity if present
    if let Some(identity) = state.identity() {
        info!(
            "Identity: @{} ({})",
            identity.handle(),
            identity.identity_id()
        );
    } else {
        info!("No identity registered");
    }

    // Create and run service
    match NodeService::new(config, state).await {
        Ok(service) => {
            info!("Node service initialized successfully");
            info!("Starting network layer...");
            service.run().await?;
        }
        Err(e) => {
            error!("Failed to create node service: {}", e);
            return Err(e);
        }
    }

    info!("Node stopped");
    Ok(())
}
