//! Node daemon for OBJECTS Protocol.

use anyhow::Result;
use objects_core::service::NodeService;
use objects_core::{NodeConfig, NodeState};
use std::path::{Path, PathBuf};
use tracing::{error, info};

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received SIGTERM signal");
        },
    }
}

/// Write the node's connection info so the CLI and health probe can discover it.
fn write_node_api_file(data_dir: &str, node_id: &str, node_addr: &objects_transport::NodeAddr) {
    let api_path = Path::new(data_dir).join("node.api");
    let info = serde_json::json!({
        "node_id": node_id,
        "node_addr": node_addr,
    });
    if let Err(e) = std::fs::write(&api_path, serde_json::to_string_pretty(&info).unwrap()) {
        tracing::warn!("Failed to write node.api: {}", e);
    } else {
        info!("Node API info written to {}", api_path.display());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "objects_node=debug,info".to_string()),
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

    // Create service (spawns engine, registers protocols, initializes vault)
    let mut service = match NodeService::new(config.clone(), state).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create node service: {}", e);
            return Err(e);
        }
    };

    // Write node.api file for CLI and health probe discovery
    write_node_api_file(
        &config.node.data_dir,
        &service.node_id().to_string(),
        &service.node_addr(),
    );

    // Get shutdown trigger for network service
    let network_shutdown = service.shutdown_trigger();

    // Run network service concurrently with shutdown signal
    tokio::select! {
        result = service.run_loop() => {
            if let Err(e) = result {
                error!("Network service error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            info!("Received shutdown signal, stopping services...");
            let _ = network_shutdown.send(true);
        }
    }

    Ok(())
}
