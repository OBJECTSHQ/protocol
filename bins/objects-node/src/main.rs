//! Node daemon for OBJECTS Protocol.

use anyhow::Result;
use objects_node::service::NodeService;
use objects_node::{NodeConfig, NodeState};
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

    // Create service
    let service = match NodeService::new(config, state).await {
        Ok(s) => {
            info!("Node service initialized successfully");
            s
        }
        Err(e) => {
            error!("Failed to create node service: {}", e);
            return Err(e);
        }
    };

    // Run with graceful shutdown
    // Spawn the service run task
    info!("Starting network layer...");
    let run_handle = tokio::spawn(async move { service.run().await });

    // Wait for either completion or shutdown signal
    tokio::select! {
        result = run_handle => {
            match result {
                Ok(Ok(())) => {
                    info!("Service completed normally");
                }
                Ok(Err(e)) => {
                    error!("Service error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    error!("Service task panicked: {}", e);
                    return Err(e.into());
                }
            }
        }
        _ = shutdown_signal() => {
            info!("Initiating graceful shutdown...");
            // Service will cleanup when dropped or on next loop iteration
            // In a full implementation, we'd use a channel to signal shutdown
        }
    }

    info!("Node stopped gracefully");
    Ok(())
}
