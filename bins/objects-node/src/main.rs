//! Node daemon for OBJECTS Protocol.

use anyhow::Result;
use objects_core::api::handlers::{AppState, NodeInfo};
use objects_core::api::registry::RegistryClient;
use objects_core::engine::NodeEngine;
use objects_core::rpc::proto::NODE_RPC_ALPN;
use objects_core::service::NodeService;
use objects_core::{NodeConfig, NodeState};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};

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

/// Write the node's connection info so the CLI can discover it.
fn write_node_api_file(data_dir: &str, node_id: &str, node_addr: &objects_transport::NodeAddr) {
    let api_path = Path::new(data_dir).join("node.api");
    let info = serde_json::json!({
        "node_id": node_id,
        "node_addr": node_addr,
    });
    if let Err(e) = std::fs::write(&api_path, serde_json::to_string_pretty(&info).unwrap()) {
        warn!("Failed to write node.api: {}", e);
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

    // Create service
    let mut service = match NodeService::new(config.clone(), state.clone()).await {
        Ok(s) => {
            info!("Node service initialized successfully");
            s
        }
        Err(e) => {
            error!("Failed to create node service: {}", e);
            return Err(e);
        }
    };

    // Build shared state for the RPC engine
    let node_info = Arc::new(NodeInfo {
        node_id: service.node_id(),
        node_addr: service.node_addr(),
    });

    let discovery = service.discovery.clone();
    let node_state_arc = Arc::new(RwLock::new(state));

    let app_state = AppState {
        node_info: node_info.clone(),
        discovery: discovery.clone(),
        node_state: node_state_arc.clone(),
        config: config.clone(),
        registry_client: RegistryClient::new(&config),
        sync_engine: service.sync_engine().clone(),
        endpoint: service.endpoint(),
    };

    // Vault startup: open vault replica and log discovered projects.
    let vault_signing_key = node_state_arc
        .read()
        .unwrap()
        .identity()
        .and_then(|i| i.signing_key().copied());

    if let Some(signing_key_bytes) = vault_signing_key {
        match objects_identity::vault::VaultKeys::derive_from_signing_key(&signing_key_bytes) {
            Ok(vault_keys) => {
                let vault_ns = vault_keys.namespace_id();
                let sync_engine = service.sync_engine();

                match sync_engine
                    .docs()
                    .create_replica_with_secret(vault_keys.namespace_secret().clone())
                    .await
                {
                    Ok(_) => {
                        info!("Vault replica opened: {}", vault_ns);
                        match sync_engine
                            .docs()
                            .list_catalog(
                                sync_engine.blobs(),
                                vault_ns,
                                Some(&vault_keys.catalog_encryption_key),
                            )
                            .await
                        {
                            Ok(entries) if entries.is_empty() => {
                                info!("Vault: empty (no projects)");
                            }
                            Ok(entries) => {
                                info!("Vault: {} project(s) discovered", entries.len());
                                for entry in &entries {
                                    let local = sync_engine
                                        .docs()
                                        .list_replicas()
                                        .await
                                        .unwrap_or_default()
                                        .iter()
                                        .any(|r| hex::encode(r.as_bytes()) == entry.project_id);
                                    let status = if local { "local" } else { "remote" };
                                    info!(
                                        "  {} [{}] {}",
                                        entry.project_name,
                                        status,
                                        &entry.project_id[..16]
                                    );
                                }
                            }
                            Err(e) => warn!("Vault: failed to read catalog: {}", e),
                        }
                    }
                    Err(e) => warn!("Vault: failed to open replica: {}", e),
                }
            }
            Err(e) => warn!("Vault: failed to derive keys: {}", e),
        }
    }

    // Spawn NodeEngine actor — this handles all RPC requests
    let (_engine_handle, _node_api) = NodeEngine::spawn(app_state);

    // Write node.api file for CLI discovery
    write_node_api_file(
        &config.node.data_dir,
        &service.node_id().to_string(),
        &service.node_addr(),
    );

    info!(
        "Node RPC available via irpc (ALPN: {})",
        String::from_utf8_lossy(NODE_RPC_ALPN)
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
