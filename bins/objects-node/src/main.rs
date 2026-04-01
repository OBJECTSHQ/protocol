//! Node daemon for OBJECTS Protocol.

use anyhow::Result;
use objects_core::api::{AppState, NodeInfo, RegistryClient, create_router};
use objects_core::service::NodeService;
use objects_core::{NodeConfig, NodeState};
use std::net::SocketAddr;
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

    // Create shared state components for API
    let node_info = Arc::new(NodeInfo {
        node_id: service.node_id(),
        node_addr: service.node_addr(),
    });

    let discovery = service.discovery.clone();
    let node_state_arc = Arc::new(RwLock::new(state));

    // Create AppState for HTTP handlers
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
    // This syncs catalog metadata only — does NOT download project replicas.
    // Users can selectively pull projects via `objects vault pull <id>`.
    // Extract signing key before any async work to avoid holding RwLock across await.
    let vault_signing_key = node_state_arc
        .read()
        .unwrap()
        .identity()
        .and_then(|i| i.signing_key().copied());

    if let Some(signing_key_bytes) = vault_signing_key {
        {
            match objects_identity::vault::VaultKeys::derive_from_signing_key(&signing_key_bytes) {
                Ok(vault_keys) => {
                    let vault_ns = vault_keys.namespace_id();
                    let sync_engine = service.sync_engine();

                    // Open the vault replica (creates if first device, syncs if exists)
                    match sync_engine
                        .docs()
                        .create_replica_with_secret(vault_keys.namespace_secret().clone())
                        .await
                    {
                        Ok(_) => {
                            info!("Vault replica opened: {}", vault_ns);

                            // Read catalog entries (decrypted)
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
                                        // Check if project replica exists locally
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
                                Err(e) => {
                                    warn!("Vault: failed to read catalog: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Vault: failed to open replica: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Vault: failed to derive keys: {}", e);
                }
            }
        }
    }

    // Create shutdown channel for coordinating tasks
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Get shutdown trigger for network service before moving it
    let network_shutdown = service.shutdown_trigger();

    // Spawn HTTP server
    let api_handle = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let config_clone = config.clone();
        tokio::spawn(async move {
            let app = create_router(app_state);
            let ip: std::net::IpAddr =
                config_clone.node.api_bind.parse().expect(
                    "Invalid api_bind address (should have been caught by config validation)",
                );
            let addr = SocketAddr::from((ip, config_clone.node.api_port));
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind API server: {}", e);
                    return Err(anyhow::anyhow!("Failed to bind: {}", e));
                }
            };

            info!("API server listening on {}", addr);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.recv().await;
                })
                .await
                .map_err(|e| anyhow::anyhow!("API server error: {}", e))
        })
    };

    // Run network service concurrently with API and shutdown signal
    tokio::select! {
        result = service.run_loop() => {
            if let Err(e) = result {
                error!("Network service error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            info!("Received shutdown signal, stopping services...");

            // Trigger network service shutdown via watch channel
            let _ = network_shutdown.send(true);

            // Broadcast shutdown to API server
            let _ = shutdown_tx.send(());

            // Wait for API server to finish
            if let Err(e) = api_handle.await {
                error!("API server task error: {}", e);
            }
        }
    }

    Ok(())
}
