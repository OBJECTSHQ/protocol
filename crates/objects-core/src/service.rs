//! Node service orchestrating transport layer components.

use crate::api::handlers::{AppState, NodeInfo};
use crate::api::registry::RegistryClient;
use crate::engine::NodeEngine;
use crate::node_api::NodeApi;
use crate::rpc::proto::{NODE_RPC_ALPN, NodeCommand, NodeProtocol};
use crate::{NodeConfig, NodeState};
use anyhow::Result;
use futures::StreamExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use iroh::protocol::Router;
use irpc_iroh::IrohProtocol;
use objects_sync::SyncEngine;
use objects_sync::storage::StorageConfig;
use objects_transport::discovery::{
    BootstrapResolver, Discovery, DiscoveryConfig, GossipDiscovery,
};
use objects_transport::{NetworkConfig, NodeAddr, NodeId, ObjectsEndpoint, RelayUrl};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

/// Node service orchestrating P2P networking components.
pub struct NodeService {
    #[allow(dead_code)]
    config: NodeConfig,
    #[allow(dead_code)]
    node_state: Arc<RwLock<NodeState>>,
    endpoint: Arc<ObjectsEndpoint>,
    /// Gossip discovery instance (shared with API layer via Arc<Mutex>).
    pub discovery: Arc<Mutex<GossipDiscovery>>,
    sync_engine: SyncEngine,
    /// Node RPC API client (local channel to the engine actor).
    node_api: NodeApi,
    /// Background engine actor task.
    _engine_handle: tokio::task::JoinHandle<()>,
    /// Iroh protocol router handling gossip + node RPC connections.
    router: Router,
    /// Background DNS refresh task (if DNS bootstrap is active).
    dns_refresh: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl NodeService {
    /// Create a new node service with the given config and state.
    ///
    /// This initializes the Iroh endpoint, spawns the RPC engine actor,
    /// registers both gossip and node RPC protocols with the router,
    /// and performs best-effort vault initialization.
    pub async fn new(config: NodeConfig, state: NodeState) -> Result<Self> {
        info!("Creating node service");

        // Parse relay URL
        let relay_url = RelayUrl::from_str(&config.network.relay_url)?;

        // Create network config from node config
        let network_config = NetworkConfig::devnet()
            .with_relay_url(relay_url.clone())
            .with_max_connections(50);

        debug!(
            "Network config: relay={}, discovery={}",
            config.network.relay_url, config.network.discovery_topic
        );

        // Create endpoint with node's secret key
        let mut builder = ObjectsEndpoint::builder()
            .config(network_config)
            .secret_key(state.node_key().clone());

        if let Some(port) = config.node.quic_port {
            debug!("Binding QUIC endpoint to port {}", port);
            builder = builder.bind_port(port);
        }

        let endpoint = builder.bind().await?;

        info!("Endpoint created with node_id: {}", endpoint.node_id());

        // Create gossip protocol (Router is deferred until engine is ready)
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.inner().clone());

        // Wait for relay connection
        endpoint.inner().online().await;
        info!("Connected to relay: {}", config.network.relay_url);

        // Set up peer discovery
        info!("Setting up peer discovery");

        // Resolve bootstrap nodes: DNS → hardcoded fallback → env override
        let env_override = std::env::var("OBJECTS_BOOTSTRAP_NODES").is_ok();
        let resolver = BootstrapResolver::new(
            &config.network.bootstrap_dns,
            config.network.bootstrap_nodes.clone(),
            relay_url.clone(),
            env_override,
        );
        let boot_result = resolver.resolve().await;

        // Filter out our own node ID from bootstrap list (avoid self-dial)
        let our_id = endpoint.node_id();
        let bootstrap_addrs: Vec<NodeAddr> = boot_result
            .addrs
            .into_iter()
            .filter(|addr| addr.id != our_id)
            .collect();

        // Create discovery with devnet config
        let endpoint_arc = Arc::new(endpoint);

        // Spawn periodic DNS refresh (every 5 min) for observability
        let dns_refresh = resolver.spawn_refresh(std::time::Duration::from_secs(300));
        let discovery = GossipDiscovery::new(
            gossip.clone(),
            endpoint_arc.clone(),
            bootstrap_addrs,
            DiscoveryConfig::devnet(),
        )
        .await?;

        info!("Joined discovery topic: {}", config.network.discovery_topic);

        // Create storage config
        let storage_base = config
            .storage
            .base_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(&config.node.data_dir).join("storage"));
        let storage_config = StorageConfig::from_base_dir(&storage_base);

        // Create sync engine builder and extract router builder.
        // We'll add gossip + node RPC to the same Router before spawning,
        // so all protocols share a single Router (avoids ALPN conflicts).
        let (sync_finalizer, router_builder) =
            SyncEngine::with_storage(endpoint_arc.inner(), &storage_config)
                .await?
                .into_router_builder();

        info!("Sync engine initialized with persistent storage");

        // Create irpc channel + handler (messages buffer until engine starts)
        let (tx, rx) = tokio::sync::mpsc::channel::<NodeCommand>(128);
        let client = irpc::Client::<NodeProtocol>::local(tx);
        let irpc_handler = IrohProtocol::with_sender(client.as_local().unwrap());
        let node_api = NodeApi::from_client(client);

        // Single Router with ALL protocols: blobs + docs + gossip + node RPC
        let router = router_builder
            .accept(iroh_gossip::ALPN, gossip)
            .accept(NODE_RPC_ALPN, irpc_handler)
            .spawn();
        info!("Protocol router started (blobs + docs + gossip + node RPC)");

        // Finalize sync engine with the shared Router
        let sync_engine = sync_finalizer.finalize(router.clone());

        // Build AppState for the engine actor
        let discovery_arc = Arc::new(Mutex::new(discovery));
        let node_state_arc = Arc::new(RwLock::new(state));

        let app_state = AppState {
            node_info: Arc::new(NodeInfo {
                node_id: endpoint_arc.node_id(),
                node_addr: endpoint_arc.node_addr(),
            }),
            discovery: discovery_arc.clone(),
            node_state: node_state_arc.clone(),
            config: config.clone(),
            registry_client: RegistryClient::new(&config),
            sync_engine: sync_engine.clone(),
            endpoint: endpoint_arc.clone(),
        };

        // Spawn engine actor (reads from rx, processes commands)
        let engine = NodeEngine::new(app_state);
        let engine_handle = tokio::spawn(engine.run(rx.into()));

        // Best-effort vault startup
        let vault_signing_key = node_state_arc
            .read()
            .unwrap()
            .identity()
            .and_then(|i| i.signing_key().copied());

        if let Some(signing_key_bytes) = vault_signing_key {
            match objects_identity::vault::VaultKeys::derive_from_signing_key(&signing_key_bytes) {
                Ok(vault_keys) => {
                    let vault_ns = vault_keys.namespace_id();

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

        // Spawn HTTP health server
        let health_addr = format!("{}:{}", config.node.api_bind, config.node.api_port);
        match tokio::net::TcpListener::bind(&health_addr).await {
            Ok(listener) => {
                let health_api = node_api.clone();
                tokio::spawn(run_health_server(listener, health_api));
                info!("HTTP health server listening on {}", health_addr);
            }
            Err(e) => {
                warn!(
                    "Failed to bind HTTP health server on {}: {}",
                    health_addr, e
                );
            }
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            config,
            node_state: node_state_arc,
            endpoint: endpoint_arc,
            discovery: discovery_arc,
            sync_engine,
            node_api,
            _engine_handle: engine_handle,
            router,
            dns_refresh,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Get the node's unique identifier.
    pub fn node_id(&self) -> NodeId {
        self.endpoint.as_ref().node_id()
    }

    /// Get the node's network address.
    pub fn node_addr(&self) -> NodeAddr {
        self.endpoint.as_ref().node_addr()
    }

    /// Get the transport endpoint.
    pub fn endpoint(&self) -> Arc<ObjectsEndpoint> {
        self.endpoint.clone()
    }

    /// Get a reference to the sync engine.
    pub fn sync_engine(&self) -> &SyncEngine {
        &self.sync_engine
    }

    /// Get a reference to the node RPC API client.
    pub fn node_api(&self) -> &NodeApi {
        &self.node_api
    }

    /// Run the node service, listening for peer announcements.
    ///
    /// This method consumes the service and runs until the announcement
    /// stream ends or an error occurs.
    pub async fn run(mut self) -> Result<()> {
        info!("Node service running");

        let mut announcements = self.discovery.lock().await.announcements();
        let mut shutdown = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                Some(announcement) = announcements.next() => {
                    info!(
                        "Discovered peer: {} (relay: {:?})",
                        announcement.node_id,
                        announcement.relay_url
                    );
                    debug!("Peer age: {:?}", announcement.age());
                }
                _ = shutdown.changed() => {
                    info!("Shutdown signal received");
                    break;
                }
                else => {
                    debug!("Announcement stream ended");
                    break;
                }
            }
        }

        // Cleanup on exit
        self.shutdown_inner().await?;
        Ok(())
    }

    /// Run the node service event loop without consuming self.
    ///
    /// This method is used when the service needs to run concurrently
    /// with other tasks (e.g., HTTP server) that share access to the
    /// discovery and state.
    pub async fn run_loop(&mut self) -> Result<()> {
        info!("Node service running");

        let mut announcements = self.discovery.lock().await.announcements();
        let mut shutdown = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                Some(announcement) = announcements.next() => {
                    info!(
                        "Discovered peer: {} (relay: {:?})",
                        announcement.node_id,
                        announcement.relay_url
                    );
                    debug!("Peer age: {:?}", announcement.age());
                }
                _ = shutdown.changed() => {
                    info!("Shutdown signal received");
                    break;
                }
                else => {
                    debug!("Announcement stream ended");
                    break;
                }
            }
        }

        self.shutdown_inner().await?;
        Ok(())
    }

    /// Internal shutdown logic shared by run() and shutdown().
    async fn shutdown_inner(&mut self) -> Result<()> {
        info!("Shutting down node service...");

        // Abort DNS refresh background task
        if let Some(handle) = self.dns_refresh.take() {
            handle.abort();
            debug!("DNS refresh task aborted");
        }

        // Shutdown discovery
        if let Err(e) = self.discovery.lock().await.shutdown().await {
            tracing::error!("Error shutting down discovery: {}", e);
        } else {
            info!("Discovery closed");
        }

        // Shutdown the protocol router (closes endpoint and gossip accept loop)
        if let Err(e) = self.router.shutdown().await {
            tracing::error!("Error shutting down router: {}", e);
        } else {
            info!("Protocol router closed");
        }

        info!("Node service shutdown complete");
        Ok(())
    }

    /// Get the current number of discovered peers.
    pub async fn peer_count(&self) -> usize {
        self.discovery.lock().await.peer_count()
    }

    /// Get a shutdown trigger that can be used to signal shutdown.
    ///
    /// This should be called before moving the service into a spawn.
    pub fn shutdown_trigger(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Shutdown the node service gracefully.
    ///
    /// Closes discovery and endpoint in order.
    pub async fn shutdown(mut self) -> Result<()> {
        self.shutdown_inner().await
    }
}

async fn run_health_server(listener: tokio::net::TcpListener, node_api: NodeApi) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("Health server accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let api = node_api.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let api = api.clone();
                async move { handle_health_request(req, api).await }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!("Health server connection error: {e}");
            }
        });
    }
}

async fn handle_health_request(
    req: Request<hyper::body::Incoming>,
    node_api: NodeApi,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/health") => match node_api.health().await {
            Ok(resp) => {
                let body = serde_json::to_string(&resp).unwrap();
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap())
            }
            Err(_) => {
                let body = r#"{"status":"unhealthy"}"#;
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap())
            }
        },
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    async fn create_test_config() -> (NodeConfig, TempDir) {
        let temp = TempDir::new().unwrap();
        let mut config = NodeConfig::default();
        config.node.data_dir = temp.path().to_string_lossy().to_string();
        config.network.bootstrap_nodes = vec![]; // No bootstrap peers in tests
        (config, temp)
    }

    #[tokio::test]
    async fn test_service_creation() {
        tracing_subscriber::fmt::try_init().ok();

        let (config, _temp) = create_test_config().await;
        let state_path = Path::new(&config.node.data_dir).join("node.key");
        let state = NodeState::load_or_create(&state_path).unwrap();

        let service = NodeService::new(config.clone(), state).await.unwrap();

        // Verify endpoint initialized with correct node_id
        let node_id = service.node_id();
        assert_eq!(node_id.as_bytes().len(), 32);

        // Verify relay URL in node address uses our relay, not N0's default
        let addr = service.node_addr();
        let relay_urls: Vec<_> = addr.relay_urls().collect();
        assert!(!relay_urls.is_empty());
        assert!(
            relay_urls
                .iter()
                .any(|url| url.as_str().contains("relay.objects.foundation")),
            "Expected relay.objects.foundation in relay URLs, got: {:?}",
            relay_urls
        );
    }

    #[tokio::test]
    async fn test_endpoint_uses_state_key() {
        tracing_subscriber::fmt::try_init().ok();

        let (config, _temp) = create_test_config().await;
        let state_path = Path::new(&config.node.data_dir).join("node.key");
        let state = NodeState::load_or_create(&state_path).unwrap();

        let expected_node_id = state.node_key().public();

        let service = NodeService::new(config, state).await.unwrap();

        // Node ID should match state's public key
        assert_eq!(service.node_id().to_string(), expected_node_id.to_string());
    }

    #[tokio::test]
    async fn test_discovery_setup() {
        tracing_subscriber::fmt::try_init().ok();

        let (config, _temp) = create_test_config().await;
        let state_path = Path::new(&config.node.data_dir).join("node.key");
        let state = NodeState::load_or_create(&state_path).unwrap();

        let service = NodeService::new(config, state).await.unwrap();

        // Discovery should be initialized
        assert_eq!(service.peer_count().await, 0); // No peers discovered yet
    }

    #[tokio::test]
    async fn test_service_run_loop() {
        use std::time::Duration;

        tracing_subscriber::fmt::try_init().ok();

        let (config, _temp) = create_test_config().await;
        let state_path = Path::new(&config.node.data_dir).join("node.key");
        let state = NodeState::load_or_create(&state_path).unwrap();

        let service = NodeService::new(config, state).await.unwrap();

        // Spawn service in background
        let handle = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), service.run()).await
        });

        // Wait briefly for discovery to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Service should be running (timeout will end it)
        let result = handle.await.unwrap();
        assert!(result.is_err()); // Expect timeout
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        tracing_subscriber::fmt::try_init().ok();

        let (config, _temp) = create_test_config().await;
        let state_path = Path::new(&config.node.data_dir).join("node.key");
        let state = NodeState::load_or_create(&state_path).unwrap();

        let service = NodeService::new(config, state).await.unwrap();

        // Shutdown should complete without errors
        service.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_run_and_shutdown() {
        use std::time::Duration;

        tracing_subscriber::fmt::try_init().ok();

        let (config, _temp) = create_test_config().await;
        let state_path = Path::new(&config.node.data_dir).join("node.key");
        let state = NodeState::load_or_create(&state_path).unwrap();

        let service = NodeService::new(config, state).await.unwrap();

        // Get shutdown trigger before moving service
        let shutdown_trigger = service.shutdown_trigger();

        // Spawn service
        let handle = tokio::spawn(async move { service.run().await });

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Service should still be running
        assert!(!handle.is_finished());

        // Trigger graceful shutdown
        shutdown_trigger.send(true).unwrap();

        // Service should complete gracefully
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("Shutdown should complete within timeout");

        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
}
