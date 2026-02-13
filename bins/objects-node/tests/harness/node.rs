//! Test node harness for spawning in-process node instances.

use anyhow::Result;
use objects_node::api::client::RegistryClient;
use objects_node::api::handlers::{AppState, NodeInfo};
use objects_node::api::routes::create_router;
use objects_node::{NodeConfig, NodeState};
use objects_sync::SyncEngine;
use objects_sync::storage::StorageConfig;
use objects_transport::discovery::{DiscoveryConfig, GossipDiscovery};
use objects_transport::{NodeAddr, RelayUrl};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// In-process node for testing.
///
/// Spawns a complete node instance with:
/// - Temporary data directory
/// - Iroh endpoint with transport layer
/// - Gossip discovery
/// - Sync engine (blobs + docs)
/// - REST API server
#[allow(dead_code)]
pub struct TestNode {
    pub base_url: String,
    pub node_addr: NodeAddr,
    pub sync_engine: SyncEngine,
    pub(crate) _discovery: Arc<Mutex<GossipDiscovery>>,
    _temp_dir: TempDir,
    _server_handle: JoinHandle<()>,
}

impl TestNode {
    /// Create and start a new test node.
    ///
    /// This:
    /// 1. Creates a temporary directory for node data
    /// 2. Initializes node state with new keypair
    /// 3. Creates Iroh endpoint with relay connection
    /// 4. Sets up gossip discovery
    /// 5. Initializes sync engine
    /// 6. Spawns REST API server on random port
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Temp directory creation fails
    /// - Node initialization fails
    /// - Endpoint binding fails
    /// - Server binding fails
    pub async fn new(registry_url: &str) -> Result<Self> {
        // Create temp directory
        let temp_dir = tempfile::tempdir()?;
        let data_dir = temp_dir.path().to_path_buf();

        // Create node config pointing to test relay
        let config = NodeConfig {
            node: objects_node::config::NodeSettings {
                data_dir: data_dir.to_str().unwrap().to_string(),
                api_port: 0, // Random port
                api_bind: "127.0.0.1".to_string(),
            },
            network: objects_node::config::NetworkSettings {
                relay_url: "https://relay.objects.foundation".to_string(),
                discovery_topic: "/objects/devnet/0.1/discovery".to_string(),
            },
            storage: objects_node::config::StorageSettings::default(),
            identity: objects_node::config::IdentitySettings {
                registry_url: registry_url.to_string(),
                ..Default::default()
            },
        };

        // Initialize node state
        let state_path = std::path::PathBuf::from(&config.node.data_dir).join("state.json");
        let state = NodeState::load_or_create(&state_path)?;

        // Parse relay URL
        let relay_url = RelayUrl::from_str(&config.network.relay_url)?;

        // Create network config
        let network_config = objects_transport::NetworkConfig::devnet()
            .with_relay_url(relay_url)
            .with_max_connections(50);

        // Create endpoint with node's secret key
        let endpoint = objects_transport::ObjectsEndpoint::builder()
            .config(network_config)
            .secret_key(state.node_key().clone())
            .bind()
            .await?;

        let node_id = endpoint.node_id();
        let node_addr = endpoint.node_addr();

        // Wait for relay connection
        endpoint.inner().online().await;

        // Set up peer discovery
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.inner().clone());

        let endpoint_arc = Arc::new(endpoint);
        let discovery = GossipDiscovery::new(
            gossip,
            endpoint_arc.clone(),
            vec![],
            DiscoveryConfig::devnet(),
        )
        .await?;

        let discovery_arc = Arc::new(Mutex::new(discovery));

        // Create sync engine with persistent storage
        let storage_config = StorageConfig::from_base_dir(&data_dir);
        let sync_engine = SyncEngine::with_storage(endpoint_arc.inner(), &storage_config).await?;

        // Create node info
        let node_info = Arc::new(NodeInfo {
            node_id,
            node_addr: node_addr.clone(),
        });

        // Create app state
        let registry_client = RegistryClient::new(&config);
        let app_state = AppState {
            node_info,
            discovery: discovery_arc.clone(),
            node_state: Arc::new(RwLock::new(state)),
            config: config.clone(),
            registry_client,
            sync_engine: sync_engine.clone(),
        };

        // Create router
        let app = create_router(app_state);

        // Bind to random port
        let addr: SocketAddr = "127.0.0.1:0".parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        let base_url = format!("http://{}", bound_addr);

        // Spawn server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("Node server failed");
        });

        Ok(Self {
            base_url,
            node_addr,
            sync_engine,
            _temp_dir: temp_dir,
            _server_handle: server_handle,
            _discovery: discovery_arc,
        })
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        // Server handle is aborted on drop
        self._server_handle.abort();
        // Temp directory is cleaned up automatically
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let registry_url = "http://localhost:8080";
        let node = TestNode::new(registry_url).await;
        assert!(node.is_ok(), "Failed to create test node");
    }

    #[tokio::test]
    async fn test_node_health_endpoint() {
        let registry_url = "http://localhost:8080";
        let node = TestNode::new(registry_url).await.unwrap();

        // Test health endpoint
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/health", node.base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ok");
    }
}
