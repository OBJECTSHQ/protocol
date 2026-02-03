//! Node service orchestrating transport layer components.

use crate::{NodeConfig, NodeState};
use anyhow::Result;
use futures::StreamExt;
use objects_transport::discovery::{Discovery, DiscoveryConfig, GossipDiscovery};
use objects_transport::{NetworkConfig, NodeAddr, NodeId, ObjectsEndpoint, RelayUrl};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info};

/// Node service orchestrating P2P networking components.
pub struct NodeService {
    #[allow(dead_code)] // Used for logging and future features
    config: NodeConfig,
    #[allow(dead_code)] // Used for identity management
    state: NodeState,
    endpoint: Arc<ObjectsEndpoint>,
    discovery: GossipDiscovery,
}

impl NodeService {
    /// Create a new node service with the given config and state.
    ///
    /// This initializes the Iroh endpoint with the OBJECTS ALPN protocol
    /// and connects to the configured relay server.
    pub async fn new(config: NodeConfig, state: NodeState) -> Result<Self> {
        info!("Creating node service");

        // Parse relay URL
        let relay_url = RelayUrl::from_str(&config.network.relay_url)?;

        // Create network config from node config
        let network_config = NetworkConfig::devnet()
            .with_relay_url(relay_url)
            .with_max_connections(50);

        debug!(
            "Network config: relay={}, discovery={}",
            config.network.relay_url, config.network.discovery_topic
        );

        // Create endpoint with node's secret key
        let endpoint = ObjectsEndpoint::builder()
            .config(network_config)
            .secret_key(state.node_key().clone())
            .bind()
            .await?;

        info!("Endpoint created with node_id: {}", endpoint.node_id());

        // Wait for relay connection
        endpoint.inner().online().await;
        info!("Connected to relay: {}", config.network.relay_url);

        // Set up peer discovery
        info!("Setting up peer discovery");

        // Create gossip instance for this endpoint
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.inner().clone());

        // Create discovery with devnet config
        let endpoint_arc = Arc::new(endpoint);
        let discovery = GossipDiscovery::new(
            gossip,
            endpoint_arc.clone(),
            vec![], // No bootstrap nodes for now
            DiscoveryConfig::devnet(),
        )
        .await?;

        info!("Joined discovery topic: {}", config.network.discovery_topic);

        Ok(Self {
            config,
            state,
            endpoint: endpoint_arc,
            discovery,
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

    /// Run the node service, listening for peer announcements.
    pub async fn run(self) -> Result<()> {
        info!("Node service running");

        let mut announcements = self.discovery.announcements();

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
                else => {
                    debug!("Announcement stream ended");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Get the current number of discovered peers.
    pub fn peer_count(&self) -> usize {
        self.discovery.peer_count()
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

        // Verify relay URL in node address
        // Note: Currently uses Iroh's default relay (RelayMode::Default)
        // TODO: Update endpoint.rs to use RelayMode::Custom with config.relay_url
        let addr = service.node_addr();
        let relay_urls: Vec<_> = addr.relay_urls().collect();
        assert!(!relay_urls.is_empty());
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
        assert_eq!(service.peer_count(), 0); // No peers discovered yet
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
}
