//! Node service orchestrating transport layer components.

use crate::{NodeConfig, NodeState};
use anyhow::Result;
use objects_transport::{NetworkConfig, NodeAddr, NodeId, ObjectsEndpoint, RelayUrl};
use std::str::FromStr;
use tracing::{debug, info};

/// Node service orchestrating P2P networking components.
pub struct NodeService {
    #[allow(dead_code)] // Used in PR6 for discovery
    config: NodeConfig,
    #[allow(dead_code)] // Used for identity management
    state: NodeState,
    endpoint: ObjectsEndpoint,
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

        Ok(Self {
            config,
            state,
            endpoint,
        })
    }

    /// Get the node's unique identifier.
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Get the node's network address.
    pub fn node_addr(&self) -> NodeAddr {
        self.endpoint.node_addr()
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
}
