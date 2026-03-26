//! Test harness for spinning up full OBJECTS stack (registry + nodes).
//!
//! This module provides a reusable test harness that spins up:
//! - TestRegistry: Docker-based registry container
//! - TestNode: One or more node instances with API servers
//! - Helper methods for accessing URLs and addresses

use anyhow::Result;
use objects_cli::client::NodeClient;
use objects_transport::NodeAddr;

pub mod node;
pub mod registry;

pub use node::TestNode;
pub use registry::TestRegistry;

/// Complete test harness with registry and two nodes.
///
/// Creates:
/// - One Docker-based registry container
/// - Two node instances (node_a and node_b)
/// - Each node has a running API server
///
/// # Cleanup
///
/// The harness implements proper cleanup on drop:
/// - Shuts down API servers
/// - Cleans up temporary directories
/// - Stops registry container
pub struct TestHarness {
    pub registry: TestRegistry,
    pub node_a: TestNode,
    pub node_b: TestNode,
}

#[allow(dead_code)]
impl TestHarness {
    /// Create a new test harness with registry and two nodes.
    ///
    /// This spawns:
    /// 1. Docker-based registry container
    /// 2. Two nodes with separate temp directories and API servers
    pub async fn new() -> Result<Self> {
        // Spawn registry first
        let registry = TestRegistry::new().await?;

        // Spawn two nodes — they connect via iroh's N0 relay
        let node_a = TestNode::new(&registry.base_url).await?;
        let node_b = TestNode::new(&registry.base_url).await?;

        Ok(Self {
            registry,
            node_a,
            node_b,
        })
    }

    /// Get the registry base URL.
    pub fn registry_url(&self) -> &str {
        &self.registry.base_url
    }

    /// Get node A's API base URL.
    pub fn node_a_url(&self) -> &str {
        &self.node_a.base_url
    }

    /// Get node B's API base URL.
    pub fn node_b_url(&self) -> &str {
        &self.node_b.base_url
    }

    /// Get node A's network address.
    pub fn node_a_addr(&self) -> &NodeAddr {
        &self.node_a.node_addr
    }

    /// Get node B's network address.
    pub fn node_b_addr(&self) -> &NodeAddr {
        &self.node_b.node_addr
    }

    /// Create a CLI client configured for node A.
    pub fn cli_client_a(&self) -> NodeClient {
        NodeClient::new(self.node_a_url().to_string())
    }

    /// Create a CLI client configured for node B.
    pub fn cli_client_b(&self) -> NodeClient {
        NodeClient::new(self.node_b_url().to_string())
    }

    /// Register test identities on both nodes via registry.
    ///
    /// Creates identities with unique handles (using process ID for isolation).
    /// Required before creating projects or other operations that need an identity.
    pub async fn register_test_identities(&self) -> Result<()> {
        let id: u32 = rand::random();
        self.register_identity(self.node_a_url(), &format!("test_a_{id:08x}"))
            .await?;
        self.register_identity(self.node_b_url(), &format!("test_b_{id:08x}"))
            .await?;
        Ok(())
    }

    /// Register a single identity on a node with a specified handle.
    /// The node generates the signing key — we just send the handle.
    async fn register_identity(&self, node_url: &str, handle: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/identity", node_url))
            .json(&serde_json::json!({ "handle": handle }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            anyhow::bail!(
                "Failed to register identity {}: {} - {}",
                handle,
                status,
                body
            );
        }

        Ok(())
    }

    /// Shut down the test harness.
    pub async fn shutdown(self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_harness_creation() {
        if !registry::docker_available() {
            eprintln!("Skipping: Docker registry image not available");
            return;
        }
        let harness = TestHarness::new().await;
        assert!(harness.is_ok(), "Failed to create test harness");
    }

    #[tokio::test]
    async fn test_harness_urls() {
        if !registry::docker_available() {
            eprintln!("Skipping: Docker registry image not available");
            return;
        }
        let harness = TestHarness::new().await.unwrap();

        assert!(!harness.registry_url().is_empty());
        assert!(!harness.node_a_url().is_empty());
        assert!(!harness.node_b_url().is_empty());
        assert_ne!(harness.node_a_url(), harness.node_b_url());
    }

    #[tokio::test]
    async fn test_cli_clients() {
        if !registry::docker_available() {
            eprintln!("Skipping: Docker registry image not available");
            return;
        }
        let harness = TestHarness::new().await.unwrap();
        let _client_a = harness.cli_client_a();
        let _client_b = harness.cli_client_b();
    }
}
