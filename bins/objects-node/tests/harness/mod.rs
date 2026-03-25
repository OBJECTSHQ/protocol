//! Test harness for spinning up full OBJECTS stack (registry + nodes).
//!
//! This module provides a reusable test harness that spins up:
//! - TestRegistry: Docker-based registry container
//! - TestNode: One or more node instances with API servers
//! - Helper methods for accessing URLs and addresses

use anyhow::Result;
use base64::Engine;
use objects_cli::client::NodeClient;
use objects_cli::types::{CreateIdentityRequest, SignatureData};
use objects_identity::{
    IdentityId, PasskeySigningKey, generate_nonce, message::create_identity_message,
};
use objects_transport::NodeAddr;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let pid = std::process::id();
        self.register_identity(self.node_a_url(), &format!("test_user_a_{pid}"))
            .await?;
        self.register_identity(self.node_b_url(), &format!("test_user_b_{pid}"))
            .await?;
        Ok(())
    }

    /// Register a single identity on a node with a specified handle.
    async fn register_identity(&self, node_url: &str, handle: &str) -> Result<()> {
        let signing_key = PasskeySigningKey::generate();
        let public_key_bytes = signing_key.public_key();
        let public_key: [u8; 33] = public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Public key must be 33 bytes"))?;

        let nonce = generate_nonce();
        let identity_id = IdentityId::derive(&public_key, &nonce);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = create_identity_message(identity_id.as_str(), handle, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let signature_data = SignatureData {
            signature: base64::engine::general_purpose::STANDARD
                .encode(signature.signature_bytes()),
            public_key: signature
                .public_key_bytes()
                .map(|pk| base64::engine::general_purpose::STANDARD.encode(pk)),
            address: signature.address().map(|a| a.to_string()),
            authenticator_data: signature
                .authenticator_data()
                .map(|ad| base64::engine::general_purpose::STANDARD.encode(ad)),
            client_data_json: signature
                .client_data_json()
                .map(|cdj| base64::engine::general_purpose::STANDARD.encode(cdj)),
        };

        let request = CreateIdentityRequest {
            handle: handle.to_string(),
            signer_type: "PASSKEY".to_string(),
            signer_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
            timestamp,
            signature: signature_data,
        };

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/identity", node_url))
            .json(&request)
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
