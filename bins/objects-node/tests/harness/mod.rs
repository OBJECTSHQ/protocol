//! Test harness for spinning up full OBJECTS stack (registry + nodes).
//!
//! This module provides a reusable test harness that spins up:
//! - TestRegistry: In-process registry with PostgreSQL test database
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
use sqlx::{ConnectOptions, PgPool};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod node;
pub mod registry;

pub use node::TestNode;
pub use registry::TestRegistry;

/// Complete test harness with registry and two nodes.
///
/// Creates:
/// - One in-process registry with test database
/// - Two node instances (node_a and node_b)
/// - Each node has a running API server
///
/// # Cleanup
///
/// The harness implements proper cleanup on drop:
/// - Shuts down API servers
/// - Cleans up temporary directories
/// - Closes database connections
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
    /// 1. PostgreSQL test database via sqlx::test
    /// 2. In-process registry API server
    /// 3. Two nodes with separate temp directories and API servers
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Database connection fails
    /// - Registry server fails to start
    /// - Node initialization fails
    /// - API server binding fails
    pub async fn new() -> Result<Self> {
        // Spawn registry first
        let registry = TestRegistry::new().await?;

        // Spawn two nodes
        let node_a = TestNode::new(&registry.base_url).await?;
        let node_b = TestNode::new(&registry.base_url).await?;

        Ok(Self {
            registry,
            node_a,
            node_b,
        })
    }

    /// Create harness with provided database pool (for sqlx::test isolation).
    ///
    /// This is used by E2E tests that need isolated test databases.
    /// Each test gets its own PostgreSQL schema from sqlx::test.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Registry server fails to start
    /// - Node initialization fails
    /// - API server binding fails
    pub async fn with_pool(pool: PgPool) -> Result<Self> {
        // Get database URL from pool
        let database_url = pool.connect_options().to_url_lossy().to_string();

        // Spawn registry with the provided pool
        let registry = TestRegistry::with_pool(pool, database_url).await?;

        // Spawn two nodes
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
    /// Creates identities with fixed handles ("test_user_a" and "test_user_b").
    /// Safe to use fixed handles because each test gets an isolated database via sqlx::test.
    ///
    /// Required before creating projects or other operations that need an identity.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - HTTP request to identity endpoint fails
    /// - Registry returns non-success status
    /// - Cryptographic operations fail
    pub async fn register_test_identities(&self) -> Result<()> {
        // Use fixed handles - safe because each test gets isolated database
        self.register_identity(self.node_a_url(), "test_user_a")
            .await?;
        self.register_identity(self.node_b_url(), "test_user_b")
            .await?;
        Ok(())
    }

    /// Register a single identity on a node with a specified handle.
    ///
    /// Helper that generates keys, signs the identity creation message with the provided
    /// handle, and posts to the node's /identity endpoint.
    async fn register_identity(&self, node_url: &str, handle: &str) -> Result<()> {
        // Generate signing key
        let signing_key = PasskeySigningKey::generate();
        let public_key_bytes = signing_key.public_key();
        let public_key: [u8; 33] = public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Public key must be 33 bytes"))?;

        // Generate nonce
        let nonce = generate_nonce();

        // Derive identity ID (unique per keypair + nonce)
        let identity_id = IdentityId::derive(&public_key, &nonce);

        // Get timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Create message to sign
        let message = create_identity_message(identity_id.as_str(), &handle, timestamp);

        // Sign the message
        let signature = signing_key.sign(message.as_bytes());

        // Build signature data
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

        // Build create identity request
        let request = CreateIdentityRequest {
            handle: handle.to_string(),
            signer_type: "PASSKEY".to_string(),
            signer_public_key: base64::engine::general_purpose::STANDARD.encode(&public_key),
            nonce: base64::engine::general_purpose::STANDARD.encode(&nonce),
            timestamp,
            signature: signature_data,
        };

        // Post to node
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
    ///
    /// This is called automatically on drop, but can be called explicitly
    /// to handle shutdown errors.
    pub async fn shutdown(self) -> Result<()> {
        // Shutdown happens via Drop implementations
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_harness_creation() {
        let harness = TestHarness::new().await;
        assert!(harness.is_ok(), "Failed to create test harness");
    }

    #[tokio::test]
    async fn test_harness_urls() {
        let harness = TestHarness::new().await.unwrap();

        // Verify URLs are non-empty
        assert!(!harness.registry_url().is_empty());
        assert!(!harness.node_a_url().is_empty());
        assert!(!harness.node_b_url().is_empty());

        // Verify URLs are different
        assert_ne!(harness.node_a_url(), harness.node_b_url());
    }

    #[tokio::test]
    async fn test_cli_clients() {
        let harness = TestHarness::new().await.unwrap();

        let _client_a = harness.cli_client_a();
        let _client_b = harness.cli_client_b();

        // Clients are created successfully
        // (NodeClient doesn't expose base_url for comparison)
    }
}
