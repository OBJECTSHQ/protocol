//! Sync-layer test utilities for SyncEngine and sync operations.
//!
//! This module provides factories for creating test sync engines with
//! sensible defaults for testing blob and metadata sync operations.

use crate::{identity, time, transport};
use objects_data::{Asset, ContentHash, Project};
use objects_sync::{ReplicaId, SyncEngine};

/// Creates a sync engine for testing.
///
/// Creates a new ObjectsEndpoint and initializes a SyncEngine with it.
/// Each call creates a fresh endpoint bound to a random port.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::sync;
///
/// #[tokio::test]
/// async fn test_sync_operations() {
///     let engine = sync::sync_engine().await.unwrap();
///     // Use engine for blob/doc operations
/// }
/// ```
#[allow(deprecated)] // Test utilities intentionally use in-memory storage for speed and isolation
pub async fn sync_engine() -> anyhow::Result<SyncEngine> {
    let endpoint = transport::endpoint().await;
    SyncEngine::new(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create sync engine: {}", e))
}

/// Creates a test project derived from a replica using RFC-004 derivation.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::sync;
///
/// #[tokio::test]
/// async fn test_project() {
///     let engine = sync::sync_engine().await.unwrap();
///     let replica_id = engine.docs().create_replica().await.unwrap();
///     let project = sync::project_from_replica(replica_id, "My Project").unwrap();
/// }
/// ```
pub fn project_from_replica(
    replica_id: ReplicaId,
    name: impl Into<String>,
) -> anyhow::Result<Project> {
    let project_id = objects_data::project_id_from_replica(replica_id.as_bytes());
    Project::new(
        project_id,
        name.into(),
        Some("Test project description".to_string()),
        identity::test_identity_id(),
        time::TEST_TIMESTAMP,
        time::TEST_TIMESTAMP,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create test project: {}", e))
}

/// Creates a test asset with valid data.
///
/// Returns Result for compatibility with sync tests that use `?` operator.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::sync;
/// use objects_data::ContentHash;
///
/// #[tokio::test]
/// async fn test_asset() {
///     let hash = ContentHash([1u8; 32]);
///     let asset = sync::asset("asset-1", hash).unwrap();
///     assert_eq!(asset.id(), "asset-1");
/// }
/// ```
pub fn asset(id: impl Into<String>, content_hash: ContentHash) -> anyhow::Result<Asset> {
    Asset::new(
        id.into(),
        "Test Asset".to_string(),
        identity::test_identity_id(),
        content_hash,
        1024,
        Some("application/octet-stream".to_string()),
        time::TEST_TIMESTAMP,
        time::TEST_TIMESTAMP,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create test asset: {}", e))
}

/// Test harness for two-node sync scenarios.
///
/// Creates two isolated sync engines for testing sync operations
/// between nodes, such as ticket-based project sharing.
pub struct TwoNodeTestHarness {
    /// First sync engine (typically the "source" node).
    pub node_a: SyncEngine,
    /// First node address (for creating tickets).
    pub node_a_addr: objects_transport::NodeAddr,
    /// Second sync engine (typically the "destination" node).
    pub node_b: SyncEngine,
    /// Second node address (for creating tickets).
    pub node_b_addr: objects_transport::NodeAddr,
}

impl TwoNodeTestHarness {
    /// Create two isolated sync engines for testing.
    ///
    /// Each engine has its own endpoint and storage, suitable for
    /// testing sync operations between nodes.
    #[allow(deprecated)] // Test utilities intentionally use in-memory storage
    pub async fn new() -> anyhow::Result<Self> {
        let endpoint_a = transport::endpoint().await;
        let node_a_addr = endpoint_a.node_addr();
        let node_a = SyncEngine::new(endpoint_a)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create sync engine A: {}", e))?;

        let endpoint_b = transport::endpoint().await;
        let node_b_addr = endpoint_b.node_addr();
        let node_b = SyncEngine::new(endpoint_b)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create sync engine B: {}", e))?;

        Ok(Self {
            node_a,
            node_a_addr,
            node_b,
            node_b_addr,
        })
    }

    /// Share project from node_a to node_b via ticket.
    ///
    /// Creates a ticket on node_a and redeems it on node_b.
    /// Returns the replica ID on node_b.
    pub async fn share_project(&self, replica_id: ReplicaId) -> anyhow::Result<ReplicaId> {
        // Create ticket on node_a
        let ticket = self
            .node_a
            .docs()
            .create_ticket(replica_id, self.node_a_addr.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create ticket: {}", e))?;

        // Redeem ticket on node_b
        let synced_replica = self
            .node_b
            .docs()
            .download_from_ticket(ticket)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to redeem ticket: {}", e))?;

        Ok(synced_replica)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_engine_creation() {
        let engine = sync_engine().await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_sync_engine_has_blobs_interface() {
        let engine = sync_engine().await.unwrap();
        // Verify blobs interface is accessible
        let test_data = b"test";
        let hash = engine.blobs().add_bytes(&test_data[..]).await;
        assert!(hash.is_ok());
    }

    #[tokio::test]
    async fn test_sync_engine_has_docs_interface() {
        let engine = sync_engine().await.unwrap();
        // Verify docs interface is accessible
        let replica_id = engine.docs().create_replica().await;
        assert!(replica_id.is_ok());
    }

    #[tokio::test]
    async fn test_two_node_harness_creation() {
        let harness = TwoNodeTestHarness::new().await;
        assert!(harness.is_ok());
    }
}
