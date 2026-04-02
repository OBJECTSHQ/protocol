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
    Ok(SyncEngine::in_memory(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create sync engine: {}", e))?
        .spawn())
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

/// Creates two sync engines that can communicate with each other.
///
/// Each engine has its own `MemoryLookup` for discovery. After both
/// engines (and their iroh Routers) are created, the endpoints cross-register
/// each other's addresses. This follows the iroh canonical test pattern.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::sync;
///
/// #[tokio::test]
/// async fn test_two_node_sync() {
///     let (sync_a, sync_b) = sync::sync_engine_pair().await.unwrap();
///     // sync_a and sync_b can transfer blobs and sync docs
/// }
/// ```
pub async fn sync_engine_pair() -> anyhow::Result<(SyncEngine, SyncEngine)> {
    use objects_transport::{MemoryLookup, RelayMode};

    let sp1 = MemoryLookup::new();
    let sp2 = MemoryLookup::new();

    // Use RelayMode::Disabled for fast, deterministic local connections.
    // Matches transport::endpoint_pair() pattern.
    let ep1 = objects_transport::ObjectsEndpoint::builder()
        .config(transport::network_config())
        .relay_mode(RelayMode::Disabled)
        .static_discovery(sp1.clone())
        .bind()
        .await
        .expect("failed to create endpoint 1");

    let ep2 = objects_transport::ObjectsEndpoint::builder()
        .config(transport::network_config())
        .relay_mode(RelayMode::Disabled)
        .static_discovery(sp2.clone())
        .bind()
        .await
        .expect("failed to create endpoint 2");

    let sync1 = SyncEngine::in_memory(ep1)
        .await
        .map_err(|e| anyhow::anyhow!("sync engine 1: {}", e))?
        .spawn();
    let sync2 = SyncEngine::in_memory(ep2)
        .await
        .map_err(|e| anyhow::anyhow!("sync engine 2: {}", e))?
        .spawn();

    // Cross-register addresses AFTER Routers are spawned (iroh canonical pattern).
    sp1.add_endpoint_info(sync2.endpoint().addr());
    sp2.add_endpoint_info(sync1.endpoint().addr());

    Ok((sync1, sync2))
}

/// Creates two sync engines connected via the OBJECTS relay.
///
/// Uses `relay.objects.foundation` for NAT traversal, testing the
/// real production relay path. Slower than `sync_engine_pair()` and
/// requires internet. Use in `#[ignore]` integration tests.
pub async fn sync_engine_pair_with_relay() -> anyhow::Result<(SyncEngine, SyncEngine)> {
    use objects_transport::MemoryLookup;

    let sp1 = MemoryLookup::new();
    let sp2 = MemoryLookup::new();

    let relay_config = transport::network_config_with_relay("https://relay.objects.foundation");

    let ep1 = objects_transport::ObjectsEndpoint::builder()
        .config(relay_config.clone())
        .static_discovery(sp1.clone())
        .bind()
        .await
        .expect("failed to create relay endpoint 1");

    let ep2 = objects_transport::ObjectsEndpoint::builder()
        .config(relay_config)
        .static_discovery(sp2.clone())
        .bind()
        .await
        .expect("failed to create relay endpoint 2");

    let sync1 = SyncEngine::in_memory(ep1)
        .await
        .map_err(|e| anyhow::anyhow!("sync engine 1: {}", e))?
        .spawn();
    let sync2 = SyncEngine::in_memory(ep2)
        .await
        .map_err(|e| anyhow::anyhow!("sync engine 2: {}", e))?
        .spawn();

    sp1.add_endpoint_info(sync2.endpoint().addr());
    sp2.add_endpoint_info(sync1.endpoint().addr());

    Ok((sync1, sync2))
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
}
