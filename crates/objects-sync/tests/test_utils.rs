//! Test utilities for objects-sync integration tests.

use objects_data::{Asset, ContentHash, Project};
use objects_identity::IdentityId;
use objects_sync::{ReplicaId, SyncEngine};
use objects_transport::ObjectsEndpoint;

/// RFC-001 test vector identity ID.
pub fn test_identity_id() -> IdentityId {
    IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap()
}

/// Standard test timestamp (2024-01-06 12:00:00 UTC).
pub const TEST_TIMESTAMP: u64 = 1704542400;

/// Creates a sync engine for testing.
pub async fn create_test_sync_engine() -> objects_sync::Result<SyncEngine> {
    let endpoint = ObjectsEndpoint::builder().bind().await?;
    SyncEngine::new(endpoint).await
}

/// Creates a test project derived from a replica.
///
/// Uses RFC-004 project ID derivation.
pub fn test_project_from_replica(
    replica_id: ReplicaId,
    name: impl Into<String>,
) -> objects_sync::Result<Project> {
    let project_id = Project::project_id_from_replica(replica_id.as_bytes());
    Project::new(
        project_id,
        name.into(),
        Some("Test project description".to_string()),
        test_identity_id(),
        TEST_TIMESTAMP,
        TEST_TIMESTAMP,
    )
    .map_err(|e| objects_sync::Error::Iroh(anyhow::anyhow!(e)))
}

/// Creates a test asset with valid data.
pub fn test_asset(id: impl Into<String>, content_hash: ContentHash) -> objects_sync::Result<Asset> {
    Asset::new(
        id.into(),
        "Test Asset".to_string(),
        test_identity_id(),
        content_hash,
        1024,
        Some("application/octet-stream".to_string()),
        TEST_TIMESTAMP,
        TEST_TIMESTAMP,
    )
    .map_err(|e| objects_sync::Error::Iroh(anyhow::anyhow!(e)))
}
