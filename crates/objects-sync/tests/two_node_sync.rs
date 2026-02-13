//! Two-node sync integration tests.
//!
//! Tests the TwoNodeTestHarness setup and ticket creation/redemption flow.
//! Note: With in-memory storage, actual data sync requires a real network
//! connection which isn't available in unit tests. These tests verify the
//! harness setup and ticket API correctness.

use bytes::Bytes;
use objects_test_utils::sync::{TwoNodeTestHarness, asset, project_from_replica};

/// Test that TwoNodeTestHarness creates two working sync engines.
#[tokio::test]
async fn test_harness_creates_two_engines() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    // Both engines should be functional
    let replica_a = harness.node_a.docs().create_replica().await.unwrap();
    let replica_b = harness.node_b.docs().create_replica().await.unwrap();

    // They should have different replica IDs
    assert_ne!(replica_a, replica_b);
}

/// Test that we can create tickets for replicas.
#[tokio::test]
async fn test_ticket_creation() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    // Create a project on node A
    let replica_id = harness.node_a.docs().create_replica().await.unwrap();
    let author = harness.node_a.docs().create_author().await.unwrap();

    let project = project_from_replica(replica_id, "Ticket Test Project").unwrap();
    harness
        .node_a
        .docs()
        .store_project(replica_id, author, &project)
        .await
        .unwrap();

    // Create a ticket - this should succeed
    let ticket = harness
        .node_a
        .docs()
        .create_ticket(replica_id, harness.node_a_addr.clone())
        .await
        .unwrap();

    // Ticket should serialize to a non-empty string
    let ticket_str = ticket.to_string();
    assert!(!ticket_str.is_empty());
    assert!(ticket_str.starts_with("doc"));
}

/// Test project storage and retrieval on a single node.
#[tokio::test]
async fn test_project_storage_single_node() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    // Create and store project
    let replica_id = harness.node_a.docs().create_replica().await.unwrap();
    let author = harness.node_a.docs().create_author().await.unwrap();

    let project = project_from_replica(replica_id, "Single Node Project").unwrap();
    harness
        .node_a
        .docs()
        .store_project(replica_id, author, &project)
        .await
        .unwrap();

    // Retrieve and verify
    let retrieved = harness
        .node_a
        .docs()
        .get_project(harness.node_a.blobs(), replica_id)
        .await
        .unwrap();

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name(), "Single Node Project");
}

/// Test asset storage and retrieval on a single node.
#[tokio::test]
async fn test_asset_storage_single_node() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    let replica_id = harness.node_a.docs().create_replica().await.unwrap();
    let author = harness.node_a.docs().create_author().await.unwrap();

    // Add blob and create asset
    let content = Bytes::from("test asset content");
    let blob_hash = harness.node_a.blobs().add_bytes(content).await.unwrap();
    let content_hash = objects_sync::hash_to_content_hash(blob_hash);

    let test_asset = asset("test-asset-1", content_hash).unwrap();
    harness
        .node_a
        .docs()
        .store_asset(replica_id, author, &test_asset)
        .await
        .unwrap();

    // Retrieve and verify
    let retrieved = harness
        .node_a
        .docs()
        .get_asset(harness.node_a.blobs(), replica_id, "test-asset-1")
        .await
        .unwrap();

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id(), "test-asset-1");
}

/// Test listing multiple assets on a single node.
#[tokio::test]
async fn test_list_assets_single_node() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    let replica_id = harness.node_a.docs().create_replica().await.unwrap();
    let author = harness.node_a.docs().create_author().await.unwrap();

    // Create multiple assets
    for i in 0..3 {
        let content = Bytes::from(format!("content-{}", i));
        let blob_hash = harness.node_a.blobs().add_bytes(content).await.unwrap();
        let content_hash = objects_sync::hash_to_content_hash(blob_hash);
        let test_asset = asset(format!("asset-{}", i), content_hash).unwrap();
        harness
            .node_a
            .docs()
            .store_asset(replica_id, author, &test_asset)
            .await
            .unwrap();
    }

    // List and verify
    let assets = harness
        .node_a
        .docs()
        .list_assets(harness.node_a.blobs(), replica_id)
        .await
        .unwrap();

    assert_eq!(assets.len(), 3);
}
