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

/// Test blob ticket creation.
///
/// Verifies that we can create valid blob tickets for sharing.
/// Note: Full blob sync via ticket requires network infrastructure
/// and is tested in higher-level E2E tests.
#[tokio::test]
async fn test_blob_ticket_creation() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    // Node A: Add a blob
    let content = Bytes::from("test blob content for ticket");
    let blob_hash = harness
        .node_a
        .blobs()
        .add_bytes(content.clone())
        .await
        .unwrap();

    // Node A: Create a blob ticket
    let ticket = harness
        .node_a
        .blobs()
        .create_ticket(blob_hash, harness.node_a_addr.clone())
        .await
        .unwrap();

    // Verify ticket serializes correctly
    let ticket_str = ticket.to_string();
    assert!(!ticket_str.is_empty());
    assert!(ticket_str.starts_with("blob"));

    // Verify ticket contains correct hash
    assert_eq!(ticket.hash(), blob_hash);
}

/// Test doc ticket creation.
///
/// Note: With in-memory storage, actual cross-node sync requires real network
/// infrastructure. This test verifies ticket creation API. Real sync is tested
/// in bins/objects-node/tests/e2e_sync.rs with persistent storage.
#[tokio::test]
async fn test_doc_ticket_creation() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    // Node A: Create project
    let replica_id = harness.node_a.docs().create_replica().await.unwrap();
    let author = harness.node_a.docs().create_author().await.unwrap();

    let project = project_from_replica(replica_id, "Ticket Test Project").unwrap();
    harness
        .node_a
        .docs()
        .store_project(replica_id, author, &project)
        .await
        .unwrap();

    // Node A: Create ticket
    let ticket = harness
        .node_a
        .docs()
        .create_ticket(replica_id, harness.node_a_addr.clone())
        .await
        .unwrap();

    // Verify ticket serializes correctly
    let ticket_str = ticket.to_string();
    assert!(!ticket_str.is_empty());
    assert!(ticket_str.starts_with("doc"));
}

/// Test creating project with multiple assets on single node.
///
/// Note: With in-memory storage, cross-node sync doesn't work. Real sync tests
/// are in bins/objects-node/tests/e2e_sync.rs with persistent storage and network.
#[tokio::test]
async fn test_multi_asset_project_single_node() {
    let harness = TwoNodeTestHarness::new().await.unwrap();

    // Node A: Create project
    let replica_id = harness.node_a.docs().create_replica().await.unwrap();
    let author = harness.node_a.docs().create_author().await.unwrap();

    let project = project_from_replica(replica_id, "Multi-Asset Project").unwrap();
    harness
        .node_a
        .docs()
        .store_project(replica_id, author, &project)
        .await
        .unwrap();

    // Node A: Add multiple assets
    let mut asset_ids = Vec::new();
    for i in 0..3 {
        let content = Bytes::from(format!("asset-content-{}", i));
        let blob_hash = harness.node_a.blobs().add_bytes(content).await.unwrap();
        let content_hash = objects_sync::hash_to_content_hash(blob_hash);

        let test_asset = asset(format!("asset-{}", i), content_hash).unwrap();
        harness
            .node_a
            .docs()
            .store_asset(replica_id, author, &test_asset)
            .await
            .unwrap();

        asset_ids.push(format!("asset-{}", i));
    }

    // Node A: Verify all assets stored correctly
    let assets = harness
        .node_a
        .docs()
        .list_assets(harness.node_a.blobs(), replica_id)
        .await
        .unwrap();

    assert_eq!(assets.len(), 3, "All 3 assets should be stored");

    // Verify each asset exists and has correct ID
    for (i, asset_id) in asset_ids.iter().enumerate() {
        let asset = harness
            .node_a
            .docs()
            .get_asset(harness.node_a.blobs(), replica_id, asset_id)
            .await
            .unwrap();

        assert!(asset.is_some(), "Asset {} should exist", i);
        assert_eq!(asset.unwrap().id(), asset_id);
    }
}
