//! E2E tests for cross-node sync operations.
//!
//! Tests basic blob and docs operations with persistent storage.

mod harness;

use harness::TestHarness;

#[tokio::test]
async fn test_blob_addition_and_retrieval() {
    let harness = TestHarness::new().await.unwrap();

    // Node A: Add a blob
    let test_data = b"Hello from Node A!";
    let hash = harness
        .node_a
        .sync_engine
        .blobs()
        .add_bytes(&test_data[..])
        .await
        .unwrap();

    // Verify blob exists on Node A
    let has_blob = harness.node_a.sync_engine.blobs().has_blob(hash).await;

    assert!(has_blob);

    // Read back the blob content
    let content = harness
        .node_a
        .sync_engine
        .blobs()
        .read_to_bytes(hash)
        .await
        .unwrap();

    assert_eq!(&content[..], test_data);
}

#[tokio::test]
async fn test_blob_ticket_creation() {
    let harness = TestHarness::new().await.unwrap();

    // Node A: Add a blob
    let test_data = b"Test blob for ticket";
    let hash = harness
        .node_a
        .sync_engine
        .blobs()
        .add_bytes(&test_data[..])
        .await
        .unwrap();

    // Node A: Create a blob ticket
    let ticket = harness
        .node_a
        .sync_engine
        .blobs()
        .create_ticket(hash, harness.node_a_addr().clone())
        .await
        .unwrap();

    // Verify ticket is non-empty
    assert!(!ticket.to_string().is_empty());
}

#[tokio::test]
async fn test_doc_replica_creation() {
    let harness = TestHarness::new().await.unwrap();

    // Create a docs replica
    let replica = harness
        .node_a
        .sync_engine
        .docs()
        .create_replica()
        .await
        .unwrap();

    // Verify replica ID is not empty
    assert!(!replica.to_string().is_empty());

    // List replicas - should include our new one
    let replicas = harness
        .node_a
        .sync_engine
        .docs()
        .list_replicas()
        .await
        .unwrap();

    assert!(!replicas.is_empty());
}

#[tokio::test]
async fn test_doc_set_and_get_bytes() {
    let harness = TestHarness::new().await.unwrap();

    // Create replica
    let replica = harness
        .node_a
        .sync_engine
        .docs()
        .create_replica()
        .await
        .unwrap();

    // Create author
    let author = harness
        .node_a
        .sync_engine
        .docs()
        .create_author()
        .await
        .unwrap();

    // Set some data
    let key = "test_key";
    let value = b"test_value";

    let content_hash = harness
        .node_a
        .sync_engine
        .docs()
        .set_bytes(replica, author, key, &value[..])
        .await
        .unwrap();

    // Get it back via the entry
    let entry_opt = harness
        .node_a
        .sync_engine
        .docs()
        .get_latest(replica, key)
        .await
        .unwrap();

    assert!(entry_opt.is_some());
    let entry = entry_opt.unwrap();

    // Get content hash from entry
    let retrieved_hash = harness.node_a.sync_engine.docs().entry_content_hash(&entry);

    // Hashes should match
    assert_eq!(content_hash, retrieved_hash);

    // Read the blob content
    let retrieved_content = harness
        .node_a
        .sync_engine
        .blobs()
        .read_to_bytes(retrieved_hash)
        .await
        .unwrap();

    assert_eq!(&retrieved_content[..], value);
}

#[tokio::test]
async fn test_doc_ticket_creation() {
    let harness = TestHarness::new().await.unwrap();

    // Create replica
    let replica = harness
        .node_a
        .sync_engine
        .docs()
        .create_replica()
        .await
        .unwrap();

    // Create doc ticket
    let ticket = harness
        .node_a
        .sync_engine
        .docs()
        .create_ticket(replica, harness.node_a_addr().clone())
        .await
        .unwrap();

    // Verify ticket is non-empty
    assert!(!ticket.to_string().is_empty());
}

#[tokio::test]
async fn test_multiple_doc_replicas() {
    let harness = TestHarness::new().await.unwrap();

    // Create multiple replicas
    let replica1 = harness
        .node_a
        .sync_engine
        .docs()
        .create_replica()
        .await
        .unwrap();

    let replica2 = harness
        .node_a
        .sync_engine
        .docs()
        .create_replica()
        .await
        .unwrap();

    // They should be different
    assert_ne!(replica1, replica2);

    // Both should be listable
    let replicas = harness
        .node_a
        .sync_engine
        .docs()
        .list_replicas()
        .await
        .unwrap();

    assert!(replicas.len() >= 2);
}

#[tokio::test]
async fn test_node_sync_engines_independent() {
    let harness = TestHarness::new().await.unwrap();

    // Node A adds a blob
    let data_a = b"Node A data";
    let hash_a = harness
        .node_a
        .sync_engine
        .blobs()
        .add_bytes(&data_a[..])
        .await
        .unwrap();

    // Node B adds a different blob
    let data_b = b"Node B data - different content";
    let hash_b = harness
        .node_b
        .sync_engine
        .blobs()
        .add_bytes(&data_b[..])
        .await
        .unwrap();

    // Hashes should be different
    assert_ne!(hash_a, hash_b);

    // Node A should have its blob
    assert!(harness.node_a.sync_engine.blobs().has_blob(hash_a).await);

    // Node B should have its blob
    assert!(harness.node_b.sync_engine.blobs().has_blob(hash_b).await);

    // Node A should NOT have Node B's blob (no sync yet)
    assert!(!harness.node_a.sync_engine.blobs().has_blob(hash_b).await);

    // Node B should NOT have Node A's blob (no sync yet)
    assert!(!harness.node_b.sync_engine.blobs().has_blob(hash_a).await);
}
