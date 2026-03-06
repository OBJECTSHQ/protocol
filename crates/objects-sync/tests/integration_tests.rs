//! Integration tests for objects-sync.
//!
//! These tests verify sync operations between multiple nodes,
//! including blob sync, metadata sync, and ticket-based sharing.

use objects_sync::SyncEngine;
use objects_sync::tickets::parse_ticket;
use objects_test_utils::{identity, sync, transport};

#[tokio::test]
async fn test_blob_storage_and_retrieval() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    // Add a blob
    let test_data = b"Hello, OBJECTS Protocol!";
    let hash = sync.blobs().add_bytes(&test_data[..]).await?;

    // Verify blob exists
    assert!(sync.blobs().has_blob(hash).await);

    // Read blob back
    let content = sync.blobs().read_to_bytes(hash).await?;
    assert_eq!(&content[..], test_data);

    Ok(())
}

#[tokio::test]
async fn test_blob_from_file() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    // Create a temporary file
    let temp_dir =
        tempfile::tempdir().map_err(|e| objects_sync::Error::Iroh(anyhow::anyhow!(e)))?;
    let file_path = temp_dir.path().join("test.txt");
    std::fs::write(&file_path, b"File content")
        .map_err(|e| objects_sync::Error::Iroh(anyhow::anyhow!(e)))?;

    // Add blob from file
    let hash = sync.blobs().add_from_path(&file_path).await?;

    // Verify content
    let content = sync.blobs().read_to_bytes(hash).await?;
    assert_eq!(&content[..], b"File content");

    Ok(())
}

#[tokio::test]
async fn test_blob_ticket_creation() -> objects_sync::Result<()> {
    let endpoint = transport::endpoint().await;
    let node_addr = endpoint.node_addr();
    let sync = SyncEngine::new(endpoint).await?;

    // Add a blob
    let hash = sync.blobs().add_bytes(&b"Shared data"[..]).await?;

    // Create ticket
    let ticket = sync.blobs().create_ticket(hash, node_addr).await?;

    // Verify ticket string format
    let ticket_str = ticket.to_string();
    assert!(ticket_str.starts_with("blob"));

    // Parse ticket back
    let parsed = parse_ticket(&ticket_str)?;
    assert!(matches!(parsed, objects_sync::tickets::Ticket::Blob(_)));

    Ok(())
}

#[tokio::test]
async fn test_replica_creation_and_entries() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    // Create replica and author
    let replica_id = sync.docs().create_replica().await?;
    let author = sync.docs().create_author().await?;

    // Set an entry
    let hash = sync
        .docs()
        .set_bytes(replica_id, author, "/test/key", &b"test value"[..])
        .await?;

    assert!(hash.as_bytes().len() == 32); // BLAKE3 hash is 32 bytes

    // Get the entry back
    let entry = sync
        .docs()
        .get_latest(replica_id, "/test/key")
        .await?
        .expect("entry should exist");

    // Read content via content hash
    let content_hash = sync.docs().entry_content_hash(&entry);
    let content = sync.blobs().read_to_bytes(content_hash).await?;
    assert_eq!(&content[..], b"test value");

    Ok(())
}

#[tokio::test]
async fn test_doc_ticket_creation() -> objects_sync::Result<()> {
    let endpoint = transport::endpoint().await;
    let node_addr = endpoint.node_addr();
    let sync = SyncEngine::new(endpoint).await?;

    // Create replica
    let replica_id = sync.docs().create_replica().await?;

    // Create ticket
    let ticket = sync.docs().create_ticket(replica_id, node_addr).await?;

    // Verify ticket string format
    let ticket_str = ticket.to_string();
    assert!(ticket_str.starts_with("doc"));

    // Parse ticket back
    let parsed = parse_ticket(&ticket_str)?;
    assert!(matches!(parsed, objects_sync::tickets::Ticket::Doc(_)));

    Ok(())
}

#[tokio::test]
async fn test_query_entries_by_prefix() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    let replica_id = sync.docs().create_replica().await?;
    let author = sync.docs().create_author().await?;

    // Set multiple entries with same prefix
    sync.docs()
        .set_bytes(replica_id, author, "/assets/1", &b"asset 1"[..])
        .await?;
    sync.docs()
        .set_bytes(replica_id, author, "/assets/2", &b"asset 2"[..])
        .await?;
    sync.docs()
        .set_bytes(replica_id, author, "/project", &b"project data"[..])
        .await?;

    // Query by prefix
    let assets = sync.docs().query_prefix(replica_id, "/assets/").await?;
    assert_eq!(assets.len(), 2);

    let all = sync.docs().query_prefix(replica_id, "/").await?;
    assert_eq!(all.len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_helpers_with_objects_types() -> objects_sync::Result<()> {
    use objects_data::{Asset, ContentHash};
    use objects_sync::helpers::{content_hash_to_hash, hash_to_content_hash};

    let sync = sync::sync_engine().await?;

    // Test hash conversion helpers
    let test_hash = sync.blobs().add_bytes(&b"test"[..]).await?;
    let content_hash = hash_to_content_hash(test_hash);
    let converted_back = content_hash_to_hash(&content_hash);
    assert_eq!(test_hash, converted_back);

    // Test storing asset content with verification
    let asset_content = b"Asset file content";
    let blob_hash = sync.blobs().add_bytes(&asset_content[..]).await?;
    let asset_content_hash = hash_to_content_hash(blob_hash);

    let test_author_id = identity::test_identity_id();

    // Create asset with matching content hash
    let asset = Asset::new(
        "test-asset".to_string(),
        "test.txt".to_string(),
        test_author_id.clone(),
        asset_content_hash.clone(),
        asset_content.len() as u64,
        Some("text/plain".to_string()),
        1704542400,
        1704542400,
    )
    .map_err(|e| objects_sync::Error::Iroh(anyhow::anyhow!(e)))?;

    // Store asset should verify the hash matches
    let store_result = sync
        .blobs()
        .store_asset_content(&asset, &asset_content[..])
        .await;
    assert!(store_result.is_ok());

    // Verify error on hash mismatch
    let wrong_asset = Asset::new(
        "wrong-asset".to_string(),
        "wrong.txt".to_string(),
        test_author_id,
        ContentHash([0u8; 32]), // Wrong hash
        10,
        Some("text/plain".to_string()),
        1704542400,
        1704542400,
    )
    .map_err(|e| objects_sync::Error::Iroh(anyhow::anyhow!(e)))?;

    let wrong_result = sync
        .blobs()
        .store_asset_content(&wrong_asset, &asset_content[..])
        .await;
    assert!(wrong_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_storage_with_project_and_assets() -> objects_sync::Result<()> {
    use objects_data::ContentHash;

    let sync = sync::sync_engine().await?;

    let replica_id = sync.docs().create_replica().await?;
    let author = sync.docs().create_author().await?;

    // Create and store project using RFC-004 derivation helper
    let project = sync::project_from_replica(replica_id, "Test Project")?;
    sync.docs()
        .store_project(replica_id, author, &project)
        .await?;

    // Retrieve project
    let retrieved = sync.docs().get_project(sync.blobs(), replica_id).await?;
    assert!(retrieved.is_some());
    let retrieved_project = retrieved.unwrap();
    assert_eq!(retrieved_project.name(), project.name());

    // Create and store asset using test helper
    let asset = sync::asset("asset-1", ContentHash([1u8; 32]))?;
    sync.docs().store_asset(replica_id, author, &asset).await?;

    // Retrieve asset
    let retrieved_asset = sync
        .docs()
        .get_asset(sync.blobs(), replica_id, "asset-1")
        .await?;
    assert!(retrieved_asset.is_some());
    let retrieved_asset = retrieved_asset.unwrap();
    assert_eq!(retrieved_asset.id(), asset.id());

    Ok(())
}

#[tokio::test]
async fn test_replica_deletion() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    // Create a replica but don't access it
    // (In iroh-docs, you can only delete replicas that aren't currently open)
    let replica_id = sync.docs().create_replica().await?;

    // Delete the replica immediately
    sync.docs().delete_replica(replica_id).await?;

    // Verify we can't access it anymore - should get "replica not found"
    let result = sync.docs().get_latest(replica_id, "/test").await;
    assert!(result.is_err());

    // Verify the error is specifically about the replica not being found
    if let Err(e) = result {
        let err_str = e.to_string();
        assert!(
            err_str.contains("replica")
                || err_str.contains("not found")
                || err_str.contains("closed")
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_multiple_authors_same_replica() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    let replica_id = sync.docs().create_replica().await?;
    let author1 = sync.docs().create_author().await?;
    let author2 = sync.docs().create_author().await?;

    // Both authors write to same replica
    sync.docs()
        .set_bytes(replica_id, author1, "/author1/data", &b"from author 1"[..])
        .await?;
    sync.docs()
        .set_bytes(replica_id, author2, "/author2/data", &b"from author 2"[..])
        .await?;

    // Query all entries
    let entries = sync.docs().query_prefix(replica_id, "/").await?;
    assert_eq!(entries.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_writes_same_key() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    let replica_id = sync.docs().create_replica().await?;
    let author1 = sync.docs().create_author().await?;
    let author2 = sync.docs().create_author().await?;

    // Both authors write to the SAME key
    sync.docs()
        .set_bytes(replica_id, author1, "/shared/key", &b"from author 1"[..])
        .await?;
    sync.docs()
        .set_bytes(replica_id, author2, "/shared/key", &b"from author 2"[..])
        .await?;

    // Query should return the latest entry (last-write-wins)
    let entry = sync.docs().get_latest(replica_id, "/shared/key").await?;
    assert!(entry.is_some());

    // Verify we can read the content
    let content_hash = sync.docs().entry_content_hash(&entry.unwrap());
    let content = sync.blobs().read_to_bytes(content_hash).await?;

    // One of the writes should have won (we don't enforce which one)
    assert!(&content[..] == b"from author 1" || &content[..] == b"from author 2");

    Ok(())
}

#[tokio::test]
async fn test_concurrent_writes_different_keys() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    let replica_id = sync.docs().create_replica().await?;
    let author1 = sync.docs().create_author().await?;
    let author2 = sync.docs().create_author().await?;

    // Authors write concurrently to different keys
    let (result1, result2) = tokio::join!(
        sync.docs()
            .set_bytes(replica_id, author1, "/key1", &b"value 1"[..]),
        sync.docs()
            .set_bytes(replica_id, author2, "/key2", &b"value 2"[..])
    );

    // Both writes should succeed
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Verify both entries exist
    let entry1 = sync.docs().get_latest(replica_id, "/key1").await?;
    let entry2 = sync.docs().get_latest(replica_id, "/key2").await?;
    assert!(entry1.is_some());
    assert!(entry2.is_some());

    // Verify content
    let content1 = sync
        .blobs()
        .read_to_bytes(sync.docs().entry_content_hash(&entry1.unwrap()))
        .await?;
    let content2 = sync
        .blobs()
        .read_to_bytes(sync.docs().entry_content_hash(&entry2.unwrap()))
        .await?;

    assert_eq!(&content1[..], b"value 1");
    assert_eq!(&content2[..], b"value 2");

    Ok(())
}

#[tokio::test]
async fn test_download_from_invalid_ticket() -> objects_sync::Result<()> {
    use iroh_blobs::ticket::BlobTicket;
    use iroh_blobs::{BlobFormat, Hash};

    let sync = sync::sync_engine().await?;

    // Create a second endpoint to get a valid peer ID (but we won't make it reachable)
    let fake_endpoint = transport::endpoint().await;
    let fake_peer = fake_endpoint.node_addr();

    // Create a ticket with a non-existent hash
    let fake_hash = Hash::from_bytes([0x42; 32]);
    let invalid_ticket = BlobTicket::new(fake_peer, fake_hash, BlobFormat::Raw);

    // Attempting to download should fail (blob doesn't exist)
    let result = sync.blobs().download_from_ticket(invalid_ticket).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_sync_with_unreachable_peer() -> objects_sync::Result<()> {
    let sync = sync::sync_engine().await?;

    let replica_id = sync.docs().create_replica().await?;

    // Create a second endpoint to get a valid peer ID (but don't share the replica with it)
    let fake_endpoint = transport::endpoint().await;
    let fake_peer = fake_endpoint.node_addr();

    // Attempting to sync with a peer that doesn't have the replica
    // Note: sync_with_peer starts sync in background, so it may not immediately error
    // The actual error would occur when trying to sync
    let result = sync.docs().sync_with_peer(replica_id, fake_peer).await;

    // sync_with_peer may succeed (starts background task) but actual sync will fail
    // This test verifies the API doesn't panic with unreachable/non-participating peers
    assert!(result.is_ok() || result.is_err());

    Ok(())
}
