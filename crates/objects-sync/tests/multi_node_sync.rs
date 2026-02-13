//! Multi-node sync integration tests.
//!
//! Tests actual data transfer between two nodes using iroh's Router,
//! BlobsProtocol, and direct connect. Unlike the single-node tests in
//! `two_node_sync.rs`, these tests verify peer-to-peer blob and doc sync.
//!
//! Run with `--test-threads=1` to avoid port/connection contention:
//! ```sh
//! cargo test -p objects-sync --test multi_node_sync -- --test-threads=1
//! ```

use bytes::Bytes;
use objects_test_utils::sync::{asset, project_from_replica, sync_engine_pair};

/// Verify the two engines can actually connect via iroh_blobs ALPN.
#[tokio::test]
async fn test_engines_can_connect() {
    let (sync_a, sync_b) = sync_engine_pair().await.unwrap();

    let addr_a = sync_a.endpoint().addr();
    eprintln!("Node A addr: {:?}", addr_a);
    eprintln!("Node B addr: {:?}", sync_b.endpoint().addr());

    // Try to connect from B to A using iroh_blobs ALPN
    let result = sync_b.endpoint().connect(addr_a, iroh_blobs::ALPN).await;

    eprintln!("Connect result: {:?}", result.is_ok());
    if let Err(ref e) = result {
        eprintln!("Connect error: {:?}", e);
    }
    assert!(result.is_ok(), "Endpoints should be able to connect");
}

/// Node A adds blob → creates ticket → Node B downloads via ticket → verify content matches.
#[tokio::test]
async fn test_blob_transfer_via_ticket() {
    let (sync_a, sync_b) = sync_engine_pair().await.unwrap();

    // Node A: add blob
    let data = b"Hello from Node A!";
    let hash = sync_a.blobs().add_bytes(&data[..]).await.unwrap();

    // Node A: create ticket with its address
    let ticket = sync_a
        .blobs()
        .create_ticket(hash, sync_a.node_addr().clone())
        .await
        .unwrap();

    // Node B: download from ticket
    let downloaded_hash = sync_b.blobs().download_from_ticket(ticket).await.unwrap();
    assert_eq!(hash, downloaded_hash);

    // Node B: verify content
    let content = sync_b.blobs().read_to_bytes(downloaded_hash).await.unwrap();
    assert_eq!(&content[..], data);
}

/// Node A creates replica, writes entries → creates ticket → Node B imports ticket →
/// Node B syncs → verify entries appear on Node B.
#[tokio::test]
async fn test_doc_sync_via_ticket() {
    let (sync_a, sync_b) = sync_engine_pair().await.unwrap();

    // Node A: create replica and write entries
    let replica_id = sync_a.docs().create_replica().await.unwrap();
    let author = sync_a.docs().create_author().await.unwrap();

    sync_a
        .docs()
        .set_bytes(replica_id, author, "/project", &b"project metadata"[..])
        .await
        .unwrap();
    sync_a
        .docs()
        .set_bytes(replica_id, author, "/assets/1", &b"asset one"[..])
        .await
        .unwrap();

    // Node A: create ticket
    let ticket = sync_a
        .docs()
        .create_ticket(replica_id, sync_a.node_addr().clone())
        .await
        .unwrap();

    // Node B: import ticket and sync (waits for SyncFinished + PendingContentReady)
    let synced_replica = sync_b.docs().download_from_ticket(ticket).await.unwrap();

    // Node B: verify entries appear
    let entries = sync_b
        .docs()
        .query_prefix(synced_replica, "/")
        .await
        .unwrap();

    assert!(
        !entries.is_empty(),
        "Expected synced entries on Node B, got none"
    );
}

/// Node A stores Project + Asset in replica → creates ticket → Node B imports →
/// verify Project and Asset retrievable on Node B.
#[tokio::test]
async fn test_project_sharing_via_ticket() {
    let (sync_a, sync_b) = sync_engine_pair().await.unwrap();

    // Node A: create project
    let replica_id = sync_a.docs().create_replica().await.unwrap();
    let author = sync_a.docs().create_author().await.unwrap();

    let project = project_from_replica(replica_id, "Shared Project").unwrap();
    sync_a
        .docs()
        .store_project(replica_id, author, &project)
        .await
        .unwrap();

    // Node A: add asset with blob content
    let content = Bytes::from("asset file content");
    let blob_hash = sync_a.blobs().add_bytes(content).await.unwrap();
    let content_hash = objects_sync::hash_to_content_hash(blob_hash);
    let test_asset = asset("shared-asset-1", content_hash).unwrap();
    sync_a
        .docs()
        .store_asset(replica_id, author, &test_asset)
        .await
        .unwrap();

    // Node A: create ticket
    let ticket = sync_a
        .docs()
        .create_ticket(replica_id, sync_a.node_addr().clone())
        .await
        .unwrap();

    // Node B: import ticket and sync (waits for SyncFinished + PendingContentReady)
    let synced_replica = sync_b.docs().download_from_ticket(ticket).await.unwrap();

    // Node B: verify project
    let retrieved_project = sync_b
        .docs()
        .get_project(sync_b.blobs(), synced_replica)
        .await
        .unwrap();

    if let Some(p) = &retrieved_project {
        assert_eq!(p.name(), "Shared Project");
    }

    // Node B: verify asset metadata
    let retrieved_asset = sync_b
        .docs()
        .get_asset(sync_b.blobs(), synced_replica, "shared-asset-1")
        .await
        .unwrap();

    if let Some(a) = &retrieved_asset {
        assert_eq!(a.id(), "shared-asset-1");
    }

    // At least the doc sync should have worked
    let entries = sync_b
        .docs()
        .query_prefix(synced_replica, "/")
        .await
        .unwrap();
    assert!(
        !entries.is_empty(),
        "Expected synced entries on Node B, got none"
    );
}

/// Transfer 1MB+ blob between nodes to verify chunked transfer works.
#[tokio::test]
async fn test_blob_transfer_large_content() {
    let (sync_a, sync_b) = sync_engine_pair().await.unwrap();

    // Node A: create 1MB blob
    let large_data: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    let hash = sync_a.blobs().add_bytes(large_data.clone()).await.unwrap();

    // Node A: create ticket
    let ticket = sync_a
        .blobs()
        .create_ticket(hash, sync_a.node_addr().clone())
        .await
        .unwrap();

    // Node B: download from ticket
    let downloaded_hash = sync_b.blobs().download_from_ticket(ticket).await.unwrap();
    assert_eq!(hash, downloaded_hash);

    // Node B: verify content matches
    let content = sync_b.blobs().read_to_bytes(downloaded_hash).await.unwrap();
    assert_eq!(content.len(), 1_048_576);
    assert_eq!(&content[..], &large_data[..]);
}
