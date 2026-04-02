//! E2E tests for the NodeEngine irpc actor.
//!
//! These tests exercise the full engine via its [`NodeApi`] client,
//! validating every RPC operation through the irpc channel layer.

use std::sync::{Arc, RwLock};

use objects_core::api::handlers::{AppState, NodeInfo};
use objects_core::api::registry::RegistryClient;
use objects_core::engine::NodeEngine;
use objects_core::node_api::{NodeApi, NodeApiError};
use objects_core::rpc::proto::RpcError;
use objects_core::state::IdentityInfo;
use objects_core::{NodeConfig, NodeState};
use objects_identity::{Handle, IdentityId};
use objects_sync::SyncEngine;
use objects_sync::storage::StorageConfig;
use objects_transport::discovery::{DiscoveryConfig, GossipDiscovery};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// ============================================================================
// Test helpers
// ============================================================================

/// Core helper: build and spawn a NodeEngine, optionally setting a test identity.
async fn spawn_engine_inner(with_identity: bool) -> (JoinHandle<()>, NodeApi, TempDir) {
    let temp = TempDir::new().expect("failed to create temp dir");

    // Transport
    let endpoint = objects_test_utils::transport::endpoint().await;
    let endpoint_arc = Arc::new(endpoint);

    // Gossip + discovery
    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint_arc.inner().clone());
    let discovery = GossipDiscovery::new(
        gossip,
        endpoint_arc.clone(),
        vec![],
        DiscoveryConfig::devnet(),
    )
    .await
    .expect("failed to create discovery");

    // Node state
    let node_state = Arc::new(RwLock::new(NodeState::generate_new()));

    if with_identity {
        let nonce = [1u8; 8];
        let public_key = [2u8; 32];
        let identity_id = IdentityId::derive(&public_key, &nonce);
        let handle = Handle::parse("testuser").expect("valid handle");
        let identity = IdentityInfo::new(identity_id, handle, nonce);
        node_state.write().unwrap().set_identity(identity);
    }

    // Config
    let mut config = NodeConfig::default();
    config.node.data_dir = temp.path().to_string_lossy().into_owned();

    let registry_client = RegistryClient::new(&config);

    // Sync engine (persistent storage under temp dir)
    let storage_config = StorageConfig::from_base_dir(temp.path());
    let sync_engine = SyncEngine::with_storage(endpoint_arc.inner(), &storage_config)
        .await
        .expect("failed to create sync engine")
        .spawn();

    let node_info = Arc::new(NodeInfo {
        node_id: endpoint_arc.node_id(),
        node_addr: endpoint_arc.node_addr(),
    });

    let app_state = AppState {
        node_info,
        discovery: Arc::new(Mutex::new(discovery)),
        node_state,
        config,
        registry_client,
        sync_engine,
        endpoint: endpoint_arc,
    };

    let (handle, api) = NodeEngine::spawn(app_state);
    (handle, api, temp)
}

/// Spawn a test engine without an identity (anonymous mode).
async fn spawn_test_engine() -> (JoinHandle<()>, NodeApi, TempDir) {
    spawn_engine_inner(false).await
}

/// Spawn a test engine with a pre-set test identity.
async fn spawn_test_engine_with_identity() -> (JoinHandle<()>, NodeApi, TempDir) {
    spawn_engine_inner(true).await
}

// ============================================================================
// Health & status
// ============================================================================

#[tokio::test]
async fn test_health() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let resp = api.health().await.unwrap();
    assert_eq!(resp.status, "ok");
}

#[tokio::test]
async fn test_status_no_identity() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let resp = api.status().await.unwrap();

    assert!(!resp.node_id.is_empty());
    assert_eq!(resp.peer_count, 0);
    assert!(resp.identity.is_none());
}

// ============================================================================
// Identity
// ============================================================================

#[tokio::test]
async fn test_get_identity_not_found() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let result = api.get_identity().await;
    assert!(
        matches!(result, Err(NodeApiError::Rpc(RpcError::NotFound(_)))),
        "expected NotFound, got: {result:?}"
    );
}

// ============================================================================
// Peers
// ============================================================================

#[tokio::test]
async fn test_list_peers_empty() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let resp = api.list_peers().await.unwrap();
    assert!(resp.peers.is_empty());
}

// ============================================================================
// Projects
// ============================================================================

#[tokio::test]
async fn test_list_projects_empty() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let resp = api.list_projects().await.unwrap();
    assert!(resp.projects.is_empty());
}

#[tokio::test]
async fn test_create_project() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("Test", None).await.unwrap();

    assert_eq!(project.id.len(), 64);
    assert!(project.id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(project.name, "Test");
}

#[tokio::test]
async fn test_create_project_with_desc() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("P", Some("desc")).await.unwrap();

    assert_eq!(project.description, Some("desc".to_owned()));
}

#[tokio::test]
async fn test_create_project_empty_name() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let result = api.create_project("", None).await;
    assert!(
        matches!(result, Err(NodeApiError::Rpc(RpcError::BadRequest(_)))),
        "expected BadRequest, got: {result:?}"
    );
}

#[tokio::test]
async fn test_list_projects_after_create() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;

    api.create_project("Alpha", None).await.unwrap();
    api.create_project("Beta", None).await.unwrap();

    let resp = api.list_projects().await.unwrap();
    assert_eq!(resp.projects.len(), 2);
}

#[tokio::test]
async fn test_get_project_by_id() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let created = api.create_project("Lookup", None).await.unwrap();
    let fetched = api.get_project(&created.id).await.unwrap();

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.name, "Lookup");
}

#[tokio::test]
async fn test_get_project_not_found() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let result = api.get_project(&"a".repeat(64)).await;
    assert!(
        matches!(result, Err(NodeApiError::Rpc(RpcError::NotFound(_)))),
        "expected NotFound, got: {result:?}"
    );
}

// ============================================================================
// Tickets
// ============================================================================

#[tokio::test]
async fn test_create_ticket() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("Ticketed", None).await.unwrap();
    let ticket = api.create_ticket(&project.id).await.unwrap();

    assert!(!ticket.ticket.is_empty());
}

// ============================================================================
// Assets
// ============================================================================

#[tokio::test]
async fn test_list_assets_empty() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("Empty Assets", None).await.unwrap();
    let resp = api.list_assets(&project.id).await.unwrap();
    assert!(resp.assets.is_empty());
}

// ============================================================================
// Vault
// ============================================================================

#[tokio::test]
async fn test_list_vault_no_identity() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let result = api.list_vault().await;
    assert!(
        matches!(result, Err(NodeApiError::Rpc(RpcError::BadRequest(_)))),
        "expected BadRequest, got: {result:?}"
    );
}

#[tokio::test]
async fn test_sync_vault() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let resp = api.sync_vault().await.unwrap();
    assert_eq!(resp.status, "synced");
}

#[tokio::test]
async fn test_pull_vault_project() {
    let (_h, api, _tmp) = spawn_test_engine().await;
    let resp = api.pull_vault_project("abc").await.unwrap();
    assert_eq!(resp.status, "pulled");
}

// ============================================================================
// Assets
// ============================================================================

#[tokio::test]
async fn test_add_asset() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("Asset Test", None).await.unwrap();

    let data = b"hello world asset content";
    let resp = api
        .add_asset(
            &project.id,
            "test.txt",
            "text/plain",
            bytes::Bytes::from_static(data),
        )
        .await
        .unwrap();

    assert_eq!(resp.filename, "test.txt");
    assert_eq!(resp.content_type, "text/plain");
    assert_eq!(resp.size, data.len() as u64);
    assert!(!resp.id.is_empty());
}

#[tokio::test]
async fn test_add_asset_then_list() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("List Test", None).await.unwrap();

    api.add_asset(&project.id, "a.txt", "text/plain", b"aaa"[..].into())
        .await
        .unwrap();
    api.add_asset(&project.id, "b.txt", "text/plain", b"bbb"[..].into())
        .await
        .unwrap();

    let assets = api.list_assets(&project.id).await.unwrap();
    assert_eq!(assets.assets.len(), 2);
}

#[tokio::test]
async fn test_get_asset_content() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("Content Test", None).await.unwrap();

    let original = b"the quick brown fox jumps over the lazy dog";
    let asset = api
        .add_asset(&project.id, "fox.txt", "text/plain", original[..].into())
        .await
        .unwrap();

    let (content_type, downloaded) = api.get_asset_content(&project.id, &asset.id).await.unwrap();

    assert_eq!(content_type, "text/plain");
    assert_eq!(downloaded, original);
}

#[tokio::test]
async fn test_get_asset_content_large() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("Large Test", None).await.unwrap();

    // 256 KiB — forces multiple 64 KiB chunks
    let original = vec![0xABu8; 256 * 1024];
    let asset = api
        .add_asset(
            &project.id,
            "large.bin",
            "application/octet-stream",
            original.clone().into(),
        )
        .await
        .unwrap();

    let (_, downloaded) = api.get_asset_content(&project.id, &asset.id).await.unwrap();

    assert_eq!(downloaded.len(), original.len());
    assert_eq!(downloaded, original);
}

#[tokio::test]
async fn test_get_asset_content_not_found() {
    let (_h, api, _tmp) = spawn_test_engine_with_identity().await;
    let project = api.create_project("NF Test", None).await.unwrap();

    let result = api.get_asset_content(&project.id, "nonexistent").await;
    assert!(
        matches!(result, Err(NodeApiError::Rpc(RpcError::NotFound(_)))),
        "expected NotFound, got: {result:?}"
    );
}
