//! E2E tests for identity lifecycle operations against a real registry.
//!
//! These tests require the registry Docker container to be running:
//!
//! ```bash
//! docker compose -f docker/test-compose.yml up -d
//! ```
//!
//! The tests discover the registry's mapped host port via `docker compose port`.
//! If Docker is not available or the container is not running, all tests are skipped.

use std::sync::{Arc, RwLock};

use objects_core::api::handlers::{AppState, NodeInfo};
use objects_core::api::registry::RegistryClient;
use objects_core::engine::NodeEngine;
use objects_core::node_api::{NodeApi, NodeApiError};
use objects_core::rpc::proto::RpcError;
use objects_core::{NodeConfig, NodeState};
use objects_sync::SyncEngine;
use objects_sync::storage::StorageConfig;
use objects_transport::discovery::{DiscoveryConfig, GossipDiscovery};
use rand::Rng;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// ============================================================================
// Docker helpers
// ============================================================================

/// Try to discover the registry's host port from Docker Compose.
///
/// Returns `None` if Docker is not available or the container is not running.
fn registry_url() -> Option<String> {
    let output = std::process::Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker/test-compose.yml",
            "port",
            "registry",
            "8080",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let host_port = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if host_port.is_empty() {
        return None;
    }

    // `docker compose port` returns e.g. "0.0.0.0:55123" — rewrite to localhost
    let port = host_port.rsplit_once(':')?.1;
    Some(format!("http://localhost:{port}"))
}

/// Macro that skips the test when the Docker registry is unavailable.
macro_rules! require_registry {
    () => {
        match registry_url() {
            Some(url) => url,
            None => {
                eprintln!("SKIP: Docker registry not running (docker compose -f docker/test-compose.yml up -d)");
                return;
            }
        }
    };
}

// ============================================================================
// Test helpers
// ============================================================================

/// Generate a random handle suffix to avoid collisions between test runs.
fn random_handle(prefix: &str) -> String {
    let suffix: u32 = rand::rng().random_range(100_000..999_999);
    format!("{prefix}{suffix}")
}

/// Spawn a NodeEngine pointing at the real Docker registry.
///
/// Returns `(engine_handle, api, _temp_dir)`. Keep the TempDir alive
/// for the duration of the test.
async fn spawn_test_engine(registry_url: &str) -> (JoinHandle<()>, NodeApi, TempDir) {
    let temp = TempDir::new().expect("failed to create temp dir");

    let endpoint = objects_test_utils::transport::endpoint().await;
    let endpoint_arc = Arc::new(endpoint);

    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint_arc.inner().clone());
    let discovery = GossipDiscovery::new(
        gossip,
        endpoint_arc.clone(),
        vec![],
        DiscoveryConfig::devnet(),
    )
    .await
    .expect("failed to create discovery");

    let node_state = Arc::new(RwLock::new(NodeState::generate_new()));

    let mut config = NodeConfig::default();
    config.node.data_dir = temp.path().to_string_lossy().into_owned();
    config.identity.registry_url = registry_url.to_string();

    let registry_client = RegistryClient::new(&config);

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

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn test_create_identity() {
    let url = require_registry!();
    let (_h, api, _tmp) = spawn_test_engine(&url).await;

    let handle = random_handle("alice");
    let identity = api
        .create_identity(&handle)
        .await
        .expect("create_identity should succeed");

    assert!(identity.id.starts_with("obj_"), "id = {}", identity.id);
    assert!(!identity.nonce.is_empty());
    assert_eq!(identity.handle, handle);
}

#[tokio::test]
async fn test_duplicate_handle() {
    let url = require_registry!();
    let handle = random_handle("dupetest");

    // First creation succeeds
    let (_h1, api1, _tmp1) = spawn_test_engine(&url).await;
    api1.create_identity(&handle)
        .await
        .expect("first create should succeed");

    // Second creation with the same handle fails
    let (_h2, api2, _tmp2) = spawn_test_engine(&url).await;
    let result = api2.create_identity(&handle).await;
    assert!(
        matches!(result, Err(NodeApiError::Rpc(RpcError::Registry(_)))),
        "expected Registry error for duplicate handle, got: {result:?}"
    );
}

#[tokio::test]
async fn test_rename_identity() {
    let url = require_registry!();
    let (_h, api, _tmp) = spawn_test_engine(&url).await;

    let old_handle = random_handle("rename");
    let identity = api
        .create_identity(&old_handle)
        .await
        .expect("create should succeed");

    let new_handle = random_handle("renamed");
    let renamed = api
        .rename_identity(&new_handle)
        .await
        .expect("rename should succeed");

    assert_eq!(renamed.id, identity.id, "id must not change after rename");
    assert_eq!(renamed.handle, new_handle);
}

#[tokio::test]
async fn test_get_identity_after_create() {
    let url = require_registry!();
    let (_h, api, _tmp) = spawn_test_engine(&url).await;

    let handle = random_handle("getme");
    let created = api
        .create_identity(&handle)
        .await
        .expect("create should succeed");

    let fetched = api
        .get_identity()
        .await
        .expect("get_identity should succeed after create");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.handle, created.handle);
}

#[tokio::test]
async fn test_list_vault_after_identity() {
    let url = require_registry!();
    let (_h, api, _tmp) = spawn_test_engine(&url).await;

    let handle = random_handle("vault");
    api.create_identity(&handle)
        .await
        .expect("create should succeed");

    // After identity creation the vault replica should exist (empty catalog)
    let vault = api
        .list_vault()
        .await
        .expect("list_vault should succeed after identity");

    assert!(
        vault.entries.is_empty(),
        "vault should be empty right after identity creation"
    );
}
