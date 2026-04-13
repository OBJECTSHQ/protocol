//! ObjectsNode — the primary FFI entry point.
//!
//! Wraps [`NodeService`] and [`NodeApi`] behind a uniffi-exported `Object`.
//!
//! **Connect-or-start:** `ObjectsNode::start(dataDir)` first tries to connect
//! to an already-running node (reading `node.api`). If none is healthy, it
//! acquires an exclusive lock and starts a full in-process node.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fs4::fs_std::FileExt;
use objects_core::node_api::NodeApi;
use objects_core::rpc::proto::{NODE_RPC_ALPN, NodeProtocol};
use objects_core::service::NodeService;
use objects_core::{NodeConfig, NodeState};
use objects_transport::{NodeAddr, ObjectsEndpoint};
use tokio::sync::watch;
use tracing::info;

use crate::error::SdkError;
use crate::types::{
    AssetContent, AssetInfo, HealthInfo, IdentityInfo, PeerConnectionInfo, ProjectInfo, StatusInfo,
    VaultEntryInfo, assets_from, peers_from, projects_from, vault_entries_from,
};

/// An OBJECTS Protocol node handle.
///
/// May be backed by a local in-process node (this app owns it) or a remote
/// connection to a node started by another app.
///
/// Kotlin: `val node = ObjectsNode.start("/path/to/data")`
/// Swift:  `let node = try ObjectsNode.start(dataDir: "/path/to/data")`
#[derive(uniffi::Object)]
pub struct ObjectsNode {
    /// Kept alive to sustain background tasks (local node or client endpoint).
    #[allow(dead_code)]
    runtime: Arc<tokio::runtime::Runtime>,
    api: NodeApi,
    /// Present only when we own the node (started it locally).
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Held to prevent other processes from starting a second node.
    /// Released on drop / shutdown.
    #[allow(dead_code)]
    _lock: Option<File>,
}

#[uniffi::export]
impl ObjectsNode {
    /// Connect to an existing node or start a new one.
    ///
    /// 1. Read `{data_dir}/node.api` and health-check the existing node.
    /// 2. If healthy → return a client connected to it (no local engine).
    /// 3. If not → acquire `{data_dir}/.node.lock`, start a full node,
    ///    write `node.api`, and return.
    #[uniffi::constructor]
    pub fn start(data_dir: String) -> Result<Arc<Self>, SdkError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| SdkError::Internal {
                message: format!("failed to create tokio runtime: {e}"),
            })?;

        let result = runtime.block_on(async { connect_or_start(&data_dir).await })?;

        Ok(Arc::new(Self {
            runtime: Arc::new(runtime),
            api: result.api,
            shutdown_tx: result.shutdown_tx,
            _lock: result.lock,
        }))
    }

    // =====================================================================
    // Health & Status
    // =====================================================================

    /// Check if the node is healthy.
    pub async fn health(&self) -> Result<HealthInfo, SdkError> {
        Ok(self.api.health().await?.into())
    }

    /// Get node status including identity and peer count.
    pub async fn status(&self) -> Result<StatusInfo, SdkError> {
        Ok(self.api.status().await?.into())
    }

    // =====================================================================
    // Identity
    // =====================================================================

    /// Register a new identity with the given handle.
    pub async fn create_identity(&self, handle: String) -> Result<IdentityInfo, SdkError> {
        Ok(self.api.create_identity(&handle).await?.into())
    }

    /// Get the current node's identity.
    pub async fn get_identity(&self) -> Result<IdentityInfo, SdkError> {
        Ok(self.api.get_identity().await?.into())
    }

    /// Rename the current identity.
    pub async fn rename_identity(&self, new_handle: String) -> Result<IdentityInfo, SdkError> {
        Ok(self.api.rename_identity(&new_handle).await?.into())
    }

    // =====================================================================
    // Peers
    // =====================================================================

    /// List discovered peers.
    pub async fn list_peers(&self) -> Result<Vec<PeerConnectionInfo>, SdkError> {
        Ok(peers_from(self.api.list_peers().await?))
    }

    // =====================================================================
    // Projects
    // =====================================================================

    /// List all local projects.
    pub async fn list_projects(&self) -> Result<Vec<ProjectInfo>, SdkError> {
        Ok(projects_from(self.api.list_projects().await?))
    }

    /// Create a new project.
    pub async fn create_project(
        &self,
        name: String,
        description: Option<String>,
    ) -> Result<ProjectInfo, SdkError> {
        Ok(self
            .api
            .create_project(&name, description.as_deref())
            .await?
            .into())
    }

    /// Get a project by ID.
    pub async fn get_project(&self, project_id: String) -> Result<ProjectInfo, SdkError> {
        Ok(self.api.get_project(&project_id).await?.into())
    }

    /// Update a project's name and/or description.
    pub async fn update_project(
        &self,
        project_id: String,
        name: Option<String>,
        description: Option<String>,
        clear_description: bool,
    ) -> Result<ProjectInfo, SdkError> {
        Ok(self
            .api
            .update_project(
                &project_id,
                name.as_deref(),
                description.as_deref(),
                clear_description,
            )
            .await?
            .into())
    }

    /// Delete a project and all associated data.
    pub async fn delete_project(&self, project_id: String) -> Result<(), SdkError> {
        self.api.delete_project(&project_id).await?;
        Ok(())
    }

    // =====================================================================
    // Assets
    // =====================================================================

    /// List assets in a project.
    pub async fn list_assets(&self, project_id: String) -> Result<Vec<AssetInfo>, SdkError> {
        Ok(assets_from(self.api.list_assets(&project_id).await?))
    }

    /// Upload an asset to a project.
    ///
    /// The entire file content is passed as `data`. Streaming is handled
    /// internally — the FFI layer does not expose the chunked protocol.
    pub async fn add_asset(
        &self,
        project_id: String,
        filename: String,
        content_type: String,
        data: Vec<u8>,
    ) -> Result<AssetInfo, SdkError> {
        Ok(self
            .api
            .add_asset(
                &project_id,
                &filename,
                &content_type,
                bytes::Bytes::from(data),
            )
            .await?
            .into())
    }

    /// Download asset content.
    ///
    /// Returns the content type and raw bytes. Streaming is handled
    /// internally — the full content is buffered before returning.
    pub async fn get_asset_content(
        &self,
        project_id: String,
        asset_id: String,
    ) -> Result<AssetContent, SdkError> {
        let (content_type, data) = self.api.get_asset_content(&project_id, &asset_id).await?;
        Ok(AssetContent { content_type, data })
    }

    // =====================================================================
    // Tickets
    // =====================================================================

    /// Create a share ticket for a project.
    pub async fn create_ticket(&self, project_id: String) -> Result<String, SdkError> {
        Ok(self.api.create_ticket(&project_id).await?.ticket)
    }

    /// Redeem a share ticket to join a project.
    pub async fn redeem_ticket(&self, ticket: String) -> Result<ProjectInfo, SdkError> {
        Ok(self.api.redeem_ticket(&ticket).await?.into())
    }

    // =====================================================================
    // Vault
    // =====================================================================

    /// List all projects in the vault catalog.
    pub async fn list_vault(&self) -> Result<Vec<VaultEntryInfo>, SdkError> {
        Ok(vault_entries_from(self.api.list_vault().await?))
    }

    /// Sync the vault catalog with remote peers.
    pub async fn sync_vault(&self) -> Result<String, SdkError> {
        Ok(self.api.sync_vault().await?.status)
    }

    /// Pull a specific project from the vault to local storage.
    pub async fn pull_vault_project(&self, project_id: String) -> Result<String, SdkError> {
        Ok(self.api.pull_vault_project(&project_id).await?.status)
    }

    // =====================================================================
    // Lifecycle
    // =====================================================================

    /// Shut down the node gracefully.
    ///
    /// If this app owns the node (started it), stops discovery, closes
    /// connections, and releases resources. If connected to another app's
    /// node, just drops the connection without affecting the shared node.
    pub fn shutdown(&self) -> Result<(), SdkError> {
        if let Some(ref tx) = self.shutdown_tx {
            let _ = tx.send(true);
        }
        Ok(())
    }
}

// =============================================================================
// Internal: connect-or-start logic
// =============================================================================

struct StartResult {
    api: NodeApi,
    shutdown_tx: Option<watch::Sender<bool>>,
    lock: Option<File>,
}

/// Try to connect to an existing node; if none is running, start one.
async fn connect_or_start(data_dir: &str) -> Result<StartResult, SdkError> {
    std::fs::create_dir_all(data_dir).map_err(|e| SdkError::Internal {
        message: format!("failed to create data directory: {e}"),
    })?;

    // Try connecting to an existing node first
    if let Some(api) = try_connect_existing(data_dir).await {
        info!("Connected to existing node via node.api");
        return Ok(StartResult {
            api,
            shutdown_tx: None,
            lock: None,
        });
    }

    // No healthy node found — acquire lock and start our own
    let lock = acquire_lock(data_dir)?;
    info!("No existing node found, starting new node");

    let (api, shutdown_tx) = start_node(data_dir).await?;

    Ok(StartResult {
        api,
        shutdown_tx: Some(shutdown_tx),
        lock: Some(lock),
    })
}

/// Try to connect to an already-running node by reading node.api.
async fn try_connect_existing(data_dir: &str) -> Option<NodeApi> {
    let api_path = Path::new(data_dir).join("node.api");
    let content = std::fs::read_to_string(&api_path).ok()?;
    let info: serde_json::Value = serde_json::from_str(&content).ok()?;
    let node_addr: NodeAddr = serde_json::from_value(info.get("node_addr")?.clone()).ok()?;

    // Lightweight endpoint — just for the QUIC client connection, no engine
    let endpoint = ObjectsEndpoint::builder().bind().await.ok()?;

    let client =
        irpc_iroh::client::<NodeProtocol>(endpoint.inner().clone(), node_addr, NODE_RPC_ALPN);
    let api = NodeApi::from_client(client);

    // Health check with timeout — if the node is dead, this fails fast
    match tokio::time::timeout(Duration::from_secs(2), api.health()).await {
        Ok(Ok(_)) => Some(api),
        _ => {
            info!("Existing node not healthy, will start a new one");
            None
        }
    }
}

/// Acquire an exclusive lock file to prevent multiple nodes on the same data dir.
fn acquire_lock(data_dir: &str) -> Result<File, SdkError> {
    let lock_path = Path::new(data_dir).join(".node.lock");
    let file = File::create(&lock_path).map_err(|e| SdkError::Internal {
        message: format!("failed to create lock file: {e}"),
    })?;
    file.try_lock_exclusive().map_err(|_| SdkError::Internal {
        message: "another node is starting up on this data directory".into(),
    })?;
    Ok(file)
}

/// Write node.api file so other apps (and CLI) can discover this node.
fn write_node_api(data_dir: &str, service: &NodeService) {
    let api_path = Path::new(data_dir).join("node.api");
    let info = serde_json::json!({
        "node_id": service.node_id().to_string(),
        "node_addr": service.node_addr(),
    });

    if let Err(e) = std::fs::write(&api_path, serde_json::to_string_pretty(&info).unwrap()) {
        tracing::warn!("Failed to write node.api: {e}");
    } else {
        info!("Node API info written to {}", api_path.display());
    }
}

/// Start a full in-process node and return the API client + shutdown handle.
async fn start_node(data_dir: &str) -> Result<(NodeApi, watch::Sender<bool>), SdkError> {
    // Load or create config
    let config_path = Path::new(data_dir).join("config.toml");
    let mut config = NodeConfig::load_or_create(&config_path).map_err(|e| SdkError::Internal {
        message: format!("failed to load config: {e}"),
    })?;
    config.node.data_dir = data_dir.to_string();

    // Load or create node state (keypair)
    let state_path = Path::new(data_dir).join("node.key");
    let state = NodeState::load_or_create(&state_path).map_err(|e| SdkError::Internal {
        message: format!("failed to load node state: {e}"),
    })?;

    // Start the full node service
    let service = NodeService::new(config, state)
        .await
        .map_err(|e| SdkError::Internal {
            message: format!("failed to start node service: {e}"),
        })?;

    let api = service.node_api().clone();
    let shutdown_tx = service.shutdown_trigger();

    // Write node.api so other apps can discover us
    write_node_api(data_dir, &service);

    // Run the service event loop in the background
    tokio::spawn(async move {
        if let Err(e) = service.run().await {
            tracing::error!("Node service error: {e}");
        }
    });

    Ok((api, shutdown_tx))
}
