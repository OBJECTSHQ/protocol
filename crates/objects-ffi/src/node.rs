//! ObjectsNode — the primary FFI entry point.
//!
//! Wraps [`NodeService`] and [`NodeApi`] behind a uniffi-exported `Object`.
//! The constructor starts a full in-process OBJECTS node (endpoint, discovery,
//! sync engine, vault) and returns a handle. Async methods delegate to
//! [`NodeApi`] which communicates with the engine actor over an irpc channel.

use std::path::Path;
use std::sync::Arc;

use objects_core::node_api::NodeApi;
use objects_core::service::NodeService;
use objects_core::{NodeConfig, NodeState};
use tokio::sync::watch;

use crate::error::SdkError;
use crate::types::{
    AssetContent, AssetInfo, HealthInfo, IdentityInfo, PeerConnectionInfo, ProjectInfo, StatusInfo,
    VaultEntryInfo, assets_from, peers_from, projects_from, vault_entries_from,
};

/// An in-process OBJECTS Protocol node.
///
/// Kotlin: `val node = ObjectsNode.start("/path/to/data")`
/// Swift:  `let node = try ObjectsNode.start(dataDir: "/path/to/data")`
///
/// The node runs its own tokio runtime and background tasks. Call [`shutdown`]
/// when done to release resources cleanly.
#[derive(uniffi::Object)]
pub struct ObjectsNode {
    /// Kept alive to sustain background tasks spawned during node startup.
    #[allow(dead_code)]
    runtime: Arc<tokio::runtime::Runtime>,
    api: NodeApi,
    shutdown_tx: watch::Sender<bool>,
}

#[uniffi::export]
impl ObjectsNode {
    /// Start an in-process OBJECTS node.
    ///
    /// Creates the data directory if it does not exist, loads or generates
    /// a node keypair, connects to the relay, joins the discovery topic,
    /// and initializes the sync engine.
    ///
    /// The `data_dir` is the root directory for all node data (config, keys,
    /// blob storage). Equivalent to `~/.objects` for the CLI daemon.
    #[uniffi::constructor]
    pub fn start(data_dir: String) -> Result<Arc<Self>, SdkError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| SdkError::Internal {
                message: format!("failed to create tokio runtime: {e}"),
            })?;

        let (api, shutdown_tx) = runtime.block_on(async { start_node(&data_dir).await })?;

        Ok(Arc::new(Self {
            runtime: Arc::new(runtime),
            api,
            shutdown_tx,
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
    /// Stops discovery, closes connections, and releases resources.
    /// After calling this, the node cannot be used again.
    pub fn shutdown(&self) -> Result<(), SdkError> {
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }
}

/// Internal: starts the full node and returns the API client + shutdown handle.
async fn start_node(data_dir: &str) -> Result<(NodeApi, watch::Sender<bool>), SdkError> {
    // Ensure data directory exists
    std::fs::create_dir_all(data_dir).map_err(|e| SdkError::Internal {
        message: format!("failed to create data directory: {e}"),
    })?;

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

    // Run the service event loop in the background
    tokio::spawn(async move {
        if let Err(e) = service.run().await {
            tracing::error!("Node service error: {e}");
        }
    });

    Ok((api, shutdown_tx))
}
