//! Node engine — irpc server actor.
//!
//! Receives [`NodeCommand`] messages via an irpc channel and dispatches
//! to handler logic. This is the core of the embeddable node.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use tracing::info;

use crate::api::handlers::{AppState, format_elapsed};
use crate::api::registry;
use crate::api::types::{
    AssetListResponse, AssetResponse, CreateProjectRequest, HealthResponse, IdentityResponse,
    PeerInfo, ProjectListResponse, ProjectResponse, StatusResponse, TicketResponse, VaultEntry,
    VaultResponse,
};
use crate::rpc::proto::*;
use crate::state::IdentityInfo;
use objects_identity::{
    Ed25519SigningKey, Handle, IdentityId, generate_nonce,
    message::{change_handle_message, create_identity_message},
};
use objects_transport::discovery::Discovery;

/// The node engine — an actor that processes RPC requests.
///
/// Spawned via [`NodeEngine::spawn`], which returns a [`NodeApi`](crate::node_api::NodeApi)
/// for sending requests to the engine.
pub struct NodeEngine {
    state: AppState,
}

impl NodeEngine {
    /// Create a new engine from shared state.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Spawn the engine actor, returning a local API client.
    ///
    /// The engine runs in a background task, processing incoming
    /// [`NodeCommand`] messages until the sender is dropped.
    pub fn spawn(state: AppState) -> (tokio::task::JoinHandle<()>, crate::node_api::NodeApi) {
        let (tx, rx) = irpc::channel::mpsc::channel::<NodeCommand>(128);
        let engine = Self::new(state);
        let handle = tokio::spawn(engine.run(rx));
        let api = crate::node_api::NodeApi::local(tx);
        (handle, api)
    }

    /// Run the engine loop, processing commands until the channel closes.
    pub async fn run(self, mut rx: irpc::channel::mpsc::Receiver<NodeCommand>) {
        while let Ok(Some(cmd)) = rx.recv().await {
            self.dispatch(cmd).await;
        }
        info!("NodeEngine shutting down — channel closed");
    }

    /// Dispatch a single command to the appropriate handler.
    async fn dispatch(&self, cmd: NodeCommand) {
        match cmd {
            // --- Implemented handlers ---
            NodeCommand::Health(msg) => {
                let resp = self.handle_health();
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::Status(msg) => {
                let resp = self.handle_status().await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::GetIdentity(msg) => {
                let resp = self.handle_get_identity();
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::ListPeers(msg) => {
                let resp = self.handle_list_peers().await;
                msg.tx.send(resp).await.ok();
            }

            NodeCommand::CreateIdentity(msg) => {
                let resp = self.handle_create_identity(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::RenameIdentity(msg) => {
                let resp = self.handle_rename_identity(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }

            // --- Projects ---
            NodeCommand::ListProjects(msg) => {
                let resp = self.handle_list_projects().await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::CreateProject(msg) => {
                let resp = self.handle_create_project(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::GetProject(msg) => {
                let resp = self.handle_get_project(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }

            // --- Assets ---
            NodeCommand::ListAssets(msg) => {
                let resp = self.handle_list_assets(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::AddAsset(msg) => {
                let resp = self.handle_add_asset(msg.inner, msg.rx).await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::GetAssetContent(msg) => {
                self.handle_get_asset_content(msg.inner, msg.tx).await;
            }

            // --- Tickets ---
            NodeCommand::CreateTicket(msg) => {
                let resp = self.handle_create_ticket(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::RedeemTicket(msg) => {
                let resp = self.handle_redeem_ticket(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }

            // --- Vault ---
            NodeCommand::ListVault(msg) => {
                let resp = self.handle_list_vault().await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::SyncVault(msg) => {
                msg.tx
                    .send(Ok(SyncVaultResponse {
                        status: "synced".into(),
                    }))
                    .await
                    .ok();
            }
            NodeCommand::PullVaultProject(msg) => {
                let id = msg.inner.project_id.clone();
                msg.tx
                    .send(Ok(PullVaultResponse {
                        status: "pulled".into(),
                        project_id: id,
                    }))
                    .await
                    .ok();
            }
        }
    }

    // =========================================================================
    // Handler implementations
    // =========================================================================

    /// Persist node state to disk.
    fn save_state(&self, node_state: &crate::NodeState) -> Result<(), RpcError> {
        let state_path = Path::new(&self.state.config.node.data_dir).join("node.key");
        node_state
            .save(&state_path)
            .map_err(|e| RpcError::Internal(format!("Failed to save state: {e}")))
    }

    fn handle_health(&self) -> HealthResponse {
        HealthResponse {
            status: "ok".to_string(),
        }
    }

    async fn handle_status(&self) -> StatusResponse {
        let peer_count = self.state.discovery.lock().await.peer_count();

        let identity = self
            .state
            .node_state
            .read()
            .expect("node_state lock poisoned")
            .identity()
            .map(IdentityResponse::from);

        StatusResponse {
            node_id: self.state.node_info.node_id.to_string(),
            node_addr: self.state.node_info.node_addr.clone(),
            peer_count,
            identity,
            relay_url: self.state.config.network.relay_url.clone(),
        }
    }

    fn handle_get_identity(&self) -> Result<IdentityResponse, RpcError> {
        self.state
            .node_state
            .read()
            .expect("node_state lock poisoned")
            .identity()
            .map(IdentityResponse::from)
            .ok_or_else(|| RpcError::NotFound("No identity registered".into()))
    }

    async fn handle_create_identity(
        &self,
        req: CreateIdentityRpcRequest,
    ) -> Result<IdentityResponse, RpcError> {
        let handle = Handle::parse(&req.handle).map_err(|e| RpcError::BadRequest(e.to_string()))?;

        let signing_key = Ed25519SigningKey::generate();
        let public_key = signing_key.public_key_bytes();
        let nonce = generate_nonce();
        let identity_id = IdentityId::derive(&public_key, &nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RpcError::Internal(format!("System time error: {e}")))?
            .as_secs();

        let message = create_identity_message(identity_id.as_str(), handle.as_str(), timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let b64 = &base64::engine::general_purpose::STANDARD;
        let registry_request = registry::CreateIdentityRequest {
            handle: handle.to_string(),
            public_key: b64.encode(public_key),
            nonce: b64.encode(nonce),
            timestamp,
            signature: registry::SignatureData {
                signature: b64.encode(signature.signature_bytes()),
                public_key: b64.encode(signature.public_key_bytes()),
            },
        };

        let registry_response = self
            .state
            .registry_client
            .create_identity(registry_request)
            .await
            .map_err(|e| RpcError::Registry(e.to_string()))?;

        let identity_info = IdentityInfo::with_signing_key(
            IdentityId::parse(&registry_response.id)
                .map_err(|e| RpcError::Internal(format!("Invalid identity ID: {e}")))?,
            Handle::parse(&registry_response.handle)
                .map_err(|e| RpcError::Internal(format!("Invalid handle: {e}")))?,
            nonce,
            signing_key.to_bytes(),
        );

        // Create vault replica before persisting so we can save once
        let vault_namespace_id = if let Some(sk_bytes) = identity_info.signing_key() {
            let vault_keys = objects_identity::vault::VaultKeys::derive_from_signing_key(sk_bytes)
                .map_err(|e| RpcError::Internal(format!("Failed to derive vault keys: {e}")))?;

            self.state
                .sync_engine
                .docs()
                .create_replica_with_secret(vault_keys.namespace_secret().clone())
                .await
                .map_err(|e| RpcError::Internal(format!("Failed to create vault replica: {e}")))?;

            info!("Vault replica created: {}", vault_keys.namespace_id());
            Some(vault_keys.namespace_id().to_string())
        } else {
            None
        };

        // Persist identity + vault namespace in a single save
        {
            let mut node_state = self.state.node_state.write().unwrap();
            node_state.set_identity(identity_info.clone());
            if let Some(ns_id) = vault_namespace_id
                && let Some(identity) = node_state.identity_mut()
            {
                identity.set_vault_namespace_id(ns_id);
            }
            self.save_state(&node_state)?;
        }

        info!("Identity created: {}", identity_info.handle());

        Ok(IdentityResponse {
            id: registry_response.id,
            handle: registry_response.handle,
            nonce: b64.encode(nonce),
        })
    }

    async fn handle_rename_identity(
        &self,
        req: RenameIdentityRpcRequest,
    ) -> Result<IdentityResponse, RpcError> {
        let new_handle =
            Handle::parse(&req.new_handle).map_err(|e| RpcError::BadRequest(e.to_string()))?;

        let (identity_id, signing_key_bytes) = {
            let node_state = self.state.node_state.read().unwrap();
            let identity = node_state
                .identity()
                .ok_or_else(|| RpcError::BadRequest("No identity registered".into()))?;
            let signing_key = identity
                .signing_key()
                .ok_or_else(|| RpcError::Internal("No signing key available".into()))?;
            (identity.identity_id().clone(), *signing_key)
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RpcError::Internal(format!("System time error: {e}")))?
            .as_secs();

        let message = change_handle_message(identity_id.as_str(), new_handle.as_str(), timestamp);
        let signing_key = Ed25519SigningKey::from_bytes(&signing_key_bytes);
        let signature = signing_key.sign(message.as_bytes());

        let b64 = &base64::engine::general_purpose::STANDARD;
        let registry_request = serde_json::json!({
            "new_handle": new_handle.as_str(),
            "timestamp": timestamp,
            "signature": {
                "signature": b64.encode(signature.signature_bytes()),
                "public_key": b64.encode(signature.public_key_bytes()),
            }
        });

        self.state
            .registry_client
            .change_handle(identity_id.as_str(), registry_request)
            .await
            .map_err(|e| RpcError::Registry(e.to_string()))?;

        {
            let mut node_state = self.state.node_state.write().unwrap();
            if let Some(identity) = node_state.identity_mut() {
                identity.set_handle(new_handle.clone());
            }
            self.save_state(&node_state)?;
        }

        info!("Identity renamed to @{}", new_handle);

        Ok(IdentityResponse {
            id: identity_id.to_string(),
            handle: new_handle.to_string(),
            nonce: String::new(),
        })
    }

    // =========================================================================
    // Project handlers
    // =========================================================================

    async fn handle_list_projects(&self) -> Result<ProjectListResponse, RpcError> {
        let replica_ids = self
            .state
            .sync_engine
            .docs()
            .list_replicas()
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to list replicas: {e}")))?;

        let mut projects = Vec::new();
        for replica_id in replica_ids {
            if let Ok(Some(entry)) = self
                .state
                .sync_engine
                .docs()
                .get_latest(replica_id, objects_sync::PROJECT_KEY)
                .await
            {
                let content_hash = self.state.sync_engine.docs().entry_content_hash(&entry);
                if let Ok(bytes) = self
                    .state
                    .sync_engine
                    .blobs()
                    .read_to_bytes(content_hash)
                    .await
                    && let Ok(project) = serde_json::from_slice::<objects_data::Project>(&bytes)
                {
                    projects.push(ProjectResponse::from(project));
                }
            }
        }

        Ok(ProjectListResponse { projects })
    }

    async fn handle_create_project(
        &self,
        req: CreateProjectRpcRequest,
    ) -> Result<ProjectResponse, RpcError> {
        let req: CreateProjectRequest = req.into();
        req.validate().map_err(RpcError::BadRequest)?;

        let owner_id = self
            .state
            .node_state
            .read()
            .unwrap()
            .identity()
            .map(|info| info.identity_id().clone())
            .ok_or_else(|| RpcError::BadRequest("Identity required to create project".into()))?;

        let replica_id = self
            .state
            .sync_engine
            .docs()
            .create_replica()
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to create replica: {e}")))?;

        let result: Result<objects_data::Project, RpcError> = async {
            let author = self.state.sync_engine.default_author();
            let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
            let project_id = objects_data::Project::project_id_from_replica(&replica_bytes);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| RpcError::Internal(format!("System time error: {e}")))?
                .as_secs();

            let project = objects_data::Project::new(
                project_id,
                req.name.clone(),
                req.description.clone(),
                owner_id,
                now,
                now,
            )
            .map_err(|e| RpcError::Internal(format!("Failed to create project: {e}")))?;

            let project_json = serde_json::to_vec(&project)
                .map_err(|e| RpcError::Internal(format!("Failed to serialize project: {e}")))?;

            self.state
                .sync_engine
                .docs()
                .set_bytes(replica_id, author, objects_sync::PROJECT_KEY, project_json)
                .await
                .map_err(|e| {
                    RpcError::Internal(format!("Failed to store project metadata: {e}"))
                })?;

            Ok(project)
        }
        .await;

        match result {
            Ok(project) => {
                // Best-effort vault catalog entry
                self.add_project_to_vault(&project, replica_id).await;
                info!("Project created: {} ({})", req.name, project.id());
                Ok(ProjectResponse::from(project))
            }
            Err(e) => {
                if let Err(cleanup_err) = self
                    .state
                    .sync_engine
                    .docs()
                    .delete_replica(replica_id)
                    .await
                {
                    tracing::warn!("Failed to cleanup replica after error: {cleanup_err}");
                }
                Err(e)
            }
        }
    }

    async fn handle_get_project(
        &self,
        req: GetProjectRequest,
    ) -> Result<ProjectResponse, RpcError> {
        if req.project_id.len() != 64 || !req.project_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RpcError::BadRequest("Invalid project ID format".into()));
        }

        let replica_ids = self
            .state
            .sync_engine
            .docs()
            .list_replicas()
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to list replicas: {e}")))?;

        for replica_id in replica_ids {
            let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
            let project_id = objects_data::Project::project_id_from_replica(&replica_bytes);

            if project_id == req.project_id {
                let entry = self
                    .state
                    .sync_engine
                    .docs()
                    .get_latest(replica_id, objects_sync::PROJECT_KEY)
                    .await
                    .map_err(|e| RpcError::Internal(format!("Failed to read project: {e}")))?
                    .ok_or_else(|| RpcError::NotFound("Project metadata not found".into()))?;

                let content_hash = self.state.sync_engine.docs().entry_content_hash(&entry);
                let bytes = self
                    .state
                    .sync_engine
                    .blobs()
                    .read_to_bytes(content_hash)
                    .await
                    .map_err(|e| RpcError::Internal(format!("Failed to read content: {e}")))?;

                let project: objects_data::Project = serde_json::from_slice(&bytes)
                    .map_err(|e| RpcError::Internal(format!("Failed to parse project: {e}")))?;

                return Ok(ProjectResponse::from(project));
            }
        }

        Err(RpcError::NotFound(format!(
            "Project not found: {}",
            req.project_id
        )))
    }

    /// Best-effort add project to vault catalog (encrypted).
    async fn add_project_to_vault(
        &self,
        project: &objects_data::Project,
        replica_id: objects_sync::ReplicaId,
    ) {
        let signing_key_opt = self
            .state
            .node_state
            .read()
            .unwrap()
            .identity()
            .and_then(|i| i.signing_key().cloned());

        let Some(signing_key_bytes) = signing_key_opt else {
            return;
        };

        let vault_keys =
            match objects_identity::vault::VaultKeys::derive_from_signing_key(&signing_key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!("Vault key derivation failed: {e}");
                    return;
                }
            };

        let author = self.state.sync_engine.default_author();
        let catalog_entry = objects_sync::ProjectCatalogEntry {
            project_id: project.id().to_string(),
            replica_id: replica_id.as_bytes().to_vec(),
            project_name: project.name().to_string(),
            created_at: project.created_at(),
        };

        if let Err(e) = self
            .state
            .sync_engine
            .docs()
            .add_catalog_entry(
                vault_keys.namespace_id(),
                author,
                &catalog_entry,
                Some(&vault_keys.catalog_encryption_key),
            )
            .await
        {
            tracing::warn!(
                "Failed to add vault catalog entry for '{}': {e}",
                project.name()
            );
        } else {
            info!("Added project '{}' to vault catalog", project.name());
        }
    }

    // =========================================================================
    // Asset handlers
    // =========================================================================

    async fn handle_list_assets(
        &self,
        req: ListAssetsRequest,
    ) -> Result<AssetListResponse, RpcError> {
        let replica_id = self.find_replica(&req.project_id).await?;

        let entries = self
            .state
            .sync_engine
            .docs()
            .query_prefix(replica_id, objects_sync::ASSETS_PREFIX)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to query assets: {e}")))?;

        let mut assets = Vec::new();
        for entry in entries {
            let content_hash = self.state.sync_engine.docs().entry_content_hash(&entry);
            if let Ok(bytes) = self
                .state
                .sync_engine
                .blobs()
                .read_to_bytes(content_hash)
                .await
                && let Ok(asset) = serde_json::from_slice::<objects_data::Asset>(&bytes)
            {
                assets.push(AssetResponse::from(asset));
            }
        }

        Ok(AssetListResponse { assets })
    }

    async fn handle_add_asset(
        &self,
        req: AddAssetRequest,
        mut rx: irpc::channel::mpsc::Receiver<AssetChunk>,
    ) -> Result<AssetResponse, RpcError> {
        let replica_id = self.find_replica(&req.project_id).await?;

        let author_identity_id = self
            .state
            .node_state
            .read()
            .unwrap()
            .identity()
            .map(|info| info.identity_id().clone())
            .ok_or_else(|| RpcError::BadRequest("Identity required to add asset".into()))?;

        // Receive all chunks
        let mut data = Vec::with_capacity(req.total_size as usize);
        while let Ok(Some(chunk)) = rx.recv().await {
            data.extend_from_slice(&chunk.data);
        }

        // Store blob
        let content_size = data.len() as u64;
        let blob_hash = self
            .state
            .sync_engine
            .blobs()
            .add_bytes(bytes::Bytes::from(data))
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to store blob: {e}")))?;

        let author = self.state.sync_engine.default_author();
        let content_hash = objects_sync::hash_to_content_hash(blob_hash);

        // Generate asset ID from filename
        let asset_id: String = req
            .filename
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(64)
            .collect();
        let asset_id = if asset_id.is_empty() {
            format!("asset-{}", hex::encode(&blob_hash.as_bytes()[..8]))
        } else {
            asset_id
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RpcError::Internal(format!("System time error: {e}")))?
            .as_secs();

        let asset = objects_data::Asset::new(
            asset_id.clone(),
            req.filename,
            author_identity_id,
            content_hash,
            content_size,
            Some(req.content_type),
            now,
            now,
        )
        .map_err(|e| RpcError::Internal(format!("Failed to create asset: {e}")))?;

        self.state
            .sync_engine
            .docs()
            .store_asset(replica_id, author, &asset)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to store asset metadata: {e}")))?;

        info!("Asset added: {} to project {}", asset_id, req.project_id);
        Ok(AssetResponse::from(asset))
    }

    async fn handle_get_asset_content(
        &self,
        req: GetAssetContentRequest,
        tx: irpc::channel::mpsc::Sender<Result<ContentChunk, RpcError>>,
    ) {
        let result = self.stream_asset_content(&req, &tx).await;
        if let Err(e) = result {
            tx.send(Err(e)).await.ok();
        }
    }

    async fn stream_asset_content(
        &self,
        req: &GetAssetContentRequest,
        tx: &irpc::channel::mpsc::Sender<Result<ContentChunk, RpcError>>,
    ) -> Result<(), RpcError> {
        let replica_id = self.find_replica(&req.project_id).await?;

        let asset = self
            .state
            .sync_engine
            .docs()
            .get_asset(self.state.sync_engine.blobs(), replica_id, &req.asset_id)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to get asset: {e}")))?
            .ok_or_else(|| RpcError::NotFound(format!("Asset not found: {}", req.asset_id)))?;

        let blob_hash = objects_sync::content_hash_to_hash(asset.content_hash());
        let content = self
            .state
            .sync_engine
            .blobs()
            .read_to_bytes(blob_hash)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to read asset content: {e}")))?;

        let content_type = asset
            .format()
            .unwrap_or("application/octet-stream")
            .to_string();

        // Send content in chunks (64 KiB)
        let mut first = true;
        for chunk_data in content.chunks(64 * 1024) {
            let chunk = ContentChunk {
                data: chunk_data.to_vec(),
                content_type: if first {
                    first = false;
                    Some(content_type.clone())
                } else {
                    None
                },
            };
            tx.send(Ok(chunk))
                .await
                .map_err(|_| RpcError::Internal("Client disconnected".into()))?;
        }

        Ok(())
    }

    // =========================================================================
    // Ticket handlers
    // =========================================================================

    async fn handle_create_ticket(
        &self,
        req: CreateTicketRpcRequest,
    ) -> Result<TicketResponse, RpcError> {
        let replica_id = self.find_replica(&req.project_id).await?;

        let ticket = self
            .state
            .sync_engine
            .docs()
            .create_ticket(replica_id)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to create ticket: {e}")))?;

        info!("Ticket created for project {}", req.project_id);
        Ok(TicketResponse {
            ticket: ticket.to_string(),
        })
    }

    async fn handle_redeem_ticket(
        &self,
        req: RedeemTicketRpcRequest,
    ) -> Result<ProjectResponse, RpcError> {
        let ticket: objects_sync::DocTicket = req
            .ticket
            .parse()
            .map_err(|e| RpcError::BadRequest(format!("Invalid ticket: {e}")))?;

        let replica_id = self
            .state
            .sync_engine
            .docs()
            .download_from_ticket(ticket)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to import ticket: {e}")))?;

        let project = self
            .state
            .sync_engine
            .docs()
            .get_project(self.state.sync_engine.blobs(), replica_id)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to read project: {e}")))?
            .ok_or_else(|| RpcError::Internal("Project metadata not found in ticket".into()))?;

        info!("Ticket redeemed: project {}", project.name());
        Ok(ProjectResponse::from(project))
    }

    // =========================================================================
    // Vault handlers
    // =========================================================================

    async fn handle_list_vault(&self) -> Result<VaultResponse, RpcError> {
        let signing_key_bytes = self
            .state
            .node_state
            .read()
            .unwrap()
            .identity()
            .and_then(|i| i.signing_key().cloned())
            .ok_or_else(|| RpcError::BadRequest("No identity with signing key".into()))?;

        let vault_keys =
            objects_identity::vault::VaultKeys::derive_from_signing_key(&signing_key_bytes)
                .map_err(|e| RpcError::Internal(format!("Vault derivation failed: {e}")))?;

        let entries = self
            .state
            .sync_engine
            .docs()
            .list_catalog(
                self.state.sync_engine.blobs(),
                vault_keys.namespace_id(),
                Some(&vault_keys.catalog_encryption_key),
            )
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to list vault: {e}")))?;

        let local_replicas = self
            .state
            .sync_engine
            .docs()
            .list_replicas()
            .await
            .unwrap_or_default();

        let local_replica_bytes: Vec<[u8; 32]> = local_replicas
            .iter()
            .map(|r| r.as_bytes().to_owned())
            .collect();

        let items: Vec<VaultEntry> = entries
            .iter()
            .map(|e| {
                let replica_bytes: [u8; 32] =
                    e.replica_id.as_slice().try_into().unwrap_or([0u8; 32]);
                let local = local_replica_bytes.contains(&replica_bytes);
                VaultEntry {
                    project_id: e.project_id.clone(),
                    name: e.project_name.clone(),
                    created_at: e.created_at,
                    local,
                }
            })
            .collect();

        Ok(VaultResponse { entries: items })
    }

    // =========================================================================
    // Shared helpers
    // =========================================================================

    /// Find the replica ID for a project by its hex project ID.
    async fn find_replica(&self, project_id: &str) -> Result<objects_sync::ReplicaId, RpcError> {
        if project_id.len() != 64 || !project_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RpcError::BadRequest("Invalid project ID format".into()));
        }

        let replica_ids = self
            .state
            .sync_engine
            .docs()
            .list_replicas()
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to list replicas: {e}")))?;

        for replica_id in replica_ids {
            let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
            let derived_id = objects_data::Project::project_id_from_replica(&replica_bytes);
            if derived_id == project_id {
                return Ok(replica_id);
            }
        }

        Err(RpcError::NotFound(format!(
            "Project not found: {project_id}"
        )))
    }

    // =========================================================================
    // Peer handlers
    // =========================================================================

    async fn handle_list_peers(&self) -> ListPeersResponse {
        let peer_details = self.state.discovery.lock().await.peer_details();
        let mut peers = Vec::with_capacity(peer_details.len());

        for (addr, elapsed) in peer_details {
            let connection_type = match self.state.endpoint.inner().remote_info(addr.id).await {
                Some(info) => {
                    let has_relay = info.addrs().any(|a| a.addr().is_relay());
                    let has_direct = info.addrs().any(|a| !a.addr().is_relay());
                    match (has_direct, has_relay) {
                        (true, true) => "mixed",
                        (true, false) => "direct",
                        (false, true) => "relay",
                        (false, false) => "none",
                    }
                }
                None => "none",
            }
            .to_string();

            peers.push(PeerInfo {
                node_id: addr.id.to_string(),
                relay_url: addr.relay_urls().next().map(|u| u.to_string()),
                last_seen_ago: format_elapsed(elapsed),
                connection_type,
            });
        }

        ListPeersResponse { peers }
    }
}
