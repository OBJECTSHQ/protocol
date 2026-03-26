//! HTTP request handlers for the node API.

use crate::state::IdentityInfo;
use crate::{NodeConfig, NodeState};
use axum::{Json, extract::Path as AxumPath, extract::State, http::StatusCode};
use base64::Engine;
use objects_data::Project;
use objects_identity::{
    Ed25519SigningKey, Handle, IdentityId, generate_nonce, message::create_identity_message,
};
use objects_sync::{PROJECT_KEY, ReplicaId, SyncEngine};
use objects_transport::discovery::{Discovery, GossipDiscovery};
use objects_transport::{NodeAddr, NodeId, ObjectsEndpoint, Watcher};
use serde::Deserialize;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::info;

use super::client::{self, RegistryClient};
use super::error::NodeError;
use super::types::{
    AssetListResponse, AssetResponse, CreateProjectRequest, CreateTicketRequest, HealthResponse,
    IdentityResponse, PeerInfo, ProjectListResponse, ProjectResponse, RedeemTicketRequest,
    StatusResponse, TicketResponse, VaultEntry, VaultResponse,
};

/// Immutable node information.
///
/// This struct contains data that never changes during the node's lifetime,
/// so it can be wrapped in Arc without any locks.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Node ID from the transport layer.
    pub node_id: NodeId,
    /// Node address with relay information.
    pub node_addr: NodeAddr,
}

/// Shared state for HTTP handlers.
///
/// This state is cloned for each request handler. Uses Arc for efficient
/// sharing and appropriate synchronization primitives for each field:
/// - NodeInfo: Immutable, no lock needed
/// - GossipDiscovery: Mutable, exclusive access (Mutex)
/// - NodeState: Read-heavy, write-rare (RwLock)
/// - NodeConfig: Immutable clone
/// - RegistryClient: Stateless, clone-safe
/// - SyncEngine: Clone-safe wrapper over iroh components
/// - ObjectsEndpoint: For querying per-peer connection types
#[derive(Clone)]
pub struct AppState {
    /// Immutable node information.
    pub node_info: Arc<NodeInfo>,
    /// Gossip discovery for peer information.
    pub discovery: Arc<Mutex<GossipDiscovery>>,
    /// Node state including identity.
    pub node_state: Arc<RwLock<NodeState>>,
    /// Node configuration.
    pub config: NodeConfig,
    /// Registry HTTP client.
    pub registry_client: RegistryClient,
    /// Sync engine for blob and metadata sync.
    pub sync_engine: SyncEngine,
    /// Transport endpoint for connection type queries.
    pub endpoint: Arc<ObjectsEndpoint>,
}

/// Health check handler.
///
/// Returns a simple JSON response indicating the node is running.
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Node status handler.
///
/// Returns current node information including:
/// - Node ID and address
/// - Number of discovered peers
/// - Identity information (if registered)
/// - Relay URL
pub async fn node_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let peer_count = state.discovery.lock().await.peer_count();

    let identity = state
        .node_state
        .read()
        .expect("node_state lock poisoned")
        .identity()
        .map(|info| IdentityResponse {
            id: info.identity_id().to_string(),
            handle: info.handle().to_string(),
            nonce: base64::engine::general_purpose::STANDARD.encode(info.nonce()),
        });

    Json(StatusResponse {
        node_id: state.node_info.node_id.to_string(),
        node_addr: state.node_info.node_addr.clone(),
        peer_count,
        identity,
        relay_url: state.config.network.relay_url.clone(),
    })
}

/// Get identity handler.
///
/// Returns the node's registered identity if it exists.
/// Returns 404 if no identity has been registered.
pub async fn get_identity(
    State(state): State<AppState>,
) -> Result<Json<IdentityResponse>, NodeError> {
    let identity = state
        .node_state
        .read()
        .unwrap()
        .identity()
        .map(|info| IdentityResponse {
            id: info.identity_id().to_string(),
            handle: info.handle().to_string(),
            nonce: base64::engine::general_purpose::STANDARD.encode(info.nonce()),
        });

    match identity {
        Some(response) => Ok(Json(response)),
        None => Err(NodeError::NotFound("No identity registered".to_string())),
    }
}

/// List peers handler.
///
/// Returns all discovered peers with their node IDs, relay URLs,
/// and time since last seen.
pub async fn list_peers(State(state): State<AppState>) -> Json<serde_json::Value> {
    let peer_details = state.discovery.lock().await.peer_details();
    let peers: Vec<PeerInfo> = peer_details
        .into_iter()
        .map(|(addr, elapsed)| {
            let connection_type = state
                .endpoint
                .inner()
                .conn_type(addr.id)
                .map(|mut watcher| format!("{}", watcher.get()))
                .unwrap_or_else(|| "none".to_string());

            PeerInfo {
                node_id: addr.id.to_string(),
                relay_url: addr.relay_urls().next().map(|u| u.to_string()),
                last_seen_ago: format_elapsed(elapsed),
                connection_type,
            }
        })
        .collect();
    Json(serde_json::json!({ "peers": peers }))
}

fn format_elapsed(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Request from CLI to create an identity. Just a handle — the node handles key generation.
#[derive(Debug, Deserialize)]
pub struct CliCreateIdentityRequest {
    pub handle: String,
}

/// Create identity handler.
///
/// The node generates the Ed25519 signing key (not the CLI), registers with
/// the registry, persists the key locally, and sets up the vault.
///
/// Flow:
/// 1. Validate handle format
/// 2. Generate Ed25519 signing key + cryptographic nonce
/// 3. Derive identity ID from public key + nonce
/// 4. Sign create-identity message
/// 5. Register with registry
/// 6. Persist signing key + identity in node state
///
/// The signing key never leaves this node. Device linking (future) will
/// transfer it explicitly via QR code or recovery phrase.
pub async fn create_identity(
    State(state): State<AppState>,
    Json(req): Json<CliCreateIdentityRequest>,
) -> Result<(StatusCode, Json<IdentityResponse>), NodeError> {
    // 1. Validate handle format
    let handle = Handle::parse(&req.handle).map_err(|e| NodeError::BadRequest(e.to_string()))?;

    // 2. Generate Ed25519 signing key (random, OS entropy)
    let signing_key = Ed25519SigningKey::generate();
    let public_key = signing_key.public_key_bytes();

    // 3. Generate cryptographic nonce (random, 8 bytes, OS entropy)
    let nonce = generate_nonce();

    // 4. Derive identity ID: SHA256(public_key || nonce), truncated + base58
    let identity_id = IdentityId::derive(&public_key, &nonce);

    // 5. Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| NodeError::Internal(format!("System time error: {}", e)))?
        .as_secs();

    // 6. Sign the create-identity message per RFC-001
    let message = create_identity_message(identity_id.as_str(), handle.as_str(), timestamp);
    let signature = signing_key.sign(message.as_bytes());

    // 7. Build registry request with full crypto data
    let b64 = &base64::engine::general_purpose::STANDARD;
    let registry_request = client::CreateIdentityRequest {
        handle: handle.to_string(),
        public_key: b64.encode(public_key),
        nonce: b64.encode(nonce),
        timestamp,
        signature: client::SignatureData {
            signature: b64.encode(signature.signature_bytes()),
            public_key: b64.encode(signature.public_key_bytes()),
        },
    };

    // 8. Register with the registry
    let registry_response = state
        .registry_client
        .create_identity(registry_request)
        .await
        .map_err(|e| NodeError::Registry(e.to_string()))?;

    // 9. Persist signing key + identity in node state
    let identity_info = IdentityInfo::with_signing_key(
        IdentityId::parse(&registry_response.id)
            .map_err(|e| NodeError::Internal(format!("Invalid identity ID: {}", e)))?,
        Handle::parse(&registry_response.handle)
            .map_err(|e| NodeError::Internal(format!("Invalid handle: {}", e)))?,
        nonce,
        signing_key.to_bytes(),
    );

    {
        let mut node_state = state.node_state.write().unwrap();
        node_state.set_identity(identity_info.clone());

        // 10. Persist to disk (signing key is in node.key, protected by 0o600 permissions)
        let state_path = Path::new(&state.config.node.data_dir).join("node.key");
        node_state
            .save(&state_path)
            .map_err(|e| NodeError::Internal(format!("Failed to save state: {}", e)))?;
    }

    // 11. Create vault replica for cross-device project discovery.
    //     The vault namespace is deterministically derived from the signing key
    //     via HKDF, so the same identity always maps to the same vault replica.
    if let Some(signing_key_bytes) = identity_info.signing_key() {
        let vault_keys =
            objects_identity::vault::VaultKeys::derive_from_signing_key(signing_key_bytes)
                .map_err(|e| NodeError::Internal(format!("Failed to derive vault keys: {}", e)))?;

        // Create the vault replica using the HKDF-derived namespace secret
        state
            .sync_engine
            .docs()
            .create_replica_with_secret(vault_keys.namespace_secret().clone())
            .await
            .map_err(|e| NodeError::Internal(format!("Failed to create vault replica: {}", e)))?;

        info!("Vault replica created: {}", vault_keys.namespace_id());

        // Store vault namespace ID in state for quick access
        let mut node_state = state.node_state.write().unwrap();
        if let Some(identity) = node_state.identity_mut() {
            identity.set_vault_namespace_id(vault_keys.namespace_id().to_string());
        }
        // Re-persist state with vault_namespace_id
        let state_path = Path::new(&state.config.node.data_dir).join("node.key");
        node_state
            .save(&state_path)
            .map_err(|e| NodeError::Internal(format!("Failed to save vault state: {}", e)))?;
    }

    info!(
        "Identity created: {} (key generated and persisted on this node)",
        identity_info.handle()
    );

    let response = IdentityResponse {
        id: registry_response.id,
        handle: registry_response.handle,
        nonce: b64.encode(nonce),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

// =============================================================================
// Project Handlers
// =============================================================================

/// Create project handler.
///
/// Creates a new project with a dedicated replica for metadata storage:
/// 1. Validates request fields
/// 2. Requires identity to be registered (for owner_id)
/// 3. Creates a new replica via SyncEngine
/// 4. Stores project metadata at /project key
///
/// Returns 201 Created with project info on success.
pub async fn create_project(
    State(state): State<AppState>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<ProjectResponse>), NodeError> {
    // 1. Validate request
    req.validate()
        .map_err(|e| NodeError::BadRequest(e.to_string()))?;

    // 2. Get owner identity (required)
    let owner_id = state
        .node_state
        .read()
        .unwrap()
        .identity()
        .map(|info| info.identity_id().clone())
        .ok_or_else(|| NodeError::BadRequest("Identity required to create project".to_string()))?;

    // 3. Create replica
    let replica_id = state
        .sync_engine
        .docs()
        .create_replica()
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to create replica: {}", e)))?;

    // 4. Build and store project metadata; clean up replica on failure
    let result: Result<_, NodeError> = async {
        let author = state.sync_engine.default_author();

        let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
        let project_id = Project::project_id_from_replica(&replica_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| NodeError::Internal(format!("System time error: {}", e)))?
            .as_secs();

        let project = Project::new(
            project_id,
            req.name.clone(),
            req.description.clone(),
            owner_id,
            now,
            now,
        )
        .map_err(|e| NodeError::Internal(format!("Failed to create project: {}", e)))?;

        let project_json = serde_json::to_vec(&project)
            .map_err(|e| NodeError::Internal(format!("Failed to serialize project: {}", e)))?;

        state
            .sync_engine
            .docs()
            .set_bytes(replica_id, author, PROJECT_KEY, project_json)
            .await
            .map_err(|e| NodeError::Internal(format!("Failed to store project metadata: {}", e)))?;

        Ok(project)
    }
    .await;

    match result {
        Ok(project) => {
            // Add project to vault catalog (encrypted) for cross-device discovery.
            // This is best-effort — project creation succeeds even if vault entry fails.
            // Extract signing key while holding the lock, then drop the guard before await.
            let signing_key_opt = {
                let node_state = state.node_state.read().unwrap();
                node_state.identity().and_then(|i| i.signing_key().cloned())
            };
            if let Some(signing_key_bytes) = signing_key_opt {
                match objects_identity::vault::VaultKeys::derive_from_signing_key(
                    &signing_key_bytes,
                ) {
                    Ok(vault_keys) => {
                        let author = state.sync_engine.default_author();
                        let catalog_entry = objects_sync::ProjectCatalogEntry {
                            project_id: project.id().to_string(),
                            replica_id: replica_id.as_bytes().to_vec(),
                            project_name: project.name().to_string(),
                            created_at: project.created_at(),
                        };

                        if let Err(e) = state
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
                                "Failed to add vault catalog entry for project '{}': {}",
                                project.name(),
                                e
                            );
                        } else {
                            info!("Added project '{}' to vault catalog", project.name());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Vault key derivation failed: {}", e);
                    }
                }
            }

            info!("Project created: {} ({})", req.name, project.id());
            Ok((StatusCode::CREATED, Json(ProjectResponse::from(project))))
        }
        Err(e) => {
            if let Err(cleanup_err) = state.sync_engine.docs().delete_replica(replica_id).await {
                tracing::warn!("Failed to cleanup replica after error: {cleanup_err}");
            }
            Err(e)
        }
    }
}

/// List projects handler.
///
/// Returns all projects owned by this node.
pub async fn list_projects(
    State(state): State<AppState>,
) -> Result<Json<ProjectListResponse>, NodeError> {
    let replica_ids = state
        .sync_engine
        .docs()
        .list_replicas()
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to list replicas: {}", e)))?;

    let mut projects = Vec::new();

    for replica_id in replica_ids {
        // Try to read project metadata from each replica
        if let Ok(Some(entry)) = state
            .sync_engine
            .docs()
            .get_latest(replica_id, PROJECT_KEY)
            .await
        {
            let content_hash = state.sync_engine.docs().entry_content_hash(&entry);
            if let Ok(bytes) = state.sync_engine.blobs().read_to_bytes(content_hash).await
                && let Ok(project) = serde_json::from_slice::<Project>(&bytes)
            {
                projects.push(ProjectResponse::from(project));
            }
        }
    }

    Ok(Json(ProjectListResponse { projects }))
}

/// Get project handler.
///
/// Returns a specific project by ID.
pub async fn get_project(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ProjectResponse>, NodeError> {
    // Validate project ID format (32 hex chars)
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NodeError::BadRequest(
            "Invalid project ID format".to_string(),
        ));
    }

    let replica_ids = state
        .sync_engine
        .docs()
        .list_replicas()
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to list replicas: {}", e)))?;

    for replica_id in replica_ids {
        // Check if this replica's project ID matches
        let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
        let project_id = Project::project_id_from_replica(&replica_bytes);

        if project_id == id {
            // Found the replica, read project metadata
            let entry = state
                .sync_engine
                .docs()
                .get_latest(replica_id, PROJECT_KEY)
                .await
                .map_err(|e| NodeError::Internal(format!("Failed to read project: {}", e)))?
                .ok_or_else(|| NodeError::NotFound("Project metadata not found".to_string()))?;

            let content_hash = state.sync_engine.docs().entry_content_hash(&entry);
            let bytes = state
                .sync_engine
                .blobs()
                .read_to_bytes(content_hash)
                .await
                .map_err(|e| NodeError::Internal(format!("Failed to read content: {}", e)))?;

            let project: Project = serde_json::from_slice(&bytes)
                .map_err(|e| NodeError::Internal(format!("Failed to parse project: {}", e)))?;

            return Ok(Json(ProjectResponse::from(project)));
        }
    }

    Err(NodeError::NotFound(format!("Project not found: {}", id)))
}

// =============================================================================
// Asset Handlers
// =============================================================================

/// Helper to find replica ID for a project.
async fn find_replica_for_project(
    sync_engine: &SyncEngine,
    project_id: &str,
) -> Result<ReplicaId, NodeError> {
    // Validate project ID format (32 hex chars)
    if project_id.len() != 32 || !project_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NodeError::BadRequest(
            "Invalid project ID format".to_string(),
        ));
    }

    let replica_ids = sync_engine
        .docs()
        .list_replicas()
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to list replicas: {}", e)))?;

    for replica_id in replica_ids {
        let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
        let derived_id = Project::project_id_from_replica(&replica_bytes);
        if derived_id == project_id {
            return Ok(replica_id);
        }
    }

    Err(NodeError::NotFound(format!(
        "Project not found: {}",
        project_id
    )))
}

/// Add asset handler - POST /projects/:id/assets
///
/// Uploads a file as an asset to a project via multipart form data.
pub async fn add_asset(
    State(state): State<AppState>,
    AxumPath(project_id): AxumPath<String>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<(StatusCode, Json<AssetResponse>), NodeError> {
    // 1. Find replica for project
    let replica_id = find_replica_for_project(&state.sync_engine, &project_id).await?;

    // 2. Get owner identity (required for author_id)
    let author_identity_id = state
        .node_state
        .read()
        .unwrap()
        .identity()
        .map(|info| info.identity_id().clone())
        .ok_or_else(|| NodeError::BadRequest("Identity required to add asset".to_string()))?;

    // 3. Extract file from multipart
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut file_data: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| NodeError::BadRequest(format!("Failed to read multipart field: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "file" {
            filename = field.file_name().map(String::from);
            content_type = field.content_type().map(String::from);
            file_data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| NodeError::BadRequest(format!("Failed to read file data: {}", e)))?
                    .to_vec(),
            );
        }
    }

    let filename =
        filename.ok_or_else(|| NodeError::BadRequest("Missing file field".to_string()))?;
    let content_type = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
    let file_data = file_data.ok_or_else(|| NodeError::BadRequest("Empty file".to_string()))?;

    // 4. Add blob via blobs().add_bytes()
    let content_size = file_data.len() as u64;
    let blob_hash = state
        .sync_engine
        .blobs()
        .add_bytes(bytes::Bytes::from(file_data))
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to store blob: {}", e)))?;

    // 5. Get default author for signing entries
    let author = state.sync_engine.default_author();

    // 6. Create Asset with content_hash from blob
    let content_hash = objects_sync::hash_to_content_hash(blob_hash);

    // Generate asset ID from filename (sanitize for RFC-004 compliance)
    let asset_id: String = filename
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
        .map_err(|e| NodeError::Internal(format!("System time error: {}", e)))?
        .as_secs();

    let asset = objects_data::Asset::new(
        asset_id.clone(),
        filename,
        author_identity_id,
        content_hash,
        content_size,
        Some(content_type),
        now,
        now,
    )
    .map_err(|e| NodeError::Internal(format!("Failed to create asset: {}", e)))?;

    // 7. Store via store_asset helper
    state
        .sync_engine
        .docs()
        .store_asset(replica_id, author, &asset)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to store asset metadata: {}", e)))?;

    info!("Asset added: {} to project {}", asset_id, project_id);

    Ok((StatusCode::CREATED, Json(AssetResponse::from(asset))))
}

/// List assets handler - GET /projects/:id/assets
///
/// Returns all assets in a project.
pub async fn list_assets(
    State(state): State<AppState>,
    AxumPath(project_id): AxumPath<String>,
) -> Result<Json<AssetListResponse>, NodeError> {
    // 1. Find replica for project
    let replica_id = find_replica_for_project(&state.sync_engine, &project_id).await?;

    // 2. List all entries with /assets/ prefix
    let entries = state
        .sync_engine
        .docs()
        .query_prefix(replica_id, objects_sync::ASSETS_PREFIX)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to query assets: {}", e)))?;

    // 3. Parse each as Asset
    let mut assets = Vec::new();
    for entry in entries {
        let content_hash = state.sync_engine.docs().entry_content_hash(&entry);
        if let Ok(bytes) = state.sync_engine.blobs().read_to_bytes(content_hash).await
            && let Ok(asset) = serde_json::from_slice::<objects_data::Asset>(&bytes)
        {
            assets.push(AssetResponse::from(asset));
        }
    }

    Ok(Json(AssetListResponse { assets }))
}

/// Get asset content handler - GET /projects/:id/assets/:asset_id/content
///
/// Returns the raw content of an asset with appropriate Content-Type header.
pub async fn get_asset_content(
    State(state): State<AppState>,
    AxumPath((project_id, asset_id)): AxumPath<(String, String)>,
) -> Result<impl axum::response::IntoResponse, NodeError> {
    use axum::http::header;
    use axum::response::Response;

    // 1. Find replica for project
    let replica_id = find_replica_for_project(&state.sync_engine, &project_id).await?;

    // 2. Get asset metadata via get_asset helper
    let asset = state
        .sync_engine
        .docs()
        .get_asset(state.sync_engine.blobs(), replica_id, &asset_id)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to get asset: {}", e)))?
        .ok_or_else(|| NodeError::NotFound(format!("Asset not found: {}", asset_id)))?;

    // 3. Read blob content via content_hash
    let blob_hash = objects_sync::content_hash_to_hash(asset.content_hash());
    let content = state
        .sync_engine
        .blobs()
        .read_to_bytes(blob_hash)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to read asset content: {}", e)))?;

    // 4. Return with Content-Type header
    let content_type = asset.format().unwrap_or("application/octet-stream");

    // Sanitize filename: escape backslashes and quotes for Content-Disposition header
    let safe_name = asset.name().replace('\\', "\\\\").replace('"', "\\\"");

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", safe_name),
        )
        .body(axum::body::Body::from(content.to_vec()))
        .map_err(|e| NodeError::Internal(format!("Failed to build response: {}", e)))
}

// =============================================================================
// Ticket Handlers
// =============================================================================

/// Create ticket handler - POST /tickets
///
/// Creates a share ticket for a project.
pub async fn create_ticket(
    State(state): State<AppState>,
    Json(req): Json<CreateTicketRequest>,
) -> Result<(StatusCode, Json<TicketResponse>), NodeError> {
    // 1. Find replica for project
    let replica_id = find_replica_for_project(&state.sync_engine, &req.project_id).await?;

    // 2. Create DocTicket
    let ticket = state
        .sync_engine
        .docs()
        .create_ticket(replica_id)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to create ticket: {}", e)))?;

    // 4. Serialize to string
    let ticket_str = ticket.to_string();

    info!("Ticket created for project {}", req.project_id);

    Ok((
        StatusCode::CREATED,
        Json(TicketResponse { ticket: ticket_str }),
    ))
}

/// Redeem ticket handler - POST /tickets/redeem
///
/// Imports a project from a share ticket.
pub async fn redeem_ticket(
    State(state): State<AppState>,
    Json(req): Json<RedeemTicketRequest>,
) -> Result<(StatusCode, Json<ProjectResponse>), NodeError> {
    use objects_sync::DocTicket;

    // 1. Parse DocTicket from string
    let ticket: DocTicket = req
        .ticket
        .parse()
        .map_err(|e| NodeError::BadRequest(format!("Invalid ticket: {}", e)))?;

    // 2. Import/sync replica via SyncEngine
    let replica_id = state
        .sync_engine
        .docs()
        .download_from_ticket(ticket)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to import ticket: {}", e)))?;

    // 3. Read project metadata
    let project = state
        .sync_engine
        .docs()
        .get_project(state.sync_engine.blobs(), replica_id)
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to read project: {}", e)))?
        .ok_or_else(|| NodeError::Internal("Project metadata not found in ticket".to_string()))?;

    info!("Ticket redeemed: project {}", project.name());

    Ok((StatusCode::CREATED, Json(ProjectResponse::from(project))))
}

// =============================================================================
// Vault Handlers
// =============================================================================

/// List vault catalog entries.
///
/// Returns all projects in the user's vault catalog (decrypted).
/// Each entry indicates whether the project replica exists locally.
pub async fn list_vault(State(state): State<AppState>) -> Result<Json<VaultResponse>, NodeError> {
    // Get signing key from identity
    let signing_key_bytes = state
        .node_state
        .read()
        .unwrap()
        .identity()
        .and_then(|i| i.signing_key().cloned())
        .ok_or_else(|| NodeError::BadRequest("No identity with signing key".to_string()))?;

    let vault_keys =
        objects_identity::vault::VaultKeys::derive_from_signing_key(&signing_key_bytes)
            .map_err(|e| NodeError::Internal(format!("Vault derivation failed: {}", e)))?;

    let entries = state
        .sync_engine
        .docs()
        .list_catalog(
            state.sync_engine.blobs(),
            vault_keys.namespace_id(),
            Some(&vault_keys.catalog_encryption_key),
        )
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to list vault: {}", e)))?;

    // Check which projects have local replicas
    let local_replicas = state
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
            // Check if the project's replica exists locally
            let replica_bytes: [u8; 32] = e.replica_id.as_slice().try_into().unwrap_or([0u8; 32]);
            let local = local_replica_bytes.contains(&replica_bytes);

            VaultEntry {
                project_id: e.project_id.clone(),
                name: e.project_name.clone(),
                created_at: e.created_at,
                local,
            }
        })
        .collect();

    Ok(Json(VaultResponse { entries: items }))
}

/// Trigger vault metadata sync with peers.
///
/// TODO: Initiate iroh-docs sync for the vault replica to pull
/// catalog updates from other devices.
pub async fn sync_vault(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, NodeError> {
    // TODO: Trigger iroh-docs sync for vault replica
    Ok(Json(serde_json::json!({"status": "synced"})))
}

/// Pull a specific project from the vault catalog.
///
/// TODO: Look up the project's write ticket in the vault catalog
/// and download the project replica from peers.
pub async fn pull_vault_project(
    State(_state): State<AppState>,
    AxumPath(project_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, NodeError> {
    // TODO: Find project ticket in vault catalog, download via ticket
    Ok(Json(
        serde_json::json!({"status": "pulled", "project_id": project_id}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use objects_transport::SecretKey;

    #[test]
    fn test_node_info_fields() {
        let secret_key = SecretKey::generate(&mut rand::rng());
        let node_id = secret_key.public();
        let node_addr = NodeAddr::new(node_id);

        let node_info = NodeInfo {
            node_id,
            node_addr: node_addr.clone(),
        };

        assert_eq!(node_info.node_id, node_id);
        assert_eq!(node_info.node_addr.id, node_id);
    }

    #[test]
    fn test_app_state_clone_semantics() {
        // Test that AppState can be cloned and Arc references work correctly
        let secret_key = SecretKey::generate(&mut rand::rng());
        let node_id = secret_key.public();
        let node_addr = NodeAddr::new(node_id);

        let node_info = Arc::new(NodeInfo {
            node_id,
            node_addr: node_addr.clone(),
        });

        let state = NodeState::generate_new();

        // Create a minimal AppState (discovery will be added in later PRs)
        // For now, just verify the Arc wrapper types work correctly
        let node_info_clone = node_info.clone();
        let state_arc = Arc::new(RwLock::new(state));
        let state_clone = state_arc.clone();

        // Verify Arc semantics - clones point to same data
        assert_eq!(
            Arc::as_ptr(&node_info),
            Arc::as_ptr(&node_info_clone),
            "Arc clones should point to same NodeInfo"
        );

        assert_eq!(
            Arc::as_ptr(&state_arc),
            Arc::as_ptr(&state_clone),
            "Arc clones should point to same NodeState"
        );
    }

    #[test]
    fn test_health_check_returns_ok() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(health_check());
        assert_eq!(response.0.status, "ok");
    }
}
