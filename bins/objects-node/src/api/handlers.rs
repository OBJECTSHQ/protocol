//! HTTP request handlers for the node API.

use crate::state::IdentityInfo;
use crate::{NodeConfig, NodeState};
use axum::{extract::Path as AxumPath, extract::State, http::StatusCode, Json};
use base64::Engine;
use objects_data::Project;
use objects_identity::{Handle, IdentityId, SignerType};
use objects_sync::{PROJECT_KEY, ReplicaId, SyncEngine};
use objects_transport::discovery::{Discovery, GossipDiscovery};
use objects_transport::{NodeAddr, NodeId};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::info;

use super::client::{CreateIdentityRequest, RegistryClient};
use super::error::NodeError;
use super::types::{
    AssetListResponse, AssetResponse, CreateProjectRequest, HealthResponse, IdentityResponse,
    ProjectListResponse, ProjectResponse, StatusResponse,
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
            signer_type: format!("{:?}", info.signer_type()).to_lowercase(),
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
            nonce: hex::encode(info.nonce()),
            signer_type: format!("{:?}", info.signer_type()).to_lowercase(),
        });

    match identity {
        Some(response) => Ok(Json(response)),
        None => Err(NodeError::NotFound("No identity registered".to_string())),
    }
}

/// Create identity handler.
///
/// Registers a new identity with the registry and persists it locally:
/// 1. Validates handle format
/// 2. Calls registry to create identity
/// 3. Updates NodeState with identity info
/// 4. Persists state to disk
///
/// Returns 201 Created with identity info on success.
pub async fn create_identity(
    State(state): State<AppState>,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<(StatusCode, Json<IdentityResponse>), NodeError> {
    // 1. Validate request
    Handle::parse(&req.handle).map_err(|e| NodeError::BadRequest(e.to_string()))?;

    // 2. Call registry to create identity
    let registry_response = state
        .registry_client
        .create_identity(req)
        .await
        .map_err(|e| NodeError::Registry(e.to_string()))?;

    // 3. Update local node state
    let signer_type = match registry_response.signer_type.to_lowercase().as_str() {
        "passkey" => SignerType::Passkey,
        "wallet" => SignerType::Wallet,
        _ => {
            return Err(NodeError::Internal(
                "Unknown signer type from registry".to_string(),
            ));
        }
    };

    let nonce = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &registry_response.nonce,
    )
    .map_err(|e| NodeError::Internal(format!("Invalid nonce from registry: {}", e)))?;

    if nonce.len() != 8 {
        return Err(NodeError::Internal(
            "Nonce must be exactly 8 bytes".to_string(),
        ));
    }

    let mut nonce_array = [0u8; 8];
    nonce_array.copy_from_slice(&nonce);

    let identity_info = IdentityInfo::new(
        IdentityId::parse(&registry_response.id)
            .map_err(|e| NodeError::Internal(format!("Invalid identity ID: {}", e)))?,
        Handle::parse(&registry_response.handle)
            .map_err(|e| NodeError::Internal(format!("Invalid handle: {}", e)))?,
        nonce_array,
        signer_type,
    );

    {
        let mut node_state = state.node_state.write().unwrap();
        node_state.set_identity(identity_info.clone());

        // 4. Persist to disk
        let state_path = Path::new(&state.config.node.data_dir).join("node.key");
        node_state
            .save(&state_path)
            .map_err(|e| NodeError::Internal(format!("Failed to save state: {}", e)))?;
    }

    info!("Identity created: {}", identity_info.handle());

    let response = IdentityResponse {
        id: registry_response.id,
        handle: registry_response.handle,
        nonce: registry_response.nonce,
        signer_type: registry_response.signer_type,
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

    // 4. Create author for signing entries
    let author = state
        .sync_engine
        .docs()
        .create_author()
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to create author: {}", e)))?;

    // 5. Derive project ID from replica ID
    let replica_bytes: [u8; 32] = replica_id.as_bytes().to_owned();
    let project_id = Project::project_id_from_replica(&replica_bytes);

    // 6. Get timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| NodeError::Internal(format!("System time error: {}", e)))?
        .as_secs();

    // 7. Create project and store metadata
    let project = Project::new(
        project_id.clone(),
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

    info!("Project created: {} ({})", req.name, project_id);

    Ok((StatusCode::CREATED, Json(ProjectResponse::from(project))))
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

    // 5. Create author for signing entries
    let author = state
        .sync_engine
        .docs()
        .create_author()
        .await
        .map_err(|e| NodeError::Internal(format!("Failed to create author: {}", e)))?;

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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", asset.name()),
        )
        .body(axum::body::Body::from(content.to_vec()))
        .unwrap())
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
