//! HTTP request handlers for the node API.

use crate::state::IdentityInfo;
use crate::{NodeConfig, NodeState};
use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use objects_identity::{Handle, IdentityId, SignerType};
use objects_transport::discovery::{Discovery, GossipDiscovery};
use objects_transport::{NodeAddr, NodeId};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use tracing::info;

use super::client::{CreateIdentityRequest, RegistryClient};
use super::error::NodeError;
use super::types::{HealthResponse, IdentityResponse, StatusResponse};

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

    let nonce = hex::decode(&registry_response.nonce)
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
