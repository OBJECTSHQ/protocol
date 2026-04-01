//! Node RPC protocol definition.
//!
//! Uses irpc's `#[rpc_requests]` macro to generate the message enum
//! and channel boilerplate. Follows the same pattern as iroh-blobs.

use irpc::{
    channel::{mpsc, oneshot},
    rpc_requests,
};
use serde::{Deserialize, Serialize};

use crate::api::types::{
    AssetListResponse, AssetResponse, CreateProjectRequest, CreateTicketRequest, HealthResponse,
    IdentityResponse, PeerInfo, ProjectListResponse, ProjectResponse, StatusResponse,
    TicketResponse, VaultResponse,
};

/// ALPN protocol identifier for the OBJECTS node RPC service.
pub const NODE_RPC_ALPN: &[u8] = b"/objects/node-rpc/0";

// =============================================================================
// Error type (must be serializable for irpc wire format)
// =============================================================================

/// Serializable error type for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum RpcError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("registry error: {0}")]
    Registry(String),
    #[error("internal error: {0}")]
    Internal(String),
}

// =============================================================================
// Protocol definition
// =============================================================================

/// The node RPC protocol — all operations the node supports.
///
/// Each variant is a request type with typed response channel(s).
/// The macro generates `NodeCommand` (the full message with channels)
/// and conversion traits.
#[rpc_requests(message = NodeCommand)]
#[derive(Debug, Serialize, Deserialize)]
pub enum NodeProtocol {
    // --- Health & Status ---
    #[rpc(tx = oneshot::Sender<HealthResponse>)]
    Health(HealthRequest),

    #[rpc(tx = oneshot::Sender<StatusResponse>)]
    Status(StatusRequest),

    // --- Identity ---
    #[rpc(tx = oneshot::Sender<Result<IdentityResponse, RpcError>>)]
    GetIdentity(GetIdentityRequest),

    #[rpc(tx = oneshot::Sender<Result<IdentityResponse, RpcError>>)]
    CreateIdentity(CreateIdentityRpcRequest),

    #[rpc(tx = oneshot::Sender<Result<IdentityResponse, RpcError>>)]
    RenameIdentity(RenameIdentityRpcRequest),

    // --- Peers ---
    #[rpc(tx = oneshot::Sender<ListPeersResponse>)]
    ListPeers(ListPeersRequest),

    // --- Projects ---
    #[rpc(tx = oneshot::Sender<Result<ProjectListResponse, RpcError>>)]
    ListProjects(ListProjectsRequest),

    #[rpc(tx = oneshot::Sender<Result<ProjectResponse, RpcError>>)]
    CreateProject(CreateProjectRpcRequest),

    #[rpc(tx = oneshot::Sender<Result<ProjectResponse, RpcError>>)]
    GetProject(GetProjectRequest),

    // --- Assets ---
    #[rpc(tx = oneshot::Sender<Result<AssetListResponse, RpcError>>)]
    ListAssets(ListAssetsRequest),

    /// Client streams file bytes, server responds with asset metadata.
    #[rpc(rx = mpsc::Receiver<AssetChunk>, tx = oneshot::Sender<Result<AssetResponse, RpcError>>)]
    AddAsset(AddAssetRequest),

    /// Server streams content bytes back to client.
    #[rpc(tx = mpsc::Sender<Result<ContentChunk, RpcError>>)]
    GetAssetContent(GetAssetContentRequest),

    // --- Tickets ---
    #[rpc(tx = oneshot::Sender<Result<TicketResponse, RpcError>>)]
    CreateTicket(CreateTicketRpcRequest),

    #[rpc(tx = oneshot::Sender<Result<ProjectResponse, RpcError>>)]
    RedeemTicket(RedeemTicketRpcRequest),

    // --- Vault ---
    #[rpc(tx = oneshot::Sender<Result<VaultResponse, RpcError>>)]
    ListVault(ListVaultRequest),

    #[rpc(tx = oneshot::Sender<Result<SyncVaultResponse, RpcError>>)]
    SyncVault(SyncVaultRequest),

    #[rpc(tx = oneshot::Sender<Result<PullVaultResponse, RpcError>>)]
    PullVaultProject(PullVaultProjectRequest),
}

// =============================================================================
// Request types
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct GetIdentityRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIdentityRpcRequest {
    pub handle: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RenameIdentityRpcRequest {
    pub new_handle: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListPeersRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ListProjectsRequest;

/// Wraps [`CreateProjectRequest`] for the RPC layer.
/// Uses the same fields but is a distinct type for irpc codegen.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateProjectRpcRequest {
    pub name: String,
    pub description: Option<String>,
}

impl From<CreateProjectRpcRequest> for CreateProjectRequest {
    fn from(r: CreateProjectRpcRequest) -> Self {
        Self {
            name: r.name,
            description: r.description,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetProjectRequest {
    pub project_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAssetsRequest {
    pub project_id: String,
}

/// Initial metadata for an asset upload (sent before byte chunks).
#[derive(Debug, Serialize, Deserialize)]
pub struct AddAssetRequest {
    pub project_id: String,
    pub filename: String,
    pub content_type: String,
    pub total_size: u64,
}

/// A chunk of file data streamed during asset upload.
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetChunk {
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAssetContentRequest {
    pub project_id: String,
    pub asset_id: String,
}

/// A chunk of content streamed during asset download.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentChunk {
    pub data: Vec<u8>,
    /// Content-Type, included in the first chunk only.
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTicketRpcRequest {
    pub project_id: String,
}

impl From<CreateTicketRpcRequest> for CreateTicketRequest {
    fn from(r: CreateTicketRpcRequest) -> Self {
        Self {
            project_id: r.project_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemTicketRpcRequest {
    pub ticket: String,
}

impl From<RedeemTicketRpcRequest> for crate::api::types::RedeemTicketRequest {
    fn from(r: RedeemTicketRpcRequest) -> Self {
        Self { ticket: r.ticket }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListVaultRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncVaultRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct PullVaultProjectRequest {
    pub project_id: String,
}

// =============================================================================
// Response types (RPC-specific, not shared with Axum)
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ListPeersResponse {
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncVaultResponse {
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullVaultResponse {
    pub status: String,
    pub project_id: String,
}
