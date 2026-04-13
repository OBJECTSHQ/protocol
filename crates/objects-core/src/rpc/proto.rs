//! Node RPC protocol definition.
//!
//! Uses irpc's `#[rpc_requests]` macro to generate the message enum
//! and channel boilerplate. Follows the same pattern as iroh-blobs.
//!
//! Request, response, and shared types are generated from
//! `proto/objects/node/v1/node.proto` via prost-build (see `build.rs`).

use irpc::{
    channel::{mpsc, oneshot},
    rpc_requests,
};
use serde::{Deserialize, Serialize};

// Re-export all proto-generated types.
pub use crate::proto_gen::*;

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
    #[rpc(tx = oneshot::Sender<Result<GetIdentityResponse, RpcError>>)]
    GetIdentity(GetIdentityRequest),

    #[rpc(tx = oneshot::Sender<Result<CreateIdentityResponse, RpcError>>)]
    CreateIdentity(CreateIdentityRequest),

    #[rpc(tx = oneshot::Sender<Result<RenameIdentityResponse, RpcError>>)]
    RenameIdentity(RenameIdentityRequest),

    // --- Peers ---
    #[rpc(tx = oneshot::Sender<ListPeersResponse>)]
    ListPeers(ListPeersRequest),

    // --- Projects ---
    #[rpc(tx = oneshot::Sender<Result<ListProjectsResponse, RpcError>>)]
    ListProjects(ListProjectsRequest),

    #[rpc(tx = oneshot::Sender<Result<CreateProjectResponse, RpcError>>)]
    CreateProject(CreateProjectRequest),

    #[rpc(tx = oneshot::Sender<Result<GetProjectResponse, RpcError>>)]
    GetProject(GetProjectRequest),

    // --- Assets ---
    #[rpc(tx = oneshot::Sender<Result<ListAssetsResponse, RpcError>>)]
    ListAssets(ListAssetsRequest),

    /// Client streams file bytes, server responds with asset metadata.
    #[rpc(rx = mpsc::Receiver<AssetChunk>, tx = oneshot::Sender<Result<AddAssetResponse, RpcError>>)]
    AddAsset(AddAssetMetadata),

    /// Server streams content bytes back to client.
    #[rpc(tx = mpsc::Sender<Result<GetAssetContentResponse, RpcError>>)]
    GetAssetContent(GetAssetContentRequest),

    // --- Tickets ---
    #[rpc(tx = oneshot::Sender<Result<CreateTicketResponse, RpcError>>)]
    CreateTicket(CreateTicketRequest),

    #[rpc(tx = oneshot::Sender<Result<RedeemTicketResponse, RpcError>>)]
    RedeemTicket(RedeemTicketRequest),

    // --- Vault ---
    #[rpc(tx = oneshot::Sender<Result<ListVaultResponse, RpcError>>)]
    ListVault(ListVaultRequest),

    #[rpc(tx = oneshot::Sender<Result<SyncVaultResponse, RpcError>>)]
    SyncVault(SyncVaultRequest),

    #[rpc(tx = oneshot::Sender<Result<PullProjectResponse, RpcError>>)]
    PullVaultProject(PullProjectRequest),
}

// =============================================================================
// Streaming types (not in proto — irpc-specific wire types)
// =============================================================================

/// A chunk of file data streamed during asset upload.
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetChunk {
    pub data: Vec<u8>,
}
