//! Typed client for the node RPC service.
//!
//! [`NodeApi`] wraps an [`irpc::Client`] and provides ergonomic async methods
//! for each node operation. Works identically over local channels (in-process)
//! or QUIC connections (CLI → node).

use crate::api::types::{
    AssetListResponse, HealthResponse, IdentityResponse, ProjectListResponse, ProjectResponse,
    StatusResponse, TicketResponse, VaultResponse,
};
use crate::rpc::proto::*;

/// Typed client for the OBJECTS node RPC service.
///
/// Created via [`NodeEngine::spawn`](crate::engine::NodeEngine::spawn)
/// for in-process use, or constructed from a remote irpc connection.
#[derive(Clone)]
pub struct NodeApi {
    client: irpc::Client<NodeProtocol>,
}

impl NodeApi {
    /// Create a local (in-process) client.
    pub fn local(tx: irpc::channel::mpsc::Sender<NodeCommand>) -> Self {
        Self {
            client: irpc::Client::local(tx),
        }
    }

    /// Create from an existing irpc Client (e.g. from irpc-iroh remote connection).
    pub fn from_client(client: irpc::Client<NodeProtocol>) -> Self {
        Self { client }
    }

    // =========================================================================
    // Health & Status
    // =========================================================================

    pub async fn health(&self) -> Result<HealthResponse, irpc::Error> {
        self.client.rpc(HealthRequest).await
    }

    pub async fn status(&self) -> Result<StatusResponse, irpc::Error> {
        self.client.rpc(StatusRequest).await
    }

    // =========================================================================
    // Identity
    // =========================================================================

    pub async fn get_identity(&self) -> Result<Result<IdentityResponse, RpcError>, irpc::Error> {
        self.client.rpc(GetIdentityRequest).await
    }

    pub async fn create_identity(
        &self,
        handle: impl Into<String>,
    ) -> Result<Result<IdentityResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(CreateIdentityRpcRequest {
                handle: handle.into(),
            })
            .await
    }

    pub async fn rename_identity(
        &self,
        new_handle: impl Into<String>,
    ) -> Result<Result<IdentityResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(RenameIdentityRpcRequest {
                new_handle: new_handle.into(),
            })
            .await
    }

    // =========================================================================
    // Peers
    // =========================================================================

    pub async fn list_peers(&self) -> Result<ListPeersResponse, irpc::Error> {
        self.client.rpc(ListPeersRequest).await
    }

    // =========================================================================
    // Projects
    // =========================================================================

    pub async fn list_projects(
        &self,
    ) -> Result<Result<ProjectListResponse, RpcError>, irpc::Error> {
        self.client.rpc(ListProjectsRequest).await
    }

    pub async fn create_project(
        &self,
        name: impl Into<String>,
        description: Option<String>,
    ) -> Result<Result<ProjectResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(CreateProjectRpcRequest {
                name: name.into(),
                description,
            })
            .await
    }

    pub async fn get_project(
        &self,
        project_id: impl Into<String>,
    ) -> Result<Result<ProjectResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(GetProjectRequest {
                project_id: project_id.into(),
            })
            .await
    }

    // =========================================================================
    // Assets
    // =========================================================================

    pub async fn list_assets(
        &self,
        project_id: impl Into<String>,
    ) -> Result<Result<AssetListResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(ListAssetsRequest {
                project_id: project_id.into(),
            })
            .await
    }

    // TODO: add_asset (streaming) — PR 5c
    // TODO: get_asset_content (streaming) — PR 5c

    // =========================================================================
    // Tickets
    // =========================================================================

    pub async fn create_ticket(
        &self,
        project_id: impl Into<String>,
    ) -> Result<Result<TicketResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(CreateTicketRpcRequest {
                project_id: project_id.into(),
            })
            .await
    }

    pub async fn redeem_ticket(
        &self,
        ticket: impl Into<String>,
    ) -> Result<Result<ProjectResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(RedeemTicketRpcRequest {
                ticket: ticket.into(),
            })
            .await
    }

    // =========================================================================
    // Vault
    // =========================================================================

    pub async fn list_vault(&self) -> Result<Result<VaultResponse, RpcError>, irpc::Error> {
        self.client.rpc(ListVaultRequest).await
    }

    pub async fn sync_vault(&self) -> Result<Result<SyncVaultResponse, RpcError>, irpc::Error> {
        self.client.rpc(SyncVaultRequest).await
    }

    pub async fn pull_vault_project(
        &self,
        project_id: impl Into<String>,
    ) -> Result<Result<PullVaultResponse, RpcError>, irpc::Error> {
        self.client
            .rpc(PullVaultProjectRequest {
                project_id: project_id.into(),
            })
            .await
    }
}
