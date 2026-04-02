//! Typed client for the node RPC service.
//!
//! [`NodeApi`] wraps an [`irpc::Client`] and provides ergonomic async methods
//! for each node operation. Works identically over local channels (in-process)
//! or QUIC connections (CLI → node).

use crate::api::types::{
    AssetListResponse, AssetResponse, HealthResponse, IdentityResponse, ProjectListResponse,
    ProjectResponse, StatusResponse, TicketResponse, VaultResponse,
};
use crate::rpc::proto::*;

/// Unified error type for NodeApi operations.
///
/// Flattens the two error layers (irpc transport + application RpcError)
/// into a single type. Callers use `?` once instead of `??`.
#[derive(Debug, thiserror::Error)]
pub enum NodeApiError {
    /// Transport-level failure (channel closed, serialization, connection dropped).
    #[error("transport: {0}")]
    Transport(#[from] irpc::Error),

    /// Streaming response channel closed before receiving a response.
    #[error("response channel closed")]
    ResponseClosed(#[from] irpc::channel::oneshot::RecvError),

    /// Application-level error (bad request, not found, registry error, etc.).
    #[error("{0}")]
    Rpc(#[from] RpcError),
}

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

    pub async fn health(&self) -> Result<HealthResponse, NodeApiError> {
        Ok(self.client.rpc(HealthRequest).await?)
    }

    pub async fn status(&self) -> Result<StatusResponse, NodeApiError> {
        Ok(self.client.rpc(StatusRequest).await?)
    }

    // =========================================================================
    // Identity
    // =========================================================================

    pub async fn get_identity(&self) -> Result<IdentityResponse, NodeApiError> {
        Ok(self.client.rpc(GetIdentityRequest).await??)
    }

    pub async fn create_identity(&self, handle: &str) -> Result<IdentityResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(CreateIdentityRpcRequest {
                handle: handle.to_owned(),
            })
            .await??)
    }

    pub async fn rename_identity(
        &self,
        new_handle: &str,
    ) -> Result<IdentityResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(RenameIdentityRpcRequest {
                new_handle: new_handle.to_owned(),
            })
            .await??)
    }

    // =========================================================================
    // Peers
    // =========================================================================

    pub async fn list_peers(&self) -> Result<ListPeersResponse, NodeApiError> {
        Ok(self.client.rpc(ListPeersRequest).await?)
    }

    // =========================================================================
    // Projects
    // =========================================================================

    pub async fn list_projects(&self) -> Result<ProjectListResponse, NodeApiError> {
        Ok(self.client.rpc(ListProjectsRequest).await??)
    }

    pub async fn create_project(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<ProjectResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(CreateProjectRpcRequest {
                name: name.to_owned(),
                description: description.map(str::to_owned),
            })
            .await??)
    }

    pub async fn get_project(&self, project_id: &str) -> Result<ProjectResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(GetProjectRequest {
                project_id: project_id.to_owned(),
            })
            .await??)
    }

    // =========================================================================
    // Assets
    // =========================================================================

    pub async fn list_assets(&self, project_id: &str) -> Result<AssetListResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(ListAssetsRequest {
                project_id: project_id.to_owned(),
            })
            .await??)
    }

    /// Upload an asset to a project via streaming chunks.
    pub async fn add_asset(
        &self,
        project_id: &str,
        filename: &str,
        content_type: &str,
        data: bytes::Bytes,
    ) -> Result<AssetResponse, NodeApiError> {
        let req = AddAssetRequest {
            project_id: project_id.to_owned(),
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
            total_size: data.len() as u64,
        };
        let (tx, rx) = self.client.client_streaming(req, 32).await?;

        for chunk in data.chunks(64 * 1024) {
            if tx
                .send(AssetChunk {
                    data: chunk.to_vec(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
        drop(tx);

        Ok(rx.await??)
    }

    /// Download asset content, returning (content_type, bytes).
    pub async fn get_asset_content(
        &self,
        project_id: &str,
        asset_id: &str,
    ) -> Result<(String, Vec<u8>), NodeApiError> {
        let req = GetAssetContentRequest {
            project_id: project_id.to_owned(),
            asset_id: asset_id.to_owned(),
        };
        let mut rx = self.client.server_streaming(req, 32).await?;

        let mut content_type = String::new();
        let mut data = Vec::new();
        while let Ok(Some(result)) = rx.recv().await {
            match result {
                Ok(chunk) => {
                    if let Some(ct) = chunk.content_type {
                        content_type = ct;
                    }
                    data.extend_from_slice(&chunk.data);
                }
                Err(e) => return Err(NodeApiError::Rpc(e)),
            }
        }
        Ok((content_type, data))
    }

    // =========================================================================
    // Tickets
    // =========================================================================

    pub async fn create_ticket(&self, project_id: &str) -> Result<TicketResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(CreateTicketRpcRequest {
                project_id: project_id.to_owned(),
            })
            .await??)
    }

    pub async fn redeem_ticket(&self, ticket: &str) -> Result<ProjectResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(RedeemTicketRpcRequest {
                ticket: ticket.to_owned(),
            })
            .await??)
    }

    // =========================================================================
    // Vault
    // =========================================================================

    pub async fn list_vault(&self) -> Result<VaultResponse, NodeApiError> {
        Ok(self.client.rpc(ListVaultRequest).await??)
    }

    pub async fn sync_vault(&self) -> Result<SyncVaultResponse, NodeApiError> {
        Ok(self.client.rpc(SyncVaultRequest).await??)
    }

    pub async fn pull_vault_project(
        &self,
        project_id: &str,
    ) -> Result<PullVaultResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(PullVaultProjectRequest {
                project_id: project_id.to_owned(),
            })
            .await??)
    }
}
