//! Typed client for the node RPC service.
//!
//! [`NodeApi`] wraps an [`irpc::Client`] and provides ergonomic async methods
//! for each node operation. Works identically over local channels (in-process)
//! or QUIC connections (CLI → node).

use crate::api::types::{
    AssetInfo, HealthResponse, IdentityInfo, ListAssetsResponse, ListProjectsResponse, ProjectInfo,
    StatusResponse,
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
        Ok(self.client.rpc(HealthRequest {}).await?)
    }

    pub async fn status(&self) -> Result<StatusResponse, NodeApiError> {
        Ok(self.client.rpc(StatusRequest {}).await?)
    }

    // =========================================================================
    // Identity
    // =========================================================================

    pub async fn get_identity(&self) -> Result<IdentityInfo, NodeApiError> {
        let resp = self.client.rpc(GetIdentityRequest {}).await??;
        Ok(resp
            .identity
            .ok_or_else(|| RpcError::Internal("Missing identity in response".into()))?)
    }

    pub async fn create_identity(&self, handle: &str) -> Result<IdentityInfo, NodeApiError> {
        let resp = self
            .client
            .rpc(CreateIdentityRequest {
                handle: handle.to_owned(),
            })
            .await??;
        Ok(resp
            .identity
            .ok_or_else(|| RpcError::Internal("Missing identity in response".into()))?)
    }

    pub async fn rename_identity(&self, new_handle: &str) -> Result<IdentityInfo, NodeApiError> {
        let resp = self
            .client
            .rpc(RenameIdentityRequest {
                new_handle: new_handle.to_owned(),
            })
            .await??;
        Ok(resp
            .identity
            .ok_or_else(|| RpcError::Internal("Missing identity in response".into()))?)
    }

    // =========================================================================
    // Peers
    // =========================================================================

    pub async fn list_peers(&self) -> Result<ListPeersResponse, NodeApiError> {
        Ok(self.client.rpc(ListPeersRequest {}).await?)
    }

    // =========================================================================
    // Projects
    // =========================================================================

    pub async fn list_projects(&self) -> Result<ListProjectsResponse, NodeApiError> {
        Ok(self.client.rpc(ListProjectsRequest {}).await??)
    }

    pub async fn create_project(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<ProjectInfo, NodeApiError> {
        let resp = self
            .client
            .rpc(CreateProjectRequest {
                name: name.to_owned(),
                description: description.map(str::to_owned),
            })
            .await??;
        Ok(resp
            .project
            .ok_or_else(|| RpcError::Internal("Missing project in response".into()))?)
    }

    pub async fn get_project(&self, project_id: &str) -> Result<ProjectInfo, NodeApiError> {
        let resp = self
            .client
            .rpc(GetProjectRequest {
                project_id: project_id.to_owned(),
            })
            .await??;
        Ok(resp
            .project
            .ok_or_else(|| RpcError::Internal("Missing project in response".into()))?)
    }

    // =========================================================================
    // Assets
    // =========================================================================

    pub async fn list_assets(&self, project_id: &str) -> Result<ListAssetsResponse, NodeApiError> {
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
    ) -> Result<AssetInfo, NodeApiError> {
        let req = AddAssetMetadata {
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

        let resp = rx.await??;
        Ok(resp
            .asset
            .ok_or_else(|| RpcError::Internal("Missing asset in response".into()))?)
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

    pub async fn create_ticket(
        &self,
        project_id: &str,
    ) -> Result<CreateTicketResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(CreateTicketRequest {
                project_id: project_id.to_owned(),
            })
            .await??)
    }

    pub async fn redeem_ticket(&self, ticket: &str) -> Result<ProjectInfo, NodeApiError> {
        let resp = self
            .client
            .rpc(RedeemTicketRequest {
                ticket: ticket.to_owned(),
            })
            .await??;
        Ok(resp
            .project
            .ok_or_else(|| RpcError::Internal("Missing project in response".into()))?)
    }

    // =========================================================================
    // Vault
    // =========================================================================

    pub async fn list_vault(&self) -> Result<ListVaultResponse, NodeApiError> {
        Ok(self.client.rpc(ListVaultRequest {}).await??)
    }

    pub async fn sync_vault(&self) -> Result<SyncVaultResponse, NodeApiError> {
        Ok(self.client.rpc(SyncVaultRequest {}).await??)
    }

    pub async fn pull_vault_project(
        &self,
        project_id: &str,
    ) -> Result<PullProjectResponse, NodeApiError> {
        Ok(self
            .client
            .rpc(PullProjectRequest {
                project_id: project_id.to_owned(),
            })
            .await??)
    }
}
