//! Node engine — irpc server actor.
//!
//! Receives [`NodeCommand`] messages via an irpc channel and dispatches
//! to handler logic. This is the core of the embeddable node.

use base64::Engine as _;
use tracing::info;

use crate::api::handlers::AppState;
use crate::api::types::{HealthResponse, IdentityResponse, PeerInfo, StatusResponse};
use crate::rpc::proto::*;
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
    async fn run(self, mut rx: irpc::channel::mpsc::Receiver<NodeCommand>) {
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

            // --- Stubs for subsequent PRs ---
            NodeCommand::CreateIdentity(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::RenameIdentity(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::ListProjects(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::CreateProject(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::GetProject(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::ListAssets(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::AddAsset(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::GetAssetContent(_) => {
                // Server-streaming — dropping the sender signals no data
            }
            NodeCommand::CreateTicket(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::RedeemTicket(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::ListVault(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::SyncVault(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
            NodeCommand::PullVaultProject(msg) => {
                self.reply_not_implemented(msg.tx).await;
            }
        }
    }

    // =========================================================================
    // Handler implementations
    // =========================================================================

    /// Send a "not yet implemented" error for stub handlers.
    async fn reply_not_implemented<T: irpc::RpcMessage>(
        &self,
        tx: irpc::channel::oneshot::Sender<Result<T, RpcError>>,
    ) {
        tx.send(Err(RpcError::Internal("not yet implemented".into())))
            .await
            .ok();
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
            .map(|info| IdentityResponse {
                id: info.identity_id().to_string(),
                handle: info.handle().to_string(),
                nonce: base64::engine::general_purpose::STANDARD.encode(info.nonce()),
            });

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
            .map(|info| IdentityResponse {
                id: info.identity_id().to_string(),
                handle: info.handle().to_string(),
                nonce: base64::engine::general_purpose::STANDARD.encode(info.nonce()),
            })
            .ok_or_else(|| RpcError::NotFound("No identity registered".into()))
    }

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
