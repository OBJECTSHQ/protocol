//! Node engine — irpc server actor.
//!
//! Receives [`NodeCommand`] messages via an irpc channel and dispatches
//! to handler logic. This is the core of the embeddable node.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use tracing::info;

use crate::api::handlers::AppState;
use crate::api::registry;
use crate::api::types::{HealthResponse, IdentityResponse, PeerInfo, StatusResponse};
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

            NodeCommand::CreateIdentity(msg) => {
                let resp = self.handle_create_identity(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }
            NodeCommand::RenameIdentity(msg) => {
                let resp = self.handle_rename_identity(msg.inner).await;
                msg.tx.send(resp).await.ok();
            }

            // --- Stubs for subsequent PRs ---
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

    async fn handle_create_identity(
        &self,
        req: CreateIdentityRpcRequest,
    ) -> Result<IdentityResponse, RpcError> {
        // 1. Validate handle format
        let handle = Handle::parse(&req.handle).map_err(|e| RpcError::BadRequest(e.to_string()))?;

        // 2. Generate Ed25519 signing key (random, OS entropy)
        let signing_key = Ed25519SigningKey::generate();
        let public_key = signing_key.public_key_bytes();

        // 3. Generate cryptographic nonce (8 bytes, OS entropy)
        let nonce = generate_nonce();

        // 4. Derive identity ID: SHA256(public_key || nonce)
        let identity_id = IdentityId::derive(&public_key, &nonce);

        // 5. Timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RpcError::Internal(format!("System time error: {e}")))?
            .as_secs();

        // 6. Sign create-identity message per RFC-001
        let message = create_identity_message(identity_id.as_str(), handle.as_str(), timestamp);
        let signature = signing_key.sign(message.as_bytes());

        // 7. Build registry request
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

        // 8. Register with the registry
        let registry_response = self
            .state
            .registry_client
            .create_identity(registry_request)
            .await
            .map_err(|e| RpcError::Registry(e.to_string()))?;

        // 9. Persist signing key + identity in node state
        let identity_info = IdentityInfo::with_signing_key(
            IdentityId::parse(&registry_response.id)
                .map_err(|e| RpcError::Internal(format!("Invalid identity ID: {e}")))?,
            Handle::parse(&registry_response.handle)
                .map_err(|e| RpcError::Internal(format!("Invalid handle: {e}")))?,
            nonce,
            signing_key.to_bytes(),
        );

        {
            let mut node_state = self.state.node_state.write().unwrap();
            node_state.set_identity(identity_info.clone());
            let state_path = Path::new(&self.state.config.node.data_dir).join("node.key");
            node_state
                .save(&state_path)
                .map_err(|e| RpcError::Internal(format!("Failed to save state: {e}")))?;
        }

        // 10. Create vault replica for cross-device project discovery
        if let Some(signing_key_bytes) = identity_info.signing_key() {
            let vault_keys =
                objects_identity::vault::VaultKeys::derive_from_signing_key(signing_key_bytes)
                    .map_err(|e| RpcError::Internal(format!("Failed to derive vault keys: {e}")))?;

            self.state
                .sync_engine
                .docs()
                .create_replica_with_secret(vault_keys.namespace_secret().clone())
                .await
                .map_err(|e| RpcError::Internal(format!("Failed to create vault replica: {e}")))?;

            info!("Vault replica created: {}", vault_keys.namespace_id());

            let mut node_state = self.state.node_state.write().unwrap();
            if let Some(identity) = node_state.identity_mut() {
                identity.set_vault_namespace_id(vault_keys.namespace_id().to_string());
            }
            let state_path = Path::new(&self.state.config.node.data_dir).join("node.key");
            node_state
                .save(&state_path)
                .map_err(|e| RpcError::Internal(format!("Failed to save vault state: {e}")))?;
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
        // 1. Validate new handle
        let new_handle =
            Handle::parse(&req.new_handle).map_err(|e| RpcError::BadRequest(e.to_string()))?;

        // 2. Get current identity + signing key
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

        // 3. Sign the change-handle message
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RpcError::Internal(format!("System time error: {e}")))?
            .as_secs();

        let message = change_handle_message(identity_id.as_str(), new_handle.as_str(), timestamp);
        let signing_key = Ed25519SigningKey::from_bytes(&signing_key_bytes);
        let signature = signing_key.sign(message.as_bytes());

        // 4. Build registry request
        let b64 = &base64::engine::general_purpose::STANDARD;
        let registry_request = serde_json::json!({
            "new_handle": new_handle.as_str(),
            "timestamp": timestamp,
            "signature": {
                "signature": b64.encode(signature.signature_bytes()),
                "public_key": b64.encode(signature.public_key_bytes()),
            }
        });

        // 5. Call registry
        self.state
            .registry_client
            .change_handle(identity_id.as_str(), registry_request)
            .await
            .map_err(|e| RpcError::Registry(e.to_string()))?;

        // 6. Update local state
        {
            let mut node_state = self.state.node_state.write().unwrap();
            if let Some(identity) = node_state.identity_mut() {
                identity.set_handle(new_handle.clone());
            }
            let state_path = Path::new(&self.state.config.node.data_dir).join("node.key");
            node_state
                .save(&state_path)
                .map_err(|e| RpcError::Internal(format!("Failed to save state: {e}")))?;
        }

        info!("Identity renamed to @{}", new_handle);

        Ok(IdentityResponse {
            id: identity_id.to_string(),
            handle: new_handle.to_string(),
            nonce: String::new(),
        })
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
