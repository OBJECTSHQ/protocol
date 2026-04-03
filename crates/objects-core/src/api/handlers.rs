//! Node API shared types.

use crate::{NodeConfig, NodeState};
use objects_sync::SyncEngine;
use objects_transport::discovery::GossipDiscovery;
use objects_transport::{NodeAddr, NodeId, ObjectsEndpoint};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;

use super::registry::RegistryClient;

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

/// Shared state for the node engine.
///
/// Uses Arc for efficient sharing and appropriate synchronization primitives
/// for each field:
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
