//! HTTP request handlers for the node API.

use crate::{NodeConfig, NodeState};
use objects_transport::discovery::GossipDiscovery;
use objects_transport::{NodeAddr, NodeId};
use std::sync::{Arc, Mutex, RwLock};

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
}
