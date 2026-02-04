//! API request and response types.

use objects_transport::NodeAddr;
use serde::{Deserialize, Serialize};

/// Response for the health check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    /// Status of the node ("ok" if healthy).
    pub status: String,
}

/// Response for the node status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node ID as a string.
    pub node_id: String,
    /// Node address with relay information.
    pub node_addr: NodeAddr,
    /// Number of currently discovered peers.
    pub peer_count: usize,
    /// Identity information if registered.
    pub identity: Option<IdentityResponse>,
    /// Relay URL the node is connected to.
    pub relay_url: String,
}

/// Identity information response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityResponse {
    /// Identity ID (e.g., "obj_2dMiYc8RhnYkorPc5pVh9").
    pub id: String,
    /// Handle (e.g., "@alice").
    pub handle: String,
    /// 8-byte nonce encoded as hex.
    pub nonce: String,
    /// Signer type ("passkey" or "wallet").
    pub signer_type: String,
}

/// Peer information for listing discovered peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's node ID.
    pub node_id: String,
    /// Peer's relay URL if known.
    pub relay_url: Option<String>,
    /// Human-readable time since last seen (e.g., "2m ago").
    pub last_seen_ago: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "ok".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"status":"ok"}"#);

        let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_identity_response_serialization() {
        let response = IdentityResponse {
            id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
            handle: "@alice".to_string(),
            nonce: "0102030405060708".to_string(),
            signer_type: "passkey".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: IdentityResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_peer_info_serialization() {
        let peer = PeerInfo {
            node_id: "abc123".to_string(),
            relay_url: Some("https://relay.example.com".to_string()),
            last_seen_ago: "5m ago".to_string(),
        };

        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.node_id, peer.node_id);
    }
}
