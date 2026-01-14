//! Network configuration.

use serde::{Deserialize, Serialize};

use crate::{DEFAULT_RELAY_URL, DISCOVERY_TOPIC_DEVNET};

/// Network configuration for OBJECTS nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Relay URL for NAT traversal.
    pub relay_url: String,
    /// Discovery topic for peer discovery.
    pub discovery_topic: String,
    /// Bootstrap node IDs (z-base-32 encoded).
    pub bootstrap_nodes: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL.to_string(),
            discovery_topic: DISCOVERY_TOPIC_DEVNET.to_string(),
            bootstrap_nodes: Vec::new(),
        }
    }
}

impl NetworkConfig {
    /// Creates a new devnet configuration.
    pub fn devnet() -> Self {
        Self::default()
    }
}
