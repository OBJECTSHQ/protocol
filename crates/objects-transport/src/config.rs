//! Network configuration for OBJECTS nodes.

use std::time::Duration;

use crate::{NodeAddr, RelayUrl, DEFAULT_RELAY_URL, DISCOVERY_TOPIC_DEVNET};

/// Network configuration for OBJECTS nodes.
///
/// Contains all parameters needed to join the OBJECTS network,
/// per RFC-002 §4 and §6.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Relay URL for NAT traversal.
    ///
    /// Per RFC-002 §4.1, nodes SHOULD include this in their published NodeAddr.
    pub relay_url: RelayUrl,

    /// Discovery topic for peer discovery.
    ///
    /// Per RFC-002 §4.1. Use [`DISCOVERY_TOPIC_DEVNET`] for devnet.
    pub discovery_topic: String,

    /// Bootstrap nodes to connect to on startup.
    ///
    /// Per RFC-002 §4.2, nodes joining the network for the first time
    /// MUST connect to at least one bootstrap node.
    pub bootstrap_nodes: Vec<NodeAddr>,

    // --- RFC-002 §6 Operational Limits ---
    /// Maximum simultaneous peer connections.
    ///
    /// Per RFC-002 §6.1, nodes SHOULD accept at least 50 connections.
    /// Default: 50
    pub max_connections: usize,

    /// Maximum concurrent streams per connection.
    ///
    /// Per RFC-002 §6.1, nodes MUST support at least 100 streams.
    /// Default: 100
    pub max_streams_per_conn: usize,

    // --- RFC-002 §6.2 Timeouts ---
    /// Close connection if no stream activity.
    ///
    /// Per RFC-002 §6.2. Default: 30 seconds.
    pub idle_timeout: Duration,

    /// Interval for NAT binding maintenance.
    ///
    /// Per RFC-002 §6.2. Default: 15 seconds.
    pub keepalive_interval: Duration,

    /// Maximum time for connection establishment.
    ///
    /// Per RFC-002 §6.2. Default: 30 seconds.
    pub connect_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL
                .parse()
                .expect("default relay URL should be valid"),
            discovery_topic: DISCOVERY_TOPIC_DEVNET.to_string(),
            bootstrap_nodes: Vec::new(),
            // RFC-002 §6.1 limits
            max_connections: 50,
            max_streams_per_conn: 100,
            // RFC-002 §6.2 timeouts (Iroh defaults)
            idle_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

impl NetworkConfig {
    /// Creates a new devnet configuration with defaults.
    ///
    /// Uses the OBJECTS devnet relay and discovery topic.
    pub fn devnet() -> Self {
        Self::default()
    }

    /// Add a bootstrap node to the configuration.
    pub fn with_bootstrap_node(mut self, node: NodeAddr) -> Self {
        self.bootstrap_nodes.push(node);
        self
    }

    /// Set the relay URL.
    pub fn with_relay_url(mut self, url: RelayUrl) -> Self {
        self.relay_url = url;
        self
    }

    /// Set the maximum number of connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }
}
