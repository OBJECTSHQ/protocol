//! Network configuration for OBJECTS nodes.

use std::time::Duration;

use crate::error::ConfigError;
use crate::{DEFAULT_RELAY_URL, DISCOVERY_TOPIC_DEVNET, NodeAddr, RelayUrl};

/// Network configuration for OBJECTS nodes.
///
/// Contains all parameters needed to join the OBJECTS network,
/// per RFC-002 §4 and §6.
///
/// Use [`NetworkConfig::builder()`] to construct with validation,
/// or [`NetworkConfig::devnet()`] for development defaults.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Relay URL for NAT traversal.
    relay_url: RelayUrl,

    /// Discovery topic for peer discovery.
    discovery_topic: String,

    /// Bootstrap nodes to connect to on startup.
    bootstrap_nodes: Vec<NodeAddr>,

    /// Maximum simultaneous peer connections.
    max_connections: usize,

    /// Maximum concurrent streams per connection.
    max_streams_per_conn: usize,

    /// Close connection if no stream activity.
    idle_timeout: Duration,

    /// Interval for NAT binding maintenance.
    keepalive_interval: Duration,

    /// Maximum time for connection establishment.
    connect_timeout: Duration,
}

impl NetworkConfig {
    /// Create a new configuration builder.
    pub fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::new()
    }

    /// Creates a devnet configuration with validated defaults.
    ///
    /// Uses the OBJECTS devnet relay and discovery topic.
    pub fn devnet() -> Self {
        // These defaults are validated to meet RFC-002 requirements
        Self {
            relay_url: DEFAULT_RELAY_URL
                .parse()
                .expect("default relay URL should be valid"),
            discovery_topic: DISCOVERY_TOPIC_DEVNET.to_string(),
            bootstrap_nodes: Vec::new(),
            max_connections: 50,
            max_streams_per_conn: 100,
            idle_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(30),
        }
    }

    // --- Getters ---

    /// Relay URL for NAT traversal.
    ///
    /// Per RFC-002 §4.1, nodes SHOULD include this in their published NodeAddr.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }

    /// Discovery topic for peer discovery.
    ///
    /// Per RFC-002 §4.1.
    pub fn discovery_topic(&self) -> &str {
        &self.discovery_topic
    }

    /// Bootstrap nodes to connect to on startup.
    ///
    /// Per RFC-002 §4.2, nodes joining the network for the first time
    /// MUST connect to at least one bootstrap node.
    pub fn bootstrap_nodes(&self) -> &[NodeAddr] {
        &self.bootstrap_nodes
    }

    /// Maximum simultaneous peer connections.
    ///
    /// Per RFC-002 §6.1, nodes SHOULD accept at least 50 connections.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Maximum concurrent streams per connection.
    ///
    /// Per RFC-002 §6.1, nodes MUST support at least 100 streams.
    pub fn max_streams_per_conn(&self) -> usize {
        self.max_streams_per_conn
    }

    /// Close connection if no stream activity.
    ///
    /// Per RFC-002 §6.2.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Interval for NAT binding maintenance.
    ///
    /// Per RFC-002 §6.2.
    pub fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    /// Maximum time for connection establishment.
    ///
    /// Per RFC-002 §6.2.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

/// Builder for [`NetworkConfig`] with RFC-002 validation.
///
/// # Example
///
/// ```rust,ignore
/// use objects_transport::NetworkConfig;
///
/// let config = NetworkConfig::builder()
///     .max_connections(100)
///     .idle_timeout(Duration::from_secs(60))
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct NetworkConfigBuilder {
    relay_url: Option<RelayUrl>,
    discovery_topic: String,
    bootstrap_nodes: Vec<NodeAddr>,
    max_connections: usize,
    max_streams_per_conn: usize,
    idle_timeout: Duration,
    keepalive_interval: Duration,
    connect_timeout: Duration,
}

impl NetworkConfigBuilder {
    /// Create a new builder with RFC-002 compliant defaults.
    pub fn new() -> Self {
        Self {
            relay_url: None,
            discovery_topic: DISCOVERY_TOPIC_DEVNET.to_string(),
            bootstrap_nodes: Vec::new(),
            // RFC-002 §6.1 minimums
            max_connections: 50,
            max_streams_per_conn: 100,
            // RFC-002 §6.2 timeouts
            idle_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(30),
        }
    }

    /// Set the relay URL.
    pub fn relay_url(mut self, url: RelayUrl) -> Self {
        self.relay_url = Some(url);
        self
    }

    /// Set the discovery topic.
    pub fn discovery_topic(mut self, topic: impl Into<String>) -> Self {
        self.discovery_topic = topic.into();
        self
    }

    /// Add a bootstrap node.
    pub fn bootstrap_node(mut self, node: NodeAddr) -> Self {
        self.bootstrap_nodes.push(node);
        self
    }

    /// Add multiple bootstrap nodes.
    pub fn bootstrap_nodes(mut self, nodes: impl IntoIterator<Item = NodeAddr>) -> Self {
        self.bootstrap_nodes.extend(nodes);
        self
    }

    /// Set the maximum number of connections.
    ///
    /// Per RFC-002 §6.1, must be at least 50.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the maximum streams per connection.
    ///
    /// Per RFC-002 §6.1, must be at least 100.
    pub fn max_streams_per_conn(mut self, max: usize) -> Self {
        self.max_streams_per_conn = max;
        self
    }

    /// Set the idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the keepalive interval.
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Set the connect timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Build the configuration with validation.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if:
    /// - `max_connections` is less than 50 (RFC-002 §6.1)
    /// - `max_streams_per_conn` is less than 100 (RFC-002 §6.1)
    pub fn build(self) -> Result<NetworkConfig, ConfigError> {
        // RFC-002 §6.1: Nodes SHOULD accept at least 50 connections
        if self.max_connections < 50 {
            return Err(ConfigError::BelowMinimum {
                field: "max_connections",
                minimum: 50,
                provided: self.max_connections,
            });
        }

        // RFC-002 §6.1: Nodes MUST support at least 100 streams per connection
        if self.max_streams_per_conn < 100 {
            return Err(ConfigError::BelowMinimum {
                field: "max_streams_per_conn",
                minimum: 100,
                provided: self.max_streams_per_conn,
            });
        }

        // Validate max_streams_per_conn fits in u32 (required by QUIC transport config)
        if self.max_streams_per_conn > u32::MAX as usize {
            return Err(ConfigError::AboveMaximum {
                field: "max_streams_per_conn",
                maximum: u32::MAX as u64,
                provided: self.max_streams_per_conn as u64,
            });
        }

        // Validate idle_timeout can be converted to QUIC's VarInt (in milliseconds)
        let timeout_ms = self.idle_timeout.as_millis() as u64;
        let _: iroh::endpoint::VarInt = timeout_ms.try_into().map_err(|_| {
            ConfigError::InvalidIdleTimeout(format!(
                "idle_timeout {:?} exceeds QUIC VarInt maximum (2^62 - 1 milliseconds)",
                self.idle_timeout
            ))
        })?;

        let relay_url = self.relay_url.unwrap_or_else(|| {
            DEFAULT_RELAY_URL
                .parse()
                .expect("default relay URL should be valid")
        });

        Ok(NetworkConfig {
            relay_url,
            discovery_topic: self.discovery_topic,
            bootstrap_nodes: self.bootstrap_nodes,
            max_connections: self.max_connections,
            max_streams_per_conn: self.max_streams_per_conn,
            idle_timeout: self.idle_timeout,
            keepalive_interval: self.keepalive_interval,
            connect_timeout: self.connect_timeout,
        })
    }
}

impl Default for NetworkConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_config_is_valid() {
        let config = NetworkConfig::devnet();
        assert!(config.max_connections() >= 50);
        assert!(config.max_streams_per_conn() >= 100);
    }

    #[test]
    fn builder_validates_max_connections() {
        let result = NetworkConfig::builder().max_connections(10).build();
        assert!(matches!(
            result,
            Err(ConfigError::BelowMinimum {
                field: "max_connections",
                ..
            })
        ));
    }

    #[test]
    fn builder_validates_max_streams() {
        let result = NetworkConfig::builder().max_streams_per_conn(50).build();
        assert!(matches!(
            result,
            Err(ConfigError::BelowMinimum {
                field: "max_streams_per_conn",
                ..
            })
        ));
    }

    #[test]
    fn builder_accepts_valid_config() {
        let config = NetworkConfig::builder()
            .max_connections(100)
            .max_streams_per_conn(200)
            .idle_timeout(Duration::from_secs(60))
            .build()
            .expect("valid config should build");

        assert_eq!(config.max_connections(), 100);
        assert_eq!(config.max_streams_per_conn(), 200);
        assert_eq!(config.idle_timeout(), Duration::from_secs(60));
    }
}
