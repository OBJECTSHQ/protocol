//! Configuration types for the OBJECTS node daemon.

use serde::{Deserialize, Serialize};

/// Main configuration for the OBJECTS node daemon.
///
/// Configuration is loaded from a TOML file and can be overridden by environment variables.
/// See individual field documentation for environment variable names.
///
/// # Example
///
/// ```
/// use objects_node::config::NodeConfig;
///
/// let config = NodeConfig::default();
/// assert_eq!(config.node.api_port, 3420);
/// assert_eq!(config.network.relay_url, "https://relay.objects.foundation");
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node-specific settings (data directory, API configuration).
    pub node: NodeSettings,
    /// Network settings (relay, discovery).
    pub network: NetworkSettings,
    /// Storage limits and constraints.
    pub storage: StorageSettings,
    /// Identity and registry settings.
    pub identity: IdentitySettings,
}

/// Node-specific configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSettings {
    /// Directory for node data storage (config, state, blobs).
    ///
    /// Environment variable: `OBJECTS_DATA_DIR`
    pub data_dir: String,
    /// Port for the node API server.
    ///
    /// Environment variable: `OBJECTS_API_PORT`
    pub api_port: u16,
    /// IP address to bind the API server to.
    pub api_bind: String,
}

impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            data_dir: "~/.objects".to_string(),
            api_port: 3420,
            api_bind: "127.0.0.1".to_string(),
        }
    }
}

/// Network configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// URL of the relay server for NAT traversal.
    ///
    /// Environment variable: `OBJECTS_RELAY_URL`
    pub relay_url: String,
    /// Discovery topic for peer discovery.
    ///
    /// Format: `/objects/{network}/0.1/discovery` where network is `devnet` or `mainnet`.
    pub discovery_topic: String,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            relay_url: "https://relay.objects.foundation".to_string(),
            discovery_topic: "/objects/devnet/0.1/discovery".to_string(),
        }
    }
}

/// Storage configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Maximum size for a single blob in megabytes.
    pub max_blob_size_mb: u64,
    /// Maximum total storage size in gigabytes.
    pub max_total_size_gb: u64,
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self {
            max_blob_size_mb: 100,
            max_total_size_gb: 10,
        }
    }
}

/// Identity and registry configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySettings {
    /// URL of the OBJECTS registry service.
    ///
    /// Environment variable: `OBJECTS_REGISTRY_URL`
    pub registry_url: String,
}

impl Default for IdentitySettings {
    fn default() -> Self {
        Self {
            registry_url: "https://registry.objects.foundation".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_serialization() {
        let config = NodeConfig::default();

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&config).unwrap();

        // Deserialize back
        let deserialized: NodeConfig = serde_json::from_str(&json).unwrap();

        // Verify round-trip
        assert_eq!(config.node.api_port, deserialized.node.api_port);
        assert_eq!(config.node.data_dir, deserialized.node.data_dir);
        assert_eq!(config.network.relay_url, deserialized.network.relay_url);
        assert_eq!(
            config.network.discovery_topic,
            deserialized.network.discovery_topic
        );
    }

    #[test]
    fn test_default_values() {
        let config = NodeConfig::default();

        assert_eq!(config.node.data_dir, "~/.objects");
        assert_eq!(config.node.api_port, 3420);
        assert_eq!(config.node.api_bind, "127.0.0.1");
        assert_eq!(config.network.relay_url, "https://relay.objects.foundation");
        assert_eq!(
            config.network.discovery_topic,
            "/objects/devnet/0.1/discovery"
        );
        assert_eq!(
            config.identity.registry_url,
            "https://registry.objects.foundation"
        );
        assert_eq!(config.storage.max_blob_size_mb, 100);
        assert_eq!(config.storage.max_total_size_gb, 10);
    }
}
