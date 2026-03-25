//! Shared configuration types for OBJECTS Protocol.
//!
//! These configuration structs are used by both the CLI and node daemon,
//! ensuring a single source of truth for configuration structure.

use serde::{Deserialize, Serialize};

/// Node-specific settings (data directory, API configuration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSettings {
    /// Data directory path (supports ~ for home directory).
    ///
    /// Environment variable: `OBJECTS_DATA_DIR`
    pub data_dir: String,
    /// Port for the node API server.
    ///
    /// Environment variable: `OBJECTS_API_PORT`
    pub api_port: u16,
    /// IP address to bind the API server to.
    ///
    /// Environment variable: `OBJECTS_API_BIND`
    pub api_bind: String,
}

impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            data_dir: dirs::home_dir()
                .map(|h| h.join(".objects").to_string_lossy().to_string())
                .unwrap_or_else(|| ".objects".to_string()),
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
    ///
    /// Environment variable: `OBJECTS_DISCOVERY_TOPIC`
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

/// CLI-specific settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliSettings {
    /// Optional API auth token (CLI-specific).
    ///
    /// Environment variable: `OBJECTS_API_TOKEN`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_node_settings() {
        let settings = NodeSettings::default();
        assert_eq!(settings.api_port, 3420);
        assert_eq!(settings.api_bind, "127.0.0.1");
        assert!(settings.data_dir.ends_with(".objects"));
    }

    #[test]
    fn test_default_network_settings() {
        let settings = NetworkSettings::default();
        assert_eq!(settings.relay_url, "https://relay.objects.foundation");
        assert_eq!(settings.discovery_topic, "/objects/devnet/0.1/discovery");
    }

    #[test]
    fn test_default_storage_settings() {
        let settings = StorageSettings::default();
        assert_eq!(settings.max_blob_size_mb, 100);
        assert_eq!(settings.max_total_size_gb, 10);
    }

    #[test]
    fn test_default_identity_settings() {
        let settings = IdentitySettings::default();
        assert_eq!(settings.registry_url, "https://registry.objects.foundation");
    }

    #[test]
    fn test_default_cli_settings() {
        let settings = CliSettings::default();
        assert!(settings.api_token.is_none());
    }
}
