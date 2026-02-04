//! Configuration types for the OBJECTS node daemon.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;
use url::Url;

/// Errors that can occur during configuration loading and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O error reading or writing configuration file.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Error parsing TOML configuration file.
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Configuration validation failed.
    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

/// Result type for configuration operations.
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Main configuration for the OBJECTS node daemon.
///
/// Configuration is loaded from a TOML file and can be overridden by environment variables.
/// See individual field documentation for environment variable names.
///
/// Configuration precedence (highest to lowest):
/// 1. Environment variables
/// 2. Config file values
/// 3. Default values
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

impl NodeConfig {
    /// Load configuration from environment variables only.
    ///
    /// Starts with default values and applies environment variable overrides.
    pub fn from_env() -> Result<Self> {
        tracing::debug!("Loading configuration from environment variables");
        let mut config = Self::default();
        config.apply_env_overrides();
        config.validate().map_err(|e| {
            tracing::error!(error = %e, "Configuration validation failed");
            e
        })?;
        tracing::info!("Successfully loaded configuration from environment");
        Ok(config)
    }

    /// Load configuration from a TOML file, creating it with defaults if it doesn't exist.
    ///
    /// If the file exists, it is loaded and environment variables are applied as overrides.
    /// If the file doesn't exist, a default configuration is created and saved to the file.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        tracing::debug!(path = %path.display(), "Loading or creating configuration");

        let mut config = if path.exists() {
            tracing::debug!(path = %path.display(), "Configuration file exists, loading");
            Self::load(path)?
        } else {
            tracing::info!(path = %path.display(), "Configuration file doesn't exist, creating with defaults");
            Self::default()
        };

        config.apply_env_overrides();
        config.validate()?;

        if !path.exists() {
            config.save(path)?;
            tracing::info!(path = %path.display(), "Created configuration file");
        }

        Ok(config)
    }

    /// Load configuration from a TOML file.
    ///
    /// Returns an error if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        tracing::debug!(path = %path.display(), "Loading configuration from file");

        let contents = std::fs::read_to_string(path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "Failed to read configuration file");
            ConfigError::IoError(e)
        })?;

        let config: Self = toml::from_str(&contents).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "Failed to parse TOML configuration");
            ConfigError::ParseError(e)
        })?;

        tracing::debug!(path = %path.display(), "Successfully loaded configuration from file");
        Ok(config)
    }

    /// Save configuration to a TOML file.
    ///
    /// Creates parent directories if they don't exist.
    pub fn save(&self, path: &Path) -> Result<()> {
        tracing::debug!(path = %path.display(), "Saving configuration to file");

        if let Some(parent) = path.parent() {
            tracing::debug!(parent = %parent.display(), "Creating parent directories");
            std::fs::create_dir_all(parent).map_err(|e| {
                tracing::error!(parent = %parent.display(), error = %e, "Failed to create parent directories");
                ConfigError::IoError(e)
            })?;
        }

        let contents = toml::to_string_pretty(self).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "Failed to serialize configuration to TOML");
            ConfigError::ValidationError(format!("Failed to serialize config: {}", e))
        })?;

        std::fs::write(path, &contents).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "Failed to write configuration file");
            ConfigError::IoError(e)
        })?;

        tracing::info!(path = %path.display(), "Successfully saved configuration");
        Ok(())
    }

    /// Validate configuration values.
    ///
    /// Checks:
    /// - API port is in valid range (1024-65535)
    /// - API bind address is a valid IP address
    /// - Relay URL is valid and uses HTTPS
    /// - Registry URL is valid and uses HTTPS
    /// - Discovery topic follows `/objects/{network}/{version}/discovery` format
    pub fn validate(&self) -> Result<()> {
        tracing::debug!("Validating configuration");

        // Validate API port
        if self.node.api_port < 1024 {
            return Err(ConfigError::ValidationError(format!(
                "API port {} is below 1024 (reserved range)",
                self.node.api_port
            )));
        }

        // Validate API bind address
        self.node.api_bind.parse::<IpAddr>().map_err(|e| {
            ConfigError::ValidationError(format!("Invalid API bind address: {}", e))
        })?;

        // Validate relay URL
        let relay_url = self.network.relay_url.parse::<Url>().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Invalid relay URL '{}': {}",
                self.network.relay_url, e
            ))
        })?;
        if relay_url.scheme() != "https" {
            return Err(ConfigError::ValidationError(format!(
                "Relay URL must use HTTPS, got: {}",
                self.network.relay_url
            )));
        }
        // Validate relay URL has a valid, non-empty host
        let host = relay_url.host_str().ok_or_else(|| {
            ConfigError::ValidationError(format!(
                "Relay URL missing host: {}",
                self.network.relay_url
            ))
        })?;
        if host.is_empty() || host == "." {
            return Err(ConfigError::ValidationError(format!(
                "Relay URL has invalid host: {}",
                self.network.relay_url
            )));
        }

        // Validate registry URL
        let registry_url = self.identity.registry_url.parse::<Url>().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Invalid registry URL '{}': {}",
                self.identity.registry_url, e
            ))
        })?;
        // Validate registry URL has a valid, non-empty host
        let host = registry_url.host_str().ok_or_else(|| {
            ConfigError::ValidationError(format!(
                "Registry URL missing host: {}",
                self.identity.registry_url
            ))
        })?;
        if host.is_empty() || host == "." {
            return Err(ConfigError::ValidationError(format!(
                "Registry URL has invalid host: {}",
                self.identity.registry_url
            )));
        }
        // Validate registry URL uses secure transport
        // Allow HTTP only for loopback addresses (127.0.0.0/8, ::1, localhost)
        let scheme = registry_url.scheme();
        let is_loopback = host == "localhost"
            || host == "::1"
            || host == "[::1]" // IPv6 loopback with brackets
            || host.starts_with("127.");

        match scheme {
            "https" => {}
            "http" if is_loopback => {}
            "http" => {
                return Err(ConfigError::ValidationError(format!(
                    "HTTP is only allowed for loopback addresses (localhost, 127.x.x.x, ::1), got: {}",
                    self.identity.registry_url
                )));
            }
            _ => {
                return Err(ConfigError::ValidationError(format!(
                    "Registry URL must use HTTP or HTTPS, got: {}",
                    self.identity.registry_url
                )));
            }
        }

        // Validate discovery topic format
        if !self.network.discovery_topic.starts_with("/objects/")
            || !self.network.discovery_topic.ends_with("/discovery")
        {
            return Err(ConfigError::ValidationError(format!(
                "Discovery topic '{}' must match format '/objects/{{network}}/{{version}}/discovery'",
                self.network.discovery_topic
            )));
        }

        tracing::debug!("Configuration validation passed");
        Ok(())
    }

    /// Apply environment variable overrides to configuration.
    ///
    /// Supported environment variables:
    /// - `OBJECTS_DATA_DIR` - Overrides node.data_dir
    /// - `OBJECTS_API_PORT` - Overrides node.api_port (invalid values logged and ignored)
    /// - `OBJECTS_RELAY_URL` - Overrides network.relay_url
    /// - `OBJECTS_REGISTRY_URL` - Overrides identity.registry_url
    ///
    /// Invalid port values are logged as warnings and the default value is retained.
    /// All overrides are logged at debug level. Validation occurs after overrides are applied.
    fn apply_env_overrides(&mut self) {
        if let Ok(data_dir) = std::env::var("OBJECTS_DATA_DIR") {
            tracing::debug!(env_var = "OBJECTS_DATA_DIR", value = %data_dir, "Applying environment override");
            self.node.data_dir = data_dir;
        }

        if let Ok(api_port_str) = std::env::var("OBJECTS_API_PORT") {
            match api_port_str.parse::<u16>() {
                Ok(port) => {
                    tracing::debug!(
                        env_var = "OBJECTS_API_PORT",
                        value = port,
                        "Applying environment override"
                    );
                    self.node.api_port = port;
                }
                Err(e) => {
                    tracing::warn!(
                        env_var = "OBJECTS_API_PORT",
                        value = %api_port_str,
                        error = %e,
                        default_port = self.node.api_port,
                        "Invalid port number in environment variable, using default"
                    );
                }
            }
        }

        if let Ok(relay_url) = std::env::var("OBJECTS_RELAY_URL") {
            tracing::debug!(env_var = "OBJECTS_RELAY_URL", value = %relay_url, "Applying environment override");
            self.network.relay_url = relay_url;
        }

        if let Ok(registry_url) = std::env::var("OBJECTS_REGISTRY_URL") {
            tracing::debug!(env_var = "OBJECTS_REGISTRY_URL", value = %registry_url, "Applying environment override");
            self.identity.registry_url = registry_url;
        }
    }
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

    #[test]
    fn test_load_or_create_missing_file() {
        // Ensure no env vars interfere with this test
        temp_env::with_vars(
            [
                ("OBJECTS_DATA_DIR", None::<&str>),
                ("OBJECTS_API_PORT", None::<&str>),
                ("OBJECTS_RELAY_URL", None::<&str>),
                ("OBJECTS_REGISTRY_URL", None::<&str>),
            ],
            || {
                let temp_dir = tempfile::tempdir().unwrap();
                let config_path = temp_dir.path().join("config.toml");

                // File doesn't exist yet
                assert!(!config_path.exists());

                // Load or create should create the file
                let config = NodeConfig::load_or_create(&config_path).unwrap();

                // File should now exist
                assert!(config_path.exists());

                // Should have default values
                assert_eq!(config.node.api_port, 3420);
            },
        );
    }

    #[test]
    fn test_load_missing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("missing.toml");

        // Should return error
        let result = NodeConfig::load(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let mut config = NodeConfig::default();
        config.node.api_port = 8080;
        config.node.data_dir = "/custom/path".to_string();

        // Save
        config.save(&config_path).unwrap();

        // Load
        let loaded = NodeConfig::load(&config_path).unwrap();

        // Verify
        assert_eq!(loaded.node.api_port, 8080);
        assert_eq!(loaded.node.data_dir, "/custom/path");
    }

    #[test]
    fn test_env_overrides() {
        temp_env::with_vars(
            [
                ("OBJECTS_DATA_DIR", Some("/env/data")),
                ("OBJECTS_API_PORT", Some("9000")),
                ("OBJECTS_RELAY_URL", Some("https://relay.example.com")),
                ("OBJECTS_REGISTRY_URL", Some("https://registry.example.com")),
            ],
            || {
                let config = NodeConfig::from_env().unwrap();

                assert_eq!(config.node.data_dir, "/env/data");
                assert_eq!(config.node.api_port, 9000);
                assert_eq!(config.network.relay_url, "https://relay.example.com");
                assert_eq!(config.identity.registry_url, "https://registry.example.com");
            },
        );
    }

    #[test]
    fn test_validation_invalid_port() {
        let mut config = NodeConfig::default();
        config.node.api_port = 500; // Below 1024

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("below 1024"));
    }

    #[test]
    fn test_validation_invalid_ip() {
        let mut config = NodeConfig::default();
        config.node.api_bind = "not-an-ip".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid API bind address")
        );
    }

    #[test]
    fn test_validation_non_https_relay() {
        let mut config = NodeConfig::default();
        config.network.relay_url = "http://insecure.relay.com".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must use HTTPS"));
    }

    #[test]
    fn test_validation_malformed_relay_url() {
        let test_cases = vec![
            ("https://", "empty host"),
            ("https://.", "invalid host"),
            ("not-a-url", "malformed URL"),
            ("https:// spaces", "spaces in URL"),
            ("", "empty string"),
        ];

        for (invalid_url, description) in test_cases {
            let mut config = NodeConfig::default();
            config.network.relay_url = invalid_url.to_string();

            let result = config.validate();
            assert!(
                result.is_err(),
                "Expected validation to fail for {}: {}",
                description,
                invalid_url
            );
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains("relay URL") || error_msg.contains("Relay URL"),
                "Expected error message about relay URL for {}, got: {}",
                description,
                error_msg
            );
        }
    }

    #[test]
    fn test_validation_non_https_registry() {
        let mut config = NodeConfig::default();
        config.identity.registry_url = "http://insecure.registry.com".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("loopback"));
    }

    #[test]
    fn test_validation_malformed_registry_url() {
        let test_cases = vec![
            ("https://", "empty host"),
            ("https://.", "invalid host"),
            ("not-a-url", "malformed URL"),
            ("", "empty string"),
        ];

        for (invalid_url, description) in test_cases {
            let mut config = NodeConfig::default();
            config.identity.registry_url = invalid_url.to_string();

            let result = config.validate();
            assert!(
                result.is_err(),
                "Expected validation to fail for {}: {}",
                description,
                invalid_url
            );
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains("registry URL") || error_msg.contains("Registry URL"),
                "Expected error message about registry URL for {}, got: {}",
                description,
                error_msg
            );
        }
    }

    #[test]
    fn test_validation_invalid_discovery_topic() {
        let mut config = NodeConfig::default();
        config.network.discovery_topic = "/invalid/topic".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must match format")
        );
    }

    #[test]
    fn test_validation_valid_config() {
        let config = NodeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_http_localhost_allowed() {
        let test_cases = vec![
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://127.0.0.2:3000",
            "http://127.1.2.3:3000",
            "http://127.255.255.254:3000",
            "http://[::1]:3000",
        ];

        for url in test_cases {
            let mut config = NodeConfig::default();
            config.identity.registry_url = url.to_string();

            let result = config.validate();
            assert!(
                result.is_ok(),
                "Expected HTTP to be allowed for loopback address: {}",
                url
            );
        }
    }

    #[test]
    fn test_validation_http_non_localhost_rejected() {
        let test_cases = vec![
            "http://example.com",
            "http://192.168.1.1:3000",
            "http://10.0.0.1:3000",
            "http://128.0.0.1:3000", // Not in 127.0.0.0/8 range
        ];

        for url in test_cases {
            let mut config = NodeConfig::default();
            config.identity.registry_url = url.to_string();

            let result = config.validate();
            assert!(
                result.is_err(),
                "Expected HTTP to be rejected for non-loopback address: {}",
                url
            );
            assert!(
                result.unwrap_err().to_string().contains("loopback"),
                "Expected error message to mention loopback for: {}",
                url
            );
        }
    }
}
