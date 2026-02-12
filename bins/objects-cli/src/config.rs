use crate::error::CliError;
use objects_common::config::{
    CliSettings, IdentitySettings, NetworkSettings, NodeSettings, StorageSettings,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Unified configuration shared between CLI and Node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeSettings,
    pub network: NetworkSettings,
    pub storage: StorageSettings,
    pub identity: IdentitySettings,
    #[serde(default)]
    pub cli: CliSettings,
}

impl Config {
    /// Load config: env var → file → default
    pub fn load() -> Result<Self, CliError> {
        let config_path = Self::config_path();

        let mut config = if config_path.exists() {
            Self::from_file(&config_path)?
        } else {
            Self::default()
        };

        // Apply env overrides
        config.apply_env();

        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, CliError> {
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|e| CliError::Config(format!("Parse error: {}", e)))
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| CliError::Config(format!("Serialize error: {}", e)))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, contents)?;
        Ok(())
    }

    pub fn config_path() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".objects/config.toml"))
            .unwrap_or_else(|| PathBuf::from(".objects/config.toml"))
    }

    pub fn data_dir(&self) -> PathBuf {
        PathBuf::from(&self.node.data_dir)
    }

    /// Construct API URL from node settings
    pub fn api_url(&self) -> String {
        format!("http://{}:{}", self.node.api_bind, self.node.api_port)
    }

    pub fn apply_env(&mut self) {
        // CLI can override API URL by setting the full URL
        if let Ok(url) = std::env::var("OBJECTS_API_URL") {
            // Parse URL to extract bind and port
            if let Ok(parsed) = url::Url::parse(&url) {
                if let Some(host) = parsed.host_str() {
                    self.node.api_bind = host.to_string();
                }
                if let Some(port) = parsed.port() {
                    self.node.api_port = port;
                }
            }
        }

        // Or override individual components
        if let Ok(port) = std::env::var("OBJECTS_API_PORT")
            && let Ok(port) = port.parse()
        {
            self.node.api_port = port;
        }

        if let Ok(token) = std::env::var("OBJECTS_API_TOKEN") {
            self.cli.api_token = Some(token);
        }

        if let Ok(dir) = std::env::var("OBJECTS_DATA_DIR") {
            self.node.data_dir = dir;
        }
    }
}
