//! Configuration for the OBJECTS Registry service.

use std::env;
use std::time::Duration;

/// Registry service configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL connection URL.
    pub database_url: String,

    /// Port for REST API server.
    pub rest_port: u16,

    /// Port for gRPC server.
    pub grpc_port: u16,

    /// Maximum allowed timestamp in the future (seconds).
    pub timestamp_future_max: Duration,

    /// Maximum allowed timestamp in the past (seconds).
    pub timestamp_past_max: Duration,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `DATABASE_URL`: PostgreSQL connection string
    ///
    /// Optional:
    /// - `REST_PORT`: REST API port (default: 8080)
    /// - `GRPC_PORT`: gRPC server port (default: 9090)
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url =
            env::var("DATABASE_URL").map_err(|_| ConfigError::MissingEnv("DATABASE_URL"))?;

        let rest_port = env::var("REST_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);

        let grpc_port = env::var("GRPC_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(9090);

        Ok(Self {
            database_url,
            rest_port,
            grpc_port,
            // RFC-001 recommended bounds
            timestamp_future_max: Duration::from_secs(5 * 60), // 5 minutes
            timestamp_past_max: Duration::from_secs(24 * 60 * 60), // 24 hours
        })
    }

    /// REST API bind address.
    pub fn rest_addr(&self) -> std::net::SocketAddr {
        ([0, 0, 0, 0], self.rest_port).into()
    }

    /// gRPC server bind address.
    #[allow(dead_code)] // TODO: Use when gRPC service is implemented
    pub fn grpc_addr(&self) -> std::net::SocketAddr {
        ([0, 0, 0, 0], self.grpc_port).into()
    }
}

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),
}
