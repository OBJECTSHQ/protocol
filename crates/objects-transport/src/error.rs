//! Error types for transport operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("relay not available: {0}")]
    RelayNotAvailable(String),

    #[error("timeout")]
    Timeout,

    #[error("protocol mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("iroh error: {0}")]
    Iroh(#[from] anyhow::Error),
}
