//! Error types for sync operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("blob not found: {0}")]
    BlobNotFound(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("sync failed: {0}")]
    SyncFailed(String),

    #[error("invalid ticket: {0}")]
    InvalidTicket(String),

    #[error("replica not found: {0}")]
    ReplicaNotFound(String),

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("storage version mismatch: expected {expected}, found {found}")]
    StorageVersionMismatch { expected: String, found: String },

    #[error("blob too large: {size} bytes (max: {max} bytes)")]
    BlobTooLarge { size: u64, max: u64 },

    #[error("storage limit exceeded: {current} / {limit} bytes")]
    StorageLimitExceeded { current: u64, limit: u64 },

    #[error("transport error: {0}")]
    Transport(#[from] objects_transport::Error),

    #[error("iroh error: {0}")]
    Iroh(#[from] anyhow::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Storage(e.to_string())
    }
}
