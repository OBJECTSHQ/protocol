//! Error types for data operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid asset: {0}")]
    InvalidAsset(String),

    #[error("invalid project: {0}")]
    InvalidProject(String),

    #[error("invalid reference: {0}")]
    InvalidReference(String),

    #[error("content hash mismatch: expected {expected}, got {actual}")]
    ContentHashMismatch { expected: String, actual: String },

    #[error("identity error: {0}")]
    Identity(#[from] objects_identity::Error),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
}
