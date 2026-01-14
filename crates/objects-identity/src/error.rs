//! Error types for identity operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid identity ID format: {0}")]
    InvalidIdentityId(String),

    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("author ID mismatch: expected {expected}, got {actual}")]
    AuthorIdMismatch { expected: String, actual: String },

    #[error("unsupported signer type: {0}")]
    UnsupportedSignerType(u32),
}
