//! Error types for the OBJECTS Registry service.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Registry domain error.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    // Domain errors (RFC-001)
    #[error("handle already taken: {0}")]
    HandleTaken(String),

    #[error("identity already exists: {0}")]
    IdentityExists(String),

    #[error("signer already has an identity")]
    SignerExists,

    #[error("wallet already linked to identity: {0}")]
    WalletLinked(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("invalid identity ID: expected {expected}, derived {derived}")]
    InvalidIdentityId { expected: String, derived: String },

    #[error("timestamp expired or too far in future")]
    TimestampInvalid,

    #[error("identity not found: {0}")]
    NotFound(String),

    // Infrastructure errors
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("identity verification failed: {0}")]
    Identity(#[from] objects_identity::Error),
}

impl RegistryError {
    /// Error code string for API responses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::HandleTaken(_) => "HANDLE_TAKEN",
            Self::IdentityExists(_) => "IDENTITY_EXISTS",
            Self::SignerExists => "SIGNER_EXISTS",
            Self::WalletLinked(_) => "WALLET_LINKED",
            Self::InvalidSignature(_) => "INVALID_SIGNATURE",
            Self::InvalidHandle(_) => "INVALID_HANDLE",
            Self::InvalidIdentityId { .. } => "INVALID_IDENTITY_ID",
            Self::TimestampInvalid => "TIMESTAMP_INVALID",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Database(_) => "DATABASE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::Identity(_) => "IDENTITY_ERROR",
        }
    }

    /// HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            // 409 Conflict - resource state conflicts
            Self::HandleTaken(_)
            | Self::IdentityExists(_)
            | Self::SignerExists
            | Self::WalletLinked(_) => StatusCode::CONFLICT,

            // 400 Bad Request - invalid input
            Self::InvalidSignature(_)
            | Self::InvalidHandle(_)
            | Self::InvalidIdentityId { .. }
            | Self::TimestampInvalid
            | Self::Identity(_) => StatusCode::BAD_REQUEST,

            // 404 Not Found
            Self::NotFound(_) => StatusCode::NOT_FOUND,

            // 500 Internal Server Error
            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// JSON error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// Error detail within response.
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse {
            error: ErrorDetail {
                code: self.code().to_string(),
                message: self.to_string(),
            },
        };
        (status, Json(body)).into_response()
    }
}

// gRPC status conversion
impl From<RegistryError> for tonic::Status {
    fn from(err: RegistryError) -> Self {
        let code = match &err {
            // ALREADY_EXISTS
            RegistryError::HandleTaken(_)
            | RegistryError::IdentityExists(_)
            | RegistryError::SignerExists
            | RegistryError::WalletLinked(_) => tonic::Code::AlreadyExists,

            // INVALID_ARGUMENT
            RegistryError::InvalidSignature(_)
            | RegistryError::InvalidHandle(_)
            | RegistryError::InvalidIdentityId { .. }
            | RegistryError::TimestampInvalid
            | RegistryError::Identity(_) => tonic::Code::InvalidArgument,

            // NOT_FOUND
            RegistryError::NotFound(_) => tonic::Code::NotFound,

            // INTERNAL
            RegistryError::Database(_) | RegistryError::Internal(_) => tonic::Code::Internal,
        };

        tonic::Status::new(code, err.to_string())
    }
}

/// Result type alias for registry operations.
pub type Result<T> = std::result::Result<T, RegistryError>;
