//! FFI error types.
//!
//! Maps internal [`NodeApiError`] and [`RpcError`] into a flat enum
//! that uniffi can expose to Kotlin and Swift.

use objects_core::node_api::NodeApiError;
use objects_core::rpc::proto::RpcError;

/// Error type exposed to Kotlin and Swift via uniffi.
///
/// Each variant carries a human-readable `message` field.
/// Kotlin sees a sealed class; Swift sees an enum with associated values.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SdkError {
    #[error("bad request: {message}")]
    BadRequest { message: String },

    #[error("not found: {message}")]
    NotFound { message: String },

    #[error("service unavailable: {message}")]
    ServiceUnavailable { message: String },

    #[error("internal: {message}")]
    Internal { message: String },
}

impl From<NodeApiError> for SdkError {
    fn from(err: NodeApiError) -> Self {
        match err {
            NodeApiError::Rpc(rpc_err) => Self::from(rpc_err),
            NodeApiError::Transport(e) => SdkError::ServiceUnavailable {
                message: e.to_string(),
            },
            NodeApiError::ResponseClosed(e) => SdkError::ServiceUnavailable {
                message: e.to_string(),
            },
        }
    }
}

impl From<RpcError> for SdkError {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::BadRequest(msg) => SdkError::BadRequest { message: msg },
            RpcError::NotFound(msg) => SdkError::NotFound { message: msg },
            RpcError::Registry(msg) => SdkError::ServiceUnavailable { message: msg },
            RpcError::Internal(msg) => SdkError::Internal { message: msg },
        }
    }
}
