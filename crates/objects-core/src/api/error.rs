//! Error types for the node API.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Node API errors.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Registry error: {0}")]
    Registry(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for NodeError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            NodeError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            NodeError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            NodeError::Registry(msg) => (StatusCode::BAD_GATEWAY, "registry_error", msg),
            NodeError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg),
        };

        (
            status,
            Json(json!({
                "error": {
                    "type": error_type,
                    "message": message
                }
            })),
        )
            .into_response()
    }
}
