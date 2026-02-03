//! API routes and router configuration.

use super::handlers::{AppState, get_identity, health_check, node_status};
use axum::{Router, routing::get};

/// Create the API router with all routes.
///
/// # Routes
///
/// - `GET /health` - Health check endpoint
/// - `GET /status` - Node status endpoint
/// - `GET /identity` - Get registered identity
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/status", get(node_status))
        .route("/identity", get(get_identity))
        .with_state(state)
}
