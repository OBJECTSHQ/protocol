//! REST API routes for OBJECTS Registry.

use axum::routing::{get, patch, post};
use axum::Router;

use super::handlers::{
    change_handle, create_identity, get_identity, health_check, link_wallet, resolve_identity,
    AppState,
};

/// Create the REST API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))
        // Identity endpoints
        .route("/v1/identities", post(create_identity))
        .route("/v1/identities", get(resolve_identity))
        .route("/v1/identities/{id}", get(get_identity))
        .route("/v1/identities/{id}/wallet", post(link_wallet))
        .route("/v1/identities/{id}/handle", patch(change_handle))
        // Add shared state
        .with_state(state)
}
