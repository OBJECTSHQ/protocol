//! Axum HTTP router for the node API.
//!
//! NOTE: This module is deprecated and will be removed once the irpc
//! migration is complete. The NodeEngine handles all RPC requests now.

use axum::{Router, routing::get, routing::post};

use super::handlers::*;

/// Create the Axum router with all API routes.
///
/// Deprecated: use [`NodeEngine`](crate::engine::NodeEngine) instead.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/status", get(node_status))
        .route(
            "/identity",
            get(get_identity)
                .post(create_identity)
                .patch(rename_identity),
        )
        .route("/peers", get(list_peers))
        .route("/projects", get(list_projects).post(create_project))
        .route("/projects/{id}", get(get_project))
        .route("/projects/{id}/assets", get(list_assets).post(add_asset))
        .route(
            "/projects/{id}/assets/{asset_id}/content",
            get(get_asset_content),
        )
        .route("/tickets", post(create_ticket))
        .route("/tickets/redeem", post(redeem_ticket))
        .route("/vault", get(list_vault))
        .route("/vault/sync", post(sync_vault))
        .route("/vault/sync/{project_id}", post(pull_vault_project))
        .with_state(state)
}
