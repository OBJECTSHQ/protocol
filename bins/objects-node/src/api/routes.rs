//! API routes and router configuration.

use super::handlers::{
    AppState, create_identity, create_project, get_identity, get_project, health_check,
    list_projects, node_status,
};
use axum::{Router, routing::get};

/// Create the API router with all routes.
///
/// # Routes
///
/// - `GET /health` - Health check endpoint
/// - `GET /status` - Node status endpoint
/// - `GET /identity` - Get registered identity
/// - `POST /identity` - Create new identity
/// - `GET /projects` - List all projects
/// - `POST /projects` - Create new project
/// - `GET /projects/:id` - Get project by ID
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/status", get(node_status))
        .route("/identity", get(get_identity).post(create_identity))
        .route("/projects", get(list_projects).post(create_project))
        .route("/projects/{id}", get(get_project))
        .with_state(state)
}
