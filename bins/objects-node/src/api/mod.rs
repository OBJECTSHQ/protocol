//! REST API module for the node daemon.

pub mod client;
pub mod error;
pub mod handlers;
pub mod routes;
pub mod types;

pub use client::RegistryClient;
pub use error::NodeError;
pub use handlers::{
    AppState, NodeInfo, create_identity, create_project, get_identity, get_project, health_check,
    list_projects, node_status,
};
pub use routes::create_router;
pub use types::{
    CreateProjectRequest, HealthResponse, IdentityResponse, PeerInfo, ProjectListResponse,
    ProjectResponse, StatusResponse,
};
