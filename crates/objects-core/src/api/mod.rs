//! REST API module for the node.

pub mod error;
pub mod handlers;
pub mod registry;
pub mod routes;
pub mod types;

pub use error::NodeError;
pub use handlers::{
    AppState, NodeInfo, create_identity, create_project, get_identity, get_project, health_check,
    list_projects, list_vault, node_status, pull_vault_project, sync_vault,
};
pub use registry::RegistryClient;
pub use routes::create_router;
pub use types::{
    CreateProjectRequest, HealthResponse, IdentityResponse, PeerInfo, ProjectListResponse,
    ProjectResponse, StatusResponse, VaultEntry, VaultResponse,
};
