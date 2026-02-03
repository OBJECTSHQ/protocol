//! REST API module for the node daemon.

pub mod client;
pub mod handlers;
pub mod routes;
pub mod types;

pub use client::RegistryClient;
pub use handlers::{AppState, NodeInfo, health_check, node_status};
pub use routes::create_router;
pub use types::{HealthResponse, IdentityResponse, PeerInfo, StatusResponse};
