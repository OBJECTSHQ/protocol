//! REST API module for the node daemon.

pub mod handlers;
pub mod types;

pub use handlers::{AppState, NodeInfo};
pub use types::{HealthResponse, IdentityResponse, PeerInfo, StatusResponse};
