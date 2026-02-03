//! API types for node communication.

use serde::{Deserialize, Serialize};

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

/// Node status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub node_id: String,
    pub peer_count: usize,
    pub identity: Option<IdentityResponse>,
    pub relay_url: String,
}

/// Identity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub id: String,
    pub handle: String,
    pub nonce: String,
    pub signer_type: String,
}

/// Create identity request.
#[derive(Debug, Clone, Serialize)]
pub struct CreateIdentityRequest {
    pub handle: String,
}
