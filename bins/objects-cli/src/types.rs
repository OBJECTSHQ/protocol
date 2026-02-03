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
    pub signer_type: String,
    pub signer_public_key: String,
    pub nonce: String,
    pub timestamp: i64,
    pub signature: SignatureData,
}

/// Signature data for identity creation.
/// Matches the registry's SignatureRequest format.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureData {
    /// Base64-encoded signature bytes
    pub signature: String,
    /// Base64-encoded public key (required for passkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Wallet address (required for wallet signatures)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Base64-encoded authenticator data (required for passkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_data: Option<String>,
    /// Base64-encoded client data JSON (required for passkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_data_json: Option<String>,
}
