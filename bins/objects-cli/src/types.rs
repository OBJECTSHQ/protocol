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
    pub timestamp: u64,
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

// =============================================================================
// Project Types
// =============================================================================

/// Create project request.
#[derive(Debug, Clone, Serialize)]
pub struct CreateProjectRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Project response.
#[derive(Debug, Clone, Deserialize)]
pub struct ProjectResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Project list response.
#[derive(Debug, Clone, Deserialize)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectResponse>,
}

// =============================================================================
// Asset Types
// =============================================================================

/// Asset response.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetResponse {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub content_hash: String,
    pub created_at: u64,
}

/// Asset list response.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetListResponse {
    pub assets: Vec<AssetResponse>,
}

// =============================================================================
// Ticket Types
// =============================================================================

/// Create ticket request.
#[derive(Debug, Clone, Serialize)]
pub struct CreateTicketRequest {
    pub project_id: String,
}

/// Ticket response.
#[derive(Debug, Clone, Deserialize)]
pub struct TicketResponse {
    pub ticket: String,
}

/// Redeem ticket request.
#[derive(Debug, Clone, Serialize)]
pub struct RedeemTicketRequest {
    pub ticket: String,
}
