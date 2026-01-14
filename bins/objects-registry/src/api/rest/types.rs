//! REST API request/response types for OBJECTS Registry.
//!
//! Binary fields (public_key, nonce, signature) are base64-encoded in JSON.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use objects_identity::SignerType;
use serde::{Deserialize, Serialize};

use crate::db::IdentityRow;

/// Request to create a new identity.
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    /// Desired handle (1-30 chars, lowercase alphanumeric + underscore + period)
    pub handle: String,
    /// Signer type: "PASSKEY" or "WALLET"
    pub signer_type: String,
    /// Base64-encoded compressed SEC1 public key (33 bytes)
    pub signer_public_key: String,
    /// Base64-encoded nonce (8 bytes)
    pub nonce: String,
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Signature over the create identity message
    pub signature: SignatureRequest,
}

/// Signature data in request.
#[derive(Debug, Deserialize)]
pub struct SignatureRequest {
    /// Base64-encoded signature bytes
    pub signature: String,
    /// Base64-encoded public key (required for passkey)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Wallet address (required for wallet signatures)
    #[serde(default)]
    pub address: Option<String>,
    /// Base64-encoded authenticator data (required for passkey)
    #[serde(default)]
    pub authenticator_data: Option<String>,
    /// Base64-encoded client data JSON (required for passkey)
    #[serde(default)]
    pub client_data_json: Option<String>,
}

/// Request to link a wallet to an identity.
#[derive(Debug, Deserialize)]
pub struct LinkWalletRequest {
    /// Wallet address (0x + 40 hex chars)
    pub wallet_address: String,
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Signature from identity's signer
    pub identity_signature: SignatureRequest,
    /// Signature from the wallet
    pub wallet_signature: SignatureRequest,
}

/// Request to change an identity's handle.
#[derive(Debug, Deserialize)]
pub struct ChangeHandleRequest {
    /// New handle
    pub new_handle: String,
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Signature from identity's signer
    pub signature: SignatureRequest,
}

/// Query parameters for resolving an identity.
#[derive(Debug, Deserialize)]
pub struct ResolveQuery {
    /// Resolve by handle
    #[serde(default)]
    pub handle: Option<String>,
    /// Resolve by signer public key (base64)
    #[serde(default)]
    pub signer: Option<String>,
    /// Resolve by wallet address
    #[serde(default)]
    pub wallet: Option<String>,
}

/// Identity response.
#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    /// Identity ID (obj_ + base58)
    pub id: String,
    /// Handle
    pub handle: String,
    /// Signer type: "PASSKEY" or "WALLET"
    pub signer_type: String,
    /// Base64-encoded public key
    pub signer_public_key: String,
    /// Base64-encoded nonce
    pub nonce: String,
    /// Linked wallet address (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
}

impl TryFrom<IdentityRow> for IdentityResponse {
    type Error = String;

    fn try_from(row: IdentityRow) -> Result<Self, Self::Error> {
        let signer_type = match row.signer_type {
            1 => "PASSKEY",
            2 => "WALLET",
            unknown => {
                return Err(format!(
                    "invalid signer_type in database: {} (expected 1 for PASSKEY or 2 for WALLET)",
                    unknown
                ))
            }
        };
        Ok(Self {
            id: row.id,
            handle: row.handle,
            signer_type: signer_type.to_string(),
            signer_public_key: BASE64.encode(&row.signer_public_key),
            nonce: BASE64.encode(&row.nonce),
            wallet_address: row.wallet_address,
            created_at: row.created_at as u64,
            updated_at: row.updated_at as u64,
        })
    }
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
}

// Helper functions for parsing request data

impl SignatureRequest {
    /// Convert to objects_identity::Signature.
    pub fn to_signature(&self, signer_type: SignerType) -> Result<objects_identity::Signature, String> {
        let signature_bytes = BASE64
            .decode(&self.signature)
            .map_err(|e| format!("invalid base64 signature: {}", e))?;

        match signer_type {
            SignerType::Passkey => {
                let public_key = self
                    .public_key
                    .as_ref()
                    .ok_or("passkey signature requires public_key")?;
                let public_key_bytes = BASE64
                    .decode(public_key)
                    .map_err(|e| format!("invalid base64 public_key: {}", e))?;

                let authenticator_data = self
                    .authenticator_data
                    .as_ref()
                    .ok_or("passkey signature requires authenticator_data")?;
                let authenticator_data_bytes = BASE64
                    .decode(authenticator_data)
                    .map_err(|e| format!("invalid base64 authenticator_data: {}", e))?;

                let client_data_json = self
                    .client_data_json
                    .as_ref()
                    .ok_or("passkey signature requires client_data_json")?;
                let client_data_json_bytes = BASE64
                    .decode(client_data_json)
                    .map_err(|e| format!("invalid base64 client_data_json: {}", e))?;

                Ok(objects_identity::Signature::passkey(
                    signature_bytes,
                    public_key_bytes,
                    authenticator_data_bytes,
                    client_data_json_bytes,
                ))
            }
            SignerType::Wallet => {
                let address = self
                    .address
                    .as_ref()
                    .ok_or("wallet signature requires address")?
                    .clone();
                Ok(objects_identity::Signature::wallet(signature_bytes, address))
            }
        }
    }
}

/// Parse signer type from string.
pub fn parse_signer_type(s: &str) -> Result<SignerType, String> {
    match s.to_uppercase().as_str() {
        "PASSKEY" => Ok(SignerType::Passkey),
        "WALLET" => Ok(SignerType::Wallet),
        _ => Err(format!("invalid signer_type: {}", s)),
    }
}

/// Decode base64 to fixed-size array.
pub fn decode_base64_array<const N: usize>(s: &str, name: &str) -> Result<[u8; N], String> {
    let bytes = BASE64
        .decode(s)
        .map_err(|e| format!("invalid base64 {}: {}", name, e))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{} must be {} bytes, got {}", name, N, v.len()))
}
