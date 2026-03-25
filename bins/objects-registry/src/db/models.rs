//! Database models for OBJECTS Registry.

use objects_identity::SignerType;

/// Database row for an identity record.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityRow {
    /// Identity ID (obj_ + base58)
    pub id: String,

    /// Handle (1-30 chars)
    pub handle: String,

    /// Signer type (1=PASSKEY, 2=WALLET)
    pub signer_type: i16,

    /// Compressed SEC1 public key (33 bytes)
    pub signer_public_key: Vec<u8>,

    /// Nonce used in derivation (8 bytes)
    pub nonce: Vec<u8>,

    /// Linked wallet address (nullable)
    pub wallet_address: Option<String>,

    /// Creation timestamp (Unix seconds)
    pub created_at: i64,

    /// Last update timestamp (Unix seconds)
    pub updated_at: i64,
}

impl IdentityRow {
    /// Convert signer_type to SignerType enum.
    pub fn signer_type_enum(&self) -> Option<SignerType> {
        match self.signer_type {
            1 => Some(SignerType::Passkey),
            2 => Some(SignerType::Wallet),
            _ => None,
        }
    }
}

/// Convert SignerType to database integer.
pub fn signer_type_to_i16(signer_type: SignerType) -> i16 {
    match signer_type {
        SignerType::Passkey => 1,
        SignerType::Wallet => 2,
    }
}
