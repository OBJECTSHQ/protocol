//! Signature types and verification.

use serde::{Deserialize, Serialize};

use crate::signer::SignerType;

/// A signature over a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// The type of signer that produced this signature.
    pub signer_type: SignerType,
    /// Raw signature bytes.
    /// - Passkey: DER-encoded ECDSA signature
    /// - Wallet: 65 bytes (r || s || v) per EIP-191
    pub signature: Vec<u8>,
    /// Public key (required for passkey signatures). 33 bytes compressed SEC1.
    pub public_key: Option<Vec<u8>>,
    /// Wallet address (required for wallet signatures).
    pub address: Option<String>,
    /// WebAuthn authenticator data (required for passkey signatures).
    pub authenticator_data: Option<Vec<u8>>,
    /// WebAuthn client data JSON (required for passkey signatures).
    pub client_data_json: Option<Vec<u8>>,
}

impl Signature {
    /// Creates a new passkey signature.
    pub fn passkey(
        signature: Vec<u8>,
        public_key: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    ) -> Self {
        Self {
            signer_type: SignerType::Passkey,
            signature,
            public_key: Some(public_key),
            address: None,
            authenticator_data: Some(authenticator_data),
            client_data_json: Some(client_data_json),
        }
    }

    /// Creates a new wallet signature.
    pub fn wallet(signature: Vec<u8>, address: String) -> Self {
        Self {
            signer_type: SignerType::Wallet,
            signature,
            public_key: None,
            address: Some(address),
            authenticator_data: None,
            client_data_json: None,
        }
    }
}

// TODO: Implement signature verification
// - Passkey: Verify ECDSA signature over SHA256(authenticator_data || SHA256(client_data_json))
// - Wallet: Verify EIP-712 typed data signature and recover address
