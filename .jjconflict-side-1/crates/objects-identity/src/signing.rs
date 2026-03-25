//! Key generation and signing for identity operations.
//!
//! This module provides secure key generation and signing using battle-tested libraries:
//! - P-256 (passkey): RustCrypto, audited by zkSecurity 2025
//! - secp256k1 (wallet): RustCrypto, constant-time implementation

use crate::{Error, Signature};
use base64::Engine as _;
use k256::ecdsa::{SigningKey as K256SigningKey, signature::Signer as _};
use k256::elliptic_curve::rand_core::OsRng;
use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::{Digest, Sha256};

/// Passkey signing key (P-256/secp256r1).
///
/// Used for WebAuthn-compatible signatures.
#[derive(Clone)]
pub struct PasskeySigningKey {
    key: P256SigningKey,
}

impl PasskeySigningKey {
    /// Generate a new random passkey signing key.
    pub fn generate() -> Self {
        Self {
            key: P256SigningKey::random(&mut OsRng),
        }
    }

    /// Create from raw secret bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let key = P256SigningKey::from_bytes(bytes.into())
            .map_err(|e| Error::InvalidSignature(format!("Invalid P-256 key: {}", e)))?;
        Ok(Self { key })
    }

    /// Get the secret key bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Get the compressed public key (33 bytes, SEC1 format).
    pub fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Get the public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Sign a message, producing a WebAuthn-compatible signature.
    ///
    /// Returns a `Signature::Passkey` with all required WebAuthn fields.
    pub fn sign(&self, message: &[u8]) -> Signature {
        // Create minimal WebAuthn authenticator_data (37 bytes)
        // Format: RP ID hash (32) + flags (1) + counter (4)
        let rp_id_hash = Sha256::digest(b"objects.foundation");
        let flags = 0x05u8; // UP (User Present) + UV (User Verified)
        let counter = 0u32.to_be_bytes();

        let mut authenticator_data = rp_id_hash.to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&counter);

        // Create client_data_json with base64url-encoded challenge
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(message);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
            challenge_b64
        )
        .into_bytes();

        // Compute client_data_hash
        let client_data_hash = Sha256::digest(&client_data_json);

        // Construct signed_data per WebAuthn spec
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        // Sign with P-256
        let signature: p256::ecdsa::Signature = self.key.sign(&signed_data);

        Signature::passkey(
            signature.to_der().to_bytes().to_vec(),
            self.public_key(),
            authenticator_data,
            client_data_json,
        )
    }
}

/// Wallet signing key (secp256k1).
///
/// Used for Ethereum-compatible signatures (EIP-191).
#[derive(Clone)]
pub struct WalletSigningKey {
    key: K256SigningKey,
}

impl WalletSigningKey {
    /// Generate a new random wallet signing key.
    pub fn generate() -> Self {
        Self {
            key: K256SigningKey::random(&mut OsRng),
        }
    }

    /// Create from raw secret bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let key = K256SigningKey::from_bytes(bytes.into())
            .map_err(|e| Error::InvalidSignature(format!("Invalid secp256k1 key: {}", e)))?;
        Ok(Self { key })
    }

    /// Get the secret key bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Get the compressed public key (33 bytes, SEC1 format).
    pub fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Get the public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Get the Ethereum address (0x + 40 hex chars).
    pub fn address(&self) -> String {
        use alloy_primitives::Address;

        let verifying_key = self.key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false); // Uncompressed
        let public_key_slice = &public_key_bytes.as_bytes()[1..]; // Skip 0x04 prefix

        // Ethereum address = last 20 bytes of keccak256(public_key)
        let hash = alloy_primitives::keccak256(public_key_slice);
        let address = Address::from_slice(&hash[12..]);

        format!("0x{}", hex::encode(address.as_slice()))
    }

    /// Sign a message using EIP-191 personal_sign format.
    ///
    /// Returns a `Signature::Wallet` with 65-byte signature (r || s || v) and address.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        // Convert k256 key bytes to alloy-compatible format
        let secret_bytes = self.key.to_bytes();
        let alloy_signer = PrivateKeySigner::from_slice(secret_bytes.as_slice())
            .map_err(|e| Error::InvalidSignature(format!("Failed to convert key: {}", e)))?;

        // Sign with EIP-191 prefix
        let signature = alloy_signer
            .sign_message_sync(message)
            .map_err(|e| Error::InvalidSignature(format!("Failed to sign message: {}", e)))?;

        Ok(Signature::wallet(
            signature.as_bytes().to_vec(),
            self.address(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignerType;

    #[test]
    fn test_passkey_generate_and_sign() {
        let key = PasskeySigningKey::generate();
        let message = b"test message";
        let signature = key.sign(message);

        assert_eq!(signature.signer_type(), SignerType::Passkey);

        // Verify signature can be verified
        let result = signature.verify(message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wallet_generate_and_sign() {
        let key = WalletSigningKey::generate();
        let message = b"test message";
        let signature = key.sign(message).expect("signing should succeed");

        assert_eq!(signature.signer_type(), SignerType::Wallet);

        // Verify signature can be verified
        let result = signature.verify(message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_passkey_roundtrip() {
        let key1 = PasskeySigningKey::generate();
        let bytes = key1.to_bytes();
        let key2 = PasskeySigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(key1.public_key(), key2.public_key());
    }

    #[test]
    fn test_wallet_roundtrip() {
        let key1 = WalletSigningKey::generate();
        let bytes = key1.to_bytes();
        let key2 = WalletSigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(key1.public_key(), key2.public_key());
        assert_eq!(key1.address(), key2.address());
    }

    #[test]
    fn test_wallet_address_format() {
        let key = WalletSigningKey::generate();
        let address = key.address();

        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars
    }
}
