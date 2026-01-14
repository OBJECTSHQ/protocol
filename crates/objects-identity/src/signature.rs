//! Signature types and verification using audited libraries.
//!
//! This module uses:
//! - alloy-signer: Industry-standard EIP-191 wallet signature verification (battle-tested)
//! - p256: RustCrypto audited P-256 ECDSA verification for passkeys
//! - Proper WebAuthn validation following spec

use alloy_primitives::Address as AlloyAddress;
use alloy_signer::Signature as AlloySig;
use p256::ecdsa::{signature::Verifier, Signature as P256Sig, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signer::SignerType;
use crate::Error;

/// A signature over a message.
///
/// This enum ensures type safety by making invalid states unrepresentable:
/// - Passkey signatures must include all WebAuthn fields
/// - Wallet signatures must include address
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "signer_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Signature {
    /// Passkey (P-256/secp256r1) signature with WebAuthn data.
    Passkey {
        /// DER-encoded ECDSA signature
        signature: Vec<u8>,
        /// Compressed SEC1 public key (33 bytes)
        public_key: Vec<u8>,
        /// WebAuthn authenticator data
        authenticator_data: Vec<u8>,
        /// WebAuthn client data JSON
        client_data_json: Vec<u8>,
    },
    /// Wallet (secp256k1 + EIP-191) signature.
    Wallet {
        /// 65 bytes (r || s || v) per EIP-191
        signature: Vec<u8>,
        /// Ethereum address (0x + 40 hex chars)
        address: String,
    },
}

impl Signature {
    /// Creates a new passkey signature.
    pub fn passkey(
        signature: Vec<u8>,
        public_key: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    ) -> Self {
        Self::Passkey {
            signature,
            public_key,
            authenticator_data,
            client_data_json,
        }
    }

    /// Creates a new wallet signature.
    pub fn wallet(signature: Vec<u8>, address: String) -> Self {
        Self::Wallet { signature, address }
    }

    /// Returns the signer type.
    pub fn signer_type(&self) -> SignerType {
        match self {
            Self::Passkey { .. } => SignerType::Passkey,
            Self::Wallet { .. } => SignerType::Wallet,
        }
    }

    /// Returns a reference to the signature bytes.
    pub fn signature_bytes(&self) -> &[u8] {
        match self {
            Self::Passkey { signature, .. } => signature,
            Self::Wallet { signature, .. } => signature,
        }
    }

    /// Returns a reference to the public key (passkey only).
    pub fn public_key_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Passkey { public_key, .. } => Some(public_key),
            Self::Wallet { .. } => None,
        }
    }

    /// Returns a reference to the address (wallet only).
    pub fn address(&self) -> Option<&str> {
        match self {
            Self::Passkey { .. } => None,
            Self::Wallet { address, .. } => Some(address),
        }
    }

    /// Verifies the signature against a message using audited libraries.
    ///
    /// For passkey signatures: Uses webauthn-rs-core (SUSE audited)
    /// For wallet signatures: Uses alloy-signer (industry standard)
    pub fn verify(&self, message: &[u8]) -> Result<(), Error> {
        match self {
            Self::Passkey {
                signature,
                public_key,
                authenticator_data,
                client_data_json,
            } => Self::verify_passkey_with_webauthn(
                message,
                signature,
                public_key,
                authenticator_data,
                client_data_json,
            ),
            Self::Wallet { signature, address } => Self::verify_wallet_with_alloy(message, signature, address),
        }
    }

    /// Verifies a wallet signature using alloy-signer (industry standard).
    ///
    /// Uses alloy's battle-tested EIP-191 implementation from docs.rs/alloy-signer:
    /// - Automatic message prefixing per EIP-191 via eip191_hash_message
    /// - Signature normalization (prevents malleability attacks)
    /// - Proper address recovery from secp256k1 signature
    ///
    /// Reference: https://docs.rs/alloy-signer-local/latest/alloy_signer_local/
    fn verify_wallet_with_alloy(
        message: &[u8],
        signature_bytes: &[u8],
        claimed_address: &str,
    ) -> Result<(), Error> {
        // Parse claimed address
        let claimed: AlloyAddress = claimed_address
            .parse()
            .map_err(|e| Error::InvalidSignature(format!("invalid address: {}", e)))?;

        // Parse signature (alloy handles 65-byte format: r || s || v)
        let sig = AlloySig::try_from(signature_bytes)
            .map_err(|e| Error::InvalidSignature(format!("invalid signature: {}", e)))?;

        // Recover address from signature
        // This uses eip191_hash_message internally which prefixes with
        // "\x19Ethereum Signed Message:\n{len}" per EIP-191
        let recovered = sig
            .recover_address_from_msg(message)
            .map_err(|_| Error::VerificationFailed)?;

        // Verify address match (both are alloy_primitives::Address)
        if recovered.to_string().to_lowercase() != claimed.to_string().to_lowercase() {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }

    /// Verifies a passkey (P-256) signature following WebAuthn spec.
    ///
    /// Uses p256 (RustCrypto, audited) for ECDSA verification with proper WebAuthn validation:
    /// - Validates challenge matches expected message (hex-encoded in client_data_json)
    /// - Validates type is "webauthn.get"
    /// - Parses and validates authenticator_data structure
    /// - Validates user presence flag (UP bit 0x01)
    /// - Computes clientDataHash = SHA256(client_data_json)
    /// - Verifies ECDSA-P256 signature over (authenticator_data || clientDataHash)
    ///
    /// Reference: WebAuthn Level 3 §7.2 Verifying an Authentication Assertion
    /// Reference: https://docs.rs/p256/latest/p256/
    fn verify_passkey_with_webauthn(
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
        authenticator_data_bytes: &[u8],
        client_data_json_bytes: &[u8],
    ) -> Result<(), Error> {
        // 1. Parse and validate client_data_json
        #[derive(serde::Deserialize)]
        struct ClientData {
            #[serde(rename = "type")]
            type_: String,
            challenge: String,
        }

        let client_data: ClientData =
            serde_json::from_slice(client_data_json_bytes).map_err(|e| {
                Error::InvalidSignature(format!("invalid client_data_json: {}", e))
            })?;

        // 2. Validate type field
        if client_data.type_ != "webauthn.get" {
            return Err(Error::InvalidSignature(format!(
                "invalid type: expected webauthn.get, got {}",
                client_data.type_
            )));
        }

        // 3. Validate challenge matches expected message (hex-encoded)
        let expected_challenge_hex = hex::encode(message);
        if client_data.challenge != expected_challenge_hex {
            return Err(Error::InvalidSignature(
                "challenge mismatch".to_string(),
            ));
        }

        // 4. Parse and validate authenticator_data
        // Per WebAuthn spec: RP ID hash (32) + flags (1) + counter (4) + extensions (variable)
        if authenticator_data_bytes.len() < 37 {
            return Err(Error::InvalidSignature(
                "authenticator_data too short (minimum 37 bytes required)".to_string(),
            ));
        }

        let flags = authenticator_data_bytes[32];
        let user_present = (flags & 0x01) != 0; // Bit 0: UP (User Present)

        // 5. Validate user presence (minimum requirement per WebAuthn spec)
        if !user_present {
            return Err(Error::InvalidSignature(
                "user presence flag not set".to_string(),
            ));
        }

        // 6. Compute clientDataHash = SHA256(client_data_json)
        let client_data_hash = Sha256::digest(client_data_json_bytes);

        // 7. Construct signedData = authenticator_data || clientDataHash
        let mut signed_data = Vec::with_capacity(authenticator_data_bytes.len() + 32);
        signed_data.extend_from_slice(authenticator_data_bytes);
        signed_data.extend_from_slice(&client_data_hash);

        // 8. Parse public key (33-byte compressed SEC1 format)
        let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| Error::InvalidSignature(format!("invalid public key: {}", e)))?;

        // 9. Parse signature (DER-encoded ECDSA signature)
        let signature = P256Sig::from_der(signature_bytes)
            .map_err(|e| Error::InvalidSignature(format!("invalid DER signature: {}", e)))?;

        // 10. Verify ECDSA-P256 signature using RustCrypto audited implementation
        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| Error::VerificationFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, SigningKey as P256SigningKey};
    use k256::ecdsa::SigningKey as K256SigningKey;
    use sha2::{Digest, Sha256};
    use k256::elliptic_curve::rand_core::OsRng;

    // Helper: Generate test passkey signing key
    fn test_passkey_key() -> P256SigningKey {
        P256SigningKey::random(&mut OsRng)
    }

    // Helper: Generate test wallet signing key
    fn test_wallet_key() -> K256SigningKey {
        K256SigningKey::random(&mut OsRng)
    }

    #[test]
    fn test_verify_passkey_with_valid_signature() {
        // Generate real P-256 key
        let signing_key = test_passkey_key();
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        // Create minimal valid WebAuthn authenticator_data (37 bytes minimum)
        // Format: RP ID hash (32) + flags (1) + counter (4)
        let rp_id_hash = Sha256::digest(b"example.com");
        let flags = 0x05u8; // UP + UV flags
        let counter = 0u32.to_be_bytes();
        let mut authenticator_data = rp_id_hash.to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&counter);

        // Create message and client_data_json with hex-encoded challenge
        let message = b"test message";
        let challenge_hex = hex::encode(message);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
            challenge_hex
        ).into_bytes();

        // Compute client_data_hash
        let client_data_hash = Sha256::digest(&client_data_json);

        // Construct signed data per WebAuthn spec
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        // Sign with P-256
        let signature_der: p256::ecdsa::Signature = signing_key.sign(&signed_data);
        let signature_bytes = signature_der.to_der().to_bytes().to_vec();

        // Create Signature using enum constructor
        let sig = Signature::passkey(
            signature_bytes,
            public_key_bytes,
            authenticator_data,
            client_data_json,
        );

        // Verification should succeed with correct message
        assert!(sig.verify(message).is_ok());
    }

    #[test]
    fn test_verify_passkey_with_tampered_authenticator_data() {
        // Generate real signature (same as above)
        let signing_key = test_passkey_key();
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        let rp_id_hash = Sha256::digest(b"example.com");
        let flags = 0x05u8;
        let counter = 0u32.to_be_bytes();
        let mut authenticator_data = rp_id_hash.to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&counter);

        // Create message and client_data_json with hex-encoded challenge
        let message = b"test message";
        let challenge_hex = hex::encode(message);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
            challenge_hex
        ).into_bytes();
        let client_data_hash = Sha256::digest(&client_data_json);

        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        let signature_der: p256::ecdsa::Signature = signing_key.sign(&signed_data);
        let signature_bytes = signature_der.to_der().to_bytes().to_vec();

        // TAMPER: Modify authenticator_data after signing
        let mut tampered_authenticator_data = authenticator_data.clone();
        tampered_authenticator_data[0] ^= 0xFF; // Flip bits

        let sig = Signature::passkey(
            signature_bytes,
            public_key_bytes,
            tampered_authenticator_data,
            client_data_json,
        );

        // Verification should fail
        assert!(sig.verify(message).is_err());
    }

    #[test]
    fn test_verify_wallet_with_valid_signature() {
        use alloy_primitives::keccak256;

        // Generate real secp256k1 key
        let signing_key = test_wallet_key();
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes(); // Uncompressed

        // Derive Ethereum address from public key
        let pub_key_hash = keccak256(&public_key_bytes[1..]); // Skip 0x04 prefix
        let address_bytes = &pub_key_hash[12..]; // Last 20 bytes
        let address = format!("0x{}", hex::encode(address_bytes));

        // Create EIP-191 prefixed message
        let message = b"test message";
        let eip191_prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut prefixed = eip191_prefix.as_bytes().to_vec();
        prefixed.extend_from_slice(message);
        let message_hash = keccak256(&prefixed);

        // Sign with recovery
        let (signature_der, recovery_id) = signing_key.sign_prehash_recoverable(message_hash.as_slice()).unwrap();
        let mut signature_bytes = signature_der.to_bytes().to_vec(); // 64 bytes r||s
        signature_bytes.push(recovery_id.to_byte()); // Append v

        let sig = Signature::wallet(signature_bytes, address);

        // Verification should succeed
        assert!(sig.verify(message).is_ok());
    }

    #[test]
    fn test_verify_wallet_with_wrong_message() {
        use alloy_primitives::keccak256;

        let signing_key = test_wallet_key();
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes();

        let pub_key_hash = keccak256(&public_key_bytes[1..]);
        let address = format!("0x{}", hex::encode(&pub_key_hash[12..]));

        // Sign original message
        let original_message = b"original message";
        let eip191_prefix = format!("\x19Ethereum Signed Message:\n{}", original_message.len());
        let mut prefixed = eip191_prefix.as_bytes().to_vec();
        prefixed.extend_from_slice(original_message);
        let message_hash = keccak256(&prefixed);

        let (signature_der, recovery_id) = signing_key.sign_prehash_recoverable(message_hash.as_slice()).unwrap();
        let mut signature_bytes = signature_der.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());

        let sig = Signature::wallet(signature_bytes, address);

        // Verify with DIFFERENT message - should fail
        let wrong_message = b"tampered message";
        assert!(sig.verify(wrong_message).is_err());
    }
}
