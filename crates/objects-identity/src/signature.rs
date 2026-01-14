//! Signature types and verification.

use alloy_primitives::{keccak256, Address};
use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey as K256VerifyingKey};
use p256::ecdsa::{signature::Verifier, Signature as P256Sig, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signer::SignerType;
use crate::Error;

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

    /// Verifies the signature against a message.
    ///
    /// For passkey signatures, the `message` parameter is not used. The signed data
    /// is constructed from the authenticator_data and client_data_json fields stored
    /// in the signature per WebAuthn spec (see verify_passkey() for details).
    ///
    /// For wallet signatures, the message is prefixed per EIP-191 and the signer
    /// address is recovered from the signature.
    pub fn verify(&self, message: &[u8]) -> Result<(), Error> {
        match self.signer_type {
            SignerType::Passkey => self.verify_passkey(),
            SignerType::Wallet => self.verify_wallet(message),
        }
    }

    /// Verifies a passkey (P-256/secp256r1) signature.
    ///
    /// Per WebAuthn spec:
    /// 1. Compute clientDataHash = SHA256(client_data_json)
    /// 2. Compute signedData = authenticator_data || clientDataHash
    /// 3. Verify ECDSA signature over signedData using public key
    fn verify_passkey(&self) -> Result<(), Error> {
        let public_key = self.public_key.as_ref().ok_or_else(|| {
            Error::InvalidSignature("passkey signature requires public_key".to_string())
        })?;

        let authenticator_data = self.authenticator_data.as_ref().ok_or_else(|| {
            Error::InvalidSignature("passkey signature requires authenticator_data".to_string())
        })?;

        let client_data_json = self.client_data_json.as_ref().ok_or_else(|| {
            Error::InvalidSignature("passkey signature requires client_data_json".to_string())
        })?;

        // 1. Compute clientDataHash = SHA256(client_data_json)
        let client_data_hash = Sha256::digest(client_data_json);

        // 2. Compute signedData = authenticator_data || clientDataHash
        let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
        signed_data.extend_from_slice(authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        // 3. Parse the public key (SEC1 compressed format)
        let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| Error::InvalidSignature(format!("invalid public key: {}", e)))?;

        // 4. Parse the signature (DER encoded)
        let signature = P256Sig::from_der(&self.signature)
            .map_err(|e| Error::InvalidSignature(format!("invalid DER signature: {}", e)))?;

        // 5. Verify the signature
        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| Error::VerificationFailed)
    }

    /// Verifies a wallet (secp256k1 + EIP-191) signature.
    ///
    /// Per EIP-191:
    /// 1. Prefix message: "\x19Ethereum Signed Message:\n" + len + message
    /// 2. Hash with keccak256
    /// 3. Recover public key from signature
    /// 4. Derive address from public key
    /// 5. Verify address matches claimed address
    fn verify_wallet(&self, message: &[u8]) -> Result<(), Error> {
        let claimed_address = self.address.as_ref().ok_or_else(|| {
            Error::InvalidSignature("wallet signature requires address".to_string())
        })?;

        // Signature must be 65 bytes (r || s || v)
        if self.signature.len() != 65 {
            return Err(Error::InvalidSignature(format!(
                "wallet signature must be 65 bytes, got {}",
                self.signature.len()
            )));
        }

        // 1. Prefix message per EIP-191
        let prefixed_message = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut full_message = prefixed_message.into_bytes();
        full_message.extend_from_slice(message);

        // 2. Hash with keccak256
        let message_hash = keccak256(&full_message);

        // 3. Parse signature (r || s || v)
        let r_s = &self.signature[..64];
        let v = self.signature[64];

        // Recovery ID: v is either 27/28 (legacy) or 0/1
        let recovery_id = match v {
            27 | 0 => RecoveryId::new(false, false),
            28 | 1 => RecoveryId::new(true, false),
            _ => {
                return Err(Error::InvalidSignature(format!(
                    "invalid recovery id: {}",
                    v
                )))
            }
        };

        let signature = K256Sig::try_from(r_s)
            .map_err(|e| Error::InvalidSignature(format!("invalid signature: {}", e)))?;

        // 4. Recover public key from signature
        let recovered_key =
            K256VerifyingKey::recover_from_prehash(message_hash.as_slice(), &signature, recovery_id)
                .map_err(|e| {
                    Error::InvalidSignature(format!("failed to recover public key: {}", e))
                })?;

        // 5. Derive address from public key (keccak256 of uncompressed pubkey, last 20 bytes)
        let pubkey_bytes = recovered_key.to_encoded_point(false);
        let pubkey_hash = keccak256(&pubkey_bytes.as_bytes()[1..]); // Skip 0x04 prefix
        let recovered_address = Address::from_slice(&pubkey_hash[12..]);

        // 6. Parse claimed address and compare
        let claimed: Address = claimed_address
            .parse()
            .map_err(|e| Error::InvalidSignature(format!("invalid address format: {}", e)))?;

        if recovered_address != claimed {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }

    /// Returns the public key bytes if this is a passkey signature.
    pub fn public_key_bytes(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }
}
