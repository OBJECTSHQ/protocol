//! Ed25519 signature type and verification.
//!
//! Uses ed25519-dalek (RustCrypto) for signature verification.

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;

/// An Ed25519 signature over a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Ed25519 signature (64 bytes).
    signature: Vec<u8>,
    /// Ed25519 public key of the signer (32 bytes).
    public_key: Vec<u8>,
}

impl Signature {
    /// Creates a new Ed25519 signature.
    pub fn new(signature: [u8; 64], public_key: [u8; 32]) -> Self {
        Self {
            signature: signature.to_vec(),
            public_key: public_key.to_vec(),
        }
    }

    /// Returns the raw signature bytes.
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Verifies the signature against a message using ed25519-dalek.
    pub fn verify(&self, message: &[u8]) -> Result<(), Error> {
        let pk_bytes: [u8; 32] = self
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature("public key must be 32 bytes".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| Error::InvalidSignature(format!("invalid Ed25519 public key: {}", e)))?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature("signature must be 64 bytes".to_string()))?;

        let sig = DalekSig::from_bytes(&sig_bytes);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| Error::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ed25519SigningKey;

    #[test]
    fn test_verify_valid_signature() {
        let key = Ed25519SigningKey::generate();
        let message = b"test message";
        let signature = key.sign(message);
        assert!(signature.verify(message).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let key = Ed25519SigningKey::generate();
        let signature = key.sign(b"original");
        assert!(signature.verify(b"tampered").is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let message = b"test message";

        let signature = key1.sign(message);
        // Manually construct with wrong public key
        let bad_sig = Signature::new(
            signature.signature_bytes().try_into().unwrap(),
            key2.public_key_bytes(),
        );
        assert!(bad_sig.verify(message).is_err());
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let key = Ed25519SigningKey::generate();
        let signature = key.sign(b"test");
        assert_eq!(signature.signature_bytes().len(), 64);
        assert_eq!(signature.public_key_bytes().len(), 32);
    }
}
