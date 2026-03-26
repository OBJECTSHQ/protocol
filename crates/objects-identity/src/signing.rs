//! Key generation and signing for identity operations.
//!
//! Uses ed25519-dalek (RustCrypto) for Ed25519 signing.

use crate::Signature;
use ed25519_dalek::{Signer, SigningKey};

/// Ed25519 signing key for identity operations.
#[derive(Clone)]
pub struct Ed25519SigningKey {
    key: SigningKey,
}

impl Ed25519SigningKey {
    /// Generate a new random Ed25519 signing key.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret);
        Self {
            key: SigningKey::from_bytes(&secret),
        }
    }

    /// Create from raw secret bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }

    /// Get the secret key bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Get the public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Sign a message, producing an Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.key.sign(message);
        Signature::new(sig.to_bytes(), self.public_key_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let key = Ed25519SigningKey::generate();
        let message = b"test message";
        let signature = key.sign(message);

        assert!(signature.verify(message).is_ok());
    }

    #[test]
    fn test_roundtrip() {
        let key1 = Ed25519SigningKey::generate();
        let bytes = key1.to_bytes();
        let key2 = Ed25519SigningKey::from_bytes(&bytes);

        assert_eq!(key1.public_key_bytes(), key2.public_key_bytes());
    }

    #[test]
    fn test_public_key_is_32_bytes() {
        let key = Ed25519SigningKey::generate();
        assert_eq!(key.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let key = Ed25519SigningKey::generate();
        let signature = key.sign(b"original message");
        assert!(signature.verify(b"tampered message").is_err());
    }
}
