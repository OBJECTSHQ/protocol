//! Signer types for identity operations.
//!
//! Identity signers use Ed25519 keys.

use serde::{Deserialize, Serialize};

/// A signer that can create signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    /// The Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],
}

impl Signer {
    /// Creates a new signer from an Ed25519 public key.
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }

    /// Returns the public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_public_key_hex() {
        let pk = [0xab; 32];
        let signer = Signer::new(pk);
        assert_eq!(signer.public_key_hex(), "ab".repeat(32));
    }
}
