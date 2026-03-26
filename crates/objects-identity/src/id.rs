//! Identity ID derivation and validation.
//!
//! Identity IDs are derived from an Ed25519 public key and a random nonce:
//! ```text
//! identity_id = "obj_" || base58(truncate(sha256(public_key || nonce), 15))
//! ```

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::Error;

/// Prefix for all OBJECTS identity IDs.
pub const IDENTITY_PREFIX: &str = "obj_";

/// Minimum length of the base58-encoded portion of an identity ID.
pub const IDENTITY_ENCODED_MIN_LEN: usize = 19;

/// Maximum length of the base58-encoded portion of an identity ID.
pub const IDENTITY_ENCODED_MAX_LEN: usize = 21;

/// Number of bytes to truncate the SHA-256 hash to.
const TRUNCATE_BYTES: usize = 15;

/// Size of the nonce in bytes.
pub const NONCE_SIZE: usize = 8;

/// Generates a cryptographically secure random nonce for identity derivation.
///
/// Uses the operating system's cryptographic random number generator.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// An OBJECTS identity identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct IdentityId(String);

impl IdentityId {
    /// Derives an identity ID from an Ed25519 public key and nonce.
    ///
    /// # Arguments
    /// * `public_key` - 32-byte Ed25519 public key
    /// * `nonce` - 8-byte random nonce
    pub fn derive(public_key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(nonce);
        let hash = hasher.finalize();

        let truncated = &hash[..TRUNCATE_BYTES];
        let encoded = bs58::encode(truncated).into_string();

        Self(format!("{}{}", IDENTITY_PREFIX, encoded))
    }

    /// Parses an identity ID from a string.
    pub fn parse(s: &str) -> Result<Self, Error> {
        if !s.starts_with(IDENTITY_PREFIX) {
            return Err(Error::InvalidIdentityId(format!(
                "must start with '{}'",
                IDENTITY_PREFIX
            )));
        }

        let encoded = &s[IDENTITY_PREFIX.len()..];
        if encoded.len() < IDENTITY_ENCODED_MIN_LEN || encoded.len() > IDENTITY_ENCODED_MAX_LEN {
            return Err(Error::InvalidIdentityId(format!(
                "encoded portion must be {}-{} characters, got {}",
                IDENTITY_ENCODED_MIN_LEN,
                IDENTITY_ENCODED_MAX_LEN,
                encoded.len()
            )));
        }

        // Validate base58 encoding and ensure it decodes to 15 bytes
        let decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| Error::InvalidIdentityId(format!("invalid base58: {}", e)))?;

        if decoded.len() != TRUNCATE_BYTES {
            return Err(Error::InvalidIdentityId(format!(
                "decoded bytes must be {} bytes, got {}",
                TRUNCATE_BYTES,
                decoded.len()
            )));
        }

        Ok(Self(s.to_string()))
    }

    /// Returns the identity ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> serde::Deserialize<'de> for IdentityId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl AsRef<str> for IdentityId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_identity_id_deterministic() {
        // Ed25519 public key (32 bytes)
        let public_key: [u8; 32] = [
            0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
            0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9,
            0x5c, 0x70, 0x9e, 0xe5,
        ];
        let nonce: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let id1 = IdentityId::derive(&public_key, &nonce);
        let id2 = IdentityId::derive(&public_key, &nonce);
        assert_eq!(id1, id2, "Same inputs must produce same ID");
        assert!(id1.as_str().starts_with("obj_"));
    }

    #[test]
    fn test_derive_different_keys_different_ids() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nonce = [0u8; 8];

        let id1 = IdentityId::derive(&key1, &nonce);
        let id2 = IdentityId::derive(&key2, &nonce);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_parse_valid_identity_id() {
        // Generate a valid ID first
        let public_key = [42u8; 32];
        let nonce = [1u8; 8];
        let id = IdentityId::derive(&public_key, &nonce);

        let parsed = IdentityId::parse(id.as_str()).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_parse_invalid_prefix() {
        let result = IdentityId::parse("abc_5KJvsngHeMpm88rD");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_length() {
        let result = IdentityId::parse("obj_short");
        assert!(result.is_err());
    }
}
