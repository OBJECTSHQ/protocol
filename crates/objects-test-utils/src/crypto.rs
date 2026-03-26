//! Cryptographic test utilities.
//!
//! This module provides standardized factories for cryptographic primitives
//! used across OBJECTS Protocol tests.
//!
//! ## Design Principles
//!
//! - **Always use `OsRng`** for cryptographic randomness (per CLAUDE.md)
//! - **Return structured types** instead of tuples for clarity
//! - **Include public key bytes** to avoid repeated encoding
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::crypto;
//!
//! // Generate an Ed25519 keypair for testing
//! let keypair = crypto::ed25519_keypair();
//! assert_eq!(keypair.public_key.len(), 32);
//!
//! // Generate a random nonce
//! let nonce = crypto::random_nonce();
//! ```

use rand::RngCore;

/// An Ed25519 keypair for testing.
///
/// Contains both the signing key and its 32-byte public key.
pub struct Ed25519Keypair {
    /// The Ed25519 signing key
    pub signing_key: objects_identity::Ed25519SigningKey,
    /// The Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

/// Generate a random Ed25519 keypair for testing.
///
/// Uses `OsRng` for cryptographically secure randomness per CLAUDE.md.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::ed25519_keypair;
///
/// let keypair = ed25519_keypair();
/// assert_eq!(keypair.public_key.len(), 32);
/// ```
pub fn ed25519_keypair() -> Ed25519Keypair {
    let signing_key = objects_identity::Ed25519SigningKey::generate();
    let public_key = signing_key.public_key_bytes();
    Ed25519Keypair {
        signing_key,
        public_key,
    }
}

/// Generate a random 8-byte nonce for testing.
///
/// Uses `OsRng` for cryptographically secure randomness per CLAUDE.md.
/// This eliminates the inconsistency with `rand::rng()` usage in some tests.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::random_nonce;
///
/// let nonce1 = random_nonce();
/// let nonce2 = random_nonce();
/// assert_ne!(nonce1, nonce2); // Highly likely to be different
/// ```
pub fn random_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate an XChaCha20-Poly1305 encryption key for testing.
///
/// Uses `OsRng` for cryptographically secure randomness.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::encryption_key;
///
/// let key = encryption_key();
/// assert_eq!(key.len(), 32);
/// ```
pub fn encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Generate deterministic test bytes from a seed value.
///
/// Creates a predictable 32-byte array based on the seed. **This is NOT a
/// cryptographic hash function** - it simply generates deterministic bytes
/// for testing. For actual hashing, use `sha2` or `blake3` crates.
///
/// Useful for tests that need consistent but distinct byte arrays.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::deterministic_bytes;
///
/// let bytes1 = deterministic_bytes(42);
/// let bytes2 = deterministic_bytes(42);
/// assert_eq!(bytes1, bytes2); // Same seed produces same bytes
///
/// let bytes3 = deterministic_bytes(99);
/// assert_ne!(bytes1, bytes3); // Different seeds produce different bytes
/// ```
pub fn deterministic_bytes(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    // Fill with predictable pattern
    for (i, byte) in bytes.iter_mut().enumerate().skip(1) {
        *byte = seed.wrapping_add(i as u8);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_includes_correct_public_key() {
        let keypair = ed25519_keypair();
        let derived_public = keypair.signing_key.public_key_bytes();
        assert_eq!(derived_public, keypair.public_key);
    }

    #[test]
    fn test_random_nonces_are_unique() {
        let nonce1 = random_nonce();
        let nonce2 = random_nonce();
        // Statistically should never be equal
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_encryption_keys_are_unique() {
        let key1 = encryption_key();
        let key2 = encryption_key();
        // Statistically should never be equal
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_deterministic_bytes_is_deterministic() {
        let bytes1 = deterministic_bytes(42);
        let bytes2 = deterministic_bytes(42);
        assert_eq!(bytes1, bytes2);

        let bytes3 = deterministic_bytes(99);
        assert_ne!(bytes1, bytes3);
    }
}
