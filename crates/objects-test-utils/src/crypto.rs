//! Cryptographic test utilities.
//!
//! This module provides standardized factories for cryptographic primitives
//! used across OBJECTS Protocol tests.
//!
//! ## Design Principles
//!
//! - **Always use `OsRng`** for cryptographic randomness (per CLAUDE.md)
//! - **Return structured types** instead of tuples for clarity
//! - **Include public key bytes** to avoid repeated SEC1 encoding
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::crypto;
//!
//! // Generate a passkey for testing
//! let keypair = crypto::passkey_keypair();
//! assert_eq!(keypair.public_key.len(), 33);
//!
//! // Generate a random nonce
//! let nonce = crypto::random_nonce();
//! ```

use k256::ecdsa::SigningKey as K256SigningKey;
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use objects_data::ContentHash;
use p256::ecdsa::SigningKey as P256SigningKey;

/// A P-256 (secp256r1) keypair for WebAuthn passkey testing.
///
/// Contains both the signing key and its compressed SEC1 public key encoding.
#[derive(Debug)]
pub struct PasskeyKeypair {
    /// The P-256 signing key
    pub signing_key: P256SigningKey,
    /// The compressed SEC1 encoded public key (33 bytes)
    pub public_key: [u8; 33],
}

/// A secp256k1 keypair for Ethereum wallet testing.
///
/// Contains both the signing key and its compressed SEC1 public key encoding.
#[derive(Debug)]
pub struct WalletKeypair {
    /// The secp256k1 signing key
    pub signing_key: K256SigningKey,
    /// The compressed SEC1 encoded public key (33 bytes)
    pub public_key: [u8; 33],
}

/// Generate a random P-256 (secp256r1) keypair for passkey tests.
///
/// Uses `OsRng` for cryptographically secure randomness per CLAUDE.md.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::passkey_keypair;
///
/// let keypair = passkey_keypair();
/// assert_eq!(keypair.public_key.len(), 33);
/// ```
pub fn passkey_keypair() -> PasskeyKeypair {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(true);
    let public_key: [u8; 33] = public_key_point
        .as_bytes()
        .try_into()
        .expect("compressed P-256 public key is 33 bytes");

    PasskeyKeypair {
        signing_key,
        public_key,
    }
}

/// Generate a random secp256k1 keypair for wallet tests.
///
/// Uses `OsRng` for cryptographically secure randomness per CLAUDE.md.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::wallet_keypair;
///
/// let keypair = wallet_keypair();
/// assert_eq!(keypair.public_key.len(), 33);
/// ```
pub fn wallet_keypair() -> WalletKeypair {
    let signing_key = K256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(true);
    let public_key: [u8; 33] = public_key_point
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 public key is 33 bytes");

    WalletKeypair {
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
    OsRng.fill_bytes(&mut nonce);
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
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a test ContentHash from a seed value for deterministic testing.
///
/// Creates a predictable 32-byte hash based on the seed, useful for tests
/// that need consistent but distinct content hashes.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::crypto::test_content_hash;
///
/// let hash1 = test_content_hash(42);
/// let hash2 = test_content_hash(42);
/// assert_eq!(hash1, hash2); // Same seed produces same hash
///
/// let hash3 = test_content_hash(99);
/// assert_ne!(hash1, hash3); // Different seeds produce different hashes
/// ```
pub fn test_content_hash(seed: u8) -> ContentHash {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    // Fill with predictable pattern
    for (i, byte) in bytes.iter_mut().enumerate().skip(1) {
        *byte = seed.wrapping_add(i as u8);
    }
    ContentHash::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_keypair_includes_correct_public_key() {
        let keypair = passkey_keypair();
        let derived_public = keypair.signing_key.verifying_key().to_encoded_point(true);
        assert_eq!(derived_public.as_bytes(), &keypair.public_key[..]);
    }

    #[test]
    fn test_wallet_keypair_includes_correct_public_key() {
        let keypair = wallet_keypair();
        let derived_public = keypair.signing_key.verifying_key().to_encoded_point(true);
        assert_eq!(derived_public.as_bytes(), &keypair.public_key[..]);
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
    fn test_content_hash_is_deterministic() {
        let hash1 = test_content_hash(42);
        let hash2 = test_content_hash(42);
        assert_eq!(hash1, hash2);

        let hash3 = test_content_hash(99);
        assert_ne!(hash1, hash3);
    }
}
