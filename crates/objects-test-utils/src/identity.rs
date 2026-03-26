//! Identity factory utilities for testing.
//!
//! Provides factory functions for creating test identities with both
//! deterministic (canonical test identity) and random values.
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::identity;
//!
//! // Get canonical test identity
//! let id = identity::test_identity_id();
//!
//! // Generate random identity
//! let random = identity::random_identity();
//! assert!(random.identity_id.as_str().starts_with("obj_"));
//! ```

use crate::crypto::{Ed25519Keypair, ed25519_keypair, random_nonce};
use objects_identity::IdentityId;

/// A randomly generated Ed25519-based identity with full context.
///
/// Contains the derived identity ID, the nonce used for derivation,
/// and the complete keypair for signing operations.
pub struct RandomIdentity {
    /// The derived identity ID
    pub identity_id: IdentityId,
    /// The nonce used for derivation (8 bytes)
    pub nonce: [u8; 8],
    /// The Ed25519 keypair (includes signing key and 32-byte public key)
    pub keypair: Ed25519Keypair,
}

/// Get a canonical test identity ID for deterministic tests.
///
/// Returns a fixed identity ID derived from known test values. Use this for tests
/// that need a consistent, predictable identity across runs.
///
/// Derived from 32-byte key (0xc6, 0x04, ..., 0xe5) + nonce (01..08).
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::identity::test_identity_id;
///
/// let id = test_identity_id();
/// assert!(id.as_str().starts_with("obj_"));
/// ```
pub fn test_identity_id() -> IdentityId {
    // Canonical test identity derived from a 32-byte Ed25519 public key + nonce.
    // public_key: c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    // nonce: 0102030405060708
    let public_key: [u8; 32] = [
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
        0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70,
        0x9e, 0xe5,
    ];
    let nonce: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    IdentityId::derive(&public_key, &nonce)
}

/// Generate a random Ed25519-based identity.
///
/// Creates a new Ed25519 keypair, generates a random nonce, and derives
/// an identity ID. Returns all components for use in tests.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::identity::random_identity;
///
/// let identity = random_identity();
///
/// // Verify the identity ID was derived correctly
/// use objects_identity::IdentityId;
/// let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
/// assert_eq!(identity.identity_id, derived);
/// ```
pub fn random_identity() -> RandomIdentity {
    let keypair = ed25519_keypair();
    let nonce = random_nonce();
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    RandomIdentity {
        identity_id,
        nonce,
        keypair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_id_is_deterministic() {
        let id1 = test_identity_id();
        let id2 = test_identity_id();
        assert_eq!(id1, id2);
        assert!(id1.as_str().starts_with("obj_"));
    }

    #[test]
    fn test_random_identity_derivation() {
        let identity = random_identity();

        // Verify the identity ID was correctly derived
        let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
        assert_eq!(identity.identity_id, derived);

        // Verify the ID has correct format
        assert!(identity.identity_id.as_str().starts_with("obj_"));
        assert!(identity.identity_id.as_str().len() >= 23);
        assert!(identity.identity_id.as_str().len() <= 25);
    }

    #[test]
    fn test_random_identities_are_unique() {
        let id1 = random_identity();
        let id2 = random_identity();

        // Statistically should never be equal
        assert_ne!(id1.identity_id, id2.identity_id);
        assert_ne!(id1.nonce, id2.nonce);
    }
}
