//! Identity factory utilities for testing.
//!
//! Provides factory functions for creating test identities with both
//! deterministic (RFC-001 vectors) and random values.
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::identity;
//!
//! // Get RFC-001 canonical identity
//! let id = identity::test_identity_id();
//!
//! // Generate random passkey identity
//! let random = identity::random_passkey_identity();
//! assert_eq!(random.identity_id.as_str().len(), 25); // obj_ prefix + 21 base58 chars
//!
//! // Generate random wallet identity
//! let wallet = identity::random_wallet_identity();
//! ```

use crate::crypto::{PasskeyKeypair, WalletKeypair, passkey_keypair, random_nonce, wallet_keypair};
use crate::rfc_vectors::rfc_001_identity_id;
use objects_identity::IdentityId;
use p256::ecdsa::SigningKey as P256SigningKey;

/// A randomly generated passkey-based identity with full context.
///
/// Contains the derived identity ID, the nonce used for derivation,
/// and the complete keypair for signing operations.
#[derive(Debug)]
pub struct RandomPasskeyIdentity {
    /// The derived identity ID
    pub identity_id: IdentityId,
    /// The nonce used for derivation (8 bytes)
    pub nonce: [u8; 8],
    /// The P-256 keypair (includes signing key and compressed public key)
    pub keypair: PasskeyKeypair,
}

/// A randomly generated wallet-based identity with full context.
///
/// Contains the derived identity ID, the nonce used for derivation,
/// and the complete keypair for signing operations.
#[derive(Debug)]
pub struct RandomWalletIdentity {
    /// The derived identity ID
    pub identity_id: IdentityId,
    /// The nonce used for derivation (8 bytes)
    pub nonce: [u8; 8],
    /// The secp256k1 keypair (includes signing key and compressed public key)
    pub keypair: WalletKeypair,
}

/// Get the RFC-001 canonical test identity ID.
///
/// This returns the identity ID from RFC-001 Appendix B.1, which is derived
/// from the canonical test vector public key and nonce. Use this for tests
/// that need a consistent, predictable identity.
///
/// Value: `obj_2dMiYc8RhnYkorPc5pVh9`
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::identity::test_identity_id;
///
/// let id = test_identity_id();
/// assert_eq!(id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
/// ```
pub fn test_identity_id() -> IdentityId {
    rfc_001_identity_id()
}

/// Generate a random passkey-based identity.
///
/// Creates a new P-256 keypair, generates a random nonce, and derives
/// an identity ID. Returns all components for use in tests.
///
/// Uses `OsRng` for cryptographically secure randomness.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::identity::random_passkey_identity;
///
/// let identity = random_passkey_identity();
///
/// // Verify the identity ID was derived correctly
/// use objects_identity::IdentityId;
/// let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
/// assert_eq!(identity.identity_id, derived);
/// ```
pub fn random_passkey_identity() -> RandomPasskeyIdentity {
    let keypair = passkey_keypair();
    let nonce = random_nonce();
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    RandomPasskeyIdentity {
        identity_id,
        nonce,
        keypair,
    }
}

/// Generate a random wallet-based identity.
///
/// Creates a new secp256k1 keypair, generates a random nonce, and derives
/// an identity ID. Returns all components for use in tests.
///
/// Uses `OsRng` for cryptographically secure randomness.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::identity::random_wallet_identity;
///
/// let identity = random_wallet_identity();
///
/// // Verify the identity ID was derived correctly
/// use objects_identity::IdentityId;
/// let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
/// assert_eq!(identity.identity_id, derived);
/// ```
pub fn random_wallet_identity() -> RandomWalletIdentity {
    let keypair = wallet_keypair();
    let nonce = random_nonce();
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    RandomWalletIdentity {
        identity_id,
        nonce,
        keypair,
    }
}

/// Deprecated: Generate a random identity with nonce (tuple return).
///
/// This function returns a tuple for backward compatibility during migration.
/// Use `random_passkey_identity()` instead for a more structured return type.
#[deprecated(
    since = "0.1.0",
    note = "Use random_passkey_identity() for structured return type"
)]
pub fn random_identity_with_nonce() -> (IdentityId, [u8; 8], P256SigningKey) {
    let identity = random_passkey_identity();
    (
        identity.identity_id,
        identity.nonce,
        identity.keypair.signing_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_id_matches_rfc_vector() {
        let id = test_identity_id();
        assert_eq!(id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
    }

    #[test]
    fn test_random_passkey_identity_derivation() {
        let identity = random_passkey_identity();

        // Verify the identity ID was correctly derived
        let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
        assert_eq!(identity.identity_id, derived);

        // Verify the ID has correct format
        assert!(identity.identity_id.as_str().starts_with("obj_"));
        assert!(identity.identity_id.as_str().len() >= 23);
        assert!(identity.identity_id.as_str().len() <= 25);
    }

    #[test]
    fn test_random_wallet_identity_derivation() {
        let identity = random_wallet_identity();

        // Verify the identity ID was correctly derived
        let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
        assert_eq!(identity.identity_id, derived);

        // Verify the ID has correct format
        assert!(identity.identity_id.as_str().starts_with("obj_"));
    }

    #[test]
    fn test_random_identities_are_unique() {
        let id1 = random_passkey_identity();
        let id2 = random_passkey_identity();

        // Statistically should never be equal
        assert_ne!(id1.identity_id, id2.identity_id);
        assert_ne!(id1.nonce, id2.nonce);
    }
}
