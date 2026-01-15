//! Common test utilities for objects-identity integration tests.
//!
//! **DEPRECATED:** This module now forwards to `objects-test-utils`.
//! Use `objects_test_utils` directly instead.
//!
//! These functions remain for backward compatibility during migration
//! but will be removed in a future PR.

use k256::ecdsa::SigningKey as K256SigningKey;
use objects_identity::IdentityId;
use objects_test_utils::{crypto, identity, time};
use p256::ecdsa::SigningKey as P256SigningKey;

/// **DEPRECATED:** Use `objects_test_utils::crypto::passkey_keypair().signing_key` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use objects_test_utils::crypto::passkey_keypair().signing_key instead"
)]
pub fn test_passkey_key() -> P256SigningKey {
    crypto::passkey_keypair().signing_key
}

/// **DEPRECATED:** Use `objects_test_utils::crypto::wallet_keypair().signing_key` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use objects_test_utils::crypto::wallet_keypair().signing_key instead"
)]
pub fn test_wallet_key() -> K256SigningKey {
    crypto::wallet_keypair().signing_key
}

/// **DEPRECATED:** Use `objects_test_utils::identity::test_identity_id()` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use objects_test_utils::identity::test_identity_id() instead"
)]
pub fn test_identity_id() -> IdentityId {
    identity::test_identity_id()
}

/// **DEPRECATED:** Use `objects_test_utils::time::now()` instead.
#[deprecated(since = "0.1.0", note = "Use objects_test_utils::time::now() instead")]
pub fn current_timestamp() -> u64 {
    time::now()
}

/// **DEPRECATED:** Use `objects_test_utils::crypto::random_nonce()` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use objects_test_utils::crypto::random_nonce() instead"
)]
pub fn random_nonce() -> [u8; 8] {
    crypto::random_nonce()
}

/// **DEPRECATED:** Use `objects_test_utils::rfc_vectors::reserved_handles()` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use objects_test_utils::rfc_vectors::reserved_handles() instead"
)]
pub fn reserved_handles() -> Vec<&'static str> {
    objects_test_utils::rfc_vectors::reserved_handles()
}

/// **DEPRECATED:** Use `objects_test_utils::rfc_vectors::is_reserved()` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use objects_test_utils::rfc_vectors::is_reserved() instead"
)]
pub fn is_reserved(handle: &str) -> bool {
    objects_test_utils::rfc_vectors::is_reserved(handle)
}
