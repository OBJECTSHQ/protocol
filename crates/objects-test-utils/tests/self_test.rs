//! Self-tests for test utilities.
//!
//! These tests validate the correctness of the test utilities themselves,
//! ensuring that test fixtures provide consistent, correct behavior.

use objects_identity::IdentityId;
use objects_test_utils::{crypto, identity, rfc_vectors, time};

// ============================================================================
// Crypto Module Tests
// ============================================================================

#[test]
fn test_passkey_keypair_public_key_matches() {
    let keypair = crypto::passkey_keypair();

    // Derive public key from signing key and verify it matches the stored one
    let derived_public = keypair.signing_key.verifying_key().to_encoded_point(true);
    assert_eq!(
        derived_public.as_bytes(),
        &keypair.public_key[..],
        "stored public key must match derived public key"
    );

    // Verify correct length
    assert_eq!(
        keypair.public_key.len(),
        33,
        "P-256 compressed key is 33 bytes"
    );
}

#[test]
fn test_wallet_keypair_public_key_matches() {
    let keypair = crypto::wallet_keypair();

    // Derive public key from signing key and verify it matches the stored one
    let derived_public = keypair.signing_key.verifying_key().to_encoded_point(true);
    assert_eq!(
        derived_public.as_bytes(),
        &keypair.public_key[..],
        "stored public key must match derived public key"
    );

    // Verify correct length
    assert_eq!(
        keypair.public_key.len(),
        33,
        "secp256k1 compressed key is 33 bytes"
    );
}

#[test]
fn test_random_nonces_are_unique() {
    let nonce1 = crypto::random_nonce();
    let nonce2 = crypto::random_nonce();

    // Statistically should never be equal (2^64 possible values)
    assert_ne!(nonce1, nonce2, "consecutive nonces should differ");
}

#[test]
fn test_encryption_keys_are_unique() {
    let key1 = crypto::encryption_key();
    let key2 = crypto::encryption_key();

    // Statistically should never be equal (2^256 possible values)
    assert_ne!(key1, key2, "consecutive encryption keys should differ");
    assert_eq!(key1.len(), 32, "encryption key is 32 bytes");
}

#[test]
fn test_content_hash_is_deterministic() {
    let hash1 = crypto::test_content_hash(42);
    let hash2 = crypto::test_content_hash(42);
    assert_eq!(hash1, hash2, "same seed should produce same hash");

    let hash3 = crypto::test_content_hash(99);
    assert_ne!(
        hash1, hash3,
        "different seeds should produce different hashes"
    );
}

// ============================================================================
// Time Module Tests
// ============================================================================

#[test]
fn test_now_returns_reasonable_timestamp() {
    let timestamp = time::now();

    // Should be after 2024-01-01 (1704067200)
    assert!(
        timestamp > 1704067200,
        "timestamp should be after 2024-01-01"
    );

    // Should be before 2030-01-01 (1893456000)
    assert!(
        timestamp < 1893456000,
        "timestamp should be before 2030-01-01"
    );
}

#[test]
fn test_future_timestamp_adds_offset() {
    let current = time::now();
    let future = time::future_timestamp(100);

    assert!(
        future >= current + 100,
        "future timestamp should be at least offset seconds ahead"
    );
    assert!(
        future <= current + 101,
        "future timestamp should not exceed offset + 1 second (for test execution time)"
    );
}

#[test]
fn test_timestamp_constant_is_correct() {
    // 2024-01-06 12:00:00 UTC
    assert_eq!(time::TEST_TIMESTAMP, 1704542400);
}

// ============================================================================
// RFC Vectors Module Tests
// ============================================================================

#[test]
fn test_rfc_001_identity_vector_is_canonical() {
    let id = rfc_vectors::rfc_001_identity_id();
    assert_eq!(
        id.as_str(),
        "obj_2dMiYc8RhnYkorPc5pVh9",
        "RFC-001 canonical identity must match specification"
    );
}

#[test]
fn test_rfc_001_public_key_format() {
    let public_key = rfc_vectors::rfc_001_signer_public_key();

    assert_eq!(public_key.len(), 33, "public key is 33 bytes");
    assert_eq!(
        public_key[0], 0x02,
        "first byte is 0x02 for compressed SEC1 encoding"
    );

    // Verify hex encoding matches RFC-001
    let hex_encoded = hex::encode(public_key);
    assert_eq!(
        hex_encoded,
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    );
}

#[test]
fn test_rfc_001_nonce_is_correct() {
    let nonce = rfc_vectors::rfc_001_nonce();
    assert_eq!(
        nonce,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "nonce must match RFC-001 specification"
    );
}

#[test]
fn test_rfc_001_identity_derivation_is_consistent() {
    // Verify that deriving the identity from the test vector components
    // produces the canonical identity ID
    let public_key = rfc_vectors::rfc_001_signer_public_key();
    let nonce = rfc_vectors::rfc_001_nonce();
    let derived = IdentityId::derive(&public_key, &nonce);

    let canonical = rfc_vectors::rfc_001_identity_id();
    assert_eq!(
        derived, canonical,
        "manual derivation must match canonical identity"
    );
}

#[test]
fn test_reserved_handles_contains_expected_values() {
    let handles = rfc_vectors::reserved_handles();

    // Check key reserved handles
    assert!(handles.contains(&"admin"));
    assert!(handles.contains(&"root"));
    assert!(handles.contains(&"system"));
    assert!(handles.contains(&"objects"));
    assert!(handles.contains(&"protocol"));

    // Verify list is not empty
    assert!(
        !handles.is_empty(),
        "reserved handles list should not be empty"
    );
}

#[test]
fn test_is_reserved_function() {
    // Reserved handles
    assert!(rfc_vectors::is_reserved("admin"));
    assert!(rfc_vectors::is_reserved("root"));
    assert!(rfc_vectors::is_reserved("system"));

    // Non-reserved handles
    assert!(!rfc_vectors::is_reserved("my_handle"));
    assert!(!rfc_vectors::is_reserved("user123"));
    assert!(!rfc_vectors::is_reserved("custom"));
}

// ============================================================================
// Identity Module Tests
// ============================================================================

#[test]
fn test_identity_id_matches_rfc_vector() {
    let id = identity::test_identity_id();
    assert_eq!(
        id.as_str(),
        "obj_2dMiYc8RhnYkorPc5pVh9",
        "test_identity_id must return RFC-001 canonical identity"
    );

    // Should be same as rfc_vectors module
    assert_eq!(id, rfc_vectors::rfc_001_identity_id());
}

#[test]
fn test_random_passkey_identity_derivation() {
    let identity = identity::random_passkey_identity();

    // Verify the identity ID was correctly derived from public key + nonce
    let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
    assert_eq!(
        identity.identity_id, derived,
        "stored identity_id must match derived value"
    );

    // Verify ID format
    assert!(identity.identity_id.as_str().starts_with("obj_"));
    assert!(identity.identity_id.as_str().len() >= 23);
    assert!(identity.identity_id.as_str().len() <= 25);
}

#[test]
fn test_random_wallet_identity_derivation() {
    let identity = identity::random_wallet_identity();

    // Verify the identity ID was correctly derived from public key + nonce
    let derived = IdentityId::derive(&identity.keypair.public_key, &identity.nonce);
    assert_eq!(
        identity.identity_id, derived,
        "stored identity_id must match derived value"
    );

    // Verify ID format
    assert!(identity.identity_id.as_str().starts_with("obj_"));
}

#[test]
fn test_random_passkey_identities_are_unique() {
    let id1 = identity::random_passkey_identity();
    let id2 = identity::random_passkey_identity();

    // Statistically should never be equal
    assert_ne!(id1.identity_id, id2.identity_id, "identities should differ");
    assert_ne!(id1.nonce, id2.nonce, "nonces should differ");
}

#[test]
fn test_random_wallet_identities_are_unique() {
    let id1 = identity::random_wallet_identity();
    let id2 = identity::random_wallet_identity();

    // Statistically should never be equal
    assert_ne!(id1.identity_id, id2.identity_id, "identities should differ");
    assert_ne!(id1.nonce, id2.nonce, "nonces should differ");
}

// ============================================================================
// Integration Tests (Cross-Module)
// ============================================================================

#[test]
fn test_passkey_keypair_can_derive_identity() {
    let keypair = crypto::passkey_keypair();
    let nonce = crypto::random_nonce();
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    // Should produce a valid identity ID
    assert!(identity_id.as_str().starts_with("obj_"));
    assert!(identity_id.as_str().len() >= 23);
}

#[test]
fn test_wallet_keypair_can_derive_identity() {
    let keypair = crypto::wallet_keypair();
    let nonce = crypto::random_nonce();
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    // Should produce a valid identity ID
    assert!(identity_id.as_str().starts_with("obj_"));
}

#[test]
fn test_rfc_vector_components_can_recreate_identity() {
    // This test verifies that the RFC vector components are consistent
    // and can be used to manually recreate the canonical identity
    let public_key = rfc_vectors::rfc_001_signer_public_key();
    let nonce = rfc_vectors::rfc_001_nonce();

    let derived = IdentityId::derive(&public_key, &nonce);
    let canonical = rfc_vectors::rfc_001_identity_id();
    let test_identity = identity::test_identity_id();

    assert_eq!(derived, canonical);
    assert_eq!(derived, test_identity);
    assert_eq!(canonical, test_identity);
}
