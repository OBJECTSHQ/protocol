//! Self-tests for test utilities.
//!
//! These tests validate the correctness of the test utilities themselves,
//! ensuring that test fixtures provide consistent, correct behavior.
//!
//! All test-utils module tests live here to avoid duplication between
//! inline `#[cfg(test)]` modules and this integration test file.

use objects_identity::IdentityId;
use objects_test_utils::{crypto, data, identity, time};

// ============================================================================
// Crypto Module Tests
// ============================================================================

#[test]
fn test_ed25519_keypair_public_key_matches() {
    let keypair = crypto::ed25519_keypair();

    // Derive public key from signing key and verify it matches the stored one
    let derived_public = keypair.signing_key.public_key_bytes();
    assert_eq!(
        derived_public, keypair.public_key,
        "stored public key must match derived public key"
    );

    // Verify correct length
    assert_eq!(
        keypair.public_key.len(),
        32,
        "Ed25519 public key is 32 bytes"
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
fn test_deterministic_bytes_is_deterministic() {
    let bytes1 = crypto::deterministic_bytes(42);
    let bytes2 = crypto::deterministic_bytes(42);
    assert_eq!(bytes1, bytes2, "same seed should produce same bytes");

    let bytes3 = crypto::deterministic_bytes(99);
    assert_ne!(
        bytes1, bytes3,
        "different seeds should produce different bytes"
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
// Identity Module Tests
// ============================================================================

#[test]
fn test_identity_id_is_deterministic() {
    let id1 = identity::test_identity_id();
    let id2 = identity::test_identity_id();
    assert_eq!(id1, id2, "test_identity_id must be deterministic");
    assert!(id1.as_str().starts_with("obj_"));
}

#[test]
fn test_random_identity_derivation() {
    let identity = identity::random_identity();

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
fn test_random_identities_are_unique() {
    let id1 = identity::random_identity();
    let id2 = identity::random_identity();

    // Statistically should never be equal
    assert_ne!(id1.identity_id, id2.identity_id, "identities should differ");
    assert_ne!(id1.nonce, id2.nonce, "nonces should differ");
}

// ============================================================================
// Data Module Tests
// ============================================================================

#[test]
fn test_asset_creation() {
    let author_id = identity::test_identity_id();
    let asset = data::asset("test-asset", author_id.clone());
    assert_eq!(asset.id(), "test-asset");
    assert_eq!(asset.author_id(), &author_id);
    assert_eq!(asset.name(), "Test Asset");
}

#[test]
fn test_asset_with_hash_uses_provided_hash() {
    let author_id = identity::test_identity_id();
    let hash = objects_data::ContentHash::new(crypto::deterministic_bytes(123));
    let asset = data::asset_with_hash("custom-hash", author_id, hash.clone());
    assert_eq!(asset.content_hash(), &hash);
}

#[test]
fn test_project_creation() {
    let owner_id = identity::test_identity_id();
    let project = data::project("Test Project", owner_id.clone());
    assert_eq!(project.name(), "Test Project");
    assert_eq!(project.owner_id(), &owner_id);
}

#[test]
fn test_project_from_replica_derives_id() {
    let replica_id = crypto::deterministic_bytes(42);
    let project = data::project_from_replica(&replica_id);
    let expected_id = objects_data::project_id_from_replica(&replica_id);
    assert_eq!(project.id(), expected_id);
}

#[test]
fn test_reference_creation() {
    let reference = data::reference("source-1", "target-2");
    assert_eq!(reference.source_asset_id, "source-1");
    assert_eq!(reference.target_asset_id, "target-2");
    assert_eq!(reference.id, "ref-source-1-target-2");
}

#[test]
fn test_signed_asset_bundle_verifies() {
    let bundle = data::signed_asset("test-asset");
    assert_eq!(bundle.asset.id(), "test-asset");
    assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
    assert!(bundle.signed_asset.verify().is_ok());
}

#[test]
fn test_signed_asset_author_matches_derived_id() {
    let bundle = data::signed_asset("test-id-match");
    let derived_id = IdentityId::derive(&bundle.signing_key.public_key_bytes(), &bundle.nonce);
    assert_eq!(bundle.identity_id, derived_id);
    assert_eq!(bundle.asset.author_id(), &derived_id);
}

// ============================================================================
// Integration Tests (Cross-Module)
// ============================================================================

#[test]
fn test_ed25519_keypair_can_derive_identity() {
    let keypair = crypto::ed25519_keypair();
    let nonce = crypto::random_nonce();
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    assert!(identity_id.as_str().starts_with("obj_"));
    assert!(identity_id.as_str().len() >= 23);
}
