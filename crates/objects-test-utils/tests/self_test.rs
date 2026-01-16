//! Self-tests for test utilities.
//!
//! These tests validate the correctness of the test utilities themselves,
//! ensuring that test fixtures provide consistent, correct behavior.

use objects_test_utils::{crypto, time};

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
