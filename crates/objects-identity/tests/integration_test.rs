//! Integration tests for objects-identity crate.
//!
//! Tests the full identity lifecycle including:
//! - Identity derivation
//! - Ed25519 signature verification
//! - Handle validation
//! - Vault key derivation
//! - Cross-module integration

use objects_identity::{
    Ed25519SigningKey, Handle, IdentityId, generate_nonce, message, vault::VaultKeys,
};
use objects_test_utils::{crypto, time};
use rstest::*;

/// Fixture providing a fresh Ed25519 signing key for each test.
#[fixture]
fn signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::generate()
}

// ============================================================================
// Identity Lifecycle Tests
// ============================================================================

#[rstest]
fn test_identity_lifecycle(signing_key: Ed25519SigningKey) {
    let nonce = crypto::random_nonce();
    let public_key = signing_key.public_key_bytes();

    // 1. Derive identity ID
    let identity_id = IdentityId::derive(&public_key, &nonce);

    // 2. Verify ID format
    assert!(identity_id.as_str().starts_with("obj_"));
    assert!(identity_id.as_str().len() >= 23);
    assert!(identity_id.as_str().len() <= 25);

    // 3. Create and validate handle
    let handle = Handle::parse("alice_test").expect("valid handle");
    assert_eq!(handle.as_str(), "alice_test");

    // 4. Test ID parsing round-trip
    let id_str = identity_id.as_str();
    let parsed_id = IdentityId::parse(id_str).expect("parse identity ID");
    assert_eq!(parsed_id, identity_id);

    // 5. Verify determinism - same key + nonce = same ID
    let identity_id_2 = IdentityId::derive(&public_key, &nonce);
    assert_eq!(identity_id, identity_id_2);

    // 6. Verify uniqueness - different nonce = different ID
    let different_nonce = [255, 254, 253, 252, 251, 250, 249, 248];
    let identity_id_3 = IdentityId::derive(&public_key, &different_nonce);
    assert_ne!(identity_id, identity_id_3);
}

#[test]
fn test_generate_nonce_produces_unique_values() {
    let nonce1 = generate_nonce();
    let nonce2 = generate_nonce();
    assert_ne!(nonce1, nonce2);
}

// ============================================================================
// Ed25519 Signature Verification Tests
// ============================================================================

#[rstest]
fn test_ed25519_signature_verification_full_lifecycle(signing_key: Ed25519SigningKey) {
    let nonce = crypto::random_nonce();
    let public_key = signing_key.public_key_bytes();

    // 1. Derive identity ID
    let identity_id = IdentityId::derive(&public_key, &nonce);

    // 2. Create a message to sign (RFC-001 format)
    let message_text = message::create_identity_message(identity_id.as_str(), "alice", time::now());
    let message_bytes = message_text.as_bytes();

    // 3. Sign with Ed25519
    let signature = signing_key.sign(message_bytes);

    // 4. Verify signature
    assert!(
        signature.verify(message_bytes).is_ok(),
        "signature verification should succeed"
    );

    // 5. Verify wrong message fails
    assert!(
        signature.verify(b"wrong message").is_err(),
        "wrong message should fail verification"
    );
}

#[rstest]
fn test_signature_from_different_key_fails(signing_key: Ed25519SigningKey) {
    let message = b"test message";
    let signature = signing_key.sign(message);

    // Signature should not verify with a different message
    assert!(signature.verify(b"different message").is_err());
}

// ============================================================================
// Handle Validation Tests
// ============================================================================

#[rstest]
#[case::valid_simple("alice")]
#[case::valid_with_underscore("alice_bob")]
#[case::valid_with_period("alice.bob")]
#[case::valid_with_numbers("alice123")]
#[case::valid_mixed("alice_123.test")]
fn test_handle_validation_valid(#[case] handle: &str) {
    let result = Handle::parse(handle);
    assert!(result.is_ok(), "handle '{}' should be valid", handle);
}

#[rstest]
#[case::empty("")]
#[case::too_long("a".repeat(31))]
#[case::uppercase("Alice")]
#[case::leading_underscore("_alice")]
#[case::leading_period(".alice")]
#[case::trailing_period("alice.")]
#[case::consecutive_periods("alice..bob")]
#[case::reserved_admin("admin")]
#[case::reserved_root("root")]
#[case::reserved_system("system")]
fn test_handle_validation_invalid(#[case] handle: String) {
    let result = Handle::parse(&handle);
    assert!(result.is_err(), "handle '{}' should be invalid", handle);
}

// ============================================================================
// Vault Key Derivation Tests
// ============================================================================

#[rstest]
fn test_vault_key_derivation(signing_key: Ed25519SigningKey) {
    let secret_bytes = signing_key.to_bytes();

    // 1. Derive vault keys
    let vault_keys =
        VaultKeys::derive_from_signing_key(&secret_bytes).expect("vault derivation succeeds");

    // 2. Verify namespace ID is derived
    let namespace_id = vault_keys.namespace_id();
    assert_eq!(
        namespace_id.as_bytes().len(),
        32,
        "namespace ID should be 32 bytes"
    );

    // 3. Verify determinism - same key = same vault
    let vault_keys_2 =
        VaultKeys::derive_from_signing_key(&secret_bytes).expect("vault derivation succeeds");
    assert_eq!(vault_keys.namespace_id(), vault_keys_2.namespace_id());
    assert_eq!(
        vault_keys.catalog_encryption_key,
        vault_keys_2.catalog_encryption_key
    );
}

#[test]
fn test_vault_key_uniqueness() {
    let key1 = Ed25519SigningKey::generate();
    let key2 = Ed25519SigningKey::generate();

    let vault1 =
        VaultKeys::derive_from_signing_key(&key1.to_bytes()).expect("vault derivation succeeds");
    let vault2 =
        VaultKeys::derive_from_signing_key(&key2.to_bytes()).expect("vault derivation succeeds");

    assert_ne!(vault1.namespace_id(), vault2.namespace_id());
    assert_ne!(vault1.catalog_encryption_key, vault2.catalog_encryption_key);
}

// ============================================================================
// Message Formatting Tests
// ============================================================================

#[test]
fn test_message_format_create_identity() {
    let key = Ed25519SigningKey::generate();
    let nonce = [1u8; 8];
    let identity_id = IdentityId::derive(&key.public_key_bytes(), &nonce);
    let timestamp = 1704067200;

    let message = message::create_identity_message(identity_id.as_str(), "alice", timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Create Identity"));
    assert!(message.contains("alice"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains("1704067200"));
}

#[test]
fn test_message_format_sign_asset() {
    let key = Ed25519SigningKey::generate();
    let nonce = [1u8; 8];
    let identity_id = IdentityId::derive(&key.public_key_bytes(), &nonce);
    let content_hash = hex::encode(crypto::deterministic_bytes(42));
    let timestamp = time::now();

    let message = message::sign_asset_message(identity_id.as_str(), &content_hash, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Sign Asset"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains(&content_hash));
}

#[test]
fn test_message_format_authenticate() {
    let app_domain = "app.example.com";
    let challenge = hex::encode([0xde, 0xad, 0xbe, 0xef].repeat(16));
    let timestamp = time::now();

    let message = message::authenticate_message(app_domain, &challenge, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Authenticate"));
    assert!(message.contains(app_domain));
    assert!(message.contains(&challenge));
}

#[test]
fn test_message_format_change_handle() {
    let key = Ed25519SigningKey::generate();
    let nonce = [1u8; 8];
    let identity_id = IdentityId::derive(&key.public_key_bytes(), &nonce);
    let new_handle = "bob";
    let timestamp = time::now();

    let message = message::change_handle_message(identity_id.as_str(), new_handle, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Change Handle"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains(new_handle));
}
