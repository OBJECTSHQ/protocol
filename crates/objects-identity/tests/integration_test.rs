//! Integration tests for objects-identity crate.
//!
//! Tests the full identity lifecycle including:
//! - Identity derivation (RFC-001 compliance)
//! - Signature verification (passkey and wallet)
//! - Handle validation
//! - Vault key derivation
//! - Cross-module integration

mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::*;
use k256::ecdsa::SigningKey as K256SigningKey;
use objects_identity::{
    Handle, IdentityId, Signature, SignerType, generate_nonce, message, vault::VaultKeys,
};
use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer as P256Signer};
use rstest::*;
use sha2::{Digest, Sha256};

/// Fixture providing a fresh passkey signer for each test.
#[fixture]
fn passkey_signer() -> P256SigningKey {
    test_passkey_key()
}

/// Fixture providing a fresh wallet signer for each test.
#[fixture]
fn wallet_signer() -> K256SigningKey {
    test_wallet_key()
}

// ============================================================================
// Identity Lifecycle Tests
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_identity_lifecycle_passkey(passkey_signer: P256SigningKey) {
    let nonce = random_nonce();
    let public_key = passkey_signer.verifying_key();

    // Get compressed SEC1 public key (33 bytes)
    let public_key_point = public_key.to_encoded_point(true);
    let public_key_bytes: [u8; 33] = public_key_point
        .as_bytes()
        .try_into()
        .expect("compressed point is 33 bytes");

    // 1. Derive identity ID
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);

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
}

#[rstest]
#[tokio::test]
async fn test_identity_lifecycle_wallet(wallet_signer: K256SigningKey) {
    let nonce = random_nonce();
    let public_key = wallet_signer.verifying_key();

    // Get compressed SEC1 public key (33 bytes)
    let public_key_point = public_key.to_encoded_point(true);
    let public_key_bytes: [u8; 33] = public_key_point
        .as_bytes()
        .try_into()
        .expect("compressed point is 33 bytes");

    // 1. Derive identity ID
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);

    // 2. Verify ID format
    assert!(identity_id.as_str().starts_with("obj_"));

    // 3. Verify determinism - same key + nonce = same ID
    let identity_id_2 = IdentityId::derive(&public_key_bytes, &nonce);
    assert_eq!(identity_id, identity_id_2);

    // 4. Verify uniqueness - different nonce = different ID
    let different_nonce = [255, 254, 253, 252, 251, 250, 249, 248];
    let identity_id_3 = IdentityId::derive(&public_key_bytes, &different_nonce);
    assert_ne!(identity_id, identity_id_3);
}

#[test]
fn test_rfc_001_test_vector() {
    // RFC-001 Appendix B test vector
    let public_key_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let public_key_bytes = hex::decode(public_key_hex).expect("valid hex");
    let public_key_array: [u8; 33] = public_key_bytes.try_into().expect("33 bytes");
    let nonce: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let identity_id = IdentityId::derive(&public_key_array, &nonce);

    assert_eq!(identity_id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
}

#[test]
fn test_generate_nonce_produces_unique_values() {
    let nonce1 = generate_nonce();
    let nonce2 = generate_nonce();

    // Statistically, two random nonces should be different
    assert_ne!(nonce1, nonce2);
}

// ============================================================================
// Cross-Module Signature Verification Tests (Passkey)
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_passkey_signature_verification_full_lifecycle(passkey_signer: P256SigningKey) {
    let nonce = random_nonce();
    let verifying_key = passkey_signer.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(true);
    let public_key_bytes: [u8; 33] = public_key_point.as_bytes().try_into().expect("33 bytes");

    // 1. Derive identity ID
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);

    // 2. Create a message to sign (RFC-001 format)
    let message_text =
        message::create_identity_message(identity_id.as_str(), "alice", current_timestamp());
    let message_bytes = message_text.as_bytes();

    // 3. Create WebAuthn authenticator_data (minimal valid format)
    // Format: RP ID hash (32) + flags (1) + counter (4)
    let rp_id_hash = Sha256::digest(b"example.com");
    let flags = 0x05u8; // UP + UV flags
    let counter = 0u32.to_be_bytes();
    let mut authenticator_data = rp_id_hash.to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&counter);

    // 4. Create client_data_json with base64url-encoded challenge
    let challenge_b64 = URL_SAFE_NO_PAD.encode(message_bytes);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
        challenge_b64
    )
    .into_bytes();

    // 5. Compute what WebAuthn signs: authenticator_data || SHA256(client_data_json)
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = authenticator_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    // 6. Sign the data with P-256
    let signature_der: p256::ecdsa::Signature = passkey_signer.sign(&signed_data);
    let signature_bytes = signature_der.to_der().to_bytes().to_vec();

    // 7. Create Signature struct
    let signature = Signature::passkey(
        signature_bytes,
        public_key_point.as_bytes().to_vec(),
        authenticator_data,
        client_data_json,
    );

    // 8. Verify signature
    let result = signature.verify(message_bytes);
    assert!(result.is_ok(), "signature verification should succeed");
}

// ============================================================================
// Cross-Module Signature Verification Tests (Wallet)
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_wallet_signature_verification_full_lifecycle(wallet_signer: K256SigningKey) {
    use alloy_primitives::keccak256;

    let nonce = random_nonce();
    let verifying_key = wallet_signer.verifying_key();

    // Get compressed public key for identity derivation
    let public_key_compressed = verifying_key.to_encoded_point(true);
    let public_key_bytes: [u8; 33] = public_key_compressed
        .as_bytes()
        .try_into()
        .expect("33 bytes");

    // 1. Derive identity ID
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);

    // 2. Derive Ethereum address from public key (for signature verification)
    let public_key_uncompressed = verifying_key.to_encoded_point(false);
    let public_key_uncompressed_bytes = public_key_uncompressed.as_bytes();
    let pub_key_hash = keccak256(&public_key_uncompressed_bytes[1..]); // Skip 0x04 prefix
    let address = format!("0x{}", hex::encode(&pub_key_hash[12..])); // Last 20 bytes

    // 3. Create a message to sign (RFC-001 format)
    let message_text =
        message::link_wallet_message(identity_id.as_str(), &address, current_timestamp());
    let message_bytes = message_text.as_bytes();

    // 4. Create EIP-191 prefixed message (Alloy does this internally, but we need to sign it)
    let eip191_prefix = format!("\x19Ethereum Signed Message:\n{}", message_bytes.len());
    let mut prefixed = eip191_prefix.as_bytes().to_vec();
    prefixed.extend_from_slice(message_bytes);
    let message_hash = keccak256(&prefixed);

    // 5. Sign with recovery
    let (signature_der, recovery_id) = wallet_signer
        .sign_prehash_recoverable(message_hash.as_slice())
        .expect("signing succeeds");

    let mut signature_bytes = signature_der.to_bytes().to_vec(); // 64 bytes r||s
    signature_bytes.push(recovery_id.to_byte()); // Append v (recovery ID)

    // 6. Create Signature struct
    let signature = Signature::wallet(signature_bytes, address);

    // 7. Verify signature
    let result = signature.verify(message_bytes);
    assert!(result.is_ok(), "signature verification should succeed");
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
#[tokio::test]
async fn test_handle_validation_valid(#[case] handle: &str) {
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
#[tokio::test]
async fn test_handle_validation_invalid(#[case] handle: String) {
    let result = Handle::parse(&handle);
    assert!(result.is_err(), "handle '{}' should be invalid", handle);
}

// ============================================================================
// Vault Key Derivation Tests
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_vault_key_derivation_passkey(passkey_signer: P256SigningKey) {
    // 1. Get secret key bytes (32 bytes)
    let secret_bytes = passkey_signer.to_bytes();
    let secret_array: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .expect("P-256 secret key is 32 bytes");

    // 2. Derive vault keys from passkey
    let vault_keys = VaultKeys::derive_from_signing_key(&secret_array, SignerType::Passkey)
        .expect("vault derivation succeeds");

    // 3. Verify namespace ID is derived
    let namespace_id = vault_keys.namespace_id();
    assert_eq!(
        namespace_id.as_bytes().len(),
        32,
        "namespace ID should be 32 bytes"
    );

    // 4. Verify determinism - same key = same vault
    let vault_keys_2 = VaultKeys::derive_from_signing_key(&secret_array, SignerType::Passkey)
        .expect("vault derivation succeeds");
    assert_eq!(vault_keys.namespace_id(), vault_keys_2.namespace_id());
    assert_eq!(
        vault_keys.catalog_encryption_key,
        vault_keys_2.catalog_encryption_key
    );
}

#[rstest]
#[tokio::test]
async fn test_vault_key_derivation_wallet(wallet_signer: K256SigningKey) {
    // 1. Get secret key bytes (32 bytes)
    let secret_bytes = wallet_signer.to_bytes();
    let secret_array: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .expect("secp256k1 secret key is 32 bytes");

    // 2. Derive vault keys from wallet
    let vault_keys = VaultKeys::derive_from_signing_key(&secret_array, SignerType::Wallet)
        .expect("vault derivation succeeds");

    // 3. Verify namespace ID is derived
    let namespace_id = vault_keys.namespace_id();
    assert_eq!(namespace_id.as_bytes().len(), 32);

    // 4. Verify uniqueness - different keys = different vaults
    let different_key = test_wallet_key();
    let different_secret = different_key.to_bytes();
    let different_secret_array: [u8; 32] =
        different_secret.as_slice().try_into().expect("32 bytes");

    let vault_keys_2 =
        VaultKeys::derive_from_signing_key(&different_secret_array, SignerType::Wallet)
            .expect("vault derivation succeeds");

    assert_ne!(vault_keys.namespace_id(), vault_keys_2.namespace_id());
    assert_ne!(
        vault_keys.catalog_encryption_key,
        vault_keys_2.catalog_encryption_key
    );
}

#[test]
fn test_vault_key_signer_type_parameter_for_documentation() {
    // Per the source code, signer_type is for documentation only
    // Same secret bytes should give same vault regardless of signer type
    let secret_bytes = [42u8; 32];

    let vault_passkey = VaultKeys::derive_from_signing_key(&secret_bytes, SignerType::Passkey)
        .expect("vault derivation succeeds");
    let vault_wallet = VaultKeys::derive_from_signing_key(&secret_bytes, SignerType::Wallet)
        .expect("vault derivation succeeds");

    // They should be the same since signer_type is not used in derivation
    assert_eq!(vault_passkey.namespace_id(), vault_wallet.namespace_id());
    assert_eq!(
        vault_passkey.catalog_encryption_key,
        vault_wallet.catalog_encryption_key
    );
}

// ============================================================================
// Message Formatting Tests
// ============================================================================

#[test]
fn test_message_format_create_identity() {
    let identity_id = test_identity_id();
    let timestamp = 1704067200; // 2024-01-01 00:00:00 UTC

    let message = message::create_identity_message(identity_id.as_str(), "alice", timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Create Identity"));
    assert!(message.contains("alice"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains("1704067200"));
}

#[test]
fn test_message_format_link_wallet() {
    let identity_id = test_identity_id();
    let wallet_address = "0x1234567890abcdef1234567890abcdef12345678";
    let timestamp = current_timestamp();

    let message = message::link_wallet_message(identity_id.as_str(), wallet_address, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Link Wallet"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains(wallet_address));
}

#[test]
fn test_message_format_sign_asset() {
    let identity_id = test_identity_id();
    let content_hash = "deadbeef".repeat(8); // 64 hex chars
    let timestamp = current_timestamp();

    let message = message::sign_asset_message(identity_id.as_str(), &content_hash, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Sign Asset"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains(&content_hash));
}

#[test]
fn test_message_format_authenticate() {
    let app_domain = "app.example.com";
    let challenge = hex::encode(&[0xde, 0xad, 0xbe, 0xef].repeat(16)); // 64 hex chars
    let timestamp = current_timestamp();

    let message = message::authenticate_message(app_domain, &challenge, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Authenticate"));
    assert!(message.contains(app_domain));
    assert!(message.contains(&challenge));
}

#[test]
fn test_message_format_change_handle() {
    let identity_id = test_identity_id();
    let new_handle = "bob";
    let timestamp = current_timestamp();

    let message = message::change_handle_message(identity_id.as_str(), new_handle, timestamp);

    assert!(message.contains("OBJECTS Identity Protocol v1"));
    assert!(message.contains("Change Handle"));
    assert!(message.contains(identity_id.as_str()));
    assert!(message.contains(new_handle));
}
