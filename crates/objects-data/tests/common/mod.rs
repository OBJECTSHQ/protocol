//! Common test utilities for objects-data integration tests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::elliptic_curve::rand_core::{OsRng, RngCore}; // Use OsRng for cryptographic randomness per CLAUDE.md
use objects_data::{Asset, ContentHash, Project, Reference, ReferenceType, SignedAsset};
use objects_identity::message::sign_asset_message;
use objects_identity::{IdentityId, Signature};
use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer as P256Signer};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a random P-256 (secp256r1) signing key for passkey tests.
pub fn test_passkey_keypair() -> (P256SigningKey, [u8; 33]) {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(true);
    let public_key_bytes: [u8; 33] = public_key_point
        .as_bytes()
        .try_into()
        .expect("compressed P-256 public key is 33 bytes");

    (signing_key, public_key_bytes)
}

/// Generate a random secp256k1 signing key for wallet tests.
#[allow(dead_code)]
pub fn test_wallet_keypair() -> (K256SigningKey, [u8; 33]) {
    let signing_key = K256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(true);
    let public_key_bytes: [u8; 33] = public_key_point
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 public key is 33 bytes");

    (signing_key, public_key_bytes)
}

/// Generate a test identity ID using a passkey with a fixed nonce.
pub fn test_identity_id() -> IdentityId {
    let (_, public_key_bytes) = test_passkey_keypair();
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    IdentityId::derive(&public_key_bytes, &nonce)
}

/// Generate a random identity with its nonce and signing key (passkey).
#[allow(dead_code)]
pub fn random_identity_with_nonce() -> (IdentityId, [u8; 8], P256SigningKey) {
    let (signing_key, public_key_bytes) = test_passkey_keypair();
    let nonce = random_nonce();
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);
    (identity_id, nonce, signing_key)
}

/// Generate a test ContentHash from a seed value.
pub fn test_content_hash(seed: u8) -> ContentHash {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    // Fill with predictable pattern
    for i in 1..32 {
        bytes[i] = seed.wrapping_add(i as u8);
    }
    ContentHash::new(bytes)
}

/// Create a test Asset with given ID and author.
#[allow(dead_code)]
pub fn test_asset(id: &str, author_id: IdentityId) -> Asset {
    let content_hash = test_content_hash(42);
    Asset::new(
        id.to_string(),
        "Test Asset".to_string(),
        author_id,
        content_hash,
        1024,
        Some("application/octet-stream".to_string()),
        now(),
        now(),
    )
    .unwrap_or_else(|e| panic!("test_asset failed for id='{}': {:?}", id, e))
}

/// Create a test Asset with specific content hash.
#[allow(dead_code)]
pub fn test_asset_with_hash(id: &str, author_id: IdentityId, hash: ContentHash) -> Asset {
    Asset::new(
        id.to_string(),
        "Test Asset".to_string(),
        author_id,
        hash,
        2048,
        Some("text/plain".to_string()),
        now(),
        now(),
    )
    .unwrap_or_else(|e| panic!("test_asset_with_hash failed for id='{}': {:?}", id, e))
}

/// Create a test Project.
#[allow(dead_code)]
pub fn test_project(name: &str, owner_id: IdentityId) -> Project {
    let id = format!("{:032x}", rand::random::<u128>());
    Project::new(
        id,
        name.to_string(),
        Some("Test project description".to_string()),
        owner_id,
        now(),
        now(),
    )
    .unwrap_or_else(|e| panic!("test_project failed for name='{}': {:?}", name, e))
}

/// Create a test Project from a ReplicaId.
#[allow(dead_code)]
pub fn test_project_from_replica(replica_id: [u8; 32]) -> Project {
    let project_id = objects_data::project_id_from_replica(&replica_id);
    let owner_id = test_identity_id();
    Project::new(
        project_id,
        "Test Project".to_string(),
        Some("From replica ID".to_string()),
        owner_id,
        now(),
        now(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "test_project_from_replica failed for replica_id={}: {:?}",
            hex::encode(replica_id),
            e
        )
    })
}

/// Create a test Reference.
#[allow(dead_code)]
pub fn test_reference(source: &str, target: &str) -> Reference {
    Reference {
        id: format!("ref-{}-{}", source, target),
        source_asset_id: source.to_string(),
        target_asset_id: target.to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: now(),
    }
}

/// Create a complete SignedAsset workflow with Passkey signer.
/// Returns (asset, signed_asset, identity_id, signing_key, nonce) for testing.
pub fn create_signed_asset_passkey_full(
    asset_id: &str,
) -> (Asset, SignedAsset, IdentityId, P256SigningKey, [u8; 8]) {
    let (signing_key, public_key_bytes) = test_passkey_keypair();
    let nonce = random_nonce();

    // Derive identity_id from public_key + nonce
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);

    // Create asset with correct author_id
    let content_hash = test_content_hash(42);
    let timestamp = now();
    let asset = Asset::new(
        asset_id.to_string(),
        "Test Asset".to_string(),
        identity_id.clone(),
        content_hash,
        1024,
        Some("application/octet-stream".to_string()),
        timestamp,
        timestamp,
    )
    .unwrap_or_else(|e| {
        panic!(
            "create_signed_asset_passkey_full failed for asset_id='{}': {:?}",
            asset_id, e
        )
    });

    // Create message per RFC-001 Section 5.3 (uses author_id, content_hash, created_at)
    let message = sign_asset_message(
        asset.author_id().as_str(),
        &asset.content_hash().to_hex(),
        asset.created_at(),
    );

    // Create WebAuthn authenticator_data (minimal valid format per WebAuthn Level 3 spec)
    // Format: RP ID hash (32 bytes) + flags (1 byte) + signature counter (4 bytes) = 37 bytes
    let rp_id_hash = Sha256::digest(b"objects.foundation");
    let flags = 0x05u8; // UP (User Present) + UV (User Verified) flags
    let counter = 0u32.to_be_bytes();
    let mut authenticator_data = rp_id_hash.to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&counter);

    // Create client_data_json with base64url-encoded challenge
    let challenge_b64 = URL_SAFE_NO_PAD.encode(message.as_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
        challenge_b64
    )
    .into_bytes();

    // Compute what WebAuthn signs: authenticator_data || SHA256(client_data_json)
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = authenticator_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    // Sign with P-256
    let p256_sig: p256::ecdsa::Signature = signing_key.sign(&signed_data);

    let signature = Signature::Passkey {
        signature: p256_sig.to_der().to_bytes().to_vec(),
        public_key: public_key_bytes.to_vec(),
        authenticator_data,
        client_data_json,
    };

    let signed_asset = SignedAsset::new(asset.clone(), signature, nonce);
    (asset, signed_asset, identity_id, signing_key, nonce)
}

/// Create a complete SignedAsset workflow with Wallet signer.
/// Returns (asset, signed_asset, identity_id, signing_key, nonce) for testing.
#[allow(dead_code)]
pub fn create_signed_asset_wallet_full(
    asset_id: &str,
) -> (Asset, SignedAsset, IdentityId, K256SigningKey, [u8; 8]) {
    let (signing_key, public_key_bytes) = test_wallet_keypair();
    let nonce = random_nonce();

    // Derive identity_id from public_key + nonce
    let identity_id = IdentityId::derive(&public_key_bytes, &nonce);

    // Create asset with correct author_id
    let content_hash = test_content_hash(99);
    let timestamp = now();
    let asset = Asset::new(
        asset_id.to_string(),
        "Wallet Test Asset".to_string(),
        identity_id.clone(),
        content_hash,
        2048,
        Some("text/plain".to_string()),
        timestamp,
        timestamp,
    )
    .expect("valid asset");

    // Create message per RFC-001 Section 5.3
    let message = sign_asset_message(
        asset.author_id().as_str(),
        &asset.content_hash().to_hex(),
        asset.created_at(),
    );

    // Hash with Keccak256 for EIP-191
    use alloy_primitives::keccak256;
    let eip191_prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut prefixed = eip191_prefix.as_bytes().to_vec();
    prefixed.extend_from_slice(message.as_bytes());
    let message_hash = keccak256(&prefixed);

    // Sign with secp256k1 and get recoverable signature
    let (signature_der, recovery_id) = signing_key
        .sign_prehash_recoverable(message_hash.as_slice())
        .expect("signing failed");

    // Get signature bytes (r || s || v format) and derive Ethereum address
    let mut signature_bytes = signature_der.to_bytes().to_vec();
    signature_bytes.push(recovery_id.to_byte());

    // Derive Ethereum address from public key
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes_uncompressed = public_key_point.as_bytes();
    let pub_key_hash = alloy_primitives::keccak256(&public_key_bytes_uncompressed[1..]);
    let address = format!("0x{}", hex::encode(&pub_key_hash[12..]));

    let signature = Signature::Wallet {
        signature: signature_bytes,
        address,
    };

    let signed_asset = SignedAsset::new(asset.clone(), signature, nonce);
    (asset, signed_asset, identity_id, signing_key, nonce)
}

/// Generate an XChaCha20-Poly1305 encryption key for testing.
#[allow(dead_code)]
pub fn test_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Get the current Unix timestamp in seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Generate a future timestamp offset by seconds.
#[allow(dead_code)]
pub fn future_timestamp(offset_secs: u64) -> u64 {
    now() + offset_secs
}

/// Generate a random 8-byte nonce for testing.
pub fn random_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Test timestamp constant (2024-01-06 12:00:00 UTC).
#[allow(dead_code)]
pub const TEST_TIMESTAMP: u64 = 1704542400;
