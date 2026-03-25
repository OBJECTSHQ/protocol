//! Data-layer test utilities for Asset, Project, Reference, and SignedAsset.
//!
//! This module provides factories for creating test instances of data types with
//! sensible defaults. All cryptographic data uses proper encoding patterns
//! (bytes → hex encoding) as per CLAUDE.md.

use crate::{crypto, identity, time};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::ecdsa::signature::Signer as K256Signer;
use objects_data::{Asset, ContentHash, Project, Reference, ReferenceType, SignedAsset};
use objects_identity::message::sign_asset_message;
use objects_identity::{IdentityId, Signature};
use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::{Digest, Sha256};

/// Create a test Asset with given ID and author.
///
/// Uses default values for other fields:
/// - name: "Test Asset"
/// - content_hash: deterministic hash from seed 42
/// - size_bytes: 1024
/// - mime_type: "application/octet-stream"
/// - timestamps: current time
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::{data, identity};
///
/// let author_id = identity::test_identity_id();
/// let asset = data::asset("asset-123", author_id);
/// assert_eq!(asset.id(), "asset-123");
/// ```
pub fn asset(id: &str, author_id: IdentityId) -> Asset {
    let content_hash = ContentHash::new(crypto::deterministic_bytes(42));
    Asset::new(
        id.to_string(),
        "Test Asset".to_string(),
        author_id,
        content_hash,
        1024,
        Some("application/octet-stream".to_string()),
        time::now(),
        time::now(),
    )
    .unwrap_or_else(|e| panic!("asset failed for id='{}': {:?}", id, e))
}

/// Create a test Asset with a specific content hash.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::{crypto, data, identity};
/// use objects_data::ContentHash;
///
/// let author_id = identity::test_identity_id();
/// let hash = ContentHash::new(crypto::deterministic_bytes(99));
/// let asset = data::asset_with_hash("asset-456", author_id, hash.clone());
/// assert_eq!(asset.content_hash(), &hash);
/// ```
pub fn asset_with_hash(id: &str, author_id: IdentityId, hash: ContentHash) -> Asset {
    Asset::new(
        id.to_string(),
        "Test Asset".to_string(),
        author_id,
        hash,
        2048,
        Some("text/plain".to_string()),
        time::now(),
        time::now(),
    )
    .unwrap_or_else(|e| panic!("asset_with_hash failed for id='{}': {:?}", id, e))
}

/// Create a test Project with given name and owner.
///
/// Generates a random project ID using proper hex encoding.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::{data, identity};
///
/// let owner_id = identity::test_identity_id();
/// let project = data::project("My Project", owner_id);
/// assert_eq!(project.name(), "My Project");
/// ```
pub fn project(name: &str, owner_id: IdentityId) -> Project {
    // Generate random project ID with proper hex encoding
    let random_bytes = crypto::deterministic_bytes(rand::random::<u8>());
    let id = hex::encode(&random_bytes[..16]); // Use first 16 bytes

    Project::new(
        id,
        name.to_string(),
        Some("Test project description".to_string()),
        owner_id,
        time::now(),
        time::now(),
    )
    .unwrap_or_else(|e| panic!("project failed for name='{}': {:?}", name, e))
}

/// Create a test Project from a ReplicaId using RFC-004 derivation.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::data;
///
/// let replica_id = [42u8; 32];
/// let project = data::project_from_replica(&replica_id);
/// assert!(project.id().len() > 0);
/// ```
pub fn project_from_replica(replica_id: &[u8; 32]) -> Project {
    let project_id = objects_data::project_id_from_replica(replica_id);
    let owner_id = identity::test_identity_id();

    Project::new(
        project_id,
        "Test Project".to_string(),
        Some("From replica ID".to_string()),
        owner_id,
        time::now(),
        time::now(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "project_from_replica failed for replica_id={}: {:?}",
            hex::encode(replica_id),
            e
        )
    })
}

/// Create a test Reference between two assets.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::data;
///
/// let reference = data::reference("asset-1", "asset-2");
/// assert_eq!(reference.source_asset_id, "asset-1");
/// assert_eq!(reference.target_asset_id, "asset-2");
/// ```
pub fn reference(source: &str, target: &str) -> Reference {
    Reference {
        id: format!("ref-{}-{}", source, target),
        source_asset_id: source.to_string(),
        target_asset_id: target.to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: time::now(),
    }
}

/// Complete bundle for a passkey-signed asset.
///
/// Contains all components needed for testing SignedAsset verification:
/// - The unsigned asset
/// - The signed asset with WebAuthn signature
/// - Identity ID derived from public key + nonce
/// - Signing key for re-signing if needed
/// - Nonce used for identity derivation
pub struct SignedAssetPasskeyBundle {
    pub asset: Asset,
    pub signed_asset: SignedAsset,
    pub identity_id: IdentityId,
    pub signing_key: P256SigningKey,
    pub nonce: [u8; 8],
}

/// Create a complete SignedAsset workflow with Passkey signer.
///
/// Follows RFC-001 Section 5.3 for WebAuthn signing:
/// 1. Generates passkey keypair and nonce
/// 2. Derives identity_id from public_key + nonce
/// 3. Creates asset with derived identity_id as author
/// 4. Creates WebAuthn signature (authenticator_data + client_data_json)
/// 5. Returns complete bundle for testing
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::data;
///
/// let bundle = data::signed_asset_passkey("asset-789");
/// assert_eq!(bundle.asset.id(), "asset-789");
/// assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
/// assert!(bundle.signed_asset.verify().is_ok());
/// ```
pub fn signed_asset_passkey(asset_id: &str) -> SignedAssetPasskeyBundle {
    let keypair = crypto::passkey_keypair();
    let nonce = crypto::random_nonce();

    // Derive identity_id from public_key + nonce
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    // Create asset with correct author_id
    let content_hash = ContentHash::new(crypto::deterministic_bytes(42));
    let timestamp = time::now();
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
            "signed_asset_passkey failed for asset_id='{}': {:?}",
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
    let p256_sig: p256::ecdsa::Signature = keypair.signing_key.sign(&signed_data);

    let signature = Signature::Passkey {
        signature: p256_sig.to_der().to_bytes().to_vec(),
        public_key: keypair.public_key.to_vec(),
        authenticator_data,
        client_data_json,
    };

    let signed_asset = SignedAsset::new(asset.clone(), signature, nonce);

    SignedAssetPasskeyBundle {
        asset,
        signed_asset,
        identity_id,
        signing_key: keypair.signing_key,
        nonce,
    }
}

/// Complete bundle for a wallet-signed asset.
///
/// Contains all components needed for testing EIP-191 SignedAsset verification.
pub struct SignedAssetWalletBundle {
    pub asset: Asset,
    pub signed_asset: SignedAsset,
    pub identity_id: IdentityId,
    pub signing_key: K256SigningKey,
    pub nonce: [u8; 8],
}

/// Create a complete SignedAsset workflow with Wallet signer (EIP-191).
///
/// Follows RFC-001 Section 5.3 for EIP-191 wallet signing:
/// 1. Generates secp256k1 keypair and nonce
/// 2. Derives identity_id from public_key + nonce
/// 3. Creates asset with derived identity_id as author
/// 4. Creates EIP-191 signature with Keccak256 hash
/// 5. Returns complete bundle for testing
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::data;
///
/// let bundle = data::signed_asset_wallet("wallet-asset");
/// assert_eq!(bundle.asset.id(), "wallet-asset");
/// assert!(bundle.signed_asset.verify().is_ok());
/// ```
pub fn signed_asset_wallet(asset_id: &str) -> SignedAssetWalletBundle {
    let keypair = crypto::wallet_keypair();
    let nonce = crypto::random_nonce();

    // Derive identity_id from public_key + nonce
    let identity_id = IdentityId::derive(&keypair.public_key, &nonce);

    // Create asset with correct author_id
    let content_hash = ContentHash::new(crypto::deterministic_bytes(99));
    let timestamp = time::now();
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
    let (signature_der, recovery_id) = keypair
        .signing_key
        .sign_prehash_recoverable(message_hash.as_slice())
        .expect("signing failed");

    // Get signature bytes (r || s || v format) and derive Ethereum address
    let mut signature_bytes = signature_der.to_bytes().to_vec();
    signature_bytes.push(recovery_id.to_byte());

    // Derive Ethereum address from public key
    let verifying_key = keypair.signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes_uncompressed = public_key_point.as_bytes();
    let pub_key_hash = alloy_primitives::keccak256(&public_key_bytes_uncompressed[1..]);
    let address = format!("0x{}", hex::encode(&pub_key_hash[12..]));

    let signature = Signature::Wallet {
        signature: signature_bytes,
        address,
    };

    let signed_asset = SignedAsset::new(asset.clone(), signature, nonce);

    SignedAssetWalletBundle {
        asset,
        signed_asset,
        identity_id,
        signing_key: keypair.signing_key,
        nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_creation() {
        let author_id = identity::test_identity_id();
        let asset = asset("test-asset", author_id.clone());
        assert_eq!(asset.id(), "test-asset");
        assert_eq!(asset.author_id(), &author_id);
        assert_eq!(asset.name(), "Test Asset");
    }

    #[test]
    fn test_asset_with_hash_uses_provided_hash() {
        let author_id = identity::test_identity_id();
        let hash = ContentHash::new(crypto::deterministic_bytes(123));
        let asset = asset_with_hash("custom-hash", author_id, hash.clone());
        assert_eq!(asset.content_hash(), &hash);
    }

    #[test]
    fn test_project_creation() {
        let owner_id = identity::test_identity_id();
        let project = project("Test Project", owner_id.clone());
        assert_eq!(project.name(), "Test Project");
        assert_eq!(project.owner_id(), &owner_id);
    }

    #[test]
    fn test_project_from_replica_derives_id() {
        let replica_id = crypto::deterministic_bytes(42);
        let project = project_from_replica(&replica_id);
        let expected_id = objects_data::project_id_from_replica(&replica_id);
        assert_eq!(project.id(), expected_id);
    }

    #[test]
    fn test_reference_creation() {
        let reference = reference("source-1", "target-2");
        assert_eq!(reference.source_asset_id, "source-1");
        assert_eq!(reference.target_asset_id, "target-2");
        assert_eq!(reference.id, "ref-source-1-target-2");
    }

    #[test]
    fn test_signed_asset_passkey_bundle_verifies() {
        let bundle = signed_asset_passkey("passkey-asset");
        assert_eq!(bundle.asset.id(), "passkey-asset");
        assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
        assert!(bundle.signed_asset.verify().is_ok());
    }

    #[test]
    fn test_signed_asset_passkey_author_matches_derived_id() {
        let bundle = signed_asset_passkey("test-id-match");
        let derived_id = IdentityId::derive(
            &bundle
                .signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            &bundle.nonce,
        );
        assert_eq!(bundle.identity_id, derived_id);
        assert_eq!(bundle.asset.author_id(), &derived_id);
    }

    #[test]
    fn test_signed_asset_wallet_bundle_verifies() {
        let bundle = signed_asset_wallet("wallet-asset");
        assert_eq!(bundle.asset.id(), "wallet-asset");
        assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
        assert!(bundle.signed_asset.verify().is_ok());
    }

    #[test]
    fn test_signed_asset_wallet_author_matches_derived_id() {
        let bundle = signed_asset_wallet("wallet-id-match");
        let derived_id = IdentityId::derive(
            &bundle
                .signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            &bundle.nonce,
        );
        assert_eq!(bundle.identity_id, derived_id);
        assert_eq!(bundle.asset.author_id(), &derived_id);
    }
}
