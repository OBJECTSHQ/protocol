//! Data-layer test utilities for Asset, Project, Reference, and SignedAsset.
//!
//! This module provides factories for creating test instances of data types with
//! sensible defaults. All cryptographic data uses proper encoding patterns
//! (bytes -> hex encoding) as per CLAUDE.md.

use crate::{crypto, identity, time};
use objects_data::{Asset, ContentHash, Project, Reference, ReferenceType, SignedAsset};
use objects_identity::message::sign_asset_message;
use objects_identity::{Ed25519SigningKey, IdentityId};

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
    // Project ID = full NamespaceId hex (64 chars). No truncation.
    let random_bytes = crypto::deterministic_bytes(rand::random::<u8>());
    let id = hex::encode(random_bytes);

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

/// Complete bundle for an Ed25519-signed asset.
///
/// Contains all components needed for testing SignedAsset verification:
/// - The unsigned asset
/// - The signed asset with Ed25519 signature
/// - Identity ID derived from public key + nonce
/// - Signing key for re-signing if needed
/// - Nonce used for identity derivation
pub struct SignedAssetBundle {
    pub asset: Asset,
    pub signed_asset: SignedAsset,
    pub identity_id: IdentityId,
    pub signing_key: Ed25519SigningKey,
    pub nonce: [u8; 8],
}

/// Create a complete SignedAsset workflow with Ed25519 signer.
///
/// 1. Generates Ed25519 keypair and nonce
/// 2. Derives identity_id from public_key + nonce
/// 3. Creates asset with derived identity_id as author
/// 4. Signs the asset message with Ed25519
/// 5. Returns complete bundle for testing
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::data;
///
/// let bundle = data::signed_asset("asset-789");
/// assert_eq!(bundle.asset.id(), "asset-789");
/// assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
/// assert!(bundle.signed_asset.verify().is_ok());
/// ```
pub fn signed_asset(asset_id: &str) -> SignedAssetBundle {
    let keypair = crypto::ed25519_keypair();
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
    .unwrap_or_else(|e| panic!("signed_asset failed for asset_id='{}': {:?}", asset_id, e));

    // Create message per RFC-001 Section 5.3 (uses author_id, content_hash, created_at)
    let message = sign_asset_message(
        asset.author_id().as_str(),
        &asset.content_hash().to_hex(),
        asset.created_at(),
    );

    // Sign with Ed25519
    let signature = keypair.signing_key.sign(message.as_bytes());

    let signed_asset = SignedAsset::new(asset.clone(), signature, nonce);

    SignedAssetBundle {
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
    fn test_signed_asset_bundle_verifies() {
        let bundle = signed_asset("test-asset");
        assert_eq!(bundle.asset.id(), "test-asset");
        assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
        assert!(bundle.signed_asset.verify().is_ok());
    }

    #[test]
    fn test_signed_asset_author_matches_derived_id() {
        let bundle = signed_asset("test-id-match");
        let derived_id = IdentityId::derive(&bundle.signing_key.public_key_bytes(), &bundle.nonce);
        assert_eq!(bundle.identity_id, derived_id);
        assert_eq!(bundle.asset.author_id(), &derived_id);
    }
}
