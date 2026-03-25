//! Integration tests for objects-data crate.
//!
//! Tests cross-module workflows including:
//! - SignedAsset lifecycle (passkey and wallet signers)
//! - Project creation and RFC-004 compliance
//! - Reference and cross-project reference workflows
//! - Storage key generation and parsing
//! - Encryption workflows
//! - Full integration scenarios

use objects_data::{
    Asset, ContentHash, KeyType, Project, Reference, ReferenceType, SignedAsset, encryption,
    parse_key, project_id_from_replica, storage,
};
use objects_test_utils::{crypto, data, identity, time};
use rstest::*;

// ============================================================================
// SignedAsset Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_signed_asset_passkey_full_lifecycle() {
    // Create a complete signed asset with passkey
    let bundle = data::signed_asset_passkey("test-asset-1");

    // Verify the asset has correct author_id
    assert_eq!(bundle.asset.author_id(), &bundle.identity_id);

    // Verify the signature
    assert!(
        bundle.signed_asset.verify().is_ok(),
        "passkey signature verification should succeed"
    );

    // Verify nonce matches
    assert_eq!(bundle.signed_asset.nonce(), &bundle.nonce);
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_wallet_full_lifecycle() {
    // Create a complete signed asset with wallet
    let bundle = data::signed_asset_wallet("test-asset-2");

    // Verify the asset has correct author_id
    assert_eq!(bundle.asset.author_id(), &bundle.identity_id);

    // Verify the signature (includes EIP-191 recovery)
    assert!(bundle.signed_asset.verify().is_ok());

    // Verify nonce matches
    assert_eq!(bundle.signed_asset.nonce(), &bundle.nonce);
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_wrong_nonce_fails() {
    // Create signed asset
    let bundle = data::signed_asset_passkey("test-asset-3");

    // Replace with wrong nonce
    let wrong_nonce = [255, 254, 253, 252, 251, 250, 249, 248];
    let wrong_signed = SignedAsset::new(
        bundle.signed_asset.asset().clone(),
        bundle.signed_asset.signature().clone(),
        wrong_nonce,
    );

    // Verification should fail - derived ID won't match author_id
    assert!(wrong_signed.verify().is_err());
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_tampered_content_fails() {
    // Create signed asset
    let bundle = data::signed_asset_passkey("test-asset-4");

    // Tamper with content hash
    let tampered_hash = ContentHash::new(crypto::deterministic_bytes(99));
    let tampered_asset = Asset::new(
        bundle.asset.id().to_string(),
        bundle.asset.name().to_string(),
        bundle.identity_id.clone(),
        tampered_hash,
        bundle.asset.content_size(),
        bundle.asset.format().map(|s| s.to_string()),
        bundle.asset.created_at(),
        bundle.asset.updated_at(),
    )
    .expect("valid asset");

    let tampered_signed = SignedAsset::new(
        tampered_asset,
        bundle.signed_asset.signature().clone(),
        bundle.nonce,
    );

    // Verification should fail - signature won't match
    assert!(tampered_signed.verify().is_err());
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_signature_replay_attack_fails() {
    // Create first signed asset
    let bundle1 = data::signed_asset_passkey("asset-original");

    // Verify first asset signature is valid
    assert!(bundle1.signed_asset.verify().is_ok());

    // Create a different asset with same author (different content)
    let different_hash = ContentHash::new(crypto::deterministic_bytes(255));
    let asset2 = Asset::new(
        "asset-different".to_string(),
        "Different Asset".to_string(),
        bundle1.identity_id.clone(),
        different_hash,
        2048,
        Some("text/plain".to_string()),
        time::now(),
        time::now(),
    )
    .expect("valid asset");

    // Attempt to replay the signature from asset1 onto asset2
    // This should fail because the signature was created over asset1's content_hash
    let replayed_signed = SignedAsset::new(
        asset2,
        bundle1.signed_asset.signature().clone(),
        bundle1.nonce,
    );

    // Verification should fail - signature replay attack detected
    assert!(
        replayed_signed.verify().is_err(),
        "signature replay attack should fail: cannot reuse signature for different asset"
    );
}

#[rstest]
#[tokio::test]
async fn test_multiple_assets_same_identity() {
    // Create first signed asset
    let bundle1 = data::signed_asset_passkey("asset-1");

    // Create second signed asset with same identity setup
    // (In real use, would reuse same keypair + nonce, but for test we create separate)
    let bundle2 = data::signed_asset_passkey("asset-2");

    // Both should verify independently
    assert!(bundle1.signed_asset.verify().is_ok());
    assert!(bundle2.signed_asset.verify().is_ok());

    // Different identities (because different keypairs)
    assert_ne!(bundle1.identity_id, bundle2.identity_id);
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_deterministic_verification() {
    // Create signed asset
    let bundle = data::signed_asset_passkey("test-asset-5");

    // Verify multiple times - should be deterministic
    assert!(bundle.signed_asset.verify().is_ok());
    assert!(bundle.signed_asset.verify().is_ok());
    assert!(bundle.signed_asset.verify().is_ok());
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_mixed_signer_types() {
    // Create with passkey
    let bundle1 = data::signed_asset_passkey("asset-passkey");

    // Create with wallet
    let bundle2 = data::signed_asset_wallet("asset-wallet");

    // Both should verify
    assert!(bundle1.signed_asset.verify().is_ok());
    assert!(bundle2.signed_asset.verify().is_ok());
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_serialization_roundtrip() {
    // Verifies that SignedAssets can be safely persisted and restored from storage.
    // This is critical for the sync layer which stores signed assets as JSON documents.
    let bundle = data::signed_asset_passkey("test-asset-6");

    // Serialize to JSON
    let json = serde_json::to_string(&bundle.signed_asset).expect("serialize");

    // Deserialize back
    let deserialized: SignedAsset = serde_json::from_str(&json).expect("deserialize");

    // Verify deserialized signature still works
    assert!(deserialized.verify().is_ok());

    // Verify content matches
    assert_eq!(deserialized.asset().id(), bundle.asset.id());
    assert_eq!(deserialized.nonce(), &bundle.nonce);
}

// ============================================================================
// Project Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_project_creation_from_replica_id() {
    // RFC-004: Project IDs are derived from iroh-docs ReplicaId
    // This test verifies the derivation and project creation workflow

    // Use deterministic bytes for test replica ID
    let replica_id = crypto::deterministic_bytes(42);

    // Derive project ID using RFC-004
    let expected_id = project_id_from_replica(&replica_id);

    // Create project from replica
    let project = data::project_from_replica(&replica_id);

    // Verify derived ID matches
    assert_eq!(project.id(), expected_id);
    assert_eq!(project.name(), "Test Project");
}

#[rstest]
#[tokio::test]
async fn test_project_id_parsing_and_validation() {
    let owner_id = identity::test_identity_id();

    // Valid project ID (32 hex characters)
    let valid_id = hex::encode(crypto::deterministic_bytes(1)[..16].to_vec());
    let project = Project::new(
        valid_id.clone(),
        "Valid Project".to_string(),
        None,
        owner_id.clone(),
        time::now(),
        time::now(),
    );
    assert!(project.is_ok());

    // Invalid: too short
    let short_id = "abc123";
    let result = Project::new(
        short_id.to_string(),
        "Invalid".to_string(),
        None,
        owner_id.clone(),
        time::now(),
        time::now(),
    );
    assert!(result.is_err());

    // Invalid: too long
    let long_id = "a".repeat(100);
    let result = Project::new(
        long_id,
        "Invalid".to_string(),
        None,
        owner_id,
        time::now(),
        time::now(),
    );
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_project_timestamp_validation() {
    let owner_id = identity::test_identity_id();
    let id = "b".repeat(32);

    // Valid: created_at <= updated_at
    let created = time::now();
    let updated = time::future_timestamp(100);
    let result = Project::new(
        id.clone(),
        "Valid".to_string(),
        None,
        owner_id.clone(),
        created,
        updated,
    );
    assert!(result.is_ok());

    // Invalid: created_at > updated_at
    let result = Project::new(id, "Invalid".to_string(), None, owner_id, updated, created);
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_project_with_owner_identity() {
    let owner_id = identity::test_identity_id();
    let project = data::project("My Project", owner_id.clone());

    assert_eq!(project.name(), "My Project");
    assert_eq!(project.owner_id(), &owner_id);
}

#[rstest]
#[tokio::test]
async fn test_project_serialization_roundtrip() {
    // Projects must serialize/deserialize correctly for storage in iroh-docs

    let owner_id = identity::test_identity_id();
    let project = data::project("Test Project", owner_id);

    // Serialize to JSON
    let json = serde_json::to_string(&project).expect("serialize");

    // Deserialize back
    let deserialized: Project = serde_json::from_str(&json).expect("deserialize");

    // Verify all fields match
    assert_eq!(deserialized.id(), project.id());
    assert_eq!(deserialized.name(), project.name());
    assert_eq!(deserialized.owner_id(), project.owner_id());
}

#[rstest]
#[tokio::test]
async fn test_project_id_from_different_replicas() {
    let replica1 = crypto::deterministic_bytes(10);
    let replica2 = crypto::deterministic_bytes(20);

    let id1 = project_id_from_replica(&replica1);
    let id2 = project_id_from_replica(&replica2);

    // Different replicas should produce different project IDs
    assert_ne!(id1, id2);

    // Same replica should produce same ID (deterministic)
    let id1_again = project_id_from_replica(&replica1);
    assert_eq!(id1, id1_again);
}

// ============================================================================
// Reference Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_reference_linking_two_assets() {
    let source_id = "asset-source";
    let target_id = "asset-target";

    let reference = data::reference(source_id, target_id);

    assert_eq!(reference.source_asset_id, source_id);
    assert_eq!(reference.target_asset_id, target_id);
    assert_eq!(reference.reference_type, ReferenceType::References);
}

#[rstest]
#[tokio::test]
async fn test_reference_with_content_hash() {
    let source_id = "source";
    let target_id = "target";
    let content_hash = ContentHash::new(crypto::deterministic_bytes(42));

    let mut reference = data::reference(source_id, target_id);
    reference.target_content_hash = Some(content_hash.clone());

    assert_eq!(reference.target_content_hash, Some(content_hash));
}

#[rstest]
#[tokio::test]
async fn test_reference_type_variations() {
    let source = "source";
    let target = "target";

    // Test different reference types
    let mut ref_references = data::reference(source, target);
    ref_references.reference_type = ReferenceType::References;
    assert_eq!(ref_references.reference_type, ReferenceType::References);

    let mut ref_derived = data::reference(source, target);
    ref_derived.reference_type = ReferenceType::DerivedFrom;
    assert_eq!(ref_derived.reference_type, ReferenceType::DerivedFrom);

    let mut ref_contains = data::reference(source, target);
    ref_contains.reference_type = ReferenceType::Contains;
    assert_eq!(ref_contains.reference_type, ReferenceType::Contains);
}

#[rstest]
#[tokio::test]
async fn test_reference_validation_requirements() {
    // References must have non-empty source and target IDs

    let valid_ref = Reference {
        id: "ref-1".to_string(),
        source_asset_id: "source".to_string(),
        target_asset_id: "target".to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: time::now(),
    };

    // Should serialize/deserialize successfully
    let json = serde_json::to_string(&valid_ref).expect("serialize");
    let _deserialized: Reference = serde_json::from_str(&json).expect("deserialize");
}

#[rstest]
#[tokio::test]
async fn test_cross_project_reference_workflow() {
    // Simulates referencing an asset from one project in another project

    let author_id = identity::test_identity_id();

    // Create two projects
    let replica1 = crypto::deterministic_bytes(1);
    let replica2 = crypto::deterministic_bytes(2);

    let _project1 = data::project_from_replica(&replica1);
    let _project2 = data::project_from_replica(&replica2);

    // Create assets in different projects
    let asset1 = data::asset("proj1-asset", author_id.clone());
    let asset2 = data::asset("proj2-asset", author_id);

    // Create cross-project reference
    let reference = data::reference(asset2.id(), asset1.id());

    assert_eq!(reference.source_asset_id, asset2.id());
    assert_eq!(reference.target_asset_id, asset1.id());
}

// ============================================================================
// Storage Key Generation
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_storage_key_generation_for_assets() {
    let asset_id = "test-asset";
    let key = storage::asset_key(asset_id);

    assert!(key.starts_with("/assets/"));
    assert!(key.contains(asset_id));
}

#[rstest]
#[tokio::test]
async fn test_storage_key_generation_for_references() {
    let ref_id = "test-ref";
    let key = storage::reference_key(ref_id);

    assert!(key.starts_with("/refs/"));
    assert!(key.contains(ref_id));
}

#[rstest]
#[tokio::test]
async fn test_storage_key_parsing_roundtrip() {
    // Asset key
    let asset_id = "asset-123";
    let asset_key = storage::asset_key(asset_id);

    match parse_key(&asset_key) {
        KeyType::Asset(id) => assert_eq!(id, asset_id),
        _ => panic!("expected Asset key type"),
    }

    // Reference key
    let ref_id = "ref-456";
    let ref_key = storage::reference_key(ref_id);

    match parse_key(&ref_key) {
        KeyType::Reference(id) => assert_eq!(id, ref_id),
        _ => panic!("expected Reference key type"),
    }
}

#[rstest]
#[tokio::test]
async fn test_project_key_constant() {
    let key = storage::PROJECT_KEY;
    assert_eq!(key, "/project");

    assert!(matches!(parse_key(key), KeyType::Project));
}

#[rstest]
#[tokio::test]
async fn test_storage_key_unknown_format() {
    let invalid_key = "/unknown/key";

    assert!(matches!(parse_key(invalid_key), KeyType::Unknown));
}

// ============================================================================
// Encryption Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_catalog_entry_encryption_roundtrip() {
    use objects_data::proto::ProjectCatalogEntry;

    // Create a project catalog entry (protobuf type)
    let replica_id = crypto::deterministic_bytes(42);
    let project_id = project_id_from_replica(&replica_id);

    let entry = ProjectCatalogEntry {
        project_id: project_id.clone(),
        replica_id: replica_id.to_vec(),
        project_name: "Test Project".to_string(),
        created_at: time::now(),
    };

    // Encrypt
    let key = crypto::encryption_key();
    let encrypted = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");

    // Should have nonce (24 bytes) + ciphertext
    assert!(encrypted.len() > 24);

    // Decrypt
    let decrypted = encryption::decrypt_catalog_entry(&encrypted, &key).expect("decrypt");

    // Should match original
    assert_eq!(decrypted, entry);
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_wrong_key_detection() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id = crypto::deterministic_bytes(99);
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Test".to_string(),
        created_at: time::now(),
    };

    // Encrypt with key1
    let key1 = crypto::encryption_key();
    let encrypted = encryption::encrypt_catalog_entry(&entry, &key1).expect("encrypt");

    // Try to decrypt with different key
    let key2 = crypto::encryption_key();
    let result = encryption::decrypt_catalog_entry(&encrypted, &key2);

    // Should fail - wrong key
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_tampered_ciphertext() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id = crypto::deterministic_bytes(77);
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Tamper Test".to_string(),
        created_at: time::now(),
    };

    let key = crypto::encryption_key();
    let mut encrypted = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");

    // Tamper with ciphertext
    if let Some(byte) = encrypted.get_mut(30) {
        *byte = byte.wrapping_add(1);
    }

    // Decryption should fail
    let result = encryption::decrypt_catalog_entry(&encrypted, &key);
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_nonce_uniqueness() {
    use objects_data::proto::ProjectCatalogEntry;

    // XChaCha20-Poly1305 nonces must be unique per encryption
    let replica_id = crypto::deterministic_bytes(55);
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Nonce Test".to_string(),
        created_at: time::now(),
    };

    let key = crypto::encryption_key();

    // Encrypt same entry twice
    let encrypted1 = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt 1");
    let encrypted2 = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt 2");

    // Ciphertexts should be different (different nonces)
    assert_ne!(encrypted1, encrypted2);

    // But both should decrypt to same entry
    let decrypted1 = encryption::decrypt_catalog_entry(&encrypted1, &key).expect("decrypt 1");
    let decrypted2 = encryption::decrypt_catalog_entry(&encrypted2, &key).expect("decrypt 2");
    assert_eq!(decrypted1, decrypted2);
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_too_short_data() {
    let key = crypto::encryption_key();

    // Ciphertext too short (needs nonce + tag + data)
    let too_short = vec![1, 2, 3];
    let result = encryption::decrypt_catalog_entry(&too_short, &key);

    assert!(result.is_err());
}

// ============================================================================
// Integration Scenarios
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_asset_with_identity_verification() {
    // Full workflow: create identity, create asset, sign, verify
    let bundle = data::signed_asset_passkey("integrated-asset");

    // Verify identity derivation
    assert_eq!(bundle.asset.author_id(), &bundle.identity_id);

    // Verify signature
    assert!(bundle.signed_asset.verify().is_ok());

    // Verify storage key generation
    let key = storage::asset_key(bundle.asset.id());
    assert!(key.contains(bundle.asset.id()));
}

#[rstest]
#[tokio::test]
async fn test_project_asset_storage_workflow() {
    // Simulates creating a project and adding assets to it
    let owner_id = identity::test_identity_id();

    let replica_id = crypto::deterministic_bytes(42);
    let _project = data::project_from_replica(&replica_id);

    // Create multiple assets for the project
    let asset1 = data::asset("asset-1", owner_id.clone());
    let asset2 = data::asset("asset-2", owner_id);

    // Generate storage keys
    let key1 = storage::asset_key(asset1.id());
    let key2 = storage::asset_key(asset2.id());

    // Keys should be unique
    assert_ne!(key1, key2);

    // Keys should parse correctly
    assert!(matches!(parse_key(&key1), KeyType::Asset(_)));
    assert!(matches!(parse_key(&key2), KeyType::Asset(_)));
}

#[rstest]
#[tokio::test]
async fn test_reference_with_asset_content_hashes() {
    let author_id = identity::test_identity_id();

    // Create assets with specific content hashes
    let hash1 = ContentHash::new(crypto::deterministic_bytes(10));
    let hash2 = ContentHash::new(crypto::deterministic_bytes(20));
    let asset1 = data::asset_with_hash("source", author_id.clone(), hash1.clone());
    let asset2 = data::asset_with_hash("target", author_id, hash2.clone());

    // Create reference with target content hash
    let mut reference = data::reference(asset1.id(), asset2.id());
    reference.target_content_hash = Some(hash2.clone());

    // Verify reference points to correct content
    assert_eq!(reference.target_content_hash, Some(hash2.clone()));
    assert_eq!(asset1.content_hash(), &hash1);
    assert_eq!(asset2.content_hash(), &hash2);
}

#[rstest]
#[tokio::test]
async fn test_full_project_graph() {
    // Simulates a complete project with assets and references
    let owner_id = identity::test_identity_id();
    let replica_id = crypto::deterministic_bytes(42);
    let project = data::project_from_replica(&replica_id);

    // Create assets
    let asset1 = data::asset("component-a", owner_id.clone());
    let asset2 = data::asset("component-b", owner_id.clone());
    let asset3 = data::asset("assembly", owner_id);

    // Create references (assembly references components)
    let ref1 = data::reference(asset3.id(), asset1.id());
    let ref2 = data::reference(asset3.id(), asset2.id());

    // Verify graph structure
    assert_eq!(project.owner_id(), asset1.author_id());
    assert_eq!(ref1.source_asset_id, asset3.id());
    assert_eq!(ref2.source_asset_id, asset3.id());
}

#[rstest]
#[tokio::test]
async fn test_signed_assets_in_project_context() {
    // Verifies signed assets work correctly within a project
    let bundle1 = data::signed_asset_passkey("proj-asset-1");
    let bundle2 = data::signed_asset_wallet("proj-asset-2");

    // Both assets should verify
    assert!(bundle1.signed_asset.verify().is_ok());
    assert!(bundle2.signed_asset.verify().is_ok());

    // Create reference between them
    let reference = data::reference(bundle1.asset.id(), bundle2.asset.id());
    assert_eq!(reference.source_asset_id, bundle1.asset.id());
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_for_active_project() {
    use objects_data::proto::ProjectCatalogEntry;

    // Simulates encrypting project metadata for registry storage
    let replica_id = crypto::deterministic_bytes(42);
    let project_id = project_id_from_replica(&replica_id);

    let entry = ProjectCatalogEntry {
        project_id: project_id.clone(),
        replica_id: replica_id.to_vec(),
        project_name: "Active Project".to_string(),
        created_at: time::now(),
    };

    // Encrypt for storage
    let key = crypto::encryption_key();
    let encrypted = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");

    // Decrypt and verify
    let decrypted = encryption::decrypt_catalog_entry(&encrypted, &key).expect("decrypt");

    assert_eq!(decrypted.project_id, project_id);
    assert_eq!(decrypted.project_name, "Active Project");
}
