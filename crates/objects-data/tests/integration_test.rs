//! Integration tests for objects-data crate.
//!
//! Tests cross-module workflows including:
//! - SignedAsset lifecycle (passkey and wallet signers)
//! - Project creation and RFC-004 compliance
//! - Reference and cross-project reference workflows
//! - Storage key generation and parsing
//! - Encryption workflows
//! - Full integration scenarios

mod common;

use common::*;
use objects_data::{
    Asset, KeyType, Project, Reference, ReferenceType, SignedAsset, encryption, parse_key,
    project_id_from_replica, storage,
};
// IdentityId imported via common module
use rstest::*;

// ============================================================================
// SignedAsset Workflows
// ============================================================================

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_signed_asset_passkey_full_lifecycle() {
    // Create a complete signed asset with passkey
    let (asset, signed_asset, identity_id, _signing_key, nonce) =
        create_signed_asset_passkey_full("test-asset-1");

    // Verify the asset has correct author_id
    assert_eq!(asset.author_id(), &identity_id);

    // Verify the signature
    let verify_result = signed_asset.verify();
    if let Err(e) = &verify_result {
        eprintln!("Verification error: {:?}", e);
    }
    assert!(verify_result.is_ok());

    // Verify nonce matches
    assert_eq!(signed_asset.nonce(), &nonce);
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_wallet_full_lifecycle() {
    // Create a complete signed asset with wallet
    let (asset, signed_asset, identity_id, _signing_key, nonce) =
        create_signed_asset_wallet_full("test-asset-2");

    // Verify the asset has correct author_id
    assert_eq!(asset.author_id(), &identity_id);

    // Verify the signature (includes EIP-191 recovery)
    assert!(signed_asset.verify().is_ok());

    // Verify nonce matches
    assert_eq!(signed_asset.nonce(), &nonce);
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_wrong_nonce_fails() {
    // Create signed asset
    let (_asset, signed_asset, _identity_id, _signing_key, _nonce) =
        create_signed_asset_passkey_full("test-asset-3");

    // Replace with wrong nonce
    let wrong_nonce = [255, 254, 253, 252, 251, 250, 249, 248];
    let wrong_signed = SignedAsset::new(
        signed_asset.asset().clone(),
        signed_asset.signature().clone(),
        wrong_nonce,
    );

    // Verification should fail - derived ID won't match author_id
    assert!(wrong_signed.verify().is_err());
}

#[rstest]
#[tokio::test]
async fn test_signed_asset_tampered_content_fails() {
    // Create signed asset
    let (asset, signed_asset, identity_id, _signing_key, nonce) =
        create_signed_asset_passkey_full("test-asset-4");

    // Tamper with content hash
    let tampered_hash = test_content_hash(99); // Different from original
    let tampered_asset = Asset::new(
        asset.id().to_string(),
        asset.name().to_string(),
        identity_id,
        tampered_hash,
        asset.content_size(),
        asset.format().map(|s| s.to_string()),
        asset.created_at(),
        asset.updated_at(),
    )
    .expect("valid asset");

    let tampered_signed = SignedAsset::new(tampered_asset, signed_asset.signature().clone(), nonce);

    // Verification should fail - signature won't match
    assert!(tampered_signed.verify().is_err());
}

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_multiple_assets_same_identity() {
    // Create first signed asset
    let (_, signed1, identity1, _, _) = create_signed_asset_passkey_full("asset-1");

    // Create second signed asset with same identity setup
    // (In real use, would reuse same keypair + nonce, but for test we create separate)
    let (_, signed2, identity2, _, _) = create_signed_asset_passkey_full("asset-2");

    // Both should verify independently
    assert!(signed1.verify().is_ok());
    assert!(signed2.verify().is_ok());

    // Different identities (because different keypairs)
    assert_ne!(identity1, identity2);
}

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_signed_asset_deterministic_verification() {
    // Create signed asset
    let (_asset, signed_asset, _identity_id, _signing_key, _nonce) =
        create_signed_asset_passkey_full("test-asset-5");

    // Verify multiple times - should be deterministic
    assert!(signed_asset.verify().is_ok());
    assert!(signed_asset.verify().is_ok());
    assert!(signed_asset.verify().is_ok());
}

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_signed_asset_mixed_signer_types() {
    // Create with passkey
    let (_asset1, signed1, _id1, _, _) = create_signed_asset_passkey_full("asset-passkey");

    // Create with wallet
    let (_asset2, signed2, _id2, _, _) = create_signed_asset_wallet_full("asset-wallet");

    // Both should verify
    assert!(signed1.verify().is_ok());
    assert!(signed2.verify().is_ok());
}

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_signed_asset_serialization_roundtrip() {
    // Create signed asset
    let (_asset, signed_asset, _identity_id, _signing_key, _nonce) =
        create_signed_asset_passkey_full("test-asset-6");

    // Serialize to JSON
    let json = serde_json::to_string(&signed_asset).expect("serialize");

    // Deserialize back
    let deserialized: SignedAsset = serde_json::from_str(&json).expect("deserialize");

    // Should still verify
    assert!(deserialized.verify().is_ok());

    // Content should match
    assert_eq!(
        deserialized.asset().content_hash().to_hex(),
        signed_asset.asset().content_hash().to_hex()
    );
}

// ============================================================================
// Project Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_project_creation_from_replica_id() {
    // Create a replica ID (32 bytes)
    let replica_id: [u8; 32] = [1u8; 32];

    // Derive project ID per RFC-004
    let project_id = project_id_from_replica(&replica_id);

    // Should be 32 hex characters (first 16 bytes of replica_id)
    assert_eq!(project_id.len(), 32);
    assert_eq!(project_id, hex::encode(&replica_id[..16]));

    // Create project with this ID
    let project = test_project_from_replica(replica_id);
    assert_eq!(project.id(), &project_id);
}

#[rstest]
#[tokio::test]
async fn test_project_id_parsing_and_validation() {
    let owner_id = test_identity_id();

    // Valid 32 hex char ID
    let valid_id = "a".repeat(32);
    let project = Project::new(
        valid_id.clone(),
        "Valid Project".to_string(),
        None,
        owner_id.clone(),
        now(),
        now(),
    );
    assert!(project.is_ok());
    assert_eq!(project.unwrap().id(), &valid_id);

    // Invalid: too short
    let short_id = "a".repeat(31);
    let result = Project::new(
        short_id,
        "Invalid".to_string(),
        None,
        owner_id.clone(),
        now(),
        now(),
    );
    assert!(result.is_err());

    // Invalid: too long
    let long_id = "a".repeat(33);
    let result = Project::new(long_id, "Invalid".to_string(), None, owner_id, now(), now());
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_project_timestamp_validation() {
    let owner_id = test_identity_id();
    let id = "b".repeat(32);

    // Valid: created_at <= updated_at
    let created = now();
    let updated = future_timestamp(100);
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

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_project_with_owner_identity() {
    let owner_id = test_identity_id();
    let project = test_project("My Project", owner_id.clone());

    // Verify owner is set correctly
    assert_eq!(project.owner_id(), &owner_id);
    assert_eq!(project.name(), "My Project");
}

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_project_serialization_roundtrip() {
    let owner_id = test_identity_id();
    let project = test_project("Test Project", owner_id);

    // Serialize to JSON
    let json = serde_json::to_string(&project).expect("serialize");

    // Deserialize back
    let deserialized: Project = serde_json::from_str(&json).expect("deserialize");

    // Fields should match
    assert_eq!(deserialized.id(), project.id());
    assert_eq!(deserialized.name(), project.name());
    assert_eq!(deserialized.owner_id(), project.owner_id());
    assert_eq!(deserialized.created_at(), project.created_at());
}

#[rstest]
#[tokio::test]
async fn test_project_id_from_different_replicas() {
    let replica1: [u8; 32] = [1u8; 32];
    let replica2: [u8; 32] = [2u8; 32];

    let id1 = project_id_from_replica(&replica1);
    let id2 = project_id_from_replica(&replica2);

    // Different replicas should produce different project IDs
    assert_ne!(id1, id2);

    // Both should be 32 hex chars
    assert_eq!(id1.len(), 32);
    assert_eq!(id2.len(), 32);
}

// ============================================================================
// Reference Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_reference_linking_two_assets() {
    let source_id = "source-asset";
    let target_id = "target-asset";

    let reference = test_reference(source_id, target_id);

    assert_eq!(&reference.source_asset_id, source_id);
    assert_eq!(&reference.target_asset_id, target_id);
    assert!(reference.validate().is_ok());
}

#[rstest]
#[tokio::test]
async fn test_reference_with_content_hash() {
    let source_id = "source";
    let target_id = "target";
    let content_hash = test_content_hash(42);

    let reference = Reference {
        id: "ref-1".to_string(),
        source_asset_id: source_id.to_string(),
        target_asset_id: target_id.to_string(),
        target_content_hash: Some(content_hash.clone()),
        reference_type: ReferenceType::DependsOn,
        created_at: now(),
    };

    assert!(reference.validate().is_ok());
    assert_eq!(reference.target_content_hash.as_ref(), Some(&content_hash));
}

#[rstest]
#[tokio::test]
async fn test_reference_type_variations() {
    let source = "source";
    let target = "target";

    // Test all reference types
    let types = vec![
        ReferenceType::Unspecified,
        ReferenceType::Contains,
        ReferenceType::DependsOn,
        ReferenceType::DerivedFrom,
        ReferenceType::References,
    ];

    for ref_type in types {
        let reference = Reference {
            id: format!("ref-{:?}", ref_type),
            source_asset_id: source.to_string(),
            target_asset_id: target.to_string(),
            target_content_hash: None,
            reference_type: ref_type,
            created_at: now(),
        };

        assert!(reference.validate().is_ok());
    }
}

#[rstest]
#[tokio::test]
async fn test_reference_validation_requirements() {
    // Valid reference
    let valid = Reference {
        id: "ref-1".to_string(),
        source_asset_id: "source".to_string(),
        target_asset_id: "target".to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: now(),
    };
    assert!(valid.validate().is_ok());

    // Invalid: empty source
    let invalid = Reference {
        id: "ref-2".to_string(),
        source_asset_id: "".to_string(),
        target_asset_id: "target".to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: now(),
    };
    assert!(invalid.validate().is_err());

    // Invalid: empty target
    let invalid = Reference {
        id: "ref-3".to_string(),
        source_asset_id: "source".to_string(),
        target_asset_id: "".to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: now(),
    };
    assert!(invalid.validate().is_err());
}

#[rstest]
#[tokio::test]
async fn test_cross_project_reference_workflow() {
    use objects_data::CrossProjectReference;

    let source_asset = "asset-1";
    let target_project = "c".repeat(32); // 32 hex chars
    let target_asset = "asset-2";

    let cross_ref = CrossProjectReference {
        id: "cross-ref-1".to_string(),
        source_asset_id: source_asset.to_string(),
        target_project_id: target_project.clone(),
        target_asset_id: target_asset.to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: now(),
    };

    // CrossProjectReference has public fields, validate by accessing directly
    assert!(!cross_ref.id.is_empty());
    assert_eq!(&cross_ref.target_project_id, &target_project);
}

// ============================================================================
// Storage Integration
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_storage_key_generation_for_assets() {
    let asset_id = "motor-mount";
    let key = storage::asset_key(asset_id);

    assert_eq!(key, "/assets/motor-mount");
}

#[rstest]
#[tokio::test]
async fn test_storage_key_generation_for_references() {
    let ref_id = "ref-assembly-to-part";
    let key = storage::reference_key(ref_id);

    assert_eq!(key, "/refs/ref-assembly-to-part");
}

#[rstest]
#[tokio::test]
async fn test_storage_key_parsing_roundtrip() {
    // Asset key roundtrip
    let asset_id = "test-asset";
    let asset_key = storage::asset_key(asset_id);
    match parse_key(&asset_key) {
        KeyType::Asset(id) => assert_eq!(id, asset_id),
        _ => panic!("expected Asset key type"),
    }

    // Reference key roundtrip
    let ref_id = "test-ref";
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

    let parsed = parse_key(key);
    assert_eq!(parsed, KeyType::Project);
}

#[rstest]
#[tokio::test]
async fn test_storage_key_unknown_format() {
    let unknown_key = "/unknown/path";
    let parsed = parse_key(unknown_key);
    assert_eq!(parsed, KeyType::Unknown);

    let empty = "";
    let parsed = parse_key(empty);
    assert_eq!(parsed, KeyType::Unknown);
}

// ============================================================================
// Encryption Workflows
// ============================================================================

#[rstest]
#[tokio::test]
async fn test_catalog_entry_encryption_roundtrip() {
    use objects_data::proto::ProjectCatalogEntry;

    // Create a project catalog entry (protobuf type)
    let replica_id: [u8; 32] = rand::random();
    let project_id = project_id_from_replica(&replica_id);

    let entry = ProjectCatalogEntry {
        project_id: project_id.clone(),
        replica_id: replica_id.to_vec(),
        project_name: "Test Project".to_string(),
        created_at: now(),
    };

    // Encrypt
    let key = test_encryption_key();
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

    let replica_id: [u8; 32] = rand::random();
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Test".to_string(),
        created_at: now(),
    };

    let key1 = test_encryption_key();
    let key2 = test_encryption_key(); // Different key

    let encrypted = encryption::encrypt_catalog_entry(&entry, &key1).expect("encrypt");

    // Wrong key should fail
    let result = encryption::decrypt_catalog_entry(&encrypted, &key2);
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_tampered_ciphertext() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id: [u8; 32] = rand::random();
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Test".to_string(),
        created_at: now(),
    };

    let key = test_encryption_key();
    let mut encrypted = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");

    // Tamper with ciphertext (skip nonce, modify actual ciphertext)
    if encrypted.len() > 25 {
        encrypted[25] ^= 0xFF;
    }

    // Decryption should fail (authentication)
    let result = encryption::decrypt_catalog_entry(&encrypted, &key);
    assert!(result.is_err());
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_nonce_uniqueness() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id: [u8; 32] = rand::random();
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Test".to_string(),
        created_at: now(),
    };

    let key = test_encryption_key();
    let encrypted1 = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");
    let encrypted2 = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");

    // Same entry encrypted twice should have different nonces
    assert_ne!(encrypted1, encrypted2);

    // Both should decrypt to same plaintext
    let dec1 = encryption::decrypt_catalog_entry(&encrypted1, &key).expect("decrypt");
    let dec2 = encryption::decrypt_catalog_entry(&encrypted2, &key).expect("decrypt");
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, entry);
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_too_short_data() {
    let key = test_encryption_key();
    let short_data = vec![1, 2, 3]; // Less than 24 bytes (nonce size)

    let result = encryption::decrypt_catalog_entry(&short_data, &key);
    assert!(result.is_err());
}

// ============================================================================
// Cross-Module Integration
// ============================================================================

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_asset_with_identity_verification() {
    // Full workflow: create identity, create asset, sign, verify
    let (asset, signed_asset, identity_id, _, _) =
        create_signed_asset_passkey_full("integrated-asset");

    // Verify identity matches
    assert_eq!(asset.author_id(), &identity_id);

    // Verify signature with identity derivation
    assert!(signed_asset.verify().is_ok());

    // Identity ID should have correct format
    assert!(identity_id.as_str().starts_with("obj_"));
}

#[rstest]
#[tokio::test]
async fn test_project_asset_storage_workflow() {
    // Create project
    let owner_id = test_identity_id();
    let replica_id: [u8; 32] = rand::random();
    let _project = test_project_from_replica(replica_id);

    // Create assets in the project
    let asset1 = test_asset("asset-1", owner_id.clone());
    let asset2 = test_asset("asset-2", owner_id);

    // Generate storage keys
    let key1 = storage::asset_key(asset1.id());
    let key2 = storage::asset_key(asset2.id());

    // Keys should be different
    assert_ne!(key1, key2);

    // Parse keys back
    assert!(matches!(parse_key(&key1), KeyType::Asset(_)));
    assert!(matches!(parse_key(&key2), KeyType::Asset(_)));
}

#[rstest]
#[tokio::test]
async fn test_reference_with_asset_content_hashes() {
    let author_id = test_identity_id();

    // Create two assets with known hashes
    let hash1 = test_content_hash(10);
    let hash2 = test_content_hash(20);
    let asset1 = test_asset_with_hash("source", author_id.clone(), hash1.clone());
    let asset2 = test_asset_with_hash("target", author_id, hash2.clone());

    // Create reference with target content hash
    let reference = Reference {
        id: "ref-1".to_string(),
        source_asset_id: asset1.id().to_string(),
        target_asset_id: asset2.id().to_string(),
        target_content_hash: Some(hash2.clone()),
        reference_type: ReferenceType::DependsOn,
        created_at: now(),
    };

    assert!(reference.validate().is_ok());
    assert_eq!(reference.target_content_hash.as_ref(), Some(&hash2));
}

#[rstest]
#[tokio::test]
async fn test_full_project_graph() {
    // Create a complete project with assets and references
    let owner_id = test_identity_id();
    let replica_id: [u8; 32] = rand::random();
    let project = test_project_from_replica(replica_id);

    // Create multiple assets
    let asset1 = test_asset("component-a", owner_id.clone());
    let asset2 = test_asset("component-b", owner_id.clone());
    let asset3 = test_asset("assembly", owner_id);

    // Create references
    let ref1 = test_reference(asset3.id(), asset1.id()); // assembly -> component-a
    let ref2 = test_reference(asset3.id(), asset2.id()); // assembly -> component-b

    // Validate references (Asset validation happens in Asset::new())
    assert!(ref1.validate().is_ok());
    assert!(ref2.validate().is_ok());

    // Project should be valid
    assert_eq!(project.id().len(), 32); // RFC-004 compliance
}

// TODO: Requires proper WebAuthn client_data_json setup from identity integration branch
#[ignore]
#[rstest]
#[tokio::test]
async fn test_signed_assets_in_project_context() {
    // Create multiple signed assets in a project
    let (asset1, signed1, _, _, _) = create_signed_asset_passkey_full("proj-asset-1");
    let (asset2, signed2, _, _, _) = create_signed_asset_wallet_full("proj-asset-2");

    // Both should verify
    assert!(signed1.verify().is_ok());
    assert!(signed2.verify().is_ok());

    // Create reference between them
    let reference = test_reference(asset1.id(), asset2.id());
    assert!(reference.validate().is_ok());
}

#[rstest]
#[tokio::test]
async fn test_catalog_entry_for_active_project() {
    // Create project
    let _owner_id = test_identity_id();
    let replica_id: [u8; 32] = rand::random();
    let project = test_project_from_replica(replica_id);
    let project_id = project.id().to_string();

    use objects_data::proto::ProjectCatalogEntry;

    // Create actual catalog entry (protobuf type)
    let catalog_entry = ProjectCatalogEntry {
        project_id: project_id.clone(),
        replica_id: replica_id.to_vec(),
        project_name: project.name().to_string(),
        created_at: project.created_at(),
    };

    // Encrypt catalog entry
    let key = test_encryption_key();
    let encrypted = encryption::encrypt_catalog_entry(&catalog_entry, &key).expect("encrypt");

    // Decrypt and verify
    let decrypted = encryption::decrypt_catalog_entry(&encrypted, &key).expect("decrypt");
    assert_eq!(decrypted, catalog_entry);

    // Generate storage key for project
    let project_key = storage::PROJECT_KEY;
    assert_eq!(parse_key(project_key), KeyType::Project);
}
