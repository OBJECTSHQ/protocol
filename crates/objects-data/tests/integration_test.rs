//! Integration tests for objects-data crate.
//!
//! Tests cross-module workflows including:
//! - SignedAsset lifecycle (Ed25519 signer)
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

// ============================================================================
// SignedAsset Workflows
// ============================================================================

#[test]
fn test_signed_asset_full_lifecycle() {
    let bundle = data::signed_asset("test-asset-1");

    assert_eq!(bundle.asset.author_id(), &bundle.identity_id);
    assert!(bundle.signed_asset.verify().is_ok());
    assert_eq!(bundle.signed_asset.nonce(), &bundle.nonce);
}

#[test]
fn test_signed_asset_wrong_nonce_fails() {
    let bundle = data::signed_asset("test-asset-3");

    let wrong_signed = SignedAsset::new(
        bundle.signed_asset.asset().clone(),
        bundle.signed_asset.signature().clone(),
        [255, 254, 253, 252, 251, 250, 249, 248],
    );
    assert!(wrong_signed.verify().is_err());
}

#[test]
fn test_signed_asset_tampered_content_fails() {
    let bundle = data::signed_asset("test-asset-4");

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
    assert!(tampered_signed.verify().is_err());
}

#[test]
fn test_signed_asset_signature_replay_attack_fails() {
    let bundle1 = data::signed_asset("asset-original");
    assert!(bundle1.signed_asset.verify().is_ok());

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

    let replayed_signed = SignedAsset::new(
        asset2,
        bundle1.signed_asset.signature().clone(),
        bundle1.nonce,
    );

    assert!(replayed_signed.verify().is_err());
}

#[test]
fn test_multiple_assets_same_identity() {
    let bundle1 = data::signed_asset("asset-1");
    let bundle2 = data::signed_asset("asset-2");

    assert!(bundle1.signed_asset.verify().is_ok());
    assert!(bundle2.signed_asset.verify().is_ok());
    // Different keypairs produce different identities
    assert_ne!(bundle1.identity_id, bundle2.identity_id);
}

#[test]
fn test_signed_asset_serialization_roundtrip() {
    let bundle = data::signed_asset("test-asset-6");

    let json = serde_json::to_string(&bundle.signed_asset).expect("serialize");
    let deserialized: SignedAsset = serde_json::from_str(&json).expect("deserialize");

    assert!(deserialized.verify().is_ok());
    assert_eq!(deserialized.asset().id(), bundle.asset.id());
    assert_eq!(deserialized.nonce(), &bundle.nonce);
}

// ============================================================================
// Project Workflows
// ============================================================================

#[test]
fn test_project_creation_from_replica_id() {
    let replica_id = crypto::deterministic_bytes(42);

    let expected_id = project_id_from_replica(&replica_id);

    let project = data::project_from_replica(&replica_id);

    assert_eq!(project.id(), expected_id);
    assert_eq!(project.name(), "Test Project");
}

#[test]
fn test_project_id_parsing_and_validation() {
    let owner_id = identity::test_identity_id();
    let now = time::now();

    // Valid: 64 hex characters
    let valid_id = hex::encode(crypto::deterministic_bytes(1));
    assert!(
        Project::new(
            valid_id,
            "Valid Project".into(),
            None,
            owner_id.clone(),
            now,
            now
        )
        .is_ok()
    );

    // Invalid: too short
    assert!(
        Project::new(
            "abc123".into(),
            "Invalid".into(),
            None,
            owner_id.clone(),
            now,
            now
        )
        .is_err()
    );

    // Invalid: too long
    assert!(Project::new("a".repeat(100), "Invalid".into(), None, owner_id, now, now).is_err());
}

#[test]
fn test_project_timestamp_validation() {
    let owner_id = identity::test_identity_id();
    let id = "b".repeat(64);
    let created = time::now();
    let updated = time::future_timestamp(100);

    assert!(
        Project::new(
            id.clone(),
            "Valid".into(),
            None,
            owner_id.clone(),
            created,
            updated
        )
        .is_ok()
    );
    assert!(Project::new(id, "Invalid".into(), None, owner_id, updated, created).is_err());
}

#[test]
fn test_project_with_owner_identity() {
    let owner_id = identity::test_identity_id();
    let project = data::project("My Project", owner_id.clone());

    assert_eq!(project.name(), "My Project");
    assert_eq!(project.owner_id(), &owner_id);
}

#[test]
fn test_project_serialization_roundtrip() {
    let owner_id = identity::test_identity_id();
    let project = data::project("Test Project", owner_id);

    let json = serde_json::to_string(&project).expect("serialize");

    let deserialized: Project = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.id(), project.id());
    assert_eq!(deserialized.name(), project.name());
    assert_eq!(deserialized.owner_id(), project.owner_id());
}

#[test]
fn test_project_id_from_different_replicas() {
    let replica1 = crypto::deterministic_bytes(10);
    let replica2 = crypto::deterministic_bytes(20);

    let id1 = project_id_from_replica(&replica1);
    let id2 = project_id_from_replica(&replica2);

    assert_ne!(id1, id2);

    let id1_again = project_id_from_replica(&replica1);
    assert_eq!(id1, id1_again);
}

// ============================================================================
// Reference Workflows
// ============================================================================

#[test]
fn test_reference_linking_two_assets() {
    let source_id = "asset-source";
    let target_id = "asset-target";

    let reference = data::reference(source_id, target_id);

    assert_eq!(reference.source_asset_id, source_id);
    assert_eq!(reference.target_asset_id, target_id);
    assert_eq!(reference.reference_type, ReferenceType::References);
}

#[test]
fn test_reference_with_content_hash() {
    let source_id = "source";
    let target_id = "target";
    let content_hash = ContentHash::new(crypto::deterministic_bytes(42));

    let mut reference = data::reference(source_id, target_id);
    reference.target_content_hash = Some(content_hash.clone());

    assert_eq!(reference.target_content_hash, Some(content_hash));
}

#[test]
fn test_reference_type_variations() {
    for ref_type in [
        ReferenceType::References,
        ReferenceType::DerivedFrom,
        ReferenceType::Contains,
        ReferenceType::DependsOn,
    ] {
        let mut reference = data::reference("source", "target");
        reference.reference_type = ref_type;
        assert_eq!(reference.reference_type, ref_type);
    }
}

#[test]
fn test_reference_serialization_roundtrip() {
    let valid_ref = Reference {
        id: "ref-1".to_string(),
        source_asset_id: "source".to_string(),
        target_asset_id: "target".to_string(),
        target_content_hash: None,
        reference_type: ReferenceType::References,
        created_at: time::now(),
    };

    let json = serde_json::to_string(&valid_ref).expect("serialize");
    let deserialized: Reference = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.source_asset_id, valid_ref.source_asset_id);
    assert_eq!(deserialized.target_asset_id, valid_ref.target_asset_id);
}

#[test]
fn test_cross_project_reference_workflow() {
    let author_id = identity::test_identity_id();

    let replica1 = crypto::deterministic_bytes(1);
    let replica2 = crypto::deterministic_bytes(2);

    let _project1 = data::project_from_replica(&replica1);
    let _project2 = data::project_from_replica(&replica2);

    let asset1 = data::asset("proj1-asset", author_id.clone());
    let asset2 = data::asset("proj2-asset", author_id);

    let reference = data::reference(asset2.id(), asset1.id());

    assert_eq!(reference.source_asset_id, asset2.id());
    assert_eq!(reference.target_asset_id, asset1.id());
}

// ============================================================================
// Storage Key Generation
// ============================================================================

#[test]
fn test_storage_key_generation_for_assets() {
    let asset_id = "test-asset";
    let key = storage::asset_key(asset_id);

    assert!(key.starts_with("/assets/"));
    assert!(key.contains(asset_id));
}

#[test]
fn test_storage_key_generation_for_references() {
    let ref_id = "test-ref";
    let key = storage::reference_key(ref_id);

    assert!(key.starts_with("/refs/"));
    assert!(key.contains(ref_id));
}

#[test]
fn test_storage_key_parsing_roundtrip() {
    let asset_id = "asset-123";
    let asset_key = storage::asset_key(asset_id);

    match parse_key(&asset_key) {
        KeyType::Asset(id) => assert_eq!(id, asset_id),
        _ => panic!("expected Asset key type"),
    }

    let ref_id = "ref-456";
    let ref_key = storage::reference_key(ref_id);

    match parse_key(&ref_key) {
        KeyType::Reference(id) => assert_eq!(id, ref_id),
        _ => panic!("expected Reference key type"),
    }
}

#[test]
fn test_project_key_constant() {
    let key = storage::PROJECT_KEY;
    assert_eq!(key, "/project");

    assert!(matches!(parse_key(key), KeyType::Project));
}

#[test]
fn test_storage_key_unknown_format() {
    let invalid_key = "/unknown/key";

    assert!(matches!(parse_key(invalid_key), KeyType::Unknown));
}

// ============================================================================
// Encryption Workflows
// ============================================================================

#[test]
fn test_catalog_entry_encryption_roundtrip() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id = crypto::deterministic_bytes(42);
    let project_id = project_id_from_replica(&replica_id);

    let entry = ProjectCatalogEntry {
        project_id: project_id.clone(),
        replica_id: replica_id.to_vec(),
        project_name: "Test Project".to_string(),
        created_at: time::now(),
    };

    let key = crypto::encryption_key();
    let encrypted = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt");

    assert!(encrypted.len() > 24);

    let decrypted = encryption::decrypt_catalog_entry(&encrypted, &key).expect("decrypt");

    assert_eq!(decrypted, entry);
}

#[test]
fn test_catalog_entry_wrong_key_detection() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id = crypto::deterministic_bytes(99);
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Test".to_string(),
        created_at: time::now(),
    };

    let key1 = crypto::encryption_key();
    let encrypted = encryption::encrypt_catalog_entry(&entry, &key1).expect("encrypt");

    let key2 = crypto::encryption_key();
    let result = encryption::decrypt_catalog_entry(&encrypted, &key2);

    assert!(result.is_err());
}

#[test]
fn test_catalog_entry_tampered_ciphertext() {
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

    if let Some(byte) = encrypted.get_mut(30) {
        *byte = byte.wrapping_add(1);
    }

    let result = encryption::decrypt_catalog_entry(&encrypted, &key);
    assert!(result.is_err());
}

#[test]
fn test_catalog_entry_nonce_uniqueness() {
    use objects_data::proto::ProjectCatalogEntry;

    let replica_id = crypto::deterministic_bytes(55);
    let entry = ProjectCatalogEntry {
        project_id: project_id_from_replica(&replica_id),
        replica_id: replica_id.to_vec(),
        project_name: "Nonce Test".to_string(),
        created_at: time::now(),
    };

    let key = crypto::encryption_key();

    let encrypted1 = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt 1");
    let encrypted2 = encryption::encrypt_catalog_entry(&entry, &key).expect("encrypt 2");

    assert_ne!(encrypted1, encrypted2);

    let decrypted1 = encryption::decrypt_catalog_entry(&encrypted1, &key).expect("decrypt 1");
    let decrypted2 = encryption::decrypt_catalog_entry(&encrypted2, &key).expect("decrypt 2");
    assert_eq!(decrypted1, decrypted2);
}

#[test]
fn test_catalog_entry_too_short_data() {
    let key = crypto::encryption_key();

    let too_short = vec![1, 2, 3];
    let result = encryption::decrypt_catalog_entry(&too_short, &key);

    assert!(result.is_err());
}

// ============================================================================
// Integration Scenarios
// ============================================================================

#[test]
fn test_project_asset_storage_workflow() {
    let owner_id = identity::test_identity_id();

    let asset1 = data::asset("asset-1", owner_id.clone());
    let asset2 = data::asset("asset-2", owner_id);

    let key1 = storage::asset_key(asset1.id());
    let key2 = storage::asset_key(asset2.id());
    assert_ne!(key1, key2);
    assert!(matches!(parse_key(&key1), KeyType::Asset(_)));
    assert!(matches!(parse_key(&key2), KeyType::Asset(_)));
}

#[test]
fn test_reference_with_asset_content_hashes() {
    let author_id = identity::test_identity_id();

    let hash1 = ContentHash::new(crypto::deterministic_bytes(10));
    let hash2 = ContentHash::new(crypto::deterministic_bytes(20));
    let asset1 = data::asset_with_hash("source", author_id.clone(), hash1.clone());
    let asset2 = data::asset_with_hash("target", author_id, hash2.clone());

    let mut reference = data::reference(asset1.id(), asset2.id());
    reference.target_content_hash = Some(hash2.clone());

    assert_eq!(reference.target_content_hash, Some(hash2.clone()));
    assert_eq!(asset1.content_hash(), &hash1);
    assert_eq!(asset2.content_hash(), &hash2);
}

#[test]
fn test_full_project_graph() {
    let owner_id = identity::test_identity_id();
    let replica_id = crypto::deterministic_bytes(42);
    let project = data::project_from_replica(&replica_id);

    let asset1 = data::asset("component-a", owner_id.clone());
    let asset2 = data::asset("component-b", owner_id.clone());
    let asset3 = data::asset("assembly", owner_id);

    let ref1 = data::reference(asset3.id(), asset1.id());
    let ref2 = data::reference(asset3.id(), asset2.id());

    assert_eq!(project.owner_id(), asset1.author_id());
    assert_eq!(ref1.source_asset_id, asset3.id());
    assert_eq!(ref2.source_asset_id, asset3.id());
}

#[test]
fn test_signed_assets_in_project_context() {
    let bundle1 = data::signed_asset("proj-asset-1");
    let bundle2 = data::signed_asset("proj-asset-2");

    assert!(bundle1.signed_asset.verify().is_ok());
    assert!(bundle2.signed_asset.verify().is_ok());

    let reference = data::reference(bundle1.asset.id(), bundle2.asset.id());
    assert_eq!(reference.source_asset_id, bundle1.asset.id());
}

// test_catalog_entry_encryption_roundtrip already covers encrypt/decrypt verification.
