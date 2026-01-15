//! Property-based tests for objects-data crate.
//!
//! Tests invariants using proptest:
//! - Validation rules
//! - Serialization round trips
//! - Deterministic operations
//! - RFC compliance

mod common;

use common::*;
use objects_data::{
    Asset, ContentHash, KeyType, Project, Reference, ReferenceType, parse_key,
    project_id_from_replica, storage,
};
use proptest::prelude::*;

proptest! {
    // ========================================================================
    // Validation Invariants
    // ========================================================================

    /// Property: Asset IDs must be 1-64 alphanumeric + hyphens
    #[test]
    fn prop_asset_id_validation(
        id in "[a-zA-Z0-9-]{1,64}",
        name in ".+",
    ) {
        let author_id = test_identity_id();
        let content_hash = test_content_hash(42);
        let timestamp = now();

        let result = Asset::new(
            id.clone(),
            name,
            author_id,
            content_hash,
            1024,
            Some("test".to_string()),
            timestamp,
            timestamp,
        );

        // Valid pattern should always succeed
        prop_assert!(
            result.is_ok(),
            "Valid asset ID '{}' should be accepted",
            id
        );
    }

    /// Property: Asset timestamps must satisfy created_at <= updated_at
    #[test]
    fn prop_asset_timestamps(
        created in 0u64..1000000u64,
        offset in 0u64..1000u64,
    ) {
        let author_id = test_identity_id();
        let content_hash = test_content_hash(42);
        let updated = created + offset;

        let result = Asset::new(
            "test-asset".to_string(),
            "Test".to_string(),
            author_id,
            content_hash,
            1024,
            Some("test".to_string()),
            created,
            updated,
        );

        prop_assert!(
            result.is_ok(),
            "created_at ({}) <= updated_at ({}) should be valid",
            created,
            updated
        );

        // Verify the invariant holds
        if let Ok(asset) = result {
            prop_assert!(asset.created_at() <= asset.updated_at());
        }
    }

    /// Property: Project IDs must always be exactly 32 hex characters
    #[test]
    fn prop_project_id_format(
        id in "[0-9a-f]{32}",
    ) {
        let owner_id = test_identity_id();
        let timestamp = now();

        let result = Project::new(
            id.clone(),
            "Test Project".to_string(),
            Some("Description".to_string()),
            owner_id,
            timestamp,
            timestamp,
        );

        prop_assert!(
            result.is_ok(),
            "32 hex char project ID '{}' should be valid",
            id
        );

        // Verify length invariant
        if let Ok(project) = result {
            prop_assert_eq!(project.id().len(), 32);
            prop_assert!(project.id().chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// Property: Project timestamps must satisfy created_at <= updated_at
    #[test]
    fn prop_project_timestamps(
        created in 0u64..1000000u64,
        offset in 0u64..1000u64,
    ) {
        let owner_id = test_identity_id();
        let id = "a".repeat(32);
        let updated = created + offset;

        let result = Project::new(
            id,
            "Test".to_string(),
            None,
            owner_id,
            created,
            updated,
        );

        prop_assert!(result.is_ok());
        if let Ok(project) = result {
            prop_assert!(project.created_at() <= project.updated_at());
        }
    }

    /// Property: References must have non-empty source, target, and id fields
    #[test]
    fn prop_reference_non_empty_fields(
        source in ".+",
        target in ".+",
        id in ".+",
    ) {
        let reference = Reference {
            id,
            source_asset_id: source,
            target_asset_id: target,
            target_content_hash: None,
            reference_type: ReferenceType::References,
            created_at: now(),
        };

        // Non-empty fields should always validate
        prop_assert!(reference.validate().is_ok());
    }

    // ========================================================================
    // Serialization Roundtrips
    // ========================================================================

    /// Property: Asset serialization preserves all fields
    #[test]
    fn prop_asset_serialization_roundtrip(
        id in "[a-zA-Z0-9-]{1,64}",
        name in ".+",
        content_size in 0u64..1000000u64,
    ) {
        let author_id = test_identity_id();
        let content_hash = test_content_hash(42);
        let timestamp = now();

        let asset = Asset::new(
            id,
            name,
            author_id,
            content_hash,
            content_size,
            Some("application/octet-stream".to_string()),
            timestamp,
            timestamp,
        )
        .expect("valid asset");

        // Serialize to JSON
        let json = serde_json::to_string(&asset).expect("serialize");

        // Deserialize back
        let deserialized: Asset = serde_json::from_str(&json).expect("deserialize");

        // All fields should match
        prop_assert_eq!(deserialized.id(), asset.id());
        prop_assert_eq!(deserialized.name(), asset.name());
        prop_assert_eq!(deserialized.author_id(), asset.author_id());
        prop_assert_eq!(deserialized.content_hash(), asset.content_hash());
        prop_assert_eq!(deserialized.content_size(), asset.content_size());
        prop_assert_eq!(deserialized.created_at(), asset.created_at());
        prop_assert_eq!(deserialized.updated_at(), asset.updated_at());
    }

    /// Property: Project serialization roundtrip preserves all fields
    #[test]
    fn prop_project_serialization_roundtrip(
        name in ".+",
    ) {
        let owner_id = test_identity_id();
        let id = "b".repeat(32);
        let timestamp = now();

        let project = Project::new(
            id,
            name,
            Some("Test description".to_string()),
            owner_id,
            timestamp,
            timestamp,
        )
        .expect("valid project");

        // Serialize to JSON
        let json = serde_json::to_string(&project).expect("serialize");

        // Deserialize back
        let deserialized: Project = serde_json::from_str(&json).expect("deserialize");

        // Fields should match
        prop_assert_eq!(deserialized.id(), project.id());
        prop_assert_eq!(deserialized.name(), project.name());
        prop_assert_eq!(deserialized.owner_id(), project.owner_id());
        prop_assert_eq!(deserialized.created_at(), project.created_at());
        prop_assert_eq!(deserialized.updated_at(), project.updated_at());
    }

    /// Property: Reference serialization roundtrip
    #[test]
    fn prop_reference_serialization_roundtrip(
        source in ".+",
        target in ".+",
    ) {
        // Use char-safe truncation to avoid UTF-8 boundary issues
        let source_prefix: String = source.chars().take(3).collect();
        let target_prefix: String = target.chars().take(3).collect();
        let id = format!("ref-{}-{}", source_prefix, target_prefix);
        let reference = Reference {
            id,
            source_asset_id: source,
            target_asset_id: target,
            target_content_hash: None,
            reference_type: ReferenceType::DependsOn,
            created_at: now(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&reference).expect("serialize");

        // Deserialize back
        let deserialized: Reference = serde_json::from_str(&json).expect("deserialize");

        // Fields should match (using public fields directly)
        prop_assert_eq!(&deserialized.source_asset_id, &reference.source_asset_id);
        prop_assert_eq!(&deserialized.target_asset_id, &reference.target_asset_id);
    }

    /// Property: ContentHash serialization preserves 32 bytes
    #[test]
    fn prop_content_hash_serialization(
        seed in any::<u8>(),
    ) {
        let hash = test_content_hash(seed);

        // Serialize to JSON
        let json = serde_json::to_string(&hash).expect("serialize");

        // Deserialize back
        let deserialized: ContentHash = serde_json::from_str(&json).expect("deserialize");

        // Should be equal
        prop_assert_eq!(&deserialized, &hash);

        // Hex representation should be deterministic
        prop_assert_eq!(&deserialized.to_hex(), &hash.to_hex());
        prop_assert_eq!(deserialized.to_hex().len(), 64); // 32 bytes = 64 hex chars
    }

    // ========================================================================
    // Determinism Properties
    // ========================================================================

    /// Property: Project ID derivation is deterministic
    #[test]
    fn prop_project_id_derivation_deterministic(
        replica_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let replica_id: [u8; 32] = replica_bytes.try_into().unwrap();

        // Derive ID multiple times
        let id1 = project_id_from_replica(&replica_id);
        let id2 = project_id_from_replica(&replica_id);
        let id3 = project_id_from_replica(&replica_id);

        // Should always be the same
        prop_assert_eq!(&id1, &id2);
        prop_assert_eq!(&id2, &id3);

        // Should be 32 hex chars (first 16 bytes of replica_id)
        prop_assert_eq!(id1.len(), 32);
        prop_assert_eq!(&id1, &hex::encode(&replica_id[..16]));
    }

    /// Property: Storage keys are deterministic
    #[test]
    fn prop_storage_keys_deterministic(
        id in "[a-zA-Z0-9-]+",
    ) {
        // Asset keys
        let asset_key1 = storage::asset_key(&id);
        let asset_key2 = storage::asset_key(&id);
        prop_assert_eq!(&asset_key1, &asset_key2);
        prop_assert_eq!(&asset_key1, &format!("/assets/{}", id));

        // Reference keys
        let ref_key1 = storage::reference_key(&id);
        let ref_key2 = storage::reference_key(&id);
        prop_assert_eq!(&ref_key1, &ref_key2);
        prop_assert_eq!(&ref_key1, &format!("/refs/{}", id));
    }

    /// Property: ContentHash hex encoding is deterministic
    #[test]
    fn prop_content_hash_encoding_deterministic(
        seed in any::<u8>(),
    ) {
        let hash = test_content_hash(seed);

        // Encode multiple times
        let hex1 = hash.to_hex();
        let hex2 = hash.to_hex();
        let hex3 = hash.to_hex();

        // Should always be the same
        prop_assert_eq!(&hex1, &hex2);
        prop_assert_eq!(&hex2, &hex3);

        // Should be lowercase hex
        prop_assert!(hex1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        prop_assert_eq!(hex1.len(), 64);
    }

    // ========================================================================
    // RFC Compliance
    // ========================================================================

    /// Property: Project ID matches RFC-004 spec (first 16 bytes of ReplicaId → hex)
    #[test]
    fn prop_project_id_rfc004_compliance(
        replica_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let replica_id: [u8; 32] = replica_bytes.try_into().unwrap();

        let project_id = project_id_from_replica(&replica_id);

        // RFC-004: Project ID is hex encoding of first 16 bytes
        let expected = hex::encode(&replica_id[..16]);
        prop_assert_eq!(&project_id, &expected);

        // Must be exactly 32 hex characters
        prop_assert_eq!(project_id.len(), 32);
        prop_assert!(project_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Property: Storage key format matches RFC-004 patterns
    #[test]
    fn prop_storage_key_rfc004_format(
        id in "[a-zA-Z0-9-]+",
    ) {
        // Asset keys match /assets/{id}
        let asset_key = storage::asset_key(&id);
        prop_assert!(asset_key.starts_with(storage::ASSETS_PREFIX));
        let expected_asset = format!("{}{}", storage::ASSETS_PREFIX, id);
        prop_assert_eq!(&asset_key, &expected_asset);

        // Reference keys match /refs/{id}
        let ref_key = storage::reference_key(&id);
        prop_assert!(ref_key.starts_with(storage::REFS_PREFIX));
        let expected_ref = format!("{}{}", storage::REFS_PREFIX, id);
        prop_assert_eq!(&ref_key, &expected_ref);

        // Parsing should be reversible
        match parse_key(&asset_key) {
            KeyType::Asset(parsed_id) => prop_assert_eq!(&parsed_id, &id),
            _ => prop_assert!(false, "Asset key should parse to Asset type"),
        }

        match parse_key(&ref_key) {
            KeyType::Reference(parsed_id) => prop_assert_eq!(&parsed_id, &id),
            _ => prop_assert!(false, "Reference key should parse to Reference type"),
        }
    }

    /// Property: SignedAsset verification ensures RFC-001 identity derivation
    /// (This property test verifies that the workflow maintains identity integrity)
    #[test]
    fn prop_signed_asset_identity_derivation(
        seed in any::<u8>(),
    ) {
        // Create a complete signed asset
        let asset_id = format!("test-{}", seed);
        let (asset, signed_asset, identity_id, _, nonce) =
            create_signed_asset_passkey_full(&asset_id);

        // Verification should succeed
        prop_assert!(signed_asset.verify().is_ok());

        // The asset's author_id should match the derived identity
        prop_assert_eq!(asset.author_id(), &identity_id);

        // The nonce should match
        prop_assert_eq!(signed_asset.nonce(), &nonce);

        // Identity ID should have RFC-001 prefix
        prop_assert!(identity_id.as_str().starts_with("obj_"));

        // Identity ID length should be in valid range (23-25 chars per RFC-001)
        let id_len = identity_id.as_str().len();
        prop_assert!(
            id_len >= 23 && id_len <= 25,
            "Identity ID length {} not in valid range [23, 25]",
            id_len
        );
    }
}
