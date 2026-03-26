//! Asset types for OBJECTS Protocol.

use objects_identity::{IdentityId, Signature, message::sign_asset_message};
use serde::{Deserialize, Serialize};

use crate::Error;

/// BLAKE3 hash wrapper (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl Serialize for ContentHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes for ContentHash"))?;
        Ok(ContentHash(arr))
    }
}

impl ContentHash {
    /// Creates a new ContentHash from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the hash as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// An asset representing a versioned unit of content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// Unique identifier within the project.
    id: String,
    /// Human-readable name.
    name: String,
    /// Identity ID of the asset creator (RFC-001).
    author_id: IdentityId,
    /// BLAKE3 hash of the content blob (32 bytes).
    content_hash: ContentHash,
    /// Size of the content blob in bytes.
    content_size: u64,
    /// MIME type or format identifier.
    format: Option<String>,
    /// Unix timestamp (seconds) when asset was created.
    created_at: u64,
    /// Unix timestamp (seconds) when asset was last updated.
    updated_at: u64,
}

impl Asset {
    /// Creates a new Asset with validated fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAsset`] if validation fails:
    /// - `id`: must be alphanumeric + hyphens, 1-64 characters
    /// - `name`: must be non-empty
    /// - `created_at <= updated_at`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        name: String,
        author_id: IdentityId,
        content_hash: ContentHash,
        content_size: u64,
        format: Option<String>,
        created_at: u64,
        updated_at: u64,
    ) -> Result<Self, Error> {
        let asset = Self {
            id,
            name,
            author_id,
            content_hash,
            content_size,
            format,
            created_at,
            updated_at,
        };
        asset.validate()?;
        Ok(asset)
    }

    /// Returns the asset ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the asset name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the author identity ID.
    pub fn author_id(&self) -> &IdentityId {
        &self.author_id
    }

    /// Returns the content hash.
    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    /// Returns the content size in bytes.
    pub fn content_size(&self) -> u64 {
        self.content_size
    }

    /// Returns the format/MIME type.
    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// Returns the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the last update timestamp.
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Validates the asset according to RFC-004 rules.
    ///
    /// Checks:
    /// - `id`: alphanumeric + hyphens, 1-64 characters
    /// - `name`: non-empty
    /// - `created_at <= updated_at`
    fn validate(&self) -> Result<(), Error> {
        // Validate id: alphanumeric + hyphens, 1-64 chars
        if self.id.is_empty() || self.id.len() > 64 {
            return Err(Error::InvalidAsset(
                "id must be 1-64 characters".to_string(),
            ));
        }
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(Error::InvalidAsset(
                "id must be alphanumeric with hyphens only".to_string(),
            ));
        }

        // Validate name is not empty
        if self.name.is_empty() {
            return Err(Error::InvalidAsset("name is required".to_string()));
        }

        // Validate timestamps
        if self.created_at > self.updated_at {
            return Err(Error::InvalidAsset(
                "created_at must not be greater than updated_at".to_string(),
            ));
        }

        Ok(())
    }
}

/// Nonce wrapper (8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(pub [u8; 8]);

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 8 bytes for Nonce"))?;
        Ok(Nonce(arr))
    }
}

/// A signed asset with authorship proof.
///
/// The nonce is required for author_id verification:
/// 1. Verify Ed25519 signature over message using public key
/// 2. Derive identity_id from signature.public_key + nonce
/// 3. Confirm derived ID matches asset.author_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAsset {
    /// The asset being signed.
    asset: Asset,
    /// Signature proving authorship.
    signature: Signature,
    /// Nonce used in author_id derivation (8 bytes).
    nonce: Nonce,
}

impl SignedAsset {
    /// Creates a new signed asset.
    pub fn new(asset: Asset, signature: Signature, nonce: [u8; 8]) -> Self {
        Self {
            asset,
            signature,
            nonce: Nonce(nonce),
        }
    }

    /// Returns a reference to the asset.
    pub fn asset(&self) -> &Asset {
        &self.asset
    }

    /// Returns a reference to the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the nonce used in identity derivation.
    pub fn nonce(&self) -> &[u8; 8] {
        &self.nonce.0
    }

    /// Verifies the signed asset.
    ///
    /// Verification steps:
    /// 1. Validate the asset fields
    /// 2. Construct the signature message using asset metadata
    /// 3. Verify Ed25519 signature over the message
    /// 4. Derive identity_id from signer public_key + nonce
    /// 5. Confirm derived ID matches asset.author_id
    pub fn verify(&self) -> Result<(), Error> {
        // 1. Validate the asset
        self.asset.validate()?;

        // 2. Construct the message (RFC-001 Section 5.3)
        let message = sign_asset_message(
            self.asset.author_id.as_str(),
            &self.asset.content_hash.to_hex(),
            self.asset.created_at,
        );

        // 3. Verify Ed25519 signature
        self.signature.verify(message.as_bytes())?;

        // 4. Get signer's public key (32 bytes Ed25519)
        let public_key: [u8; 32] = self
            .signature
            .public_key_bytes()
            .try_into()
            .map_err(|_| Error::InvalidAsset("public key must be 32 bytes".to_string()))?;

        // 5. Derive identity_id from public_key + nonce
        let derived_id = IdentityId::derive(&public_key, &self.nonce.0);

        // 6. Verify derived ID matches claimed author_id
        if derived_id.as_str() != self.asset.author_id.as_str() {
            return Err(Error::Identity(objects_identity::Error::AuthorIdMismatch {
                expected: self.asset.author_id.to_string(),
                actual: derived_id.to_string(),
            }));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_content_hash() -> ContentHash {
        ContentHash::new([0xab; 32])
    }

    fn test_author_id() -> IdentityId {
        // Derive from canonical test key + nonce (matches objects-test-utils)
        let public_key: [u8; 32] = [
            0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
            0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9,
            0x5c, 0x70, 0x9e, 0xe5,
        ];
        let nonce: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        IdentityId::derive(&public_key, &nonce)
    }

    fn valid_asset() -> Asset {
        Asset::new(
            "motor-mount-v1".to_string(),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        )
        .unwrap()
    }

    #[test]
    fn test_content_hash_to_hex() {
        let hash = ContentHash::new([0xab; 32]);
        assert_eq!(hash.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn test_asset_validate_valid() {
        let asset = valid_asset();
        // Constructor already validates, so if we got here it's valid
        assert_eq!(asset.id(), "motor-mount-v1");
    }

    #[test]
    fn test_asset_validate_empty_id() {
        let result = Asset::new(
            "".to_string(),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_asset_validate_id_too_long() {
        let result = Asset::new(
            "a".repeat(65),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_asset_validate_invalid_id_chars() {
        let result = Asset::new(
            "invalid@id".to_string(),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_asset_validate_id_with_hyphen() {
        let result = Asset::new(
            "motor-mount-v1".to_string(),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_asset_validate_empty_name() {
        let result = Asset::new(
            "motor-mount-v1".to_string(),
            "".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_asset_validate_timestamps() {
        let result = Asset::new(
            "motor-mount-v1".to_string(),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            200, // created_at
            100, // updated_at - created_at > updated_at
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_asset_validate_same_timestamps() {
        let result = Asset::new(
            "motor-mount-v1".to_string(),
            "Motor Mount".to_string(),
            test_author_id(),
            test_content_hash(),
            1024,
            Some("model/step".to_string()),
            100,
            100,
        );
        assert!(result.is_ok());
    }

    #[cfg(test)]
    mod signed_asset_tests {
        use super::*;
        use objects_identity::{Ed25519SigningKey, IdentityId, message::sign_asset_message};

        // Test helper: Sign asset with Ed25519
        fn sign_asset_ed25519(asset: &Asset, signing_key: &Ed25519SigningKey) -> Signature {
            let message = sign_asset_message(
                asset.author_id.as_str(),
                &asset.content_hash.to_hex(),
                asset.created_at,
            );
            signing_key.sign(message.as_bytes())
        }

        #[test]
        fn test_signed_asset_verify_with_ed25519() {
            let nonce = rand::random::<[u8; 8]>();
            let signing_key = Ed25519SigningKey::generate();
            let public_key = signing_key.public_key_bytes();
            let identity_id = IdentityId::derive(&public_key, &nonce);

            let asset = Asset::new(
                "test-asset".to_string(),
                "Test Asset".to_string(),
                identity_id,
                ContentHash::new([0xaa; 32]),
                1024,
                Some("png".to_string()),
                1000,
                1000,
            )
            .unwrap();

            let signature = sign_asset_ed25519(&asset, &signing_key);
            let signed_asset = SignedAsset::new(asset, signature, nonce);

            signed_asset.verify().unwrap();
        }

        #[test]
        fn test_signed_asset_verify_wrong_nonce() {
            let correct_nonce = rand::random::<[u8; 8]>();
            let signing_key = Ed25519SigningKey::generate();
            let public_key = signing_key.public_key_bytes();
            let identity_id = IdentityId::derive(&public_key, &correct_nonce);

            let asset = Asset::new(
                "nonce-test".to_string(),
                "Nonce Test".to_string(),
                identity_id,
                ContentHash::new([0xcc; 32]),
                512,
                Some("txt".to_string()),
                3000,
                3000,
            )
            .unwrap();

            let signature = sign_asset_ed25519(&asset, &signing_key);

            // Create SignedAsset with WRONG nonce
            let wrong_nonce = rand::random::<[u8; 8]>();
            let signed_asset = SignedAsset::new(asset, signature, wrong_nonce);

            // Should fail with author ID mismatch
            let result = signed_asset.verify();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("author ID mismatch")
            );
        }

        #[test]
        fn test_signed_asset_verify_tampered_content() {
            let nonce = rand::random::<[u8; 8]>();
            let signing_key = Ed25519SigningKey::generate();
            let public_key = signing_key.public_key_bytes();
            let identity_id = IdentityId::derive(&public_key, &nonce);

            let asset = Asset::new(
                "tamper-test".to_string(),
                "Original Name".to_string(),
                identity_id.clone(),
                ContentHash::new([0xdd; 32]),
                256,
                Some("pdf".to_string()),
                4000,
                4000,
            )
            .unwrap();

            let signature = sign_asset_ed25519(&asset, &signing_key);

            // TAMPER: Create asset with different content_hash
            let tampered_asset = Asset::new(
                "tamper-test".to_string(),
                "Original Name".to_string(),
                identity_id,
                ContentHash::new([0xee; 32]), // Different hash
                256,
                Some("pdf".to_string()),
                4000,
                4000,
            )
            .unwrap();

            let signed_asset = SignedAsset::new(tampered_asset, signature, nonce);

            // Should fail signature verification
            assert!(signed_asset.verify().is_err());
        }

        #[test]
        fn test_signed_asset_fields_are_private() {
            let asset = super::valid_asset();
            let signing_key = Ed25519SigningKey::generate();
            let signature = signing_key.sign(b"dummy");
            let nonce = [1u8; 8];

            let signed_asset = SignedAsset::new(asset.clone(), signature, nonce);

            // Accessors work
            assert_eq!(signed_asset.asset().id, asset.id);
            assert_eq!(signed_asset.signature().public_key_bytes().len(), 32);
            assert_eq!(signed_asset.nonce(), &nonce);
        }
    }
}
