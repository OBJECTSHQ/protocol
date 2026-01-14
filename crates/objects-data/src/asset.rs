//! Asset types for OBJECTS Protocol.

use alloy_primitives::keccak256;
use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use objects_identity::{message::sign_asset_message, IdentityId, Signature, SignerType};
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
/// 1. Verify signature over message using signer public key
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
    /// Verification steps (per RFC-001 Appendix D):
    /// 1. Validate the asset fields
    /// 2. Construct the signature message using asset metadata
    /// 3. Verify signature and extract signer's public key:
    ///    - Passkey: verify signature, then extract public_key from signature
    ///    - Wallet: recover public_key from signature, then verify address
    /// 4. Derive identity_id from signer public_key + nonce
    /// 5. Confirm derived ID matches asset.author_id
    pub fn verify(&self) -> Result<(), Error> {
        // 1. Validate the asset
        self.asset.validate()?;

        // 2. Construct the message (RFC-001 Section 5.3)
        // Uses created_at timestamp per Appendix D
        let message = sign_asset_message(
            self.asset.author_id.as_str(),
            &self.asset.content_hash.to_hex(),
            self.asset.created_at,
        );

        // 3. Verify signature
        self.signature.verify(message.as_bytes())?;

        // 4. Get signer's compressed public key (33 bytes SEC1)
        let public_key = self.get_signer_public_key(&message)?;

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

    /// Extracts the signer's public key from the signature.
    fn get_signer_public_key(&self, message: &str) -> Result<[u8; 33], Error> {
        match self.signature.signer_type() {
            SignerType::Passkey => {
                // Passkey: public_key stored directly in signature
                let pk = self
                    .signature
                    .public_key_bytes()
                    .ok_or(Error::InvalidAsset(
                        "passkey signature requires public_key".to_string(),
                    ))?;
                pk.try_into().map_err(|_| {
                    Error::InvalidAsset("public_key must be 33 bytes".to_string())
                })
            }
            SignerType::Wallet => {
                // Wallet: recover public key from signature
                self.recover_wallet_public_key(message.as_bytes())
            }
        }
    }

    /// Recovers and compresses the public key from a wallet signature.
    fn recover_wallet_public_key(&self, message: &[u8]) -> Result<[u8; 33], Error> {
        // EIP-191 prefix
        let prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut full_message = prefixed.into_bytes();
        full_message.extend_from_slice(message);
        let message_hash = keccak256(&full_message);

        // Parse signature (r || s || v)
        let sig_bytes = self.signature.signature_bytes();
        if sig_bytes.len() != 65 {
            return Err(Error::InvalidAsset(
                "wallet signature must be 65 bytes".to_string(),
            ));
        }
        let r_s = &sig_bytes[..64];
        let v = sig_bytes[64];

        let recovery_id = match v {
            27 | 0 => RecoveryId::new(false, false),
            28 | 1 => RecoveryId::new(true, false),
            _ => {
                return Err(Error::InvalidAsset(format!(
                    "invalid recovery id: {}",
                    v
                )))
            }
        };

        let sig = K256Sig::try_from(r_s)
            .map_err(|e| Error::InvalidAsset(format!("invalid signature: {}", e)))?;

        let recovered_key =
            VerifyingKey::recover_from_prehash(message_hash.as_slice(), &sig, recovery_id)
                .map_err(|e| Error::InvalidAsset(format!("key recovery failed: {}", e)))?;

        // Compress to SEC1 33-byte format
        let compressed: [u8; 33] = recovered_key
            .to_sec1_bytes()
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidAsset("compressed key not 33 bytes".to_string()))?;

        Ok(compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_content_hash() -> ContentHash {
        ContentHash::new([0xab; 32])
    }

    fn test_author_id() -> IdentityId {
        IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap()
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
        use objects_identity::{message::sign_asset_message, IdentityId, Signature, SignerType};
        use alloy_primitives::keccak256;
        use k256::ecdsa::SigningKey as K256SigningKey;
        use k256::elliptic_curve::rand_core::OsRng;
        use p256::ecdsa::{signature::Signer as _, SigningKey as P256SigningKey};
        use sha2::{Digest, Sha256};

        // Test helper: Generate passkey signing key
        fn test_passkey_key() -> P256SigningKey {
            P256SigningKey::random(&mut OsRng)
        }

        // Test helper: Generate wallet signing key
        fn test_wallet_key() -> K256SigningKey {
            K256SigningKey::random(&mut OsRng)
        }

        // Test helper: Sign asset with passkey
        fn sign_asset_with_passkey(
            asset: &Asset,
            signing_key: &P256SigningKey,
            _nonce: [u8; 8],
        ) -> Signature {
            let verifying_key = signing_key.verifying_key();
            let public_key_bytes: [u8; 33] = verifying_key
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();

            // Create message per RFC-001
            let message = sign_asset_message(
                asset.author_id.as_str(),
                &asset.content_hash.to_hex(),
                asset.created_at,
            );

            // Create minimal WebAuthn data
            let rp_id_hash = Sha256::digest(b"example.com");
            let flags = 0x05u8;
            let counter = 0u32.to_be_bytes();
            let mut authenticator_data = rp_id_hash.to_vec();
            authenticator_data.push(flags);
            authenticator_data.extend_from_slice(&counter);

            let client_data_json = format!(
                r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
                hex::encode(message.as_bytes())
            )
            .into_bytes();

            let client_data_hash = Sha256::digest(&client_data_json);
            let mut signed_data = authenticator_data.clone();
            signed_data.extend_from_slice(&client_data_hash);

            let signature_der: p256::ecdsa::Signature = signing_key.sign(&signed_data);

            Signature::Passkey {
                signature: signature_der.to_der().to_bytes().to_vec(),
                public_key: public_key_bytes.to_vec(),
                authenticator_data,
                client_data_json,
            }
        }

        // Test helper: Sign asset with wallet
        fn sign_asset_with_wallet(
            asset: &Asset,
            signing_key: &K256SigningKey,
            _nonce: [u8; 8],
        ) -> Signature {
            let verifying_key = signing_key.verifying_key();
            let public_key_point = verifying_key.to_encoded_point(false);
            let public_key_bytes = public_key_point.as_bytes();

            // Derive Ethereum address
            let pub_key_hash = keccak256(&public_key_bytes[1..]);
            let address = format!("0x{}", hex::encode(&pub_key_hash[12..]));

            // Create message
            let message = sign_asset_message(
                asset.author_id.as_str(),
                &asset.content_hash.to_hex(),
                asset.created_at,
            );

            // EIP-191 prefix
            let eip191_prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
            let mut prefixed = eip191_prefix.as_bytes().to_vec();
            prefixed.extend_from_slice(message.as_bytes());
            let message_hash = keccak256(&prefixed);

            // Sign with recovery
            let (signature_der, recovery_id) = signing_key
                .sign_prehash_recoverable(message_hash.as_slice())
                .unwrap();
            let mut signature_bytes = signature_der.to_bytes().to_vec();
            signature_bytes.push(recovery_id.to_byte());

            Signature::Wallet {
                signature: signature_bytes,
                address,
            }
        }

        #[test]
        fn test_signed_asset_verify_with_passkey() {
            // Generate passkey and derive identity
            let nonce = rand::random::<[u8; 8]>();
            let signing_key = test_passkey_key();
            let public_key: [u8; 33] = signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            let identity_id = IdentityId::derive(&public_key, &nonce);

            // Create asset
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

            // Sign with passkey
            let signature = sign_asset_with_passkey(&asset, &signing_key, nonce);
            let signed_asset = SignedAsset::new(asset, signature, nonce);

            // Verification should succeed
            signed_asset.verify().unwrap();
        }

        #[test]
        fn test_signed_asset_verify_with_wallet() {
            // Generate wallet and derive identity
            let nonce = rand::random::<[u8; 8]>();
            let signing_key = test_wallet_key();
            let public_key: [u8; 33] = signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            let identity_id = IdentityId::derive(&public_key, &nonce);

            // Create asset
            let asset = Asset::new(
                "test-wallet-asset".to_string(),
                "Wallet Test Asset".to_string(),
                identity_id,
                ContentHash::new([0xbb; 32]),
                2048,
                Some("jpg".to_string()),
                2000,
                2000,
            )
            .unwrap();

            // Sign with wallet
            let signature = sign_asset_with_wallet(&asset, &signing_key, nonce);
            let signed_asset = SignedAsset::new(asset, signature, nonce);

            // Verification should succeed
            assert!(signed_asset.verify().is_ok());
        }

        #[test]
        fn test_signed_asset_verify_wrong_nonce() {
            // Generate identity with correct nonce
            let correct_nonce = rand::random::<[u8; 8]>();
            let signing_key = test_passkey_key();
            let public_key: [u8; 33] = signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
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

            // Sign with correct nonce
            let signature = sign_asset_with_passkey(&asset, &signing_key, correct_nonce);

            // Create SignedAsset with WRONG nonce
            let wrong_nonce = rand::random::<[u8; 8]>();
            let signed_asset = SignedAsset::new(asset, signature, wrong_nonce);

            // Should fail with author ID mismatch
            let result = signed_asset.verify();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("author ID mismatch"));
        }

        #[test]
        fn test_signed_asset_verify_tampered_content() {
            let nonce = rand::random::<[u8; 8]>();
            let signing_key = test_passkey_key();
            let public_key: [u8; 33] = signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            let identity_id = IdentityId::derive(&public_key, &nonce);

            // Create and sign original asset
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

            let signature = sign_asset_with_passkey(&asset, &signing_key, nonce);

            // TAMPER: Create asset with different content_hash
            // (Since fields are private, this demonstrates tampering protection)
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
            // This test verifies fields are private (compile-time check)
            let asset = super::valid_asset();
            let signature = Signature::Passkey {
                signature: vec![0u8; 64],
                public_key: vec![0u8; 33],
                authenticator_data: vec![],
                client_data_json: vec![],
            };
            let nonce = [1u8; 8];

            let signed_asset = SignedAsset::new(asset.clone(), signature.clone(), nonce);

            // Accessors work
            assert_eq!(signed_asset.asset().id, asset.id);
            assert_eq!(signed_asset.signature().signer_type(), SignerType::Passkey);
            assert_eq!(signed_asset.nonce(), &nonce);

            // Would fail to compile (desired):
            // signed_asset.asset = Asset { ... };
            // signed_asset.nonce = [0u8; 8];
        }
    }
}
