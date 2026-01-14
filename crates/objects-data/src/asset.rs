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
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Identity ID of the asset creator (RFC-001).
    pub author_id: IdentityId,
    /// BLAKE3 hash of the content blob (32 bytes).
    pub content_hash: ContentHash,
    /// Size of the content blob in bytes.
    pub content_size: u64,
    /// MIME type or format identifier.
    pub format: Option<String>,
    /// Unix timestamp (seconds) when asset was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when asset was last updated.
    pub updated_at: u64,
}

impl Asset {
    /// Validates the asset according to RFC-004 rules.
    ///
    /// Checks:
    /// - `id`: alphanumeric + hyphens, 1-64 characters
    /// - `name`: non-empty
    /// - `created_at <= updated_at`
    pub fn validate(&self) -> Result<(), Error> {
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
    pub asset: Asset,
    /// Signature proving authorship.
    pub signature: Signature,
    /// Nonce used in author_id derivation (8 bytes).
    pub nonce: Nonce,
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

    /// Verifies the signed asset.
    ///
    /// Verification steps (per RFC-001 Appendix D):
    /// 1. Validate the asset fields
    /// 2. Construct the signature message using asset metadata
    /// 3. Verify signature over message using signer public key
    /// 4. Extract signer's public key (direct for passkey, recovered for wallet)
    /// 5. Derive identity_id from signature.public_key + nonce
    /// 6. Confirm derived ID matches asset.author_id
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
        match self.signature.signer_type {
            SignerType::Passkey => {
                // Passkey: public_key stored directly in signature
                let pk = self
                    .signature
                    .public_key
                    .as_ref()
                    .ok_or(Error::InvalidAsset(
                        "passkey signature requires public_key".to_string(),
                    ))?;
                pk.as_slice().try_into().map_err(|_| {
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
        if self.signature.signature.len() != 65 {
            return Err(Error::InvalidAsset(
                "wallet signature must be 65 bytes".to_string(),
            ));
        }
        let r_s = &self.signature.signature[..64];
        let v = self.signature.signature[64];

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
        Asset {
            id: "motor-mount-v1".to_string(),
            name: "Motor Mount".to_string(),
            author_id: test_author_id(),
            content_hash: test_content_hash(),
            content_size: 1024,
            format: Some("model/step".to_string()),
            created_at: 1704542400,
            updated_at: 1704542500,
        }
    }

    #[test]
    fn test_content_hash_to_hex() {
        let hash = ContentHash::new([0xab; 32]);
        assert_eq!(hash.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn test_asset_validate_valid() {
        let asset = valid_asset();
        assert!(asset.validate().is_ok());
    }

    #[test]
    fn test_asset_validate_empty_id() {
        let mut asset = valid_asset();
        asset.id = "".to_string();
        assert!(asset.validate().is_err());
    }

    #[test]
    fn test_asset_validate_id_too_long() {
        let mut asset = valid_asset();
        asset.id = "a".repeat(65);
        assert!(asset.validate().is_err());
    }

    #[test]
    fn test_asset_validate_invalid_id_chars() {
        let mut asset = valid_asset();
        asset.id = "invalid@id".to_string();
        assert!(asset.validate().is_err());
    }

    #[test]
    fn test_asset_validate_id_with_hyphen() {
        let mut asset = valid_asset();
        asset.id = "motor-mount-v1".to_string();
        assert!(asset.validate().is_ok());
    }

    #[test]
    fn test_asset_validate_empty_name() {
        let mut asset = valid_asset();
        asset.name = "".to_string();
        assert!(asset.validate().is_err());
    }

    #[test]
    fn test_asset_validate_timestamps() {
        let mut asset = valid_asset();
        asset.created_at = 200;
        asset.updated_at = 100; // created_at > updated_at
        assert!(asset.validate().is_err());
    }

    #[test]
    fn test_asset_validate_same_timestamps() {
        let mut asset = valid_asset();
        asset.created_at = 100;
        asset.updated_at = 100;
        assert!(asset.validate().is_ok());
    }
}
