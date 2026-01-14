//! Asset types for OBJECTS Protocol.

use objects_identity::{IdentityId, Signature};
use serde::{Deserialize, Serialize};

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

    // TODO: Implement verify() method
    // 1. Verify signature over message
    // 2. Derive identity_id from signature.public_key + nonce
    // 3. Confirm derived ID matches asset.author_id
}
