//! OBJECTS Protocol integration helpers.
//!
//! Bridges between Sync layer (iroh-blobs/iroh-docs) and OBJECTS types.

use bytes::Bytes;
use iroh_blobs::Hash;
use iroh_docs::{AuthorId, NamespaceId};
use objects_data::storage::{PROJECT_KEY, asset_key};
use objects_data::{Asset, ContentHash, Project};

use crate::{BlobClient, DocsClient, Error, Result};

/// Converts iroh-blobs Hash to OBJECTS ContentHash.
///
/// Both are 32-byte BLAKE3 hashes, but different types.
///
/// # Example
///
/// ```rust,no_run
/// # use objects_sync::helpers::hash_to_content_hash;
/// # use iroh_blobs::Hash;
/// let iroh_hash = Hash::from_bytes([0u8; 32]);
/// let content_hash = hash_to_content_hash(iroh_hash);
/// ```
pub fn hash_to_content_hash(hash: Hash) -> ContentHash {
    let bytes = hash.as_bytes();
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    ContentHash(array)
}

/// Converts OBJECTS ContentHash to iroh-blobs Hash.
///
/// Both are 32-byte BLAKE3 hashes, but different types.
///
/// # Example
///
/// ```rust,no_run
/// # use objects_sync::helpers::content_hash_to_hash;
/// # use objects_data::ContentHash;
/// let content_hash = ContentHash([0u8; 32]);
/// let iroh_hash = content_hash_to_hash(&content_hash);
/// ```
pub fn content_hash_to_hash(content_hash: &ContentHash) -> Hash {
    Hash::from_bytes(content_hash.0)
}

/// Helper methods for working with OBJECTS Asset types.
impl BlobClient {
    /// Stores an Asset's content and returns the hash.
    ///
    /// The hash is verified to match Asset.content_hash.
    ///
    /// # Errors
    ///
    /// Returns `Error::VerificationFailed` if content hash doesn't match.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # use objects_data::Asset;
    /// # async fn example(asset: Asset) -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// let content = std::fs::read("model.step")?;
    /// let hash = sync.blobs().store_asset_content(&asset, content).await?;
    /// println!("Stored with hash: {}", hash);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn store_asset_content(
        &self,
        asset: &Asset,
        content: impl Into<Bytes>,
    ) -> Result<Hash> {
        let hash = self.add_bytes(content).await?;

        // Verify hash matches asset's content_hash
        let expected = content_hash_to_hash(asset.content_hash());
        if hash != expected {
            return Err(Error::VerificationFailed(format!(
                "content hash mismatch: expected {}, got {}",
                expected, hash
            )));
        }

        Ok(hash)
    }
}

/// Helper methods for working with OBJECTS Project types.
impl DocsClient {
    /// Stores an Asset in a project replica.
    ///
    /// Uses RFC-004 key convention: `/assets/{id}`
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # use objects_data::Asset;
    /// # use iroh_docs::NamespaceId;
    /// # async fn example(replica_id: NamespaceId, asset: Asset) -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let author = sync.docs().create_author().await?;
    /// let hash = sync.docs().store_asset(replica_id, author, &asset).await?;
    /// println!("Stored asset with entry hash: {}", hash);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn store_asset(
        &self,
        replica_id: NamespaceId,
        author: AuthorId,
        asset: &Asset,
    ) -> Result<Hash> {
        let key = asset_key(asset.id());
        let asset_bytes = serde_json::to_vec(asset).map_err(|e| Error::Iroh(anyhow::anyhow!(e)))?;

        self.set_bytes(replica_id, author, key, asset_bytes).await
    }

    /// Retrieves an Asset from a project replica.
    ///
    /// Requires a BlobClient to read the entry content.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # use iroh_docs::NamespaceId;
    /// # async fn example(replica_id: NamespaceId) -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// if let Some(asset) = sync.docs().get_asset(sync.blobs(), replica_id, "motor-mount").await? {
    ///     println!("Found asset: {}", asset.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_asset(
        &self,
        blobs: &BlobClient,
        replica_id: NamespaceId,
        asset_id: &str,
    ) -> Result<Option<Asset>> {
        let key = asset_key(asset_id);

        let Some(entry) = self.get_latest(replica_id, key).await? else {
            return Ok(None);
        };

        let content_hash = self.entry_content_hash(&entry);
        let bytes = blobs.read_to_bytes(content_hash).await?;
        let asset = serde_json::from_slice(&bytes).map_err(|e| Error::Iroh(anyhow::anyhow!(e)))?;

        Ok(Some(asset))
    }

    /// Stores a Project in its replica.
    ///
    /// Uses RFC-004 key convention: `/project`
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # use objects_data::Project;
    /// # use iroh_docs::NamespaceId;
    /// # async fn example(replica_id: NamespaceId, project: Project) -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let author = sync.docs().create_author().await?;
    /// let hash = sync.docs().store_project(replica_id, author, &project).await?;
    /// println!("Stored project with entry hash: {}", hash);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn store_project(
        &self,
        replica_id: NamespaceId,
        author: AuthorId,
        project: &Project,
    ) -> Result<Hash> {
        let project_bytes =
            serde_json::to_vec(project).map_err(|e| Error::Iroh(anyhow::anyhow!(e)))?;

        self.set_bytes(replica_id, author, PROJECT_KEY, project_bytes)
            .await
    }

    /// Retrieves a Project from its replica.
    ///
    /// Requires a BlobClient to read the entry content.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # use iroh_docs::NamespaceId;
    /// # async fn example(replica_id: NamespaceId) -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// if let Some(project) = sync.docs().get_project(sync.blobs(), replica_id).await? {
    ///     println!("Found project: {}", project.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_project(
        &self,
        blobs: &BlobClient,
        replica_id: NamespaceId,
    ) -> Result<Option<Project>> {
        let Some(entry) = self.get_latest(replica_id, PROJECT_KEY).await? else {
            return Ok(None);
        };

        let content_hash = self.entry_content_hash(&entry);
        let bytes = blobs.read_to_bytes(content_hash).await?;
        let project =
            serde_json::from_slice(&bytes).map_err(|e| Error::Iroh(anyhow::anyhow!(e)))?;

        Ok(Some(project))
    }
}
