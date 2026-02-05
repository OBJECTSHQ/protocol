//! Metadata sync operations using iroh-docs.
//!
//! This module provides replica-based metadata synchronization with set reconciliation.
//! Entries are signed and verified using Ed25519 signatures.
//!
//! # Example
//!
//! ```rust,no_run
//! use objects_sync::SyncEngine;
//! use objects_transport::ObjectsEndpoint;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let endpoint = ObjectsEndpoint::builder().bind().await?;
//! let sync = SyncEngine::new(endpoint).await?;
//!
//! // Create replica and author
//! let replica_id = sync.docs().create_replica().await?;
//! let author = sync.docs().create_author().await?;
//!
//! // Set entry
//! sync.docs().set_bytes(replica_id, author, "/project", &b"metadata"[..]).await?;
//!
//! // Query entries
//! let entries = sync.docs().query_prefix(replica_id, "/").await?;
//! println!("Found {} entries", entries.len());
//! # Ok(())
//! # }
//! ```

use bytes::Bytes;
use futures::StreamExt;
use iroh_docs::{AuthorId, Capability, DocTicket, Entry, NamespaceId, protocol::Docs};

use crate::{Error, Result};

/// Client for metadata sync operations.
///
/// Wraps iroh-docs with OBJECTS-specific entry conventions.
/// Entries are signed with Ed25519 and synced via set reconciliation.
#[derive(Clone)]
pub struct DocsClient {
    inner: Docs,
}

impl DocsClient {
    /// Creates a new docs client.
    ///
    /// This is typically called by [`SyncEngine`](crate::SyncEngine), not directly.
    pub(crate) fn new(inner: Docs) -> Self {
        Self { inner }
    }

    /// Creates a new replica with a random namespace ID.
    ///
    /// Returns the namespace ID which serves as the replica ID.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// let replica_id = sync.docs().create_replica().await?;
    /// println!("Created replica: {}", replica_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_replica(&self) -> Result<NamespaceId> {
        let doc = self.inner.create().await.map_err(Error::Iroh)?;
        Ok(doc.id())
    }

    /// Creates a new author for signing entries.
    ///
    /// Each author has a unique Ed25519 key pair.
    /// The author ID is visible in all entries they create.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// let author = sync.docs().create_author().await?;
    /// println!("Created author: {}", author);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_author(&self) -> Result<iroh_docs::AuthorId> {
        let author_id = self.inner.author_create().await.map_err(Error::Iroh)?;
        Ok(author_id)
    }

    /// Sets an entry in a replica.
    ///
    /// Creates or updates the entry at `key` with `value`.
    /// The entry is signed by `author`.
    ///
    /// # OBJECTS Conventions
    ///
    /// Keys should follow RFC-004 patterns:
    /// - `/project` for project metadata
    /// - `/assets/{id}` for asset records
    /// - `/refs/{id}` for reference records
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// # let author = sync.docs().create_author().await?;
    /// sync.docs()
    ///     .set_bytes(replica_id, author, "/project", &b"metadata"[..])
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_bytes(
        &self,
        replica_id: NamespaceId,
        author: AuthorId,
        key: impl AsRef<str>,
        value: impl Into<Bytes>,
    ) -> Result<iroh_blobs::Hash> {
        let key_bytes = key.as_ref().as_bytes().to_vec();
        let value_bytes = value.into();

        let doc = self
            .inner
            .open(replica_id)
            .await
            .map_err(Error::Iroh)?
            .ok_or_else(|| Error::ReplicaNotFound(replica_id.to_string()))?;

        let hash = doc
            .set_bytes(author, key_bytes, value_bytes)
            .await
            .map_err(Error::Iroh)?;

        Ok(hash)
    }

    /// Gets the latest entry for a key.
    ///
    /// Returns `None` if no entry exists.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// # let author = sync.docs().create_author().await?;
    /// # sync.docs().set_bytes(replica_id, author, "/project", &b"test"[..]).await?;
    /// if let Some(entry) = sync.docs().get_latest(replica_id, "/project").await? {
    ///     let content_hash = sync.docs().entry_content_hash(&entry);
    ///     let content = sync.blobs().read_to_bytes(content_hash).await?;
    ///     println!("Entry content: {:?}", content);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_latest(
        &self,
        replica_id: NamespaceId,
        key: impl AsRef<str>,
    ) -> Result<Option<Entry>> {
        let key_bytes = key.as_ref().as_bytes().to_vec();

        let doc = self
            .inner
            .open(replica_id)
            .await
            .map_err(Error::Iroh)?
            .ok_or_else(|| Error::ReplicaNotFound(replica_id.to_string()))?;

        let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key_bytes);

        let stream = doc.get_many(query).await.map_err(Error::Iroh)?;

        // Pin the stream so we can call .next() on it
        futures::pin_mut!(stream);

        let entry = stream.next().await;
        match entry {
            Some(Ok(e)) => Ok(Some(e)),
            Some(Err(e)) => Err(Error::Iroh(e)),
            None => Ok(None),
        }
    }

    /// Gets the content hash for an entry.
    ///
    /// In iroh-docs, entries don't contain content directly - they reference
    /// blob storage via a content hash. Use this hash with `BlobClient::read_to_bytes()`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// # let author = sync.docs().create_author().await?;
    /// # sync.docs().set_bytes(replica_id, author, "/project", &b"test"[..]).await?;
    /// let entry = sync.docs().get_latest(replica_id, "/project").await?.unwrap();
    /// let content_hash = sync.docs().entry_content_hash(&entry);
    /// let bytes = sync.blobs().read_to_bytes(content_hash).await?;
    /// println!("Content: {:?}", bytes);
    /// # Ok(())
    /// # }
    /// ```
    pub fn entry_content_hash(&self, entry: &Entry) -> iroh_blobs::Hash {
        entry.content_hash()
    }

    /// Queries entries in a replica by key prefix.
    ///
    /// Returns entries matching the query criteria.
    ///
    /// # Example - Get all assets
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// let entries = sync.docs().query_prefix(replica_id, "/assets/").await?;
    /// for entry in entries {
    ///     println!("Asset: {}", String::from_utf8_lossy(entry.key()));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_prefix(
        &self,
        replica_id: NamespaceId,
        prefix: impl AsRef<str>,
    ) -> Result<Vec<Entry>> {
        let prefix_bytes = prefix.as_ref().as_bytes().to_vec();

        let doc = self
            .inner
            .open(replica_id)
            .await
            .map_err(Error::Iroh)?
            .ok_or_else(|| Error::ReplicaNotFound(replica_id.to_string()))?;

        let query = iroh_docs::store::Query::key_prefix(prefix_bytes);
        let stream = doc.get_many(query).await.map_err(Error::Iroh)?;

        // Pin the stream so we can call .next() on it
        futures::pin_mut!(stream);

        let mut entries = Vec::new();
        while let Some(entry_result) = stream.next().await {
            let entry = entry_result.map_err(Error::Iroh)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Syncs a replica with a peer.
    ///
    /// Initiates set reconciliation to exchange missing entries.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let peer_addr = endpoint.node_addr(); // In reality, this would be a remote peer
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// sync.docs().sync_with_peer(replica_id, peer_addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sync_with_peer(
        &self,
        replica_id: NamespaceId,
        peer: objects_transport::NodeAddr,
    ) -> Result<()> {
        let doc = self
            .inner
            .open(replica_id)
            .await
            .map_err(Error::Iroh)?
            .ok_or_else(|| Error::ReplicaNotFound(replica_id.to_string()))?;

        doc.start_sync(vec![peer])
            .await
            .map_err(|e| Error::SyncFailed(e.to_string()))?;

        Ok(())
    }

    /// Downloads a replica from a doc ticket.
    ///
    /// Fetches all entries from peers specified in the ticket.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # use iroh_docs::DocTicket;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// let ticket: DocTicket = "docaaaa...".parse()?;
    /// let replica_id = sync.docs().download_from_ticket(ticket).await?;
    /// println!("Downloaded replica: {}", replica_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_from_ticket(&self, ticket: DocTicket) -> Result<NamespaceId> {
        let doc = self
            .inner
            .import(ticket)
            .await
            .map_err(|e| Error::SyncFailed(e.to_string()))?;

        Ok(doc.id())
    }

    /// Creates a read-only doc ticket for sharing.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let node_addr = endpoint.node_addr();
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// let ticket = sync.docs()
    ///     .create_ticket(replica_id, node_addr)
    ///     .await?;
    /// println!("Share this: {}", ticket);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_ticket(
        &self,
        replica_id: NamespaceId,
        node_addr: objects_transport::NodeAddr,
    ) -> Result<DocTicket> {
        let ticket = DocTicket {
            capability: Capability::Read(replica_id),
            nodes: vec![node_addr],
        };

        Ok(ticket)
    }

    /// Lists all replicas managed by this client.
    ///
    /// Returns a list of namespace IDs for all replicas.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// let replicas = sync.docs().list_replicas().await?;
    /// println!("Found {} replicas", replicas.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_replicas(&self) -> Result<Vec<NamespaceId>> {
        let stream = self.inner.list().await.map_err(Error::Iroh)?;

        futures::pin_mut!(stream);

        let mut replicas = Vec::new();
        while let Some(result) = stream.next().await {
            let (namespace_id, _capability) = result.map_err(Error::Iroh)?;
            replicas.push(namespace_id);
        }

        Ok(replicas)
    }

    /// Deletes a replica and all its entries.
    ///
    /// # Warning
    ///
    /// This permanently removes all data. Use with caution.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use objects_sync::SyncEngine;
    /// # use objects_transport::ObjectsEndpoint;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let endpoint = ObjectsEndpoint::builder().bind().await?;
    /// # let sync = SyncEngine::new(endpoint).await?;
    /// # let replica_id = sync.docs().create_replica().await?;
    /// sync.docs().delete_replica(replica_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_replica(&self, replica_id: NamespaceId) -> Result<()> {
        self.inner.drop_doc(replica_id).await.map_err(Error::Iroh)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Note: Full integration tests are in tests/integration_tests.rs
    // These are basic unit tests for the API surface
}
