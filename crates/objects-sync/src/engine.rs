//! Unified sync engine coordinating blob and metadata operations.
//!
//! The [`SyncEngine`] is the main entry point for all sync operations in the OBJECTS Protocol.

use iroh_blobs::store::mem::MemStore;
use iroh_docs::protocol::Docs;
use iroh_gossip::net::Gossip;
use objects_transport::ObjectsEndpoint;
use std::ops::Deref;

use crate::{BlobClient, DocsClient, Result};

/// Unified sync engine for OBJECTS Protocol.
///
/// Coordinates blob sync (iroh-blobs) and metadata sync (iroh-docs).
pub struct SyncEngine {
    blobs: BlobClient,
    docs: DocsClient,
}

impl SyncEngine {
    /// Creates a new sync engine from an OBJECTS endpoint.
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub async fn new(endpoint: ObjectsEndpoint) -> Result<Self> {
        // Create in-memory blob store for v0.1
        let store = MemStore::new();

        // Get underlying Iroh endpoint
        let iroh_endpoint = endpoint.inner().clone();

        // Create Iroh blobs client from store
        let blobs_client = store.blobs().clone();

        // Create gossip for docs protocol
        let gossip = Gossip::builder().spawn(iroh_endpoint.clone());

        // Spawn docs protocol with endpoint, blobs store, and gossip
        let docs_protocol = Docs::memory()
            .spawn(iroh_endpoint, store.deref().clone(), gossip)
            .await
            .map_err(crate::Error::Iroh)?;

        Ok(Self {
            blobs: BlobClient::new(blobs_client),
            docs: DocsClient::new(docs_protocol),
        })
    }

    /// Returns a reference to the blob client.
    pub fn blobs(&self) -> &BlobClient {
        &self.blobs
    }

    /// Returns a reference to the docs client.
    pub fn docs(&self) -> &DocsClient {
        &self.docs
    }

    /// Gracefully shutdown the sync engine.
    pub async fn shutdown(self) -> Result<()> {
        Ok(())
    }
}
