//! Unified sync engine coordinating blob and metadata operations.
//!
//! The [`SyncEngine`] is the main entry point for all sync operations in the OBJECTS Protocol.

use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::mem::MemStore;
use iroh_docs::protocol::Docs;
use iroh_gossip::net::Gossip;
use objects_transport::ObjectsEndpoint;
use std::ops::Deref;
use std::sync::Arc;

use crate::storage::{StorageConfig, blobs, docs};
use crate::{BlobClient, DocsClient, Result};

/// Unified sync engine for OBJECTS Protocol.
///
/// Coordinates blob sync (iroh-blobs) and metadata sync (iroh-docs).
pub struct SyncEngine {
    blobs: BlobClient,
    docs: DocsClient,
    /// Optional persistent blob store (kept alive for shutdown)
    blob_store: Option<Arc<FsStore>>,
}

impl SyncEngine {
    /// Creates a new sync engine with persistent storage.
    ///
    /// Uses FsStore for content-addressed blob storage and persistent Docs
    /// backend for metadata synchronization.
    ///
    /// # Errors
    ///
    /// Returns error if storage initialization fails.
    pub async fn with_storage(
        iroh_endpoint: &iroh::Endpoint,
        storage_config: &StorageConfig,
    ) -> Result<Self> {
        // Ensure directories exist
        storage_config.ensure_directories()?;

        // Create persistent blob store
        let store = blobs::create_blob_store(storage_config.blobs_path()).await?;

        // Create Iroh blobs client from store
        let blobs_client = store.blobs().clone();

        // Create gossip for docs protocol
        let gossip = Gossip::builder().spawn(iroh_endpoint.clone());

        // Create persistent docs protocol
        let docs_protocol = docs::create_docs_store(
            storage_config.docs_path(),
            iroh_endpoint.clone(),
            &store,
            gossip,
        )
        .await?;

        Ok(Self {
            blobs: BlobClient::new(blobs_client),
            docs: DocsClient::new(docs_protocol),
            blob_store: Some(Arc::new(store)),
        })
    }

    /// Creates a new sync engine with in-memory storage.
    ///
    /// **Deprecated:** Use `with_storage()` for production.
    /// Kept for backward compatibility in tests only.
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    #[deprecated(note = "Use with_storage() for production")]
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
            blob_store: None,
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
        // Shutdown persistent blob store if present
        if let Some(store) = self.blob_store {
            // Try to get exclusive ownership
            if let Ok(store) = Arc::try_unwrap(store) {
                store.shutdown().await.map_err(|e| {
                    crate::Error::Storage(format!("Failed to shutdown blob store: {}", e))
                })?;
            }
            // If Arc has other references, just drop our reference
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageConfig;
    use objects_test_utils::transport;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_persistent_sync_engine_basic() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());
        let endpoint = transport::endpoint().await;

        // Should create engine with persistent storage
        let engine = SyncEngine::with_storage(endpoint.inner(), &config)
            .await
            .unwrap();

        // Should be able to access clients
        let _blobs = engine.blobs();
        let _docs = engine.docs();

        // Cleanup
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_persistent_sync_engine_blob_persistence() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        let hash;

        // Session 1: Create and add blob
        {
            let endpoint = transport::endpoint().await;
            let engine = SyncEngine::with_storage(endpoint.inner(), &config)
                .await
                .unwrap();

            // Add blob
            hash = engine
                .blobs()
                .add_bytes(&b"persistent test"[..])
                .await
                .unwrap();

            // Shutdown gracefully
            engine.shutdown().await.unwrap();
        }

        // Session 2: Reload and verify blob exists
        {
            let endpoint2 = transport::endpoint().await;
            let engine2 = SyncEngine::with_storage(endpoint2.inner(), &config)
                .await
                .unwrap();

            // Verify blob still exists
            let bytes = engine2.blobs().read_to_bytes(hash).await.unwrap();
            assert_eq!(&bytes[..], b"persistent test");

            engine2.shutdown().await.unwrap();
        }
    }
}
