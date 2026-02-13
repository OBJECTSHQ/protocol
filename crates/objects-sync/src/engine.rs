//! Unified sync engine coordinating blob and metadata operations.
//!
//! The [`SyncEngine`] is the main entry point for all sync operations in the OBJECTS Protocol.

use iroh::protocol::Router;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::mem::MemStore;
use iroh_docs::protocol::Docs;
use iroh_gossip::net::Gossip;
use objects_transport::{NodeAddr, ObjectsEndpoint};
use std::ops::Deref;

use crate::storage::{StorageConfig, blobs, docs};
use crate::{BlobClient, DocsClient, Result};

/// Unified sync engine for OBJECTS Protocol.
///
/// Coordinates blob sync (iroh-blobs) and metadata sync (iroh-docs).
/// Uses iroh's Router to handle incoming connections for blob and doc protocols.
#[derive(Clone)]
pub struct SyncEngine {
    blobs: BlobClient,
    docs: DocsClient,
    node_addr: NodeAddr,
    /// Router keeps protocol handlers alive for incoming connections.
    _router: Router,
}

impl SyncEngine {
    /// Creates a new sync engine with persistent storage.
    ///
    /// Uses FsStore for content-addressed blob storage and persistent Docs
    /// backend for metadata synchronization. Registers protocols on an iroh
    /// Router so this node can serve blob and doc requests from peers.
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

        // Capture node address before Router consumes the endpoint
        let node_addr = iroh_endpoint.addr();

        // Create blobs protocol handler for incoming connections
        let blobs_protocol = BlobsProtocol::new(&store, None);

        // Get blob API handles
        let blobs_client = store.blobs().clone();
        let store_api: iroh_blobs::api::Store = store.deref().clone();

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

        // Register protocols on router for incoming connections
        let router = Router::builder(iroh_endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs_protocol)
            .accept(iroh_docs::ALPN, docs_protocol.clone())
            .spawn();

        Ok(Self {
            blobs: BlobClient::new(blobs_client, store_api, router.endpoint().clone()),
            docs: DocsClient::new(docs_protocol),
            node_addr,
            _router: router,
        })
    }

    /// Creates a new sync engine with in-memory storage.
    ///
    /// Registers protocols on an iroh Router so this node can serve
    /// blob and doc requests from peers.
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub async fn new(endpoint: ObjectsEndpoint) -> Result<Self> {
        // Create in-memory blob store for v0.1
        let store = MemStore::new();

        // Get underlying Iroh endpoint
        let iroh_endpoint = endpoint.inner().clone();

        // Capture node address before Router consumes the endpoint
        let node_addr = endpoint.node_addr();

        // Create blobs protocol handler for incoming connections
        let blobs_protocol = BlobsProtocol::new(store.deref(), None);

        // Get blob API handles
        let blobs_client = store.blobs().clone();
        let store_api: iroh_blobs::api::Store = store.deref().clone();

        // Create gossip for docs protocol
        let gossip = Gossip::builder().spawn(iroh_endpoint.clone());

        // Spawn docs protocol with endpoint, blobs store, and gossip
        let docs_protocol = Docs::memory()
            .spawn(iroh_endpoint.clone(), store.deref().clone(), gossip)
            .await
            .map_err(crate::Error::Iroh)?;

        // Register protocols on router for incoming connections
        let router = Router::builder(iroh_endpoint)
            .accept(iroh_blobs::ALPN, blobs_protocol)
            .accept(iroh_docs::ALPN, docs_protocol.clone())
            .spawn();

        Ok(Self {
            blobs: BlobClient::new(blobs_client, store_api, router.endpoint().clone()),
            docs: DocsClient::new(docs_protocol),
            node_addr,
            _router: router,
        })
    }

    /// Returns this node's address for creating tickets.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
    }

    /// Returns the underlying iroh endpoint (via the Router).
    ///
    /// Useful for registering peer addresses for discovery.
    pub fn endpoint(&self) -> &iroh::Endpoint {
        self._router.endpoint()
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
        // Shutdown the router. This calls ProtocolHandler::shutdown() on all
        // registered protocols (including BlobsProtocol, which shuts down the
        // store) and closes the endpoint.
        self._router
            .shutdown()
            .await
            .map_err(|e| crate::Error::SyncFailed(format!("Router shutdown failed: {}", e)))?;

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
