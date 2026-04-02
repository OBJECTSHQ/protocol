//! Unified sync engine coordinating blob and metadata operations.
//!
//! The [`SyncEngine`] is the main entry point for all sync operations in the OBJECTS Protocol.

use iroh::protocol::{Router, RouterBuilder};
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
    default_author: iroh_docs::AuthorId,
    node_addr: NodeAddr,
    /// Router keeps protocol handlers alive for incoming connections.
    _router: Router,
}

/// Pre-spawn state of a sync engine.
///
/// Returned by [`SyncEngine::with_storage`] and [`SyncEngine::in_memory`].
///
/// - Call [`.spawn()`](Self::spawn) when no extra protocols are needed.
/// - Call [`.into_router_builder()`](Self::into_router_builder) to register
///   additional protocols (e.g. irpc) before spawning, then pass the Router
///   back via [`SyncEngine::from_router`].
pub struct SyncEngineBuilder {
    blobs: BlobClient,
    docs: DocsClient,
    default_author: iroh_docs::AuthorId,
    node_addr: NodeAddr,
    router_builder: RouterBuilder,
}

impl SyncEngineBuilder {
    /// Spawn the Router and finalize the SyncEngine.
    ///
    /// Use this when no additional protocols need to be registered.
    pub fn spawn(self) -> SyncEngine {
        let router = self.router_builder.spawn();
        SyncEngine {
            blobs: self.blobs,
            docs: self.docs,
            default_author: self.default_author,
            node_addr: self.node_addr,
            _router: router,
        }
    }

    /// Consume the builder, returning the `RouterBuilder` and a finalizer.
    ///
    /// Add extra protocols to the `RouterBuilder`, spawn it, then pass
    /// the `Router` to the returned [`SyncEngineFinalizer::finalize`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (finalizer, router_builder) = SyncEngine::with_storage(ep, &cfg)
    ///     .await?
    ///     .into_router_builder();
    /// let router = router_builder
    ///     .accept(MY_ALPN, my_handler)
    ///     .spawn();
    /// let engine = finalizer.finalize(router);
    /// ```
    pub fn into_router_builder(self) -> (SyncEngineFinalizer, RouterBuilder) {
        (
            SyncEngineFinalizer {
                blobs: self.blobs,
                docs: self.docs,
                default_author: self.default_author,
                node_addr: self.node_addr,
            },
            self.router_builder,
        )
    }
}

/// Holds sync engine state while the caller builds and spawns the Router.
///
/// Obtained from [`SyncEngineBuilder::into_router_builder`].
pub struct SyncEngineFinalizer {
    blobs: BlobClient,
    docs: DocsClient,
    default_author: iroh_docs::AuthorId,
    node_addr: NodeAddr,
}

impl SyncEngineFinalizer {
    /// Finalize the SyncEngine with a spawned Router.
    pub fn finalize(self, router: Router) -> SyncEngine {
        SyncEngine {
            blobs: self.blobs,
            docs: self.docs,
            default_author: self.default_author,
            node_addr: self.node_addr,
            _router: router,
        }
    }
}

impl SyncEngine {
    /// Creates a new sync engine builder with persistent storage.
    ///
    /// Returns a [`SyncEngineBuilder`] with blobs and docs protocols
    /// pre-registered on the Router.
    ///
    /// # Errors
    ///
    /// Returns error if storage initialization fails.
    pub async fn with_storage(
        iroh_endpoint: &iroh::Endpoint,
        storage_config: &StorageConfig,
    ) -> Result<SyncEngineBuilder> {
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

        // Build router with blobs + docs (caller may add more before spawning)
        let router_builder = Router::builder(iroh_endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs_protocol)
            .accept(iroh_docs::ALPN, docs_protocol.clone());

        let docs = DocsClient::new(docs_protocol);
        let default_author = docs.create_author().await?;

        Ok(SyncEngineBuilder {
            blobs: BlobClient::new(blobs_client, store_api, iroh_endpoint.clone()),
            docs,
            default_author,
            node_addr,
            router_builder,
        })
    }

    /// Creates a new sync engine builder with in-memory storage.
    ///
    /// Returns a [`SyncEngineBuilder`] with blobs and docs protocols
    /// pre-registered on the Router.
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub async fn in_memory(endpoint: ObjectsEndpoint) -> Result<SyncEngineBuilder> {
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

        // Build router with blobs + docs (caller may add more before spawning)
        let router_builder = Router::builder(iroh_endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs_protocol)
            .accept(iroh_docs::ALPN, docs_protocol.clone());

        let docs = DocsClient::new(docs_protocol);
        let default_author = docs.create_author().await?;

        Ok(SyncEngineBuilder {
            blobs: BlobClient::new(blobs_client, store_api, iroh_endpoint),
            docs,
            default_author,
            node_addr,
            router_builder,
        })
    }

    /// Returns this node's address for creating tickets.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
    }

    /// Returns the underlying iroh endpoint (via the Router).
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

    /// Returns the default author for this node.
    pub fn default_author(&self) -> iroh_docs::AuthorId {
        self.default_author
    }

    /// Gracefully shutdown the sync engine.
    pub async fn shutdown(self) -> Result<()> {
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

        let engine = SyncEngine::with_storage(endpoint.inner(), &config)
            .await
            .unwrap()
            .spawn();

        let _blobs = engine.blobs();
        let _docs = engine.docs();
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_persistent_sync_engine_blob_persistence() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        let hash;

        {
            let endpoint = transport::endpoint().await;
            let engine = SyncEngine::with_storage(endpoint.inner(), &config)
                .await
                .unwrap()
                .spawn();

            hash = engine
                .blobs()
                .add_bytes(&b"persistent test"[..])
                .await
                .unwrap();

            engine.shutdown().await.unwrap();
        }

        {
            let endpoint2 = transport::endpoint().await;
            let engine2 = SyncEngine::with_storage(endpoint2.inner(), &config)
                .await
                .unwrap()
                .spawn();

            let bytes = engine2.blobs().read_to_bytes(hash).await.unwrap();
            assert_eq!(&bytes[..], b"persistent test");
            engine2.shutdown().await.unwrap();
        }
    }
}
