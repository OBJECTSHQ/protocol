//! Blob and metadata sync for OBJECTS Protocol.
//!
//! This crate implements RFC-003: OBJECTS Sync Protocol.
//!
//! # Architecture
//!
//! - [`SyncEngine`]: Main entry point, coordinates blob + metadata sync
//! - [`BlobClient`]: Wrapper over iroh-blobs for content-addressed storage
//! - [`DocsClient`]: Wrapper over iroh-docs for metadata replication
//! - [`tickets`]: Share-able tokens for blob and replica discovery
//!
//! # Example
//!
//! ```rust,no_run
//! use objects_sync::SyncEngine;
//! use objects_transport::ObjectsEndpoint;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create transport endpoint
//! let endpoint = ObjectsEndpoint::builder().bind().await?;
//! let node_addr = endpoint.node_addr();
//!
//! // Create sync engine
//! let sync = SyncEngine::new(endpoint).await?;
//!
//! // Add blob
//! let hash = sync.blobs().add_bytes(&b"Hello, OBJECTS!"[..]).await?;
//!
//! // Create replica for project
//! let replica_id = sync.docs().create_replica().await?;
//! let author = sync.docs().create_author().await?;
//! sync.docs().set_bytes(replica_id, author, "/project", &b"metadata"[..]).await?;
//!
//! // Create tickets for sharing
//! let blob_ticket = sync.blobs().create_ticket(hash, node_addr.clone()).await?;
//! let doc_ticket = sync.docs().create_ticket(replica_id, node_addr).await?;
//!
//! println!("Share blob: {}", blob_ticket);
//! println!("Share replica: {}", doc_ticket);
//! # Ok(())
//! # }
//! ```

pub mod blobs;
pub mod docs;
pub mod helpers;
pub mod tickets;

mod engine;
mod error;

// Re-export main types
pub use blobs::BlobClient;
pub use docs::DocsClient;
pub use engine::SyncEngine;
pub use error::Error;

// Re-export key Iroh types for convenience
pub use iroh_blobs::ticket::BlobTicket;
pub use iroh_blobs::{BlobFormat, Hash as BlobHash, HashAndFormat};
pub use iroh_docs::{Author, DocTicket, Entry, NamespaceId as ReplicaId};

// Re-export OBJECTS-specific helpers
pub use helpers::{content_hash_to_hash, hash_to_content_hash};

// Re-export storage conventions from objects-data for convenience
pub use objects_data::storage::{
    ASSETS_PREFIX, PROJECT_KEY, REFS_PREFIX, asset_key, reference_key,
};

/// Result type for sync operations.
pub type Result<T> = std::result::Result<T, Error>;
