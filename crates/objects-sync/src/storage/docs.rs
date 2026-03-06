//! Persistent docs storage implementation.
//!
//! This module provides utilities for managing persistent docs storage using Iroh's Docs protocol.

use iroh::Endpoint;
use iroh_blobs::store::fs::FsStore;
use iroh_docs::protocol::Docs;
use iroh_gossip::net::Gossip;
use std::ops::Deref;
use std::path::Path;
use walkdir::WalkDir;

use crate::Result;

/// Initialize persistent docs protocol at the given path.
///
/// Creates a persistent Iroh docs store that maintains entries with full metadata
/// (author, hash, timestamp) and supports efficient set reconciliation for sync.
///
/// # Requirements
///
/// The path directory MUST exist before calling this function.
/// Use `StorageConfig::ensure_directories()` to create it.
///
/// # Errors
///
/// Returns error if directory doesn't exist or docs protocol fails to spawn.
pub async fn create_docs_store(
    path: &Path,
    endpoint: Endpoint,
    store: &FsStore,
    gossip: Gossip,
) -> Result<Docs> {
    Docs::persistent(path.to_path_buf())
        .spawn(endpoint, store.deref().clone(), gossip)
        .await
        .map_err(|e| crate::Error::Storage(format!("Failed to create docs store: {}", e)))
}

/// Get docs store size in bytes.
///
/// Walks the docs store directory and sums all file sizes.
///
/// # Errors
///
/// Returns error if directory cannot be read.
pub async fn docs_store_size(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }

    let mut total_size = 0u64;

    // Walk directory recursively
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            total_size += entry
                .metadata()
                .map_err(|e| crate::Error::Storage(format!("Failed to read metadata: {}", e)))?
                .len();
        }
    }

    Ok(total_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use objects_test_utils::transport;
    use std::fs;
    use tempfile::TempDir;

    // ===== Group 1: Docs Protocol Integration =====

    #[tokio::test]
    async fn test_create_docs_store() {
        let tmp = TempDir::new().unwrap();
        let config = crate::storage::StorageConfig::from_base_dir(tmp.path());

        // CRITICAL: Must create directories first (Docs::persistent doesn't auto-create)
        config.ensure_directories().unwrap();

        // Create FsStore for docs protocol
        let store = crate::storage::blobs::create_blob_store(config.blobs_path())
            .await
            .unwrap();

        // Create endpoint and gossip
        let endpoint = transport::endpoint().await;
        let iroh_endpoint = endpoint.inner().clone();
        let gossip = Gossip::builder().spawn(iroh_endpoint.clone());

        // Should create docs store successfully
        let _docs = create_docs_store(config.docs_path(), iroh_endpoint, &store, gossip)
            .await
            .unwrap();

        // Docs auto-cleaned up on drop (implements ProtocolHandler::shutdown)
    }

    // ===== Group 2: Directory Size Calculation =====

    #[tokio::test]
    async fn test_docs_store_size_empty() {
        let tmp = TempDir::new().unwrap();
        let docs_dir = tmp.path().join("docs");
        fs::create_dir_all(&docs_dir).unwrap();

        let size = docs_store_size(&docs_dir).await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_docs_store_size_with_files() {
        let tmp = TempDir::new().unwrap();
        let docs_dir = tmp.path().join("docs");
        fs::create_dir_all(&docs_dir).unwrap();

        // Create known-size files
        fs::write(docs_dir.join("meta1.dat"), vec![0u8; 512]).unwrap();
        fs::write(docs_dir.join("meta2.dat"), vec![0u8; 1024]).unwrap();

        let size = docs_store_size(&docs_dir).await.unwrap();
        assert_eq!(size, 512 + 1024);
    }

    #[tokio::test]
    async fn test_docs_store_size_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("does-not-exist");

        let size = docs_store_size(&nonexistent).await.unwrap();
        assert_eq!(size, 0);
    }
}
