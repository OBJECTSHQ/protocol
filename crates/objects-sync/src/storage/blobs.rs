//! Persistent blob storage implementation.
//!
//! This module provides utilities for managing persistent blob storage using Iroh's FsStore.

use iroh_blobs::Hash;
use iroh_blobs::store::fs::FsStore;
use std::path::Path;

use crate::Result;

/// Initialize persistent blob store at the given path.
///
/// Uses content-addressed storage via BLAKE3 with automatic deduplication.
/// FsStore provides verified streaming support through BLAKE3 Verified Streaming (BAO).
///
/// # Errors
///
/// Returns error if the store cannot be loaded or created.
pub async fn create_blob_store(path: &Path) -> Result<FsStore> {
    // FsStore::load creates directory if it doesn't exist
    FsStore::load(path)
        .await
        .map_err(|e| crate::Error::Storage(format!("Failed to load blob store: {}", e)))
}

/// Get blob store size in bytes.
///
/// Walks the blob store directory and sums all file sizes.
///
/// # Errors
///
/// Returns error if directory cannot be read.
pub async fn blob_store_size(path: &Path) -> Result<u64> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || super::dir_size(&path))
        .await
        .map_err(|e| crate::Error::Storage(format!("Failed to compute blob store size: {e}")))?
}

/// Check if blob store can accommodate new blob.
///
/// Validates:
/// 1. Single blob size against max_blob_size limit
/// 2. Total storage size against max_total_size limit
///
/// Note: there is an inherent TOCTOU race between checking storage size and
/// writing the blob. This is acceptable for v0.1 — concurrent writes may
/// briefly exceed the limit, but the check prevents sustained overuse.
///
/// # Errors
///
/// Returns `BlobTooLarge` if the blob exceeds max_blob_size.
/// Returns `StorageLimitExceeded` if adding the blob would exceed max_total_size.
pub async fn check_storage_limits(
    store_path: &Path,
    blob_size: u64,
    max_blob_size_mb: u64,
    max_total_size_gb: u64,
) -> Result<()> {
    // Check single blob size
    let max_blob_bytes = max_blob_size_mb * 1024 * 1024;
    if blob_size > max_blob_bytes {
        return Err(crate::Error::BlobTooLarge {
            size: blob_size,
            max: max_blob_bytes,
        });
    }

    // Check total storage
    let current_size = blob_store_size(store_path).await?;
    let max_total_bytes = max_total_size_gb * 1024 * 1024 * 1024;

    if current_size + blob_size > max_total_bytes {
        return Err(crate::Error::StorageLimitExceeded {
            current: current_size,
            limit: max_total_bytes,
        });
    }

    Ok(())
}

/// Verify that a blob exists and is retrievable from the store.
///
/// Iroh's FsStore uses BLAKE3 Authenticated Output (BAO) for verified streaming,
/// so `get_bytes(hash)` already validates content integrity against the hash during
/// retrieval. A separate re-hash would always match for any successfully retrieved blob.
///
/// Returns `Ok(true)` if the blob exists, `Ok(false)` if not found.
pub async fn verify_blob_exists(store: &FsStore, hash: Hash) -> Result<bool> {
    match store.blobs().get_bytes(hash).await {
        Ok(_) => Ok(true),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("NotFound") {
                Ok(false)
            } else {
                Err(crate::Error::Storage(format!("Failed to read blob: {e}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ===== Group 1: FsStore Integration (minimal) =====

    #[tokio::test]
    async fn test_create_blob_store() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("blobs");

        // Should create store successfully
        let store = create_blob_store(&store_path).await.unwrap();

        // Should be able to add and retrieve blob
        let content = b"test data";
        let hash = blake3::hash(content);
        let iroh_hash = Hash::from(hash);

        let _tag = store.add_bytes(&content[..]).await.unwrap();

        // Verify blob is retrievable with correct hash
        let bytes = store.blobs().get_bytes(iroh_hash).await.unwrap();
        assert_eq!(&bytes[..], content);
    }

    #[tokio::test]
    async fn test_blob_store_persistence_across_reloads() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("blobs");

        let content = b"persistent data";
        let hash = blake3::hash(content);
        let iroh_hash = Hash::from(hash);

        // Create store, add blob, shutdown store
        {
            let store = create_blob_store(&store_path).await.unwrap();
            let _tag = store.add_bytes(&content[..]).await.unwrap();
            // Gracefully shutdown FsStore
            store.shutdown().await.unwrap();
        }

        // Reload store and verify blob still exists
        let store2 = create_blob_store(&store_path).await.unwrap();
        let bytes = store2.blobs().get_bytes(iroh_hash).await.unwrap();
        assert_eq!(&bytes[..], content);

        // Cleanup
        store2.shutdown().await.unwrap();
    }

    // ===== Group 2: Pure Logic Tests (no FsStore) =====

    #[tokio::test]
    async fn test_check_storage_limits_blob_too_large() {
        let tmp = TempDir::new().unwrap();

        // Blob size exceeds max_blob_size
        let result = check_storage_limits(
            tmp.path(),
            200 * 1024 * 1024, // 200 MB blob
            100,               // 100 MB max
            10,                // 10 GB total (irrelevant here)
        )
        .await;

        assert!(matches!(
            result,
            Err(crate::Error::BlobTooLarge { size, max })
                if size == 200 * 1024 * 1024 && max == 100 * 1024 * 1024
        ));
    }

    #[tokio::test]
    async fn test_check_storage_limits_within_limits() {
        let tmp = TempDir::new().unwrap();

        // Both limits satisfied (empty directory)
        let result = check_storage_limits(
            tmp.path(),
            50 * 1024 * 1024, // 50 MB blob
            100,              // 100 MB max
            10,               // 10 GB total
        )
        .await;

        assert!(result.is_ok());
    }

    // ===== Group 3: Directory Size Calculation =====

    #[tokio::test]
    async fn test_blob_store_size_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let store_dir = tmp.path().join("blobs");
        fs::create_dir_all(&store_dir).unwrap();

        let size = blob_store_size(&store_dir).await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_blob_store_size_with_files() {
        let tmp = TempDir::new().unwrap();
        let store_dir = tmp.path().join("blobs");
        fs::create_dir_all(&store_dir).unwrap();

        // Create known-size files
        let file1 = store_dir.join("file1.dat");
        let file2 = store_dir.join("file2.dat");
        let subdir = store_dir.join("subdir");
        fs::create_dir_all(&subdir).unwrap();
        let file3 = subdir.join("file3.dat");

        fs::write(&file1, vec![0u8; 1024]).unwrap(); // 1 KB
        fs::write(&file2, vec![0u8; 2048]).unwrap(); // 2 KB
        fs::write(&file3, vec![0u8; 512]).unwrap(); // 512 bytes

        let size = blob_store_size(&store_dir).await.unwrap();
        assert_eq!(size, 1024 + 2048 + 512); // Total: 3584 bytes
    }

    #[tokio::test]
    async fn test_blob_store_size_nonexistent_directory() {
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("does-not-exist");

        let size = blob_store_size(&nonexistent).await.unwrap();
        assert_eq!(size, 0);
    }

    // ===== Group 4: Blob Existence Verification =====

    #[tokio::test]
    async fn test_verify_blob_exists_present() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("blobs");
        let store = create_blob_store(&store_path).await.unwrap();
        let content = b"valid content";
        let _tag = store.add_bytes(&content[..]).await.unwrap();
        let hash = blake3::hash(content);
        let iroh_hash = Hash::from(hash);
        assert!(verify_blob_exists(&store, iroh_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_blob_exists_missing() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("blobs");
        let store = create_blob_store(&store_path).await.unwrap();
        let fake_hash = blake3::hash(b"nonexistent");
        let iroh_hash = Hash::from(fake_hash);
        assert!(!verify_blob_exists(&store, iroh_hash).await.unwrap());
    }

    // ===== Group 5: Storage Limit Exceeded =====

    #[tokio::test]
    async fn test_check_storage_limits_total_exceeded() {
        let tmp = TempDir::new().unwrap();
        let store_dir = tmp.path().join("blobs");
        fs::create_dir_all(&store_dir).unwrap();
        // Pre-fill with ~1 MB of existing data
        fs::write(store_dir.join("existing.dat"), vec![0u8; 1024 * 1024]).unwrap();
        // 1 GB new blob + 1 MB existing > 1 GB total limit
        let result = check_storage_limits(
            &store_dir,
            1024 * 1024 * 1024, // 1 GB new blob
            2048,               // 2 TB max per blob (won't trigger)
            1,                  // 1 GB total limit
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::Error::StorageLimitExceeded { current, limit })
                if current > 0 && limit == 1024 * 1024 * 1024
        ));
    }
}
