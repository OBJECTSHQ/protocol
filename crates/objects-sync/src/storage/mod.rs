//! Persistent storage configuration and management for sync engine.
//!
//! This module provides storage configuration types and directory management
//! for the OBJECTS Protocol sync layer.

pub mod blobs;

use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;

/// Storage format version for migration detection.
pub const STORAGE_VERSION: &str = "v1";

/// Storage configuration for sync engine.
///
/// Manages paths for persistent blob and docs storage.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Path to blobs directory (FsStore).
    blobs_path: PathBuf,
    /// Path to docs directory (persistent Docs).
    docs_path: PathBuf,
}

impl StorageConfig {
    /// Create storage config with explicit paths.
    pub fn new(blobs_path: PathBuf, docs_path: PathBuf) -> Self {
        Self {
            blobs_path,
            docs_path,
        }
    }

    /// Create storage config from base directory.
    ///
    /// Creates subdirectories:
    /// - `{base}/storage/blobs/`
    /// - `{base}/storage/docs/`
    pub fn from_base_dir(base: &Path) -> Self {
        let storage_root = base.join("storage");
        Self {
            blobs_path: storage_root.join("blobs"),
            docs_path: storage_root.join("docs"),
        }
    }

    /// Ensure all storage directories exist with correct permissions.
    ///
    /// Creates directories if they don't exist, sets Unix permissions to 700,
    /// and creates/verifies storage version marker.
    pub fn ensure_directories(&self) -> Result<()> {
        // Create directories
        fs::create_dir_all(&self.blobs_path)?;
        fs::create_dir_all(&self.docs_path)?;

        // Set permissions (Unix only)
        self.ensure_permissions()?;

        // Create/verify version marker
        let version_file = self.blobs_path.parent().unwrap().join(".storage-version");

        if !version_file.exists() {
            fs::write(&version_file, STORAGE_VERSION)?;
        } else {
            let existing = fs::read_to_string(&version_file)?;
            if existing != STORAGE_VERSION {
                return Err(crate::Error::StorageVersionMismatch {
                    expected: STORAGE_VERSION.to_string(),
                    found: existing,
                });
            }
        }

        Ok(())
    }

    /// Validate paths are writable.
    ///
    /// Checks that storage directories exist and are writable.
    pub fn validate(&self) -> Result<()> {
        // Check blobs directory
        if !self.blobs_path.exists() {
            return Err(crate::Error::Storage(format!(
                "Blobs directory does not exist: {}",
                self.blobs_path.display()
            )));
        }

        // Check docs directory
        if !self.docs_path.exists() {
            return Err(crate::Error::Storage(format!(
                "Docs directory does not exist: {}",
                self.docs_path.display()
            )));
        }

        // Verify writable by attempting to create a temp file
        let test_file = self.blobs_path.join(".write-test");
        fs::write(&test_file, b"test")?;
        fs::remove_file(&test_file)?;

        Ok(())
    }

    /// Set secure permissions on storage directories (Unix only).
    fn ensure_permissions(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Storage directories: 700 (owner only)
            for dir in [&self.blobs_path, &self.docs_path] {
                let metadata = fs::metadata(dir)?;
                let mut perms = metadata.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(dir, perms)?;
            }
        }
        Ok(())
    }

    /// Get path to blobs directory.
    pub fn blobs_path(&self) -> &Path {
        &self.blobs_path
    }

    /// Get path to docs directory.
    pub fn docs_path(&self) -> &Path {
        &self.docs_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_from_base_dir_creates_correct_structure() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        assert_eq!(
            config.blobs_path(),
            tmp.path().join("storage").join("blobs")
        );
        assert_eq!(config.docs_path(), tmp.path().join("storage").join("docs"));
    }

    #[test]
    fn test_ensure_directories_creates_paths() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        config.ensure_directories().unwrap();

        assert!(config.blobs_path().exists());
        assert!(config.docs_path().exists());
    }

    #[test]
    fn test_ensure_directories_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        config.ensure_directories().unwrap();
        config.ensure_directories().unwrap();

        assert!(config.blobs_path().exists());
        assert!(config.docs_path().exists());
    }

    #[test]
    fn test_version_marker_created() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        config.ensure_directories().unwrap();

        let version_file = tmp.path().join("storage").join(".storage-version");
        assert!(version_file.exists());

        let version = fs::read_to_string(&version_file).unwrap();
        assert_eq!(version, STORAGE_VERSION);
    }

    #[test]
    fn test_version_mismatch_detected() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        // Create directories
        config.ensure_directories().unwrap();

        // Manually write wrong version
        let version_file = tmp.path().join("storage").join(".storage-version");
        fs::write(&version_file, "v0").unwrap();

        // Should fail on mismatch
        let result = config.ensure_directories();
        assert!(result.is_err());
        match result {
            Err(crate::Error::StorageVersionMismatch { expected, found }) => {
                assert_eq!(expected, STORAGE_VERSION);
                assert_eq!(found, "v0");
            }
            _ => panic!("Expected StorageVersionMismatch error"),
        }
    }

    #[test]
    fn test_validate_succeeds_after_ensure() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        config.ensure_directories().unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_validate_fails_without_ensure() {
        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        let result = config.validate();
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_permissions_set_to_700() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let config = StorageConfig::from_base_dir(tmp.path());

        config.ensure_directories().unwrap();

        for dir in [config.blobs_path(), config.docs_path()] {
            let metadata = fs::metadata(dir).unwrap();
            let perms = metadata.permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }
}
