//! Encryption utilities for vault catalog entries.
//!
//! This module provides XChaCha20-Poly1305 AEAD encryption for ProjectCatalogEntry messages.
//! Catalog entries are encrypted before storage in user vaults to preserve privacy.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use prost::Message;
use rand::RngCore;

use crate::{proto::ProjectCatalogEntry, Error};

/// Encrypt a catalog entry with XChaCha20-Poly1305.
///
/// Returns: nonce (24 bytes) || ciphertext (variable)
///
/// # Arguments
/// * `entry` - The catalog entry to encrypt
/// * `key` - 32-byte encryption key (derived from vault keys)
///
/// # Example
/// ```no_run
/// # use objects_data::{proto::ProjectCatalogEntry, encryption::encrypt_catalog_entry};
/// let entry = ProjectCatalogEntry {
///     project_id: "prj_test123".to_string(),
///     replica_id: vec![1, 2, 3, 4],
///     project_name: "Test Project".to_string(),
///     created_at: 1704542400,
/// };
/// let key = [42u8; 32];
/// let encrypted = encrypt_catalog_entry(&entry, &key).unwrap();
/// ```
pub fn encrypt_catalog_entry(
    entry: &ProjectCatalogEntry,
    key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    // Generate random 24-byte nonce
    let mut nonce_bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Serialize entry
    let plaintext = entry.encode_to_vec();

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a catalog entry.
///
/// Expects: nonce (24 bytes) || ciphertext (variable)
///
/// # Arguments
/// * `encrypted` - The encrypted data (nonce + ciphertext)
/// * `key` - 32-byte encryption key (same as used for encryption)
///
/// # Example
/// ```no_run
/// # use objects_data::{proto::ProjectCatalogEntry, encryption::{encrypt_catalog_entry, decrypt_catalog_entry}};
/// # let entry = ProjectCatalogEntry {
/// #     project_id: "prj_test123".to_string(),
/// #     replica_id: vec![1, 2, 3, 4],
/// #     project_name: "Test Project".to_string(),
/// #     created_at: 1704542400,
/// # };
/// # let key = [42u8; 32];
/// # let encrypted = encrypt_catalog_entry(&entry, &key).unwrap();
/// let decrypted = decrypt_catalog_entry(&encrypted, &key).unwrap();
/// assert_eq!(decrypted.project_id, "prj_test123");
/// ```
pub fn decrypt_catalog_entry(
    encrypted: &[u8],
    key: &[u8; 32],
) -> Result<ProjectCatalogEntry, Error> {
    if encrypted.len() < 24 {
        return Err(Error::DecryptionFailed(
            "encrypted data too short".to_string(),
        ));
    }

    let cipher = XChaCha20Poly1305::new(key.into());

    // Split nonce and ciphertext
    let nonce = XNonce::from_slice(&encrypted[0..24]);
    let ciphertext = &encrypted[24..];

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

    // Deserialize
    ProjectCatalogEntry::decode(&plaintext[..])
        .map_err(|e| Error::DeserializationFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let entry = ProjectCatalogEntry {
            project_id: "prj_test123".to_string(),
            replica_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            project_name: "Test Project".to_string(),
            created_at: 1704542400,
        };

        let key = [42u8; 32];

        // Encrypt
        let encrypted = encrypt_catalog_entry(&entry, &key).unwrap();

        // Verify format: nonce (24 bytes) + ciphertext
        assert!(
            encrypted.len() > 24,
            "Encrypted data should be longer than just nonce"
        );

        // Decrypt
        let decrypted = decrypt_catalog_entry(&encrypted, &key).unwrap();

        assert_eq!(entry.project_id, decrypted.project_id);
        assert_eq!(entry.replica_id, decrypted.replica_id);
        assert_eq!(entry.project_name, decrypted.project_name);
        assert_eq!(entry.created_at, decrypted.created_at);
    }

    #[test]
    fn test_wrong_key_fails() {
        let entry = ProjectCatalogEntry {
            project_id: "prj_test123".to_string(),
            replica_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            project_name: "Test Project".to_string(),
            created_at: 1704542400,
        };

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let encrypted = encrypt_catalog_entry(&entry, &key1).unwrap();
        let result = decrypt_catalog_entry(&encrypted, &key2);

        assert!(result.is_err(), "Wrong key should fail decryption");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let entry = ProjectCatalogEntry {
            project_id: "prj_test123".to_string(),
            replica_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            project_name: "Test Project".to_string(),
            created_at: 1704542400,
        };

        let key = [42u8; 32];
        let mut encrypted = encrypt_catalog_entry(&entry, &key).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = encrypted.get_mut(30) {
            *byte = byte.wrapping_add(1);
        }

        let result = decrypt_catalog_entry(&encrypted, &key);
        assert!(result.is_err(), "Tampered ciphertext should fail decryption");
    }

    #[test]
    fn test_too_short_data_fails() {
        let key = [42u8; 32];
        let short_data = vec![1, 2, 3]; // Less than 24 bytes

        let result = decrypt_catalog_entry(&short_data, &key);
        assert!(result.is_err(), "Too short data should fail");
    }

    #[test]
    fn test_nonce_uniqueness() {
        let entry = ProjectCatalogEntry {
            project_id: "prj_test123".to_string(),
            replica_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            project_name: "Test Project".to_string(),
            created_at: 1704542400,
        };

        let key = [42u8; 32];

        // Encrypt same entry twice
        let encrypted1 = encrypt_catalog_entry(&entry, &key).unwrap();
        let encrypted2 = encrypt_catalog_entry(&entry, &key).unwrap();

        // Nonces should be different (first 24 bytes)
        assert_ne!(
            &encrypted1[0..24],
            &encrypted2[0..24],
            "Nonces should be unique"
        );

        // But both should decrypt to the same entry
        let decrypted1 = decrypt_catalog_entry(&encrypted1, &key).unwrap();
        let decrypted2 = decrypt_catalog_entry(&encrypted2, &key).unwrap();
        assert_eq!(decrypted1.project_id, decrypted2.project_id);
    }
}
