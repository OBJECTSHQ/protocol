//! User vault key derivation for cross-device project discovery.
//!
//! Vault keys are derived using HKDF-SHA256 from the Ed25519 identity signing key.
//! Only the identity owner can compute these keys.

use hkdf::Hkdf;
use iroh_docs::{NamespaceId, NamespaceSecret};
use sha2::Sha256;

use crate::Error;

/// Info string for HKDF vault namespace derivation.
const VAULT_NAMESPACE_INFO: &[u8] = b"OBJECTS-protocol-vault-namespace-v1";

/// Vault namespace and encryption keys derived from identity signing key.
#[derive(Debug)]
pub struct VaultKeys {
    /// Iroh namespace secret (write capability).
    namespace_secret: NamespaceSecret,
    /// Iroh namespace ID (replica ID, read capability).
    namespace_id: NamespaceId,
    /// XChaCha20-Poly1305 key for encrypting catalog entries (32 bytes).
    pub catalog_encryption_key: [u8; 32],
}

impl VaultKeys {
    /// Derive vault keys from Ed25519 identity signing key.
    ///
    /// **SECURITY:** This function accesses the identity's secret key material.
    /// It MUST only be called in wallet/keyring code, never in app code.
    ///
    /// # Arguments
    /// * `secret_bytes` - The Ed25519 signing key's secret bytes (32 bytes)
    pub fn derive_from_signing_key(secret_bytes: &[u8; 32]) -> Result<Self, Error> {
        let hkdf = Hkdf::<Sha256>::new(None, secret_bytes);

        // Derive 64 bytes: 32 for namespace seed, 32 for catalog key
        let mut okm = [0u8; 64];
        hkdf.expand(VAULT_NAMESPACE_INFO, &mut okm)
            .map_err(|_| Error::VaultDerivation("HKDF expansion failed".to_string()))?;

        let namespace_seed: [u8; 32] = okm[0..32].try_into().expect("slice is exactly 32 bytes");
        let catalog_key: [u8; 32] = okm[32..64].try_into().expect("slice is exactly 32 bytes");

        let namespace_secret = NamespaceSecret::from_bytes(&namespace_seed);
        let namespace_id = namespace_secret.id();

        Ok(Self {
            namespace_secret,
            namespace_id,
            catalog_encryption_key: catalog_key,
        })
    }

    /// Get read-only namespace ID (safe to share with apps).
    pub fn namespace_id(&self) -> NamespaceId {
        self.namespace_id
    }

    /// Get namespace secret (write capability, keep private).
    pub fn namespace_secret(&self) -> &NamespaceSecret {
        &self.namespace_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_derivation_deterministic() {
        let secret_key = [42u8; 32];

        let keys1 = VaultKeys::derive_from_signing_key(&secret_key).unwrap();
        let keys2 = VaultKeys::derive_from_signing_key(&secret_key).unwrap();

        assert_eq!(
            keys1.namespace_id, keys2.namespace_id,
            "Same secret → same vault ID"
        );
        assert_eq!(
            keys1.catalog_encryption_key, keys2.catalog_encryption_key,
            "Same secret → same catalog key"
        );
    }

    #[test]
    fn test_vault_derivation_unique() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let keys1 = VaultKeys::derive_from_signing_key(&secret1).unwrap();
        let keys2 = VaultKeys::derive_from_signing_key(&secret2).unwrap();

        assert_ne!(
            keys1.namespace_id, keys2.namespace_id,
            "Different secrets → different vault IDs"
        );
        assert_ne!(
            keys1.catalog_encryption_key, keys2.catalog_encryption_key,
            "Different secrets → different catalog keys"
        );
    }
}
