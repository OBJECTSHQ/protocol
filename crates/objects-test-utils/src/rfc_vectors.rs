//! RFC-001 canonical test vectors.
//!
//! This module provides the official test vectors from RFC-001 Appendix B
//! for identity derivation and handle validation.
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::rfc_vectors::{rfc_001_identity_id, is_reserved};
//!
//! // Get RFC-001 canonical identity
//! let identity = rfc_001_identity_id();
//! assert_eq!(identity.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
//!
//! // Check if a handle is reserved
//! assert!(is_reserved("admin"));
//! assert!(!is_reserved("my_custom_handle"));
//! ```

use objects_identity::IdentityId;

/// RFC-001 Appendix B.1 test vector: signer public key (compressed SEC1).
///
/// This is the compressed secp256r1 (P-256) public key used in the canonical
/// identity derivation test vector.
///
/// Value: `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`
pub fn rfc_001_signer_public_key() -> [u8; 33] {
    hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        .expect("valid hex")
        .try_into()
        .expect("33 bytes")
}

/// RFC-001 Appendix B.1 test vector: nonce.
///
/// Value: `[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]`
pub fn rfc_001_nonce() -> [u8; 8] {
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

/// RFC-001 Appendix B.1 test vector: derived identity ID.
///
/// This is the canonical identity ID derived from the RFC-001 test vector
/// public key and nonce. Use this for tests that need a consistent identity.
///
/// Value: `obj_2dMiYc8RhnYkorPc5pVh9`
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::rfc_vectors::rfc_001_identity_id;
///
/// let id = rfc_001_identity_id();
/// assert_eq!(id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
/// ```
pub fn rfc_001_identity_id() -> IdentityId {
    let public_key = rfc_001_signer_public_key();
    let nonce = rfc_001_nonce();
    IdentityId::derive(&public_key, &nonce)
}

/// List of reserved handles from RFC-001.
///
/// These handles cannot be registered by users as they are reserved for
/// system and administrative purposes.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::rfc_vectors::reserved_handles;
///
/// let handles = reserved_handles();
/// assert!(handles.contains(&"admin"));
/// assert!(handles.contains(&"root"));
/// ```
pub fn reserved_handles() -> Vec<&'static str> {
    vec![
        "admin",
        "administrator",
        "root",
        "system",
        "objects",
        "protocol",
        "support",
        "help",
        "info",
        "contact",
        "api",
        "www",
        "mail",
        "ftp",
    ]
}

/// Check if a handle is reserved.
///
/// Returns `true` if the handle is in the reserved list, `false` otherwise.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::rfc_vectors::is_reserved;
///
/// assert!(is_reserved("admin"));
/// assert!(is_reserved("root"));
/// assert!(!is_reserved("my_custom_handle"));
/// ```
pub fn is_reserved(handle: &str) -> bool {
    reserved_handles().contains(&handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_001_identity_vector_is_canonical() {
        let id = rfc_001_identity_id();
        assert_eq!(id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
    }

    #[test]
    fn test_rfc_001_public_key_is_valid() {
        let public_key = rfc_001_signer_public_key();
        assert_eq!(public_key.len(), 33);
        assert_eq!(
            public_key[0], 0x02,
            "First byte should be 0x02 for compressed SEC1 encoding"
        );
    }

    #[test]
    fn test_rfc_001_nonce_is_correct() {
        let nonce = rfc_001_nonce();
        assert_eq!(nonce, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_reserved_handles_contains_admin() {
        let handles = reserved_handles();
        assert!(handles.contains(&"admin"));
        assert!(handles.contains(&"root"));
        assert!(handles.contains(&"system"));
    }

    #[test]
    fn test_is_reserved_function() {
        assert!(is_reserved("admin"));
        assert!(is_reserved("root"));
        assert!(is_reserved("system"));
        assert!(!is_reserved("my_handle"));
        assert!(!is_reserved("user123"));
    }
}
