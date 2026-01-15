//! Common test utilities for objects-identity integration tests.

use k256::ecdsa::SigningKey as K256SigningKey;
use k256::elliptic_curve::rand_core::OsRng; // Following source pattern
use objects_identity::IdentityId;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a random P-256 (secp256r1) signing key for passkey tests.
/// Follows the pattern from signature.rs test module.
pub fn test_passkey_key() -> P256SigningKey {
    P256SigningKey::random(&mut OsRng)
}

/// Generate a random secp256k1 signing key for wallet tests.
/// Follows the pattern from signature.rs test module.
pub fn test_wallet_key() -> K256SigningKey {
    K256SigningKey::random(&mut OsRng)
}

/// Generate a test identity ID using a passkey with a fixed nonce.
pub fn test_identity_id() -> IdentityId {
    let key = test_passkey_key();
    let verifying_key = key.verifying_key();

    // Get compressed SEC1 encoding (33 bytes)
    let public_key_bytes = verifying_key.to_encoded_point(true);
    let public_key_array: [u8; 33] = public_key_bytes
        .as_bytes()
        .try_into()
        .expect("compressed SEC1 point is 33 bytes");

    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];

    IdentityId::derive(&public_key_array, &nonce)
}

/// Get the current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Generate a random 8-byte nonce for testing.
/// Uses rand::rng() following the pattern from id.rs::generate_nonce()
pub fn random_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// List of reserved handles from RFC-001.
/// These handles cannot be registered by users.
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
pub fn is_reserved(handle: &str) -> bool {
    reserved_handles().contains(&handle)
}
