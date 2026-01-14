//! Verification logic for OBJECTS Registry.
//!
//! This module wraps objects-identity functions for use in the registry.

use std::time::{SystemTime, UNIX_EPOCH};

use objects_identity::{message, Handle, IdentityId, Signature};

use crate::config::Config;
use crate::error::{RegistryError, Result};

/// Verify that a timestamp is within acceptable bounds.
///
/// Per RFC-001 Section 5.1.3:
/// - RECOMMENDED: 5 minutes in the future maximum
/// - RECOMMENDED: 24 hours in the past maximum
pub fn verify_timestamp(timestamp: u64, config: &Config) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();

    // Check not too far in the future
    let max_future = now + config.timestamp_future_max.as_secs();
    if timestamp > max_future {
        return Err(RegistryError::TimestampInvalid);
    }

    // Check not too far in the past
    let min_past = now.saturating_sub(config.timestamp_past_max.as_secs());
    if timestamp < min_past {
        return Err(RegistryError::TimestampInvalid);
    }

    Ok(())
}

/// Verify that a derived identity ID matches the claimed ID.
///
/// Per RFC-001 Section 2:
/// identity_id = "obj_" || base58(truncate(sha256(public_key || nonce), 15))
#[allow(dead_code)] // Useful for verifying IDs from external sources
pub fn verify_id_derivation(
    public_key: &[u8; 33],
    nonce: &[u8; 8],
    claimed_id: &str,
) -> Result<()> {
    let derived = IdentityId::derive(public_key, nonce);
    if derived.as_str() != claimed_id {
        return Err(RegistryError::InvalidIdentityId {
            expected: claimed_id.to_string(),
            derived: derived.to_string(),
        });
    }
    Ok(())
}

/// Validate a handle format.
///
/// Returns the validated handle on success.
pub fn verify_handle(handle: &str) -> Result<Handle> {
    Handle::parse(handle).map_err(|e| RegistryError::InvalidHandle(e.to_string()))
}

/// Verify a signature over a message.
pub fn verify_signature(signature: &Signature, message: &[u8]) -> Result<()> {
    signature
        .verify(message)
        .map_err(|e| RegistryError::InvalidSignature(e.to_string()))
}

/// Verify that a signature's public key matches the expected public key.
///
/// For passkey signatures, the public_key field must match.
/// For wallet signatures, we don't verify public key (address is verified instead).
pub fn verify_public_key_matches(signature: &Signature, expected: &[u8]) -> Result<()> {
    match &signature.public_key {
        Some(pk) if pk.as_slice() == expected => Ok(()),
        Some(pk) => Err(RegistryError::InvalidSignature(format!(
            "public key mismatch: expected {} bytes, signature contains {} bytes",
            expected.len(),
            pk.len()
        ))),
        None => {
            // For wallet signatures, public key is not included
            // The address verification in Signature::verify handles this
            Ok(())
        }
    }
}

/// Build the message for CreateIdentity verification.
pub fn create_identity_message(identity_id: &str, handle: &str, timestamp: u64) -> String {
    message::create_identity_message(identity_id, handle, timestamp)
}

/// Build the message for LinkWallet verification.
pub fn link_wallet_message(identity_id: &str, wallet_address: &str, timestamp: u64) -> String {
    message::link_wallet_message(identity_id, wallet_address, timestamp)
}

/// Build the message for ChangeHandle verification.
pub fn change_handle_message(identity_id: &str, new_handle: &str, timestamp: u64) -> String {
    message::change_handle_message(identity_id, new_handle, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> Config {
        Config {
            database_url: String::new(),
            rest_port: 8080,
            grpc_port: 9090,
            timestamp_future_max: Duration::from_secs(300),
            timestamp_past_max: Duration::from_secs(86400),
        }
    }

    #[test]
    fn test_verify_timestamp_current() {
        let config = test_config();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_timestamp(now, &config).is_ok());
    }

    #[test]
    fn test_verify_timestamp_too_far_future() {
        let config = test_config();
        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600; // 10 minutes in future
        assert!(verify_timestamp(far_future, &config).is_err());
    }

    #[test]
    fn test_verify_timestamp_too_far_past() {
        let config = test_config();
        let far_past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 90000; // 25 hours ago
        assert!(verify_timestamp(far_past, &config).is_err());
    }

    #[test]
    fn test_verify_id_derivation_matches() {
        // Test vector from RFC-001 Appendix B
        let public_key: [u8; 33] = [
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ];
        let nonce: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let expected_id = "obj_2dMiYc8RhnYkorPc5pVh9";

        assert!(verify_id_derivation(&public_key, &nonce, expected_id).is_ok());
    }

    #[test]
    fn test_verify_id_derivation_mismatch() {
        let public_key: [u8; 33] = [0x02; 33];
        let nonce: [u8; 8] = [0x01; 8];
        let wrong_id = "obj_wrong";

        let result = verify_id_derivation(&public_key, &nonce, wrong_id);
        assert!(matches!(result, Err(RegistryError::InvalidIdentityId { .. })));
    }

    #[test]
    fn test_verify_handle_valid() {
        assert!(verify_handle("montez").is_ok());
        assert!(verify_handle("alice_123").is_ok());
        assert!(verify_handle("montez.studio").is_ok());
    }

    #[test]
    fn test_verify_handle_invalid() {
        assert!(verify_handle("").is_err());
        assert!(verify_handle("_alice").is_err());
        assert!(verify_handle("Alice").is_err());
        assert!(verify_handle("admin").is_err());
    }
}
