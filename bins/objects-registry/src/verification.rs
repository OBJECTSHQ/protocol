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
        .map_err(|e| RegistryError::Internal(format!("system clock error: {}", e)))?
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
///
/// NOTE: This function is currently unused in the codebase but is retained for potential
/// future use cases such as:
/// - Verifying identity IDs from external API requests that include a claimed ID
/// - Admin tools that need to validate identity derivation
/// - Cross-system identity verification where the ID is provided separately
#[allow(dead_code)]
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

/// Validate an Ethereum wallet address format.
///
/// Valid format: "0x" followed by exactly 40 hexadecimal characters.
/// Example: "0x742d35Cc6634C0532925a3b844Bc9e7595f1dE21"
///
/// Returns the validated wallet address on success.
pub fn verify_wallet_address(address: &str) -> Result<&str> {
    // Must be exactly 42 characters: "0x" + 40 hex chars
    if address.len() != 42 {
        return Err(RegistryError::InvalidWalletAddress(format!(
            "expected 42 characters, got {}",
            address.len()
        )));
    }

    // Must start with "0x"
    if !address.starts_with("0x") {
        return Err(RegistryError::InvalidWalletAddress(
            "must start with '0x'".to_string(),
        ));
    }

    // Remaining 40 characters must be valid hexadecimal
    let hex_part = &address[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RegistryError::InvalidWalletAddress(
            "must contain only hexadecimal characters after '0x'".to_string(),
        ));
    }

    Ok(address)
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
            "signature public key does not match request public key (signature: {} bytes, request: {} bytes)",
            pk.len(),
            expected.len()
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

    #[test]
    fn test_verify_wallet_address_valid() {
        // Lowercase hex
        assert!(verify_wallet_address("0x742d35cc6634c0532925a3b844bc9e7595f1de21").is_ok());
        // Uppercase hex
        assert!(verify_wallet_address("0x742D35CC6634C0532925A3B844BC9E7595F1DE21").is_ok());
        // Mixed case hex
        assert!(verify_wallet_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1dE21").is_ok());
        // All zeros
        assert!(verify_wallet_address("0x0000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn test_verify_wallet_address_invalid_length() {
        // Too short
        let result = verify_wallet_address("0x742d35cc");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));

        // Too long
        let result = verify_wallet_address("0x742d35cc6634c0532925a3b844bc9e7595f1de21ab");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));

        // Empty
        let result = verify_wallet_address("");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));
    }

    #[test]
    fn test_verify_wallet_address_invalid_prefix() {
        // Missing 0x prefix
        let result = verify_wallet_address("742d35cc6634c0532925a3b844bc9e7595f1de21");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));

        // Wrong prefix
        let result = verify_wallet_address("0X742d35cc6634c0532925a3b844bc9e7595f1de21");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));
    }

    #[test]
    fn test_verify_wallet_address_invalid_hex() {
        // Contains non-hex character 'g'
        let result = verify_wallet_address("0x742d35cc6634c0532925a3b844bc9e7595f1deg1");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));

        // Contains space
        let result = verify_wallet_address("0x742d35cc6634c0532925a3b844bc9e7595f1de 1");
        assert!(matches!(result, Err(RegistryError::InvalidWalletAddress(_))));
    }
}
