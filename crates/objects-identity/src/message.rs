//! Signature message formatting per RFC-001.
//!
//! This module provides functions to construct messages for signing operations.
//! Messages follow the format specified in RFC-001 Section 5.

/// Protocol version header for all messages.
pub const PROTOCOL_HEADER: &str = "OBJECTS Identity Protocol v1";

/// Constructs a plain text message for creating an identity.
///
/// Format (per RFC-001 Section 5.1.2):
/// ```text
/// OBJECTS Identity Protocol v1
/// Action: Create Identity
/// Identity: {identity_id}
/// Handle: {handle}
/// Timestamp: {timestamp}
/// ```
pub fn create_identity_message(identity_id: &str, handle: &str, timestamp: u64) -> String {
    format!(
        "{}\nAction: Create Identity\nIdentity: {}\nHandle: {}\nTimestamp: {}",
        PROTOCOL_HEADER, identity_id, handle, timestamp
    )
}

/// Constructs a plain text message for linking a wallet.
///
/// Format (per RFC-001 Section 5.2.2):
/// ```text
/// OBJECTS Identity Protocol v1
/// Action: Link Wallet
/// Identity: {identity_id}
/// Wallet: {wallet_address}
/// Timestamp: {timestamp}
/// ```
pub fn link_wallet_message(identity_id: &str, wallet_address: &str, timestamp: u64) -> String {
    format!(
        "{}\nAction: Link Wallet\nIdentity: {}\nWallet: {}\nTimestamp: {}",
        PROTOCOL_HEADER, identity_id, wallet_address, timestamp
    )
}

/// Constructs a plain text message for signing an asset.
///
/// Format (per RFC-001 Section 5.3):
/// ```text
/// OBJECTS Identity Protocol v1
/// Action: Sign Asset
/// Identity: {identity_id}
/// Asset: {asset_hash_hex}
/// Timestamp: {timestamp}
/// ```
///
/// Note: `asset_hash` should be hex-encoded (64 characters, no 0x prefix).
pub fn sign_asset_message(identity_id: &str, asset_hash_hex: &str, timestamp: u64) -> String {
    format!(
        "{}\nAction: Sign Asset\nIdentity: {}\nAsset: {}\nTimestamp: {}",
        PROTOCOL_HEADER, identity_id, asset_hash_hex, timestamp
    )
}

/// Constructs a plain text message for authentication.
///
/// Format (per RFC-001 Section 5.4):
/// ```text
/// OBJECTS Identity Protocol v1
/// Action: Authenticate
/// Application: {app_domain}
/// Challenge: {challenge_hex}
/// Timestamp: {timestamp}
/// ```
///
/// Note: `challenge` should be hex-encoded (at least 64 characters).
pub fn authenticate_message(app_domain: &str, challenge_hex: &str, timestamp: u64) -> String {
    format!(
        "{}\nAction: Authenticate\nApplication: {}\nChallenge: {}\nTimestamp: {}",
        PROTOCOL_HEADER, app_domain, challenge_hex, timestamp
    )
}

/// Constructs a plain text message for changing a handle.
///
/// Format (per RFC-001 Section 5.5.2):
/// ```text
/// OBJECTS Identity Protocol v1
/// Action: Change Handle
/// Identity: {identity_id}
/// New Handle: {new_handle}
/// Timestamp: {timestamp}
/// ```
pub fn change_handle_message(identity_id: &str, new_handle: &str, timestamp: u64) -> String {
    format!(
        "{}\nAction: Change Handle\nIdentity: {}\nNew Handle: {}\nTimestamp: {}",
        PROTOCOL_HEADER, identity_id, new_handle, timestamp
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_identity_message() {
        let msg = create_identity_message("obj_2dMiYc8RhnYkorPc5pVh9", "montez", 1704542400);
        assert!(msg.starts_with("OBJECTS Identity Protocol v1\n"));
        assert!(msg.contains("Action: Create Identity\n"));
        assert!(msg.contains("Identity: obj_2dMiYc8RhnYkorPc5pVh9\n"));
        assert!(msg.contains("Handle: montez\n"));
        assert!(msg.contains("Timestamp: 1704542400"));
        // Verify no trailing newline
        assert!(!msg.ends_with('\n'));
    }

    #[test]
    fn test_link_wallet_message() {
        let msg = link_wallet_message(
            "obj_2dMiYc8RhnYkorPc5pVh9",
            "0x5678efgh",
            1704542500,
        );
        assert!(msg.contains("Action: Link Wallet\n"));
        assert!(msg.contains("Wallet: 0x5678efgh\n"));
    }

    #[test]
    fn test_sign_asset_message() {
        let asset_hash = "a".repeat(64); // 64 hex chars
        let msg = sign_asset_message("obj_2dMiYc8RhnYkorPc5pVh9", &asset_hash, 1704542600);
        assert!(msg.contains("Action: Sign Asset\n"));
        assert!(msg.contains(&format!("Asset: {}\n", asset_hash)));
    }

    #[test]
    fn test_authenticate_message() {
        let challenge = "b".repeat(64);
        let msg = authenticate_message("app.example.com", &challenge, 1704542700);
        assert!(msg.contains("Action: Authenticate\n"));
        assert!(msg.contains("Application: app.example.com\n"));
        assert!(msg.contains(&format!("Challenge: {}\n", challenge)));
    }

    #[test]
    fn test_change_handle_message() {
        let msg = change_handle_message("obj_2dMiYc8RhnYkorPc5pVh9", "montez.studio", 1704542800);
        assert!(msg.contains("Action: Change Handle\n"));
        assert!(msg.contains("New Handle: montez.studio\n"));
    }
}
