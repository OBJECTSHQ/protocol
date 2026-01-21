//! Node state types for persistent storage.
//!
//! The node state contains:
//! - Node keypair for transport-level authentication
//! - Optional OBJECTS identity information (if registered)

use objects_identity::SignerType;
use objects_transport::SecretKey;
use serde::{Deserialize, Serialize};

/// Persistent state for the OBJECTS node daemon.
///
/// This state is stored on disk and loaded when the node starts.
///
/// # Security
///
/// The state file contains the node's private key (`node_key`) and MUST be
/// protected with restrictive file permissions (600 - owner read/write only).
/// Never commit this file to version control or share it.
///
/// # Fields
///
/// - `node_key`: The node's Ed25519 private key for transport-level authentication.
///   This is separate from the OBJECTS identity system and is used by Iroh for
///   peer-to-peer connections.
///
/// - `identity`: Optional OBJECTS identity information. `None` if the node has not
///   been registered with an identity yet. Once registered, this contains the
///   identity ID, handle, nonce, and signer type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    /// Node's Ed25519 private key for transport authentication.
    ///
    /// This key is used by Iroh for node-to-node connections and is separate
    /// from the OBJECTS identity system. Keep this secure.
    pub node_key: SecretKey,

    /// OBJECTS identity information, if registered.
    ///
    /// `None` if the node hasn't been registered with an OBJECTS identity yet.
    /// A node can operate without an OBJECTS identity (anonymous mode) but cannot
    /// publish assets or participate in identity-gated features.
    pub identity: Option<IdentityInfo>,
}

/// Information about a registered OBJECTS identity.
///
/// This links the node to an OBJECTS identity (RFC-001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// RFC-001 identity ID (format: `obj_` + base58 encoded hash).
    ///
    /// Example: `obj_2dMiYc8RhnYkorPc5pVh9`
    pub identity_id: String,

    /// Registered handle for this identity.
    ///
    /// Must follow RFC-001 handle rules: 1-30 chars, lowercase alphanumeric +
    /// underscore + period, no leading `_` or `.`, no trailing `.`, no consecutive `..`.
    pub handle: String,

    /// 8-byte nonce used for identity ID derivation.
    ///
    /// Per RFC-001, the identity ID is derived from SHA-256(signer_public_key || nonce).
    /// This nonce is required for verification of the identity ID.
    pub nonce: [u8; 8],

    /// Type of signer used for this identity.
    ///
    /// - `Passkey`: WebAuthn/FIDO2 credential (secp256r1/P-256)
    /// - `Wallet`: Ethereum EOA (secp256k1)
    pub signer_type: SignerType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_state_serialization() {
        // Generate a test node key
        let node_key = SecretKey::generate(&mut rand::rng());

        let state = NodeState {
            node_key: node_key.clone(),
            identity: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state).unwrap();

        // Deserialize back
        let deserialized: NodeState = serde_json::from_str(&json).unwrap();

        // Verify round-trip (compare public keys since SecretKey doesn't implement PartialEq)
        assert_eq!(
            node_key.public().to_string(),
            deserialized.node_key.public().to_string()
        );
        assert!(deserialized.identity.is_none());
    }

    #[test]
    fn test_node_state_with_identity() {
        let node_key = SecretKey::generate(&mut rand::rng());

        let identity_info = IdentityInfo {
            identity_id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
            handle: "test_user".to_string(),
            nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            signer_type: SignerType::Passkey,
        };

        let state = NodeState {
            node_key: node_key.clone(),
            identity: Some(identity_info.clone()),
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state).unwrap();

        // Deserialize back
        let deserialized: NodeState = serde_json::from_str(&json).unwrap();

        // Verify identity info
        let deser_identity = deserialized.identity.unwrap();
        assert_eq!(deser_identity.identity_id, "obj_2dMiYc8RhnYkorPc5pVh9");
        assert_eq!(deser_identity.handle, "test_user");
        assert_eq!(deser_identity.nonce, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(deser_identity.signer_type, SignerType::Passkey);
    }

    #[test]
    fn test_identity_info_signer_types() {
        let passkey_identity = IdentityInfo {
            identity_id: "obj_test1".to_string(),
            handle: "passkey_user".to_string(),
            nonce: [0; 8],
            signer_type: SignerType::Passkey,
        };

        let wallet_identity = IdentityInfo {
            identity_id: "obj_test2".to_string(),
            handle: "wallet_user".to_string(),
            nonce: [1; 8],
            signer_type: SignerType::Wallet,
        };

        // Serialize and deserialize both
        let passkey_json = serde_json::to_string(&passkey_identity).unwrap();
        let wallet_json = serde_json::to_string(&wallet_identity).unwrap();

        let passkey_deser: IdentityInfo = serde_json::from_str(&passkey_json).unwrap();
        let wallet_deser: IdentityInfo = serde_json::from_str(&wallet_json).unwrap();

        assert_eq!(passkey_deser.signer_type, SignerType::Passkey);
        assert_eq!(wallet_deser.signer_type, SignerType::Wallet);
    }
}
