//! Node state types for persistent storage.
//!
//! The node state contains:
//! - Node keypair for transport-level authentication
//! - Optional OBJECTS identity information (if registered)

use objects_identity::{Handle, IdentityId, SignerType};
use objects_transport::SecretKey;
use serde::{Deserialize, Serialize};

/// Persistent state for the OBJECTS node daemon.
///
/// This state is stored on disk and loaded when the node starts.
///
/// # Security
///
/// The state file contains the node's private key (`node_key`). When persisted
/// to disk (in a future PR), the file will be created with restrictive permissions
/// (600 - owner read/write only). Never commit this file to version control or share it.
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
/// Links the node to an identity from objects-identity. The identity_id
/// is derived using `IdentityId::derive()` from the signer public key and nonce.
///
/// All fields are validated at construction time. Use `IdentityInfo::new()` to create
/// instances with validated data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// Identity ID from objects-identity.
    ///
    /// Format validated by `IdentityId::parse()`.
    /// Example: `obj_2dMiYc8RhnYkorPc5pVh9`
    identity_id: IdentityId,

    /// Registered handle from objects-identity.
    ///
    /// Format validated by `Handle::parse()`. See objects-identity
    /// for validation rules (lowercase, length limits, reserved words).
    handle: Handle,

    /// 8-byte nonce used for identity ID derivation.
    ///
    /// The identity ID is derived using `IdentityId::derive(signer_public_key, nonce)`.
    /// This nonce is required for verification.
    nonce: [u8; 8],

    /// Type of signer used for this identity.
    ///
    /// - `Passkey`: WebAuthn/FIDO2 credential (secp256r1/P-256)
    /// - `Wallet`: Ethereum EOA (secp256k1)
    signer_type: SignerType,
}

impl IdentityInfo {
    /// Create a new IdentityInfo with validated fields.
    ///
    /// All parameters must be pre-validated. Use `IdentityId::parse()` and
    /// `Handle::parse()` to validate strings before passing them to this constructor.
    pub fn new(
        identity_id: IdentityId,
        handle: Handle,
        nonce: [u8; 8],
        signer_type: SignerType,
    ) -> Self {
        Self {
            identity_id,
            handle,
            nonce,
            signer_type,
        }
    }

    /// Get the identity ID.
    pub fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    /// Get the handle.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Get the nonce.
    pub fn nonce(&self) -> &[u8; 8] {
        &self.nonce
    }

    /// Get the signer type.
    pub fn signer_type(&self) -> SignerType {
        self.signer_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objects_test_utils::identity;

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

        // Use canonical test identity from objects-test-utils
        let identity_id = identity::test_identity_id();
        let handle = Handle::parse("test_user").unwrap();

        let identity_info = IdentityInfo::new(
            identity_id.clone(),
            handle.clone(),
            [1, 2, 3, 4, 5, 6, 7, 8],
            SignerType::Passkey,
        );

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
        assert_eq!(deser_identity.identity_id(), &identity_id);
        assert_eq!(deser_identity.handle(), &handle);
        assert_eq!(deser_identity.nonce(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(deser_identity.signer_type(), SignerType::Passkey);
    }

    #[test]
    fn test_identity_info_signer_types() {
        // Use random identities with proper derivation
        let passkey_identity = identity::random_passkey_identity();
        let wallet_identity = identity::random_wallet_identity();

        let handle_passkey = Handle::parse("passkey_user").unwrap();
        let handle_wallet = Handle::parse("wallet_user").unwrap();

        let passkey_info = IdentityInfo::new(
            passkey_identity.identity_id.clone(),
            handle_passkey,
            passkey_identity.nonce,
            SignerType::Passkey,
        );

        let wallet_info = IdentityInfo::new(
            wallet_identity.identity_id.clone(),
            handle_wallet,
            wallet_identity.nonce,
            SignerType::Wallet,
        );

        // Serialize and deserialize both
        let passkey_json = serde_json::to_string(&passkey_info).unwrap();
        let wallet_json = serde_json::to_string(&wallet_info).unwrap();

        let passkey_deser: IdentityInfo = serde_json::from_str(&passkey_json).unwrap();
        let wallet_deser: IdentityInfo = serde_json::from_str(&wallet_json).unwrap();

        assert_eq!(passkey_deser.signer_type(), SignerType::Passkey);
        assert_eq!(wallet_deser.signer_type(), SignerType::Wallet);
        assert_eq!(passkey_deser.identity_id(), &passkey_identity.identity_id);
        assert_eq!(wallet_deser.identity_id(), &wallet_identity.identity_id);
    }

    #[test]
    fn test_reject_invalid_handle() {
        // Uppercase should be rejected
        assert!(Handle::parse("UPPERCASE").is_err());

        // Leading underscore should be rejected
        assert!(Handle::parse("_invalid").is_err());

        // Too long (>30 chars) should be rejected
        assert!(Handle::parse("this_handle_is_way_too_long_for_validation").is_err());

        // Empty should be rejected
        assert!(Handle::parse("").is_err());

        // Reserved word should be rejected
        assert!(Handle::parse("admin").is_err());
    }

    #[test]
    fn test_reject_malformed_identity_id() {
        // Missing obj_ prefix
        assert!(IdentityId::parse("2dMiYc8RhnYkorPc5pVh9").is_err());

        // Too short
        assert!(IdentityId::parse("obj_abc").is_err());

        // Empty
        assert!(IdentityId::parse("").is_err());

        // Invalid base58 characters (0, O, I, l not in base58)
        assert!(IdentityId::parse("obj_0OIl").is_err());
    }

    #[test]
    fn test_nonce_byte_order_preservation() {
        let nonce: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let identity_id = identity::test_identity_id();
        let handle = Handle::parse("test").unwrap();

        let info = IdentityInfo::new(identity_id, handle, nonce, SignerType::Passkey);

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: IdentityInfo = serde_json::from_str(&json).unwrap();

        // Verify exact byte-for-byte match
        assert_eq!(deserialized.nonce(), &nonce);
    }

    #[test]
    fn test_identity_info_getters() {
        let identity_id = identity::test_identity_id();
        let handle = Handle::parse("test_user").unwrap();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];

        let info = IdentityInfo::new(
            identity_id.clone(),
            handle.clone(),
            nonce,
            SignerType::Passkey,
        );

        // Test all getters
        assert_eq!(info.identity_id(), &identity_id);
        assert_eq!(info.handle(), &handle);
        assert_eq!(info.nonce(), &nonce);
        assert_eq!(info.signer_type(), SignerType::Passkey);
    }

    #[test]
    fn test_node_state_clone_independence() {
        let identity_id = identity::test_identity_id();
        let handle = Handle::parse("alice").unwrap();

        let state = NodeState {
            node_key: SecretKey::generate(&mut rand::rng()),
            identity: Some(IdentityInfo::new(
                identity_id,
                handle,
                [1, 2, 3, 4, 5, 6, 7, 8],
                SignerType::Passkey,
            )),
        };

        let cloned = state.clone();

        // Verify keys are independent (comparing public keys)
        assert_eq!(
            state.node_key.public().to_string(),
            cloned.node_key.public().to_string()
        );

        // Verify identity is independent
        assert_eq!(
            state.identity.as_ref().unwrap().handle(),
            cloned.identity.as_ref().unwrap().handle()
        );
    }
}
