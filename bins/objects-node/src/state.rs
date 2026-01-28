//! Node state types for persistent storage.
//!
//! The node state contains:
//! - Node keypair for transport-level authentication
//! - Optional OBJECTS identity information (if registered)

use objects_identity::{Handle, IdentityId, SignerType};
use objects_transport::SecretKey;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during state persistence operations.
#[derive(Debug, Error)]
pub enum StateError {
    /// I/O error reading or writing state file.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Error parsing JSON state file.
    #[error("Failed to parse state: {0}")]
    ParseError(#[from] serde_json::Error),

    /// File permissions error.
    #[error("Permission error: {0}")]
    PermissionError(String),
}

/// Result type for state operations.
pub type Result<T> = std::result::Result<T, StateError>;

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
/// On Unix systems, permissions are automatically set to 0o600 and verified.
/// On non-Unix platforms, a warning is logged as permission enforcement unavailable.
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
    node_key: SecretKey,

    /// OBJECTS identity information, if registered.
    ///
    /// `None` if the node hasn't been registered with an OBJECTS identity yet.
    /// A node can operate without an OBJECTS identity (anonymous mode) but cannot
    /// publish assets or participate in identity-gated features.
    identity: Option<IdentityInfo>,
}

impl NodeState {
    /// Load state from a file, or create new state with a fresh keypair if the file doesn't exist.
    ///
    /// If the file exists, it is loaded and verified. If it doesn't exist, a new node keypair
    /// is generated and the state is saved to the file with secure permissions (600).
    ///
    /// Uses atomic file creation to prevent race conditions where multiple processes
    /// attempt to create the file simultaneously.
    ///
    /// # Security
    ///
    /// The state file is created with 600 permissions (owner read/write only) to protect
    /// the node's private key. Permissions are verified after being set.
    #[tracing::instrument(skip(path), fields(path = %path.display()))]
    pub fn load_or_create(path: &Path) -> Result<Self> {
        // Try to load first
        match Self::load(path) {
            Ok(state) => {
                tracing::debug!(
                    public_key = %state.node_key.public(),
                    has_identity = state.identity.is_some(),
                    "Loaded existing state"
                );
                return Ok(state);
            }
            Err(StateError::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("State file not found, generating new keypair");
            }
            Err(e) => return Err(e),
        }

        // Generate new state
        let state = Self::generate_new();
        ensure_permissions(path)?;

        let contents = serde_json::to_string_pretty(&state)?;

        // Atomic file creation - fail if file exists (another process created it)
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(contents.as_bytes())
                    .map_err(|e| StateError::IoError(e))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                tracing::warn!("State file created by another process, loading it");
                return Self::load(path);
            }
            Err(e) => return Err(StateError::IoError(e)),
        }

        set_secure_permissions(path)?;

        tracing::info!(public_key = %state.node_key.public(), "Generated new state");
        Ok(state)
    }

    /// Load state from a file.
    ///
    /// Returns an error if the file doesn't exist or cannot be parsed.
    #[tracing::instrument(skip(path), fields(path = %path.display()))]
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&contents)?;
        tracing::debug!(
            public_key = %state.node_key.public(),
            has_identity = state.identity.is_some(),
            "Loaded state"
        );
        Ok(state)
    }

    /// Save state to a file with secure permissions.
    ///
    /// Creates parent directories if they don't exist. Sets file permissions to 600
    /// (owner read/write only) to protect the private key.
    #[tracing::instrument(skip(self, path), fields(path = %path.display()))]
    pub fn save(&self, path: &Path) -> Result<()> {
        ensure_permissions(path)?;

        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(path, contents)?;

        // Set and verify file permissions
        set_secure_permissions(path)?;

        tracing::info!("Saved state");
        Ok(())
    }

    /// Generate new node state with a fresh keypair.
    ///
    /// The node key is generated using cryptographically secure random bytes.
    /// The identity is set to `None` (not registered).
    pub fn generate_new() -> Self {
        Self {
            node_key: SecretKey::generate(&mut rand::rng()),
            identity: None,
        }
    }

    /// Get a reference to the node key.
    pub fn node_key(&self) -> &SecretKey {
        &self.node_key
    }

    /// Get a reference to the identity info.
    pub fn identity(&self) -> Option<&IdentityInfo> {
        self.identity.as_ref()
    }

    /// Set the identity for this node.
    pub fn set_identity(&mut self, identity: IdentityInfo) {
        self.identity = Some(identity);
    }

    /// Clear the identity (return to anonymous mode).
    pub fn clear_identity(&mut self) -> Option<IdentityInfo> {
        self.identity.take()
    }
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

/// Ensure parent directory exists and has correct permissions.
///
/// Creates parent directories if they don't exist.
fn ensure_permissions(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if parent.exists() {
            // Verify parent is a directory
            if !parent.is_dir() {
                return Err(StateError::PermissionError(format!(
                    "Parent path '{}' is not a directory",
                    parent.display()
                )));
            }
        } else {
            // Create parent directory
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Set file permissions to 0o600 and verify they were set correctly.
///
/// On Unix: sets owner-only read/write and verifies.
/// On non-Unix: logs warning about missing permission enforcement.
fn set_secure_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;

        // Verify permissions were actually set
        let actual = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if actual != 0o600 {
            // Delete file to prevent key exposure
            let _ = std::fs::remove_file(path);
            return Err(StateError::PermissionError(format!(
                "Failed to set secure permissions on '{}' (got 0o{:o}, expected 0o600)",
                path.display(),
                actual
            )));
        }
    }

    #[cfg(not(unix))]
    {
        tracing::warn!(
            path = %path.display(),
            "State file saved without secure permissions (not available on this platform)"
        );
    }

    Ok(())
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

    #[test]
    fn test_generate_new() {
        let state = NodeState::generate_new();

        // Should have a node key
        assert!(state.node_key.public().to_string().len() > 0);

        // Should not have an identity
        assert!(state.identity.is_none());
    }

    #[test]
    fn test_load_or_create_missing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // File doesn't exist yet
        assert!(!state_path.exists());

        // Load or create should create the file
        let state = NodeState::load_or_create(&state_path).unwrap();

        // File should now exist
        assert!(state_path.exists());

        // Should have generated a keypair
        assert!(state.node_key.public().to_string().len() > 0);

        // Should not have an identity
        assert!(state.identity.is_none());
    }

    #[test]
    fn test_load_missing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("missing.json");

        // Should return error
        let result = NodeState::load(&state_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let original_state = NodeState::generate_new();
        let original_pubkey = original_state.node_key.public().to_string();

        // Save
        original_state.save(&state_path).unwrap();

        // Load
        let loaded_state = NodeState::load(&state_path).unwrap();

        // Verify keypair matches
        assert_eq!(loaded_state.node_key.public().to_string(), original_pubkey);

        // Verify identity is None
        assert!(loaded_state.identity.is_none());
    }

    #[test]
    fn test_save_with_identity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let mut state = NodeState::generate_new();

        // Use validated types with proper constructors
        let identity_id = identity::test_identity_id();
        let handle = Handle::parse("test_handle").unwrap();

        state.set_identity(IdentityInfo::new(
            identity_id.clone(),
            handle.clone(),
            [1, 2, 3, 4, 5, 6, 7, 8],
            SignerType::Wallet,
        ));

        // Save
        state.save(&state_path).unwrap();

        // Load
        let loaded_state = NodeState::load(&state_path).unwrap();

        // Verify identity was persisted
        let loaded_identity = loaded_state.identity().unwrap();
        assert_eq!(loaded_identity.identity_id(), &identity_id);
        assert_eq!(loaded_identity.handle(), &handle);
        assert_eq!(loaded_identity.nonce(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(loaded_identity.signer_type(), SignerType::Wallet);
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let state = NodeState::generate_new();
        state.save(&state_path).unwrap();

        // Check file permissions
        let metadata = std::fs::metadata(&state_path).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Should be 0o600 (owner read/write only)
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_parent_directory_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_path = temp_dir
            .path()
            .join("nested")
            .join("dirs")
            .join("state.json");

        // Parent directories don't exist
        assert!(!nested_path.parent().unwrap().exists());

        let state = NodeState::generate_new();
        state.save(&nested_path).unwrap();

        // Parent directories should now exist
        assert!(nested_path.parent().unwrap().exists());
        assert!(nested_path.exists());
    }

    #[test]
    fn test_error_when_parent_is_file() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a file
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "test").unwrap();

        // Try to save state with the file as parent
        let state_path = file_path.join("state.json");
        let state = NodeState::generate_new();

        let result = state.save(&state_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_corrupted_json() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("corrupt.json");

        // Write invalid JSON
        std::fs::write(&state_path, "{invalid json").unwrap();

        let result = NodeState::load(&state_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_empty_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("empty.json");

        std::fs::write(&state_path, "").unwrap();

        let result = NodeState::load(&state_path);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_permission_restoration() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create file with wrong permissions
        let state = NodeState::generate_new();
        std::fs::write(&state_path, "{}").unwrap();
        let mut perms = std::fs::metadata(&state_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&state_path, perms).unwrap();

        // Save should fix permissions
        state.save(&state_path).unwrap();

        let metadata = std::fs::metadata(&state_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
}
