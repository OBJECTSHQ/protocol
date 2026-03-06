//! Shared test utilities for OBJECTS Protocol.
//!
//! This crate provides standardized test utilities across all OBJECTS Protocol tests,
//! eliminating duplication and ensuring consistency.
//!
//! ## Design Principles
//!
//! - **Always use `OsRng`** for cryptographic randomness (per CLAUDE.md)
//! - **Return structured types** instead of tuples for clarity
//!
//! ## Module Organization
//!
//! **Tier 0 - Foundation:**
//! - [`crypto`] - Cryptographic primitives (keypairs, nonces, encryption)
//! - [`time`] - Timestamp utilities
//!
//! **Tier 1 - Identity:**
//! - [`identity`] - Identity factories and test identities
//!
//! **Tier 2 - Data:**
//! - [`data`] - Asset, Project, Reference, and SignedAsset factories
//!
//! **Tier 3 - Transport:**
//! - [`transport`] - Network endpoints, configurations, and connection testing
//!
//! **Tier 4 - Sync:**
//! - [`sync`] - Sync engine factories and sync operation testing
//!
//! ## Quick Start
//!
//! ```rust
//! use objects_test_utils::{crypto, identity, time};
//!
//! // Generate a passkey for testing
//! let keypair = crypto::passkey_keypair();
//! assert_eq!(keypair.public_key.len(), 33);
//!
//! // Get canonical test identity
//! let id = identity::test_identity_id();
//! assert_eq!(id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
//!
//! // Generate random identity
//! let random = identity::random_passkey_identity();
//! assert!(random.identity_id.as_str().starts_with("obj_"));
//! ```

pub mod crypto;
pub mod data;
pub mod identity;
pub mod sync;
pub mod time;
pub mod transport;

// Re-export commonly used types for convenience
pub use crypto::{PasskeyKeypair, WalletKeypair};
pub use data::{SignedAssetPasskeyBundle, SignedAssetWalletBundle};
pub use identity::{RandomPasskeyIdentity, RandomWalletIdentity};
pub use sync::TwoNodeTestHarness;
