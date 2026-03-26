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
//! // Generate an Ed25519 keypair for testing
//! let keypair = crypto::ed25519_keypair();
//! assert_eq!(keypair.public_key.len(), 32);
//!
//! // Get canonical test identity
//! let id = identity::test_identity_id();
//!
//! // Generate random identity
//! let random = identity::random_identity();
//! assert!(random.identity_id.as_str().starts_with("obj_"));
//! ```

pub mod crypto;
pub mod data;
pub mod identity;
pub mod sync;
pub mod time;
pub mod transport;

// Re-export commonly used types for convenience
pub use crypto::Ed25519Keypair;
pub use data::SignedAssetBundle;
pub use identity::RandomIdentity;
