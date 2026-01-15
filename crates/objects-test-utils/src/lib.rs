//! Shared test utilities for OBJECTS Protocol.
//!
//! This crate provides standardized test utilities across all OBJECTS Protocol tests,
//! eliminating duplication and ensuring consistency.
//!
//! ## Design Principles
//!
//! - **Always use `OsRng`** for cryptographic randomness (per CLAUDE.md)
//! - **Return structured types** instead of tuples for clarity
//! - **Single source of truth** for RFC-001 test vectors
//! - **Tier-based organization** mirroring production dependencies
//!
//! ## Module Organization
//!
//! - [`crypto`] - Cryptographic primitives (keypairs, nonces, encryption)
//! - [`time`] - Timestamp utilities
//! - [`rfc_vectors`] - RFC-001 canonical test vectors
//! - [`identity`] - Identity factories (depends on crypto, rfc_vectors)
//! - [`data`] - Asset, Project, SignedAsset factories (depends on identity)
//! - [`transport`] - Endpoint and networking utilities (depends on transport)
//! - [`sync`] - SyncEngine utilities (depends on transport, data)
//!
//! ## Quick Start
//!
//! ```rust
//! use objects_test_utils::{crypto, identity, time};
//!
//! // Get RFC-001 canonical identity
//! let id = identity::test_identity_id();
//! assert_eq!(id.as_str(), "obj_2dMiYc8RhnYkorPc5pVh9");
//!
//! // Generate random identity
//! let random = identity::random_passkey_identity();
//! assert!(random.identity_id.as_str().starts_with("obj_"));
//!
//! // Generate a nonce
//! let nonce = crypto::random_nonce();
//! assert_eq!(nonce.len(), 8);
//! ```

pub mod crypto;
pub mod identity;
pub mod rfc_vectors;
pub mod time;

// Higher tiers (will be implemented in later PRs)
// pub mod data;
// pub mod transport;
// pub mod sync;

// Re-export commonly used types for convenience
pub use crypto::{PasskeyKeypair, WalletKeypair};
pub use identity::{RandomPasskeyIdentity, RandomWalletIdentity};
