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
//! ## Module Organization (Tier 0 - Foundation)
//!
//! - [`crypto`] - Cryptographic primitives (keypairs, nonces, encryption)
//! - [`time`] - Timestamp utilities
//!
//! Higher-tier modules (identity, data, transport, sync) will be added in subsequent PRs.
//!
//! ## Quick Start
//!
//! ```rust
//! use objects_test_utils::{crypto, time};
//!
//! // Generate a passkey for testing
//! let keypair = crypto::passkey_keypair();
//! assert_eq!(keypair.public_key.len(), 33);
//!
//! // Generate a nonce
//! let nonce = crypto::random_nonce();
//! assert_eq!(nonce.len(), 8);
//!
//! // Get current timestamp
//! let now = time::now();
//! ```

pub mod crypto;
pub mod time;

// Re-export commonly used types for convenience
pub use crypto::{PasskeyKeypair, WalletKeypair};
