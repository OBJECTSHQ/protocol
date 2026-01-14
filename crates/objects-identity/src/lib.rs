//! Identity types, signatures, and ID derivation for OBJECTS Protocol.
//!
//! This crate implements RFC-001: OBJECTS Identity Protocol.

pub mod handle;
pub mod id;
pub mod message;
pub mod signature;
pub mod signer;
pub mod vault;

mod error;
pub mod proto;

pub use error::Error;
pub use handle::Handle;
pub use id::{IdentityId, NONCE_SIZE, generate_nonce};
pub use signature::Signature;
pub use signer::{Signer, SignerType};
pub use vault::VaultKeys;
