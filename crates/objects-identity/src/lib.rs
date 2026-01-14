//! Identity types, signatures, and ID derivation for OBJECTS Protocol.
//!
//! This crate implements RFC-001: OBJECTS Identity Protocol.

pub mod handle;
pub mod id;
pub mod message;
pub mod signature;
pub mod signer;

mod error;
mod proto;

pub use error::Error;
pub use handle::Handle;
pub use id::{generate_nonce, IdentityId, NONCE_SIZE};
pub use signature::Signature;
pub use signer::{Signer, SignerType};
