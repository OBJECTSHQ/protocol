//! Identity types, signatures, and ID derivation for OBJECTS Protocol.
//!
//! This crate implements RFC-001: OBJECTS Identity Protocol.

pub mod handle;
pub mod id;
pub mod signature;
pub mod signer;

mod error;
mod proto;

pub use error::Error;
pub use handle::Handle;
pub use id::IdentityId;
pub use signature::Signature;
pub use signer::{Signer, SignerType};
