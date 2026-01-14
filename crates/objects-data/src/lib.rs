//! Asset, Project, and Reference types for OBJECTS Protocol.
//!
//! This crate implements RFC-004: OBJECTS Data Protocol.

pub mod asset;
pub mod project;
pub mod reference;

mod error;
mod proto;

pub use asset::{Asset, ContentHash, Nonce, SignedAsset};
pub use error::Error;
pub use project::Project;
pub use reference::{Reference, ReferenceType};
