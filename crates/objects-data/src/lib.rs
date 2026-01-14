//! Asset, Project, and Reference types for OBJECTS Protocol.
//!
//! This crate implements RFC-004: OBJECTS Data Protocol.

pub mod asset;
pub mod project;
pub mod reference;
pub mod storage;

mod error;
mod proto;

pub use asset::{Asset, ContentHash, Nonce, SignedAsset};
pub use error::Error;
pub use project::Project;
pub use reference::{CrossProjectReference, Reference, ReferenceType};
pub use storage::{asset_key, parse_key, reference_key, KeyType, ASSETS_PREFIX, PROJECT_KEY, REFS_PREFIX};
