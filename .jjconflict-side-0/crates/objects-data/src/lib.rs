//! Asset, Project, and Reference types for OBJECTS Protocol.
//!
//! This crate implements RFC-004: OBJECTS Data Protocol.

pub mod asset;
pub mod encryption;
pub mod project;
pub mod reference;
pub mod storage;

mod error;
pub mod proto;

pub use asset::{Asset, ContentHash, Nonce, SignedAsset};
pub use error::Error;
pub use project::{Project, project_id_from_replica};
pub use reference::{CrossProjectReference, Reference, ReferenceType};
pub use storage::{
    ASSETS_PREFIX, KeyType, PROJECT_KEY, REFS_PREFIX, asset_key, parse_key, reference_key,
};
