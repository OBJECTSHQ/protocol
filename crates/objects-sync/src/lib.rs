//! Blob and metadata sync for OBJECTS Protocol.
//!
//! This crate implements RFC-003: OBJECTS Sync Protocol.

pub mod blobs;
pub mod docs;
pub mod tickets;

mod error;

pub use error::Error;
