//! Iroh-based transport layer for OBJECTS Protocol.
//!
//! This crate implements RFC-002: OBJECTS Transport Protocol.

pub mod config;
pub mod discovery;
pub mod endpoint;

mod error;

pub use config::NetworkConfig;
pub use error::Error;

/// ALPN identifier for OBJECTS Protocol v0.1.
pub const ALPN: &[u8] = b"/objects/0.1";

/// Discovery topic for devnet.
pub const DISCOVERY_TOPIC_DEVNET: &str = "/objects/devnet/0.1/discovery";

/// Default relay URL.
pub const DEFAULT_RELAY_URL: &str = "https://relay.objects.foundation";
