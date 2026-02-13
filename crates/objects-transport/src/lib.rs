//! P2P transport layer for OBJECTS Protocol.
//!
//! This crate implements RFC-002: OBJECTS Transport Protocol.
//!
//! # Protocol Independence
//!
//! OBJECTS uses Iroh as a transport substrate, but maintains its own:
//! - Discovery topic (`/objects/devnet/0.1/discovery`)
//! - Announcement format ([`DiscoveryAnnouncement`])
//! - Identity system (separate from NodeId)
//!
//! Iroh could be replaced with another QUIC implementation if needed.
//!
//! # Example
//!
//! ```rust,ignore
//! use objects_transport::{ObjectsEndpoint, NetworkConfig};
//!
//! let endpoint = ObjectsEndpoint::builder()
//!     .config(NetworkConfig::devnet())
//!     .bind().await?;
//!
//! // Connect to a peer
//! let conn = endpoint.connect(peer_addr).await?;
//! ```

pub mod announcement;
pub mod config;
pub mod connection;
pub mod discovery;
pub mod endpoint;

mod error;

// Re-export our types
pub use config::NetworkConfig;
pub use connection::Connection;
pub use endpoint::ObjectsEndpoint;
pub use error::{Error, Result};

/// Re-export Iroh's static discovery provider for test use.
pub use iroh::discovery::static_provider::StaticProvider;

/// Re-export Iroh's relay mode for endpoint configuration.
pub use iroh::endpoint::RelayMode;

// Re-export Iroh types with RFC-002 terminology.
// This provides protocol independence - if we switch from Iroh,
// we only change these re-exports.

/// A 32-byte Ed25519 public key uniquely identifying a node.
///
/// Per RFC-002 §3.1, this is the node's identity for transport-level
/// authentication. This is separate from OBJECTS IdentityId (user identity).
///
/// This is a re-export of Iroh's `EndpointId` (which aliases `PublicKey`).
pub type NodeId = iroh::EndpointId;

/// Network-level addressing information for connecting to a node.
///
/// Contains the node's public key plus transport addresses (relay URL,
/// direct addresses). Per RFC-002 §3.2.
///
/// This is a re-export of Iroh's `EndpointAddr`.
pub type NodeAddr = iroh::EndpointAddr;

/// Secret key for a node's identity.
///
/// Used to derive the NodeId and sign discovery announcements.
///
/// This is a re-export of Iroh's `SecretKey`.
pub type SecretKey = iroh::SecretKey;

/// URL of a relay server for NAT traversal.
///
/// This is a re-export of Iroh's `RelayUrl`.
pub type RelayUrl = iroh::RelayUrl;

/// ALPN identifier for OBJECTS Protocol v0.1.
///
/// Per RFC-002 §2.4, nodes MUST advertise this during connection establishment.
pub const ALPN: &[u8] = b"/objects/0.1";

/// Discovery topic for devnet.
///
/// Per RFC-002 §4.1. This is OBJECTS-specific, not shared with Iroh's network.
pub const DISCOVERY_TOPIC_DEVNET: &str = "/objects/devnet/0.1/discovery";

/// Default relay URL for OBJECTS network.
///
/// Per RFC-002 §4.1.
pub const DEFAULT_RELAY_URL: &str = "https://relay.objects.foundation";
