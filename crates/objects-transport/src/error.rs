//! Error types for transport operations.
//!
//! Per RFC-002 §6.3.

use std::time::Duration;

use thiserror::Error;

/// Transport layer error.
///
/// Per RFC-002 §6.3, transport-level errors follow Iroh's error semantics.
#[derive(Debug, Error)]
pub enum Error {
    // --- Connection errors (RFC-002 §6.3) ---
    /// Unable to establish connection (no route, refused).
    #[error("dial failed: {0}")]
    DialFailed(String),

    /// Cannot reach configured relay.
    #[error("relay not available: {0}")]
    RelayNotAvailable(String),

    /// Connection or operation timed out.
    #[error("timeout after {0:?}")]
    Timeout(Duration),

    /// Peer closed the connection.
    #[error("remote closed connection")]
    RemoteClosed,

    /// ALPN negotiation failed.
    #[error("protocol mismatch: expected {expected}, got {got}")]
    ProtocolMismatch { expected: String, got: String },

    // --- Discovery errors ---
    /// Announcement signature verification failed.
    ///
    /// Per RFC-002 §7.5, nodes MUST verify signatures before accepting
    /// announcements. Invalid signatures MUST be rejected.
    #[error("invalid announcement signature: {0}")]
    InvalidSignature(String),

    /// Announcement is too old to be accepted.
    ///
    /// Per RFC-002 §5.4.2, nodes SHOULD discard announcements older
    /// than 24 hours.
    #[error("stale announcement ({age:?} old)")]
    StaleAnnouncement { age: Duration },

    /// Too many announcements from this peer.
    ///
    /// Per RFC-002 §7.5, nodes SHOULD implement rate limiting.
    #[error("rate limited")]
    RateLimited,

    /// Failed to join discovery topic.
    #[error("discovery error: {0}")]
    Discovery(String),

    // --- Encoding/decoding errors ---
    /// Failed to encode announcement.
    #[error("encode error: {0}")]
    Encode(String),

    /// Failed to decode announcement.
    #[error("decode error: {0}")]
    Decode(String),

    // --- Internal errors ---
    /// Iroh library error.
    #[error("iroh: {0}")]
    Iroh(#[from] anyhow::Error),

    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for transport operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Configuration validation error.
///
/// Returned when [`NetworkConfig`] or [`DiscoveryConfig`] is built with
/// values that violate RFC-002 requirements.
///
/// [`NetworkConfig`]: crate::NetworkConfig
/// [`DiscoveryConfig`]: crate::DiscoveryConfig
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A configuration value is below the RFC-002 minimum.
    #[error("{field} must be at least {minimum}, got {provided}")]
    BelowMinimum {
        field: &'static str,
        minimum: usize,
        provided: usize,
    },

    /// Invalid relay URL.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),

    /// A configuration value exceeds the maximum allowed.
    #[error("{field} must be at most {maximum}, got {provided}")]
    AboveMaximum {
        field: &'static str,
        maximum: u64,
        provided: u64,
    },

    /// Invalid idle timeout duration.
    #[error("idle timeout conversion failed: {0}")]
    InvalidIdleTimeout(String),

    /// A configuration value is invalid relative to another value.
    #[error("{field} must be greater than {other_field} ({field_value:?} <= {other_value:?})")]
    InvalidRelation {
        field: &'static str,
        field_value: Duration,
        other_field: &'static str,
        other_value: Duration,
    },
}
