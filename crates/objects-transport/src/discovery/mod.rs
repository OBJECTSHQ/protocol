//! Peer discovery for OBJECTS network.
//!
//! Per RFC-002 §5, discovery allows nodes to find and connect to other
//! participants in the OBJECTS network.
//!
//! # Discovery Mechanisms
//!
//! The protocol supports multiple discovery mechanisms via the [`Discovery`]
//! trait. The primary implementation is [`GossipDiscovery`], which uses
//! iroh-gossip for peer announcements.
//!
//! Per RFC-002 §5.5, discovery mechanisms are additive - a node MAY use
//! multiple mechanisms simultaneously.

mod gossip;
mod peer_table;

pub use gossip::{DiscoveryConfig, GossipDiscovery};
pub use peer_table::{PeerInfo, PeerTable};

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::{NodeAddr, Result, announcement::DiscoveryAnnouncement};

/// Discovery service abstraction.
///
/// Per RFC-002 §5.5, discovery mechanisms are extensible. This trait
/// allows different discovery implementations (gossip, DHT, mDNS) to
/// be used interchangeably.
///
/// # Security
///
/// All implementations MUST:
/// - Verify announcement signatures before accepting
/// - Reject stale announcements (>24h old)
/// - Implement rate limiting to prevent flooding
#[async_trait]
pub trait Discovery: Send + Sync + 'static {
    /// Broadcast our presence to the network.
    ///
    /// Per RFC-002 §5.4.1, nodes SHOULD announce:
    /// - Immediately upon joining the network
    /// - At least once per hour thereafter
    /// - After any change to relay URL or direct addresses
    async fn announce(&self) -> Result<()>;

    /// Stream of discovered peer announcements.
    ///
    /// Returns verified announcements from other nodes on the network.
    /// Implementations MUST verify signatures and filter stale
    /// announcements before yielding them.
    fn announcements(&self) -> BoxStream<'static, DiscoveryAnnouncement>;

    /// Get addresses of all known peers.
    ///
    /// Returns a snapshot of the current peer table.
    fn peers(&self) -> Vec<NodeAddr>;

    /// Get the number of known peers.
    fn peer_count(&self) -> usize {
        self.peers().len()
    }

    /// Shutdown the discovery service.
    ///
    /// Stops background tasks and releases resources.
    async fn shutdown(&mut self) -> Result<()>;
}
