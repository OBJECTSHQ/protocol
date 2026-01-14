//! In-memory peer tracking for discovery.
//!
//! Per RFC-002 §5.4, nodes track discovered peers and their addresses.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{NodeAddr, NodeId};

/// Information about a discovered peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's network address.
    addr: NodeAddr,

    /// When we last received an announcement from this peer.
    last_seen: Instant,

    /// When we first discovered this peer.
    first_seen: Instant,

    /// Number of announcements received from this peer.
    ///
    /// Used for rate limiting per RFC-002 §7.5.
    announcement_count: u32,

    /// Timestamp when announcement_count was last reset.
    rate_limit_window_start: Instant,
}

impl PeerInfo {
    /// The peer's network address.
    pub fn addr(&self) -> &NodeAddr {
        &self.addr
    }

    /// When we last received an announcement from this peer.
    pub fn last_seen(&self) -> Instant {
        self.last_seen
    }

    /// When we first discovered this peer.
    pub fn first_seen(&self) -> Instant {
        self.first_seen
    }

    /// Number of announcements received from this peer.
    pub fn announcement_count(&self) -> u32 {
        self.announcement_count
    }
}

impl PeerInfo {
    fn new(addr: NodeAddr) -> Self {
        let now = Instant::now();
        Self {
            addr,
            last_seen: now,
            first_seen: now,
            announcement_count: 1,
            rate_limit_window_start: now,
        }
    }

    fn update(&mut self, addr: NodeAddr) {
        self.addr = addr;
        self.last_seen = Instant::now();
        self.announcement_count += 1;
    }

    /// Reset rate limit counter if the window has expired.
    fn maybe_reset_rate_limit(&mut self, window: Duration) {
        if self.rate_limit_window_start.elapsed() > window {
            self.announcement_count = 0;
            self.rate_limit_window_start = Instant::now();
        }
    }
}

/// In-memory peer tracking with rate limiting.
///
/// Per RFC-002 §5.4, maintains a table of known peers discovered
/// via gossip announcements.
///
/// # Rate Limiting
///
/// Per RFC-002 §7.5, implements per-peer rate limiting to prevent
/// flooding attacks. Peers that exceed the rate limit are rejected.
///
/// # Capacity
///
/// The table has a maximum capacity. When full, new peers are only
/// added if they replace a stale entry.
pub struct PeerTable {
    peers: HashMap<NodeId, PeerInfo>,
    max_peers: usize,
    /// Max announcements per peer per rate limit window.
    rate_limit: u32,
    /// Duration of the rate limit window.
    rate_limit_window: Duration,
}

impl PeerTable {
    /// Create a new peer table.
    ///
    /// # Arguments
    ///
    /// * `max_peers` - Maximum number of peers to track
    /// * `rate_limit` - Max announcements per peer per window
    /// * `rate_limit_window` - Duration of the rate limit window
    pub fn new(max_peers: usize, rate_limit: u32, rate_limit_window: Duration) -> Self {
        Self {
            peers: HashMap::with_capacity(max_peers.min(1000)),
            max_peers,
            rate_limit,
            rate_limit_window,
        }
    }

    /// Insert or update a peer.
    ///
    /// Returns `true` if the peer was accepted, `false` if rate limited
    /// or the table is full.
    ///
    /// # Rate Limiting
    ///
    /// Per RFC-002 §7.5, if a peer exceeds the rate limit, their
    /// announcement is rejected.
    pub fn insert(&mut self, addr: NodeAddr) -> bool {
        let node_id = addr.id;

        if let Some(info) = self.peers.get_mut(&node_id) {
            // Check rate limit for existing peer
            info.maybe_reset_rate_limit(self.rate_limit_window);

            if info.announcement_count >= self.rate_limit {
                // Rate limited
                return false;
            }

            info.update(addr);
            true
        } else {
            // New peer - check capacity
            if self.peers.len() >= self.max_peers {
                // Table full, reject
                return false;
            }

            self.peers.insert(node_id, PeerInfo::new(addr));
            true
        }
    }

    /// Get peer info by NodeId.
    pub fn get(&self, id: &NodeId) -> Option<&PeerInfo> {
        self.peers.get(id)
    }

    /// Remove a peer.
    pub fn remove(&mut self, id: &NodeId) -> Option<PeerInfo> {
        self.peers.remove(id)
    }

    /// Get all known peer addresses.
    pub fn peers(&self) -> Vec<NodeAddr> {
        self.peers.values().map(|info| info.addr.clone()).collect()
    }

    /// Remove peers not seen within the given threshold.
    ///
    /// Per RFC-002 §5.4.2, stale peers should be pruned.
    ///
    /// Returns the number of peers removed.
    pub fn prune_stale(&mut self, threshold: Duration) -> usize {
        let before = self.peers.len();
        self.peers
            .retain(|_, info| info.last_seen.elapsed() < threshold);
        before - self.peers.len()
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Check if the table is at capacity.
    pub fn is_full(&self) -> bool {
        self.peers.len() >= self.max_peers
    }

    /// Iterate over all peer info.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &PeerInfo)> {
        self.peers.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn make_node_addr() -> NodeAddr {
        let key = SecretKey::generate(&mut rand::rng());
        NodeAddr::from(key.public())
    }

    #[test]
    fn insert_and_get() {
        let mut table = PeerTable::new(100, 10, Duration::from_secs(60));
        let addr = make_node_addr();
        let node_id = addr.id;

        assert!(table.insert(addr.clone()));
        assert_eq!(table.len(), 1);

        let info = table.get(&node_id).unwrap();
        assert_eq!(info.addr().id, node_id);
        assert_eq!(info.announcement_count(), 1);
    }

    #[test]
    fn update_existing_peer() {
        let mut table = PeerTable::new(100, 10, Duration::from_secs(60));
        let addr = make_node_addr();
        let node_id = addr.id;

        assert!(table.insert(addr.clone()));
        assert!(table.insert(addr.clone()));
        assert_eq!(table.len(), 1);

        let info = table.get(&node_id).unwrap();
        assert_eq!(info.announcement_count(), 2);
    }

    #[test]
    fn rate_limiting() {
        // Allow only 3 per window
        let mut table = PeerTable::new(100, 3, Duration::from_secs(60));
        let addr = make_node_addr();

        // First 3 should succeed
        assert!(table.insert(addr.clone()));
        assert!(table.insert(addr.clone()));
        assert!(table.insert(addr.clone()));

        // 4th should be rate limited
        assert!(!table.insert(addr.clone()));
    }

    #[test]
    fn max_peers() {
        let mut table = PeerTable::new(2, 10, Duration::from_secs(60));

        let addr1 = make_node_addr();
        let addr2 = make_node_addr();
        let addr3 = make_node_addr();

        assert!(table.insert(addr1));
        assert!(table.insert(addr2));
        assert!(!table.insert(addr3)); // Should fail - at capacity
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn remove_peer() {
        let mut table = PeerTable::new(100, 10, Duration::from_secs(60));
        let addr = make_node_addr();
        let node_id = addr.id;

        table.insert(addr);
        assert_eq!(table.len(), 1);

        table.remove(&node_id);
        assert_eq!(table.len(), 0);
        assert!(table.get(&node_id).is_none());
    }

    #[test]
    fn prune_stale() {
        let mut table = PeerTable::new(100, 10, Duration::from_secs(60));

        // Insert a peer
        let addr = make_node_addr();
        table.insert(addr);
        assert_eq!(table.len(), 1);

        // Prune with zero threshold should remove all
        let pruned = table.prune_stale(Duration::ZERO);
        assert_eq!(pruned, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn peers_list() {
        let mut table = PeerTable::new(100, 10, Duration::from_secs(60));

        let addr1 = make_node_addr();
        let addr2 = make_node_addr();

        table.insert(addr1.clone());
        table.insert(addr2.clone());

        let peers = table.peers();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn rate_limit_window_reset() {
        // Use a very short window for testing
        let mut table = PeerTable::new(100, 2, Duration::from_millis(10));
        let addr = make_node_addr();

        // Hit rate limit
        assert!(table.insert(addr.clone()));
        assert!(table.insert(addr.clone()));
        assert!(!table.insert(addr.clone())); // Rate limited

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(15));

        // Should accept again after window reset
        assert!(table.insert(addr.clone()));
    }
}
