//! Gossip-based peer discovery.
//!
//! Per RFC-002 §5, uses iroh-gossip for decentralized peer discovery.
//! This is OBJECTS-specific - we define our own discovery topic and
//! announcement format.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::BoxStream;
use iroh_gossip::api::{Event, GossipTopic};
use iroh_gossip::net::Gossip;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use crate::announcement::DiscoveryAnnouncement;
use crate::discovery::{Discovery, PeerTable};
use crate::endpoint::ObjectsEndpoint;
use crate::{DISCOVERY_TOPIC_DEVNET, Error, NodeAddr, NodeId, Result};

/// Configuration for gossip discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to announce presence.
    ///
    /// Per RFC-002 §5.4.1, nodes SHOULD announce at least once per hour.
    pub announce_interval: Duration,

    /// Discard announcements older than this.
    ///
    /// Per RFC-002 §5.4.2, default is 24 hours.
    pub stale_threshold: Duration,

    /// Max announcements per minute from a single peer.
    ///
    /// Per RFC-002 §7.5.
    pub rate_limit_per_peer: u32,

    /// Maximum peers to track.
    pub max_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(3600), // 1 hour
            stale_threshold: Duration::from_secs(86400),  // 24 hours
            rate_limit_per_peer: 10,
            max_peers: 1000,
        }
    }
}

impl DiscoveryConfig {
    /// Configuration suitable for development/testing.
    ///
    /// More aggressive intervals for faster iteration.
    pub fn devnet() -> Self {
        Self {
            announce_interval: Duration::from_secs(60), // 1 minute
            stale_threshold: Duration::from_secs(3600), // 1 hour
            rate_limit_per_peer: 20,
            max_peers: 100,
        }
    }
}

/// Gossip-based peer discovery.
///
/// Uses iroh-gossip to broadcast [`DiscoveryAnnouncement`] messages
/// on the OBJECTS discovery topic.
///
/// # Security
///
/// Per RFC-002 §7.5:
/// - Verifies all announcement signatures before accepting
/// - Rejects stale announcements (>24h old)
/// - Implements per-peer rate limiting
pub struct GossipDiscovery {
    /// The underlying gossip instance.
    gossip: Gossip,

    /// Reference to the endpoint for address info.
    endpoint: Arc<ObjectsEndpoint>,

    /// Tracked peers.
    peer_table: Arc<RwLock<PeerTable>>,

    /// Discovery configuration.
    config: DiscoveryConfig,

    /// Channel for forwarding verified announcements to subscribers.
    announcement_tx: broadcast::Sender<DiscoveryAnnouncement>,

    /// Handle to the background announcement receive task.
    receive_task: Option<JoinHandle<()>>,

    /// Handle to the periodic announce task.
    announce_task: Option<JoinHandle<()>>,

    /// Topic subscription handle.
    topic: Option<GossipTopic>,
}

impl GossipDiscovery {
    /// Create and start gossip discovery.
    ///
    /// This will:
    /// 1. Join the discovery topic
    /// 2. Connect to bootstrap nodes
    /// 3. Start periodic announcements
    /// 4. Start listening for peer announcements
    ///
    /// # Arguments
    ///
    /// * `gossip` - The iroh-gossip instance (from Router)
    /// * `endpoint` - The OBJECTS endpoint
    /// * `bootstrap` - Initial peers to connect to
    /// * `config` - Discovery configuration
    pub async fn new(
        gossip: Gossip,
        endpoint: Arc<ObjectsEndpoint>,
        bootstrap: Vec<NodeAddr>,
        config: DiscoveryConfig,
    ) -> Result<Self> {
        let peer_table = Arc::new(RwLock::new(PeerTable::new(
            config.max_peers,
            config.rate_limit_per_peer,
        )));

        let (announcement_tx, _) = broadcast::channel(256);

        // Generate topic ID from our discovery topic string
        let topic_id = blake3::hash(DISCOVERY_TOPIC_DEVNET.as_bytes()).into();

        // Extract bootstrap node IDs
        let bootstrap_ids: Vec<NodeId> = bootstrap.iter().map(|a| a.id).collect();

        info!(
            topic = DISCOVERY_TOPIC_DEVNET,
            bootstrap_count = bootstrap_ids.len(),
            "Joining discovery topic"
        );

        // Join the discovery topic with bootstrap nodes
        // TODO(deployment): For production, configure proper bootstrap nodes instead of
        // using this development-friendly conditional. Bootstrap nodes should be
        // persistent, well-known peers (e.g., dedicated discovery nodes on relay network).
        let topic = if bootstrap_ids.is_empty() {
            // First node in network: subscribe without waiting for peers
            // This enables single-node development and testing
            gossip
                .subscribe(topic_id, vec![])
                .await
                .map_err(|e| Error::Discovery(e.to_string()))?
        } else {
            // Joining existing network: wait for bootstrap peers
            // Ensures P2P connectivity before proceeding
            gossip
                .subscribe_and_join(topic_id, bootstrap_ids)
                .await
                .map_err(|e| Error::Discovery(e.to_string()))?
        };

        let mut discovery = Self {
            gossip,
            endpoint,
            peer_table,
            config,
            announcement_tx,
            receive_task: None,
            announce_task: None,
            topic: Some(topic),
        };

        // Start background tasks
        discovery.start_background_tasks();

        // Send initial announcement
        discovery.announce().await?;

        Ok(discovery)
    }

    /// Force an immediate announcement.
    ///
    /// Called when our address changes or on demand.
    pub async fn announce_now(&self) -> Result<()> {
        self.announce().await
    }

    /// Get detailed peer information including last-seen durations.
    ///
    /// Returns each peer's address and the elapsed time since last seen.
    /// Uses `try_read` to avoid blocking; returns empty on contention.
    pub fn peer_details(&self) -> Vec<(NodeAddr, std::time::Duration)> {
        match self.peer_table.try_read() {
            Ok(table) => table
                .iter()
                .map(|(_, info)| (info.addr.clone(), info.last_seen.elapsed()))
                .collect(),
            Err(_) => {
                warn!("Failed to acquire peer table lock for read, returning empty peer list");
                Vec::new()
            }
        }
    }

    /// Get the current relay URL from the endpoint.
    fn get_relay_url(endpoint: &ObjectsEndpoint) -> Option<crate::RelayUrl> {
        endpoint.node_addr().relay_urls().next().cloned()
    }

    /// Start background tasks for receiving and announcing.
    fn start_background_tasks(&mut self) {
        // Take ownership of the topic for the receive task
        let topic = self.topic.take().expect("topic should be set");

        // Spawn the receive task
        let peer_table = Arc::clone(&self.peer_table);
        let announcement_tx = self.announcement_tx.clone();
        let stale_threshold = self.config.stale_threshold;

        let receive_task = tokio::spawn(async move {
            Self::receive_loop(topic, peer_table, announcement_tx, stale_threshold).await;
        });

        self.receive_task = Some(receive_task);

        // Spawn the periodic announce task
        let endpoint = Arc::clone(&self.endpoint);
        let gossip = self.gossip.clone();
        let announce_interval = self.config.announce_interval;

        let announce_task = tokio::spawn(async move {
            Self::announce_loop(endpoint, gossip, announce_interval).await;
        });

        self.announce_task = Some(announce_task);
    }

    /// Background loop for receiving announcements.
    async fn receive_loop(
        mut topic: GossipTopic,
        peer_table: Arc<RwLock<PeerTable>>,
        announcement_tx: broadcast::Sender<DiscoveryAnnouncement>,
        stale_threshold: Duration,
    ) {
        debug!("Starting discovery receive loop");

        while let Some(event) = topic.next().await {
            match event {
                Ok(Event::Received(msg)) => {
                    trace!("Received gossip message ({} bytes)", msg.content.len());

                    // Decode the announcement
                    let announcement = match DiscoveryAnnouncement::decode(&msg.content) {
                        Ok(a) => a,
                        Err(e) => {
                            debug!("Failed to decode announcement: {}", e);
                            continue;
                        }
                    };

                    // Verify signature (RFC-002 §7.5)
                    if let Err(e) = announcement.verify() {
                        warn!(
                            "Invalid signature from {}: {}",
                            announcement.node_id.fmt_short(),
                            e
                        );
                        continue;
                    }

                    // Check staleness (RFC-002 §5.4.2)
                    let age = match announcement.age() {
                        Ok(age) => age,
                        Err(e) => {
                            debug!("Failed to get announcement age: {}", e);
                            continue;
                        }
                    };

                    if age > stale_threshold {
                        debug!(
                            "Stale announcement from {} ({:?} old)",
                            announcement.node_id.fmt_short(),
                            age
                        );
                        continue;
                    }

                    // Build NodeAddr from announcement
                    let mut addr = NodeAddr::from(announcement.node_id);
                    if let Some(ref relay) = announcement.relay_url {
                        addr = addr.with_relay_url(relay.clone());
                    }

                    // Insert into peer table (rate limiting applied)
                    let accepted = {
                        let mut table = peer_table.write().await;
                        table.insert(addr)
                    };

                    if accepted {
                        // Extract node_id before moving announcement
                        let node_id_str = announcement.node_id.fmt_short();
                        debug!(
                            "Discovered peer {} (relay: {:?})",
                            node_id_str,
                            announcement.relay_url.as_ref().map(|u| u.as_str())
                        );

                        // Notify subscribers
                        match announcement_tx.send(announcement) {
                            Ok(_) => {
                                debug!("Notified subscribers of peer {} discovery", node_id_str);
                            }
                            Err(_) => {
                                debug!(
                                    "No active subscribers for announcement from {}",
                                    node_id_str
                                );
                                // This is acceptable - subscribers may not exist yet
                            }
                        }
                    } else {
                        trace!(
                            "Announcement from {} rejected (rate limited or full)",
                            announcement.node_id.fmt_short()
                        );
                    }
                }
                Ok(Event::NeighborUp(node_id)) => {
                    debug!("Gossip neighbor up: {}", node_id.fmt_short());
                }
                Ok(Event::NeighborDown(node_id)) => {
                    debug!("Gossip neighbor down: {}", node_id.fmt_short());
                }
                Ok(Event::Lagged) => {
                    warn!("Gossip event stream lagged, some messages may be lost");
                }
                Err(e) => {
                    warn!("Error receiving gossip event: {}", e);
                }
            }
        }

        debug!("Discovery receive loop ended");
    }

    /// Background loop for periodic announcements.
    async fn announce_loop(endpoint: Arc<ObjectsEndpoint>, gossip: Gossip, interval: Duration) {
        debug!("Starting periodic announce loop (interval: {:?})", interval);

        let topic_id = blake3::hash(DISCOVERY_TOPIC_DEVNET.as_bytes()).into();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            // Get current relay URL
            let relay_url = Self::get_relay_url(&endpoint);

            // Create and sign announcement
            let announcement = match DiscoveryAnnouncement::new(endpoint.secret_key(), relay_url) {
                Ok(a) => a,
                Err(e) => {
                    warn!("Failed to create announcement: {}", e);
                    continue;
                }
            };
            let data = announcement.encode();

            // Broadcast to topic
            match gossip.subscribe(topic_id, Default::default()).await {
                Ok(mut topic) => {
                    if let Err(e) = topic.broadcast(data.into()).await {
                        warn!("Failed to broadcast announcement: {}", e);
                    } else {
                        trace!("Periodic announcement sent");
                    }
                }
                Err(e) => {
                    warn!("Failed to subscribe to gossip topic: {}", e);
                }
            }
        }
    }
}

#[async_trait]
impl Discovery for GossipDiscovery {
    async fn announce(&self) -> Result<()> {
        // Get current relay URL
        let relay_url = Self::get_relay_url(&self.endpoint);

        // Create and sign announcement
        let announcement = DiscoveryAnnouncement::new(self.endpoint.secret_key(), relay_url)?;
        let data = announcement.encode();

        // Broadcast via gossip
        let topic_id = blake3::hash(DISCOVERY_TOPIC_DEVNET.as_bytes()).into();

        let mut topic = self
            .gossip
            .subscribe(topic_id, Default::default())
            .await
            .map_err(|e| Error::Discovery(e.to_string()))?;

        topic
            .broadcast(data.into())
            .await
            .map_err(|e| Error::Discovery(e.to_string()))?;

        info!("Announced presence on discovery topic");
        Ok(())
    }

    fn announcements(&self) -> BoxStream<'static, DiscoveryAnnouncement> {
        let mut rx = self.announcement_tx.subscribe();

        Box::pin(async_stream::stream! {
            while let Ok(announcement) = rx.recv().await {
                yield announcement;
            }
        })
    }

    fn peers(&self) -> Vec<NodeAddr> {
        // Use try_read to avoid blocking - returns empty on contention
        // This is safe because peer list is eventually consistent
        match self.peer_table.try_read() {
            Ok(table) => table.peers(),
            Err(_) => {
                warn!("Failed to acquire peer table lock for read, returning empty peer list");
                Vec::new()
            }
        }
    }

    fn peer_count(&self) -> usize {
        match self.peer_table.try_read() {
            Ok(table) => table.len(),
            Err(_) => {
                warn!("Failed to acquire peer table lock for read, returning 0 peer count");
                0
            }
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down gossip discovery");

        // Abort background tasks
        if let Some(task) = self.receive_task.take() {
            task.abort();
        }
        if let Some(task) = self.announce_task.take() {
            task.abort();
        }

        // Prune peer table
        {
            let mut table = self.peer_table.write().await;
            let pruned = table.prune_stale(Duration::ZERO);
            debug!("Pruned {} peers on shutdown", pruned);
        }

        Ok(())
    }
}

impl Drop for GossipDiscovery {
    fn drop(&mut self) {
        // Abort tasks on drop if not already shut down
        if let Some(task) = self.receive_task.take() {
            task.abort();
        }
        if let Some(task) = self.announce_task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.announce_interval, Duration::from_secs(3600));
        assert_eq!(config.stale_threshold, Duration::from_secs(86400));
        assert_eq!(config.rate_limit_per_peer, 10);
        assert_eq!(config.max_peers, 1000);
    }

    #[test]
    fn devnet_config() {
        let config = DiscoveryConfig::devnet();
        assert_eq!(config.announce_interval, Duration::from_secs(60));
        assert!(config.announce_interval < DiscoveryConfig::default().announce_interval);
    }
}
