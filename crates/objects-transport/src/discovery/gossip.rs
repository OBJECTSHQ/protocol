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

    /// Maximum clock skew tolerance for announcements.
    ///
    /// Announcements with timestamps further in the future than this
    /// will be rejected. Default: 5 minutes.
    pub max_clock_skew: Duration,

    /// Max announcements per minute from a single peer.
    ///
    /// Per RFC-002 §7.5.
    pub rate_limit_per_peer: u32,

    /// Maximum peers to track.
    pub max_peers: usize,

    /// Duration of the rate limit window.
    ///
    /// Rate limiting resets after this duration. Default: 60 seconds.
    pub rate_limit_window: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(3600), // 1 hour
            stale_threshold: Duration::from_secs(86400),  // 24 hours
            max_clock_skew: Duration::from_secs(300),     // 5 minutes
            rate_limit_per_peer: 10,
            max_peers: 1000,
            rate_limit_window: Duration::from_secs(60),
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
            max_clock_skew: Duration::from_secs(300),   // 5 minutes
            rate_limit_per_peer: 20,
            max_peers: 100,
            rate_limit_window: Duration::from_secs(60),
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
            config.rate_limit_window,
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
        let topic = gossip
            .subscribe_and_join(topic_id, bootstrap_ids)
            .await
            .map_err(|e| Error::Discovery(e.to_string()))?;

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

    /// Check if discovery is healthy (background tasks running).
    ///
    /// Returns `true` if both the receive and announce tasks are still running.
    /// Returns `false` if either task has finished (possibly due to an error).
    pub fn is_healthy(&self) -> bool {
        let receive_ok = self
            .receive_task
            .as_ref()
            .map(|t| !t.is_finished())
            .unwrap_or(false);
        let announce_ok = self
            .announce_task
            .as_ref()
            .map(|t| !t.is_finished())
            .unwrap_or(false);
        receive_ok && announce_ok
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
        let max_clock_skew = self.config.max_clock_skew;

        let receive_task = tokio::spawn(async move {
            Self::receive_loop(
                topic,
                peer_table,
                announcement_tx,
                stale_threshold,
                max_clock_skew,
            )
            .await;
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
        max_clock_skew: Duration,
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

                    // Reject future-dated announcements (clock skew protection)
                    if announcement.is_from_future(max_clock_skew) {
                        debug!(
                            "Rejecting future-dated announcement from {}",
                            announcement.node_id.fmt_short()
                        );
                        continue;
                    }

                    // Check staleness (RFC-002 §5.4.2)
                    if announcement.age() > stale_threshold {
                        debug!(
                            "Stale announcement from {} ({:?} old)",
                            announcement.node_id.fmt_short(),
                            announcement.age()
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
                        debug!(
                            "Discovered peer {} (relay: {:?})",
                            announcement.node_id.fmt_short(),
                            announcement.relay_url.as_ref().map(|u| u.as_str())
                        );

                        // Notify subscribers
                        let _ = announcement_tx.send(announcement);
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

        warn!("Discovery receive loop ended unexpectedly");
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
            let announcement = DiscoveryAnnouncement::new(endpoint.secret_key(), relay_url);
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
                    warn!("Failed to subscribe to discovery topic: {}", e);
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
        let announcement = DiscoveryAnnouncement::new(self.endpoint.secret_key(), relay_url);
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

    async fn peers(&self) -> Vec<NodeAddr> {
        let table = self.peer_table.read().await;
        table.peers()
    }

    async fn peer_count(&self) -> usize {
        let table = self.peer_table.read().await;
        table.len()
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
