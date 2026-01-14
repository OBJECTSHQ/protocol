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
use crate::error::ConfigError;
use crate::{DISCOVERY_TOPIC_DEVNET, Error, NodeAddr, NodeId, Result};

/// Configuration for gossip discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to announce presence.
    ///
    /// Per RFC-002 §5.4.1, nodes SHOULD announce at least once per hour.
    announce_interval: Duration,

    /// Discard announcements older than this.
    ///
    /// Per RFC-002 §5.4.2, default is 24 hours.
    stale_threshold: Duration,

    /// Maximum clock skew tolerance for announcements.
    ///
    /// Announcements with timestamps further in the future than this
    /// will be rejected. Default: 5 minutes.
    max_clock_skew: Duration,

    /// Max announcements per minute from a single peer.
    ///
    /// Per RFC-002 §7.5.
    rate_limit_per_peer: u32,

    /// Maximum peers to track.
    max_peers: usize,

    /// Duration of the rate limit window.
    ///
    /// Rate limiting resets after this duration. Default: 60 seconds.
    rate_limit_window: Duration,
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
    /// Create a new configuration builder.
    pub fn builder() -> DiscoveryConfigBuilder {
        DiscoveryConfigBuilder::new()
    }

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

    // --- Getters ---

    /// How often to announce presence.
    ///
    /// Per RFC-002 §5.4.1, nodes SHOULD announce at least once per hour.
    pub fn announce_interval(&self) -> Duration {
        self.announce_interval
    }

    /// Discard announcements older than this.
    ///
    /// Per RFC-002 §5.4.2, default is 24 hours.
    pub fn stale_threshold(&self) -> Duration {
        self.stale_threshold
    }

    /// Maximum clock skew tolerance for announcements.
    ///
    /// Announcements with timestamps further in the future than this
    /// will be rejected. Default: 5 minutes.
    pub fn max_clock_skew(&self) -> Duration {
        self.max_clock_skew
    }

    /// Max announcements per minute from a single peer.
    ///
    /// Per RFC-002 §7.5.
    pub fn rate_limit_per_peer(&self) -> u32 {
        self.rate_limit_per_peer
    }

    /// Maximum peers to track.
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Duration of the rate limit window.
    ///
    /// Rate limiting resets after this duration. Default: 60 seconds.
    pub fn rate_limit_window(&self) -> Duration {
        self.rate_limit_window
    }
}

/// Builder for [`DiscoveryConfig`] with validation.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use objects_transport::DiscoveryConfig;
///
/// let config = DiscoveryConfig::builder()
///     .announce_interval(Duration::from_secs(300))
///     .stale_threshold(Duration::from_secs(7200))
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct DiscoveryConfigBuilder {
    announce_interval: Duration,
    stale_threshold: Duration,
    max_clock_skew: Duration,
    rate_limit_per_peer: u32,
    max_peers: usize,
    rate_limit_window: Duration,
}

impl DiscoveryConfigBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        let defaults = DiscoveryConfig::default();
        Self {
            announce_interval: defaults.announce_interval,
            stale_threshold: defaults.stale_threshold,
            max_clock_skew: defaults.max_clock_skew,
            rate_limit_per_peer: defaults.rate_limit_per_peer,
            max_peers: defaults.max_peers,
            rate_limit_window: defaults.rate_limit_window,
        }
    }

    /// Set how often to announce presence.
    pub fn announce_interval(mut self, interval: Duration) -> Self {
        self.announce_interval = interval;
        self
    }

    /// Set the stale threshold for announcements.
    pub fn stale_threshold(mut self, threshold: Duration) -> Self {
        self.stale_threshold = threshold;
        self
    }

    /// Set the maximum clock skew tolerance.
    pub fn max_clock_skew(mut self, skew: Duration) -> Self {
        self.max_clock_skew = skew;
        self
    }

    /// Set the rate limit per peer.
    pub fn rate_limit_per_peer(mut self, limit: u32) -> Self {
        self.rate_limit_per_peer = limit;
        self
    }

    /// Set the maximum number of peers to track.
    pub fn max_peers(mut self, max: usize) -> Self {
        self.max_peers = max;
        self
    }

    /// Set the rate limit window duration.
    pub fn rate_limit_window(mut self, window: Duration) -> Self {
        self.rate_limit_window = window;
        self
    }

    /// Build the configuration with validation.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if:
    /// - `max_peers` is 0
    /// - `rate_limit_per_peer` is 0
    /// - `stale_threshold` is not greater than `announce_interval`
    ///   (otherwise all announcements would be stale immediately)
    pub fn build(self) -> std::result::Result<DiscoveryConfig, ConfigError> {
        // max_peers must be > 0
        if self.max_peers == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "max_peers",
                minimum: 1,
                provided: 0,
            });
        }

        // rate_limit_per_peer must be > 0
        if self.rate_limit_per_peer == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "rate_limit_per_peer",
                minimum: 1,
                provided: 0,
            });
        }

        // stale_threshold must be > announce_interval
        // (otherwise announcements would be stale immediately after being sent)
        if self.stale_threshold <= self.announce_interval {
            return Err(ConfigError::InvalidRelation {
                field: "stale_threshold",
                field_value: self.stale_threshold,
                other_field: "announce_interval",
                other_value: self.announce_interval,
            });
        }

        Ok(DiscoveryConfig {
            announce_interval: self.announce_interval,
            stale_threshold: self.stale_threshold,
            max_clock_skew: self.max_clock_skew,
            rate_limit_per_peer: self.rate_limit_per_peer,
            max_peers: self.max_peers,
            rate_limit_window: self.rate_limit_window,
        })
    }
}

impl Default for DiscoveryConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Health status of gossip discovery.
///
/// Provides detailed information about the state of background tasks
/// and peer connectivity.
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Whether the receive task is still running.
    pub receive_task_running: bool,
    /// Whether the announce task is still running.
    pub announce_task_running: bool,
    /// Number of tracked peers.
    pub peer_count: usize,
}

impl HealthStatus {
    /// Returns true if all background tasks are running.
    pub fn is_healthy(&self) -> bool {
        self.receive_task_running && self.announce_task_running
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

    /// Channel for forwarding errors from background tasks.
    error_tx: broadcast::Sender<Arc<Error>>,

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
            config.max_peers(),
            config.rate_limit_per_peer(),
            config.rate_limit_window(),
        )));

        let (announcement_tx, _) = broadcast::channel(256);
        let (error_tx, _) = broadcast::channel(16);

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
            error_tx,
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
    ///
    /// For detailed status information, use [`health_status`](Self::health_status).
    pub fn is_healthy(&self) -> bool {
        self.health_status_sync().is_healthy()
    }

    /// Get detailed health status.
    ///
    /// Returns a [`HealthStatus`] struct with information about background task
    /// states and peer count.
    ///
    /// Note: This is an async method because it needs to acquire the peer table lock.
    /// For a quick synchronous check without peer count, use [`is_healthy`](Self::is_healthy).
    pub async fn health_status(&self) -> HealthStatus {
        let peer_count = self.peer_table.read().await.len();
        HealthStatus {
            receive_task_running: self
                .receive_task
                .as_ref()
                .map(|t| !t.is_finished())
                .unwrap_or(false),
            announce_task_running: self
                .announce_task
                .as_ref()
                .map(|t| !t.is_finished())
                .unwrap_or(false),
            peer_count,
        }
    }

    /// Get health status synchronously (without peer count).
    fn health_status_sync(&self) -> HealthStatus {
        HealthStatus {
            receive_task_running: self
                .receive_task
                .as_ref()
                .map(|t| !t.is_finished())
                .unwrap_or(false),
            announce_task_running: self
                .announce_task
                .as_ref()
                .map(|t| !t.is_finished())
                .unwrap_or(false),
            peer_count: 0, // Not available without async lock
        }
    }

    /// Subscribe to errors from background tasks.
    ///
    /// Returns a stream that yields errors when background tasks fail.
    /// Useful for monitoring and reacting to discovery failures.
    pub fn errors(&self) -> BoxStream<'static, Arc<Error>> {
        let mut rx = self.error_tx.subscribe();

        Box::pin(async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(err) => yield err,
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        warn!("Error stream lagged, dropped {} error(s)", count);
                        // Continue receiving after lag
                    }
                }
            }
        })
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
        let stale_threshold = self.config.stale_threshold();
        let max_clock_skew = self.config.max_clock_skew();

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
        let announce_interval = self.config.announce_interval();

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
                            announcement.node_id().fmt_short(),
                            e
                        );
                        continue;
                    }

                    // Reject future-dated announcements (clock skew protection)
                    if announcement.is_from_future(max_clock_skew) {
                        debug!(
                            "Rejecting future-dated announcement from {}",
                            announcement.node_id().fmt_short()
                        );
                        continue;
                    }

                    // Check staleness (RFC-002 §5.4.2)
                    if announcement.age() > stale_threshold {
                        debug!(
                            "Stale announcement from {} ({:?} old)",
                            announcement.node_id().fmt_short(),
                            announcement.age()
                        );
                        continue;
                    }

                    // Build NodeAddr from announcement
                    let mut addr = NodeAddr::from(announcement.node_id());
                    if let Some(relay) = announcement.relay_url() {
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
                            announcement.node_id().fmt_short(),
                            announcement.relay_url().map(|u| u.as_str())
                        );

                        // Notify subscribers
                        let _ = announcement_tx.send(announcement);
                    } else {
                        trace!(
                            "Announcement from {} rejected (rate limited or full)",
                            announcement.node_id().fmt_short()
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
        assert_eq!(config.announce_interval(), Duration::from_secs(3600));
        assert_eq!(config.stale_threshold(), Duration::from_secs(86400));
        assert_eq!(config.rate_limit_per_peer(), 10);
        assert_eq!(config.max_peers(), 1000);
    }

    #[test]
    fn devnet_config() {
        let config = DiscoveryConfig::devnet();
        assert_eq!(config.announce_interval(), Duration::from_secs(60));
        assert!(config.announce_interval() < DiscoveryConfig::default().announce_interval());
    }

    #[test]
    fn builder_creates_valid_config() {
        let config = DiscoveryConfig::builder()
            .announce_interval(Duration::from_secs(300))
            .stale_threshold(Duration::from_secs(7200))
            .max_peers(50)
            .rate_limit_per_peer(5)
            .build()
            .expect("valid config should build");

        assert_eq!(config.announce_interval(), Duration::from_secs(300));
        assert_eq!(config.stale_threshold(), Duration::from_secs(7200));
        assert_eq!(config.max_peers(), 50);
        assert_eq!(config.rate_limit_per_peer(), 5);
    }

    #[test]
    fn builder_validates_max_peers() {
        let result = DiscoveryConfig::builder().max_peers(0).build();
        assert!(matches!(
            result,
            Err(ConfigError::BelowMinimum {
                field: "max_peers",
                ..
            })
        ));
    }

    #[test]
    fn builder_validates_rate_limit_per_peer() {
        let result = DiscoveryConfig::builder().rate_limit_per_peer(0).build();
        assert!(matches!(
            result,
            Err(ConfigError::BelowMinimum {
                field: "rate_limit_per_peer",
                ..
            })
        ));
    }

    #[test]
    fn builder_validates_stale_threshold_greater_than_announce_interval() {
        // stale_threshold <= announce_interval should fail
        let result = DiscoveryConfig::builder()
            .announce_interval(Duration::from_secs(3600))
            .stale_threshold(Duration::from_secs(3600)) // equal, should fail
            .build();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidRelation {
                field: "stale_threshold",
                other_field: "announce_interval",
                ..
            })
        ));

        // stale_threshold < announce_interval should also fail
        let result = DiscoveryConfig::builder()
            .announce_interval(Duration::from_secs(3600))
            .stale_threshold(Duration::from_secs(1800)) // less than, should fail
            .build();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidRelation {
                field: "stale_threshold",
                other_field: "announce_interval",
                ..
            })
        ));

        // stale_threshold > announce_interval should succeed
        let result = DiscoveryConfig::builder()
            .announce_interval(Duration::from_secs(3600))
            .stale_threshold(Duration::from_secs(7200)) // greater than, should succeed
            .build();
        assert!(result.is_ok());
    }
}
