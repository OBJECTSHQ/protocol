//! OBJECTS network endpoint.
//!
//! Wraps Iroh's Endpoint with OBJECTS-specific configuration.

use iroh::discovery::static_provider::StaticProvider;
use iroh::endpoint::{Endpoint, RelayMode};

use crate::{
    ALPN, Error, NodeAddr, NodeId, Result, SecretKey, config::NetworkConfig, connection::Connection,
};

/// OBJECTS network endpoint.
///
/// This is the main entry point for establishing connections to other
/// OBJECTS nodes. It wraps Iroh's [`Endpoint`] with OBJECTS-specific
/// configuration (ALPN, relay URL, timeouts).
///
/// # Example
///
/// ```rust,ignore
/// use objects_transport::{ObjectsEndpoint, NetworkConfig};
///
/// let endpoint = ObjectsEndpoint::builder()
///     .config(NetworkConfig::devnet())
///     .bind().await?;
///
/// let conn = endpoint.connect(peer_addr).await?;
/// ```
pub struct ObjectsEndpoint {
    inner: Endpoint,
    secret_key: SecretKey,
    config: NetworkConfig,
}

impl ObjectsEndpoint {
    /// Create a new endpoint builder.
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::new()
    }

    /// This node's public key (NodeId).
    ///
    /// Per RFC-002 §3.1, this uniquely identifies the node for
    /// transport-level authentication.
    pub fn node_id(&self) -> NodeId {
        self.inner.id()
    }

    /// This node's full address including relay and direct addresses.
    ///
    /// Per RFC-002 §3.2. Use this for sharing with other nodes.
    ///
    /// Note: This returns a snapshot of the current address. For a
    /// dialable address over the internet, ensure the endpoint is
    /// online first.
    pub fn node_addr(&self) -> NodeAddr {
        self.inner.addr()
    }

    /// This node's secret key.
    ///
    /// Used for signing discovery announcements.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// The network configuration used by this endpoint.
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// The underlying Iroh endpoint.
    ///
    /// Useful for advanced operations or discovery integration.
    pub fn inner(&self) -> &Endpoint {
        &self.inner
    }

    /// Connect to a remote node.
    ///
    /// Establishes a QUIC connection to the node at `addr` using the
    /// OBJECTS ALPN identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails (no route, timeout,
    /// ALPN mismatch, etc.).
    pub async fn connect(&self, addr: impl Into<NodeAddr>) -> Result<Connection> {
        let addr = addr.into();
        let conn = self
            .inner
            .connect(addr, ALPN)
            .await
            .map_err(|e| Error::DialFailed(e.to_string()))?;

        Ok(Connection::new(conn))
    }

    /// Accept an incoming connection.
    ///
    /// Returns the next incoming connection that negotiated the
    /// OBJECTS ALPN identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails.
    pub async fn accept(&self) -> Result<Connection> {
        let incoming = self
            .inner
            .accept()
            .await
            .ok_or_else(|| Error::Iroh(anyhow::anyhow!("endpoint closed")))?;

        let conn = incoming.await.map_err(|e| Error::Iroh(e.into()))?;

        Ok(Connection::new(conn))
    }

    /// Gracefully close this endpoint.
    ///
    /// Waits for all connections to close.
    pub async fn close(self) -> Result<()> {
        self.inner.close().await;
        Ok(())
    }
}

/// Builder for [`ObjectsEndpoint`].
pub struct EndpointBuilder {
    config: Option<NetworkConfig>,
    secret_key: Option<SecretKey>,
    static_discovery: Option<StaticProvider>,
    relay_mode: Option<RelayMode>,
}

impl EndpointBuilder {
    /// Create a new builder with no configuration.
    pub fn new() -> Self {
        Self {
            config: None,
            secret_key: None,
            static_discovery: None,
            relay_mode: None,
        }
    }

    /// Set the network configuration.
    pub fn config(mut self, config: NetworkConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set a specific secret key.
    ///
    /// If not set, a random key will be generated.
    pub fn secret_key(mut self, key: SecretKey) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Generate a random secret key.
    pub fn random_secret_key(mut self) -> Self {
        self.secret_key = Some(SecretKey::generate(&mut rand::rng()));
        self
    }

    /// Add a static discovery provider.
    ///
    /// Useful in tests to share peer addresses between endpoints
    /// without relying on external discovery services.
    pub fn static_discovery(mut self, provider: StaticProvider) -> Self {
        self.static_discovery = Some(provider);
        self
    }

    /// Set the relay mode.
    ///
    /// Defaults to `RelayMode::Default` if not set. Use
    /// `RelayMode::Disabled` for tests that don't need relay.
    pub fn relay_mode(mut self, mode: RelayMode) -> Self {
        self.relay_mode = Some(mode);
        self
    }

    /// Bind the endpoint and start listening.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    pub async fn bind(self) -> Result<ObjectsEndpoint> {
        let config = self.config.unwrap_or_default();
        let secret_key = self
            .secret_key
            .unwrap_or_else(|| SecretKey::generate(&mut rand::rng()));

        // Build the Iroh endpoint with OBJECTS configuration.
        // When relay is disabled (tests), use empty_builder to avoid N0 preset
        // interference. When relay is enabled (production), use the full builder.
        let relay_mode = self.relay_mode.unwrap_or(RelayMode::Default);
        let mut builder = match relay_mode {
            RelayMode::Disabled => Endpoint::empty_builder(RelayMode::Disabled),
            _ => {
                let b = Endpoint::builder();
                // Clear default N0 discovery - we use our own gossip-based discovery
                b.clear_discovery().relay_mode(relay_mode)
            }
        };

        builder = builder
            .secret_key(secret_key.clone())
            .alpns(vec![ALPN.to_vec()]);

        // Add static discovery if provided (used in tests)
        if let Some(discovery) = self.static_discovery {
            builder = builder.discovery(discovery);
        }

        let inner = builder.bind().await.map_err(|e| Error::Iroh(e.into()))?;

        Ok(ObjectsEndpoint {
            inner,
            secret_key,
            config,
        })
    }
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}
