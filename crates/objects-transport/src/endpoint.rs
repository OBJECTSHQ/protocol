//! OBJECTS network endpoint.
//!
//! Wraps Iroh's Endpoint with OBJECTS-specific configuration.

use iroh::endpoint::{Endpoint, RelayMode, TransportConfig};

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
    /// # ALPN Verification
    ///
    /// Iroh automatically filters incoming connections by the ALPNs configured
    /// in [`EndpointBuilder::bind`]. Connections that don't negotiate a matching
    /// ALPN (in our case `/objects/0.1`) are rejected before reaching this method.
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

        // Iroh filters by ALPN configured in builder.alpns().
        // Only connections using OBJECTS ALPN reach this point.
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
}

impl EndpointBuilder {
    /// Create a new builder with no configuration.
    pub fn new() -> Self {
        Self {
            config: None,
            secret_key: None,
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

    /// Bind the endpoint and start listening.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    ///
    /// # Note on max_connections
    ///
    /// QUIC/Iroh doesn't have a built-in connection limit. The `max_connections`
    /// value in [`NetworkConfig`] is intended for application-level enforcement
    /// (e.g., via a connection tracker or semaphore in the accept loop).
    pub async fn bind(self) -> Result<ObjectsEndpoint> {
        let config = self.config.unwrap_or_default();
        let secret_key = self
            .secret_key
            .unwrap_or_else(|| SecretKey::generate(&mut rand::rng()));

        // Build transport config with RFC-002 §6 settings
        let mut transport_config = TransportConfig::default();

        // Apply idle timeout (RFC-002 §6.2)
        // Note: Duration::try_into() converts to IdleTimeout, which validates
        // that timeout in milliseconds fits in QUIC VarInt (< 2^62)
        let idle_timeout = config.idle_timeout().try_into().map_err(|_| {
            Error::Iroh(anyhow::anyhow!(
                "idle timeout {:?} exceeds QUIC VarInt maximum",
                config.idle_timeout()
            ))
        })?;
        transport_config.max_idle_timeout(Some(idle_timeout));

        // Apply max streams per connection (RFC-002 §6.1)
        // Safe cast: validated in NetworkConfigBuilder::build() to fit in u32
        let max_streams: u32 = config.max_streams_per_conn().try_into().map_err(|_| {
            Error::Iroh(anyhow::anyhow!(
                "max_streams_per_conn {} exceeds u32::MAX",
                config.max_streams_per_conn()
            ))
        })?;
        transport_config.max_concurrent_bidi_streams(max_streams.into());
        transport_config.max_concurrent_uni_streams(max_streams.into());

        // Build the Iroh endpoint with OBJECTS configuration
        let mut builder = Endpoint::builder()
            .secret_key(secret_key.clone())
            .alpns(vec![ALPN.to_vec()])
            .transport_config(transport_config);

        // Configure relay mode
        // For now, use default relay mode. In production, we'd configure
        // our own relay using RelayMode::Custom.
        builder = builder.relay_mode(RelayMode::Default);

        // Clear default discovery - we use our own gossip-based discovery
        builder = builder.clear_discovery();

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
