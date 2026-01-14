//! Connection management for OBJECTS nodes.
//!
//! Wraps Iroh's Connection with OBJECTS-specific semantics.

use iroh::endpoint::{Connection as IrohConnection, RecvStream, SendStream};

use crate::{NodeId, Result};

/// An authenticated connection to a remote OBJECTS node.
///
/// Connections are established via [`ObjectsEndpoint::connect`] or
/// [`ObjectsEndpoint::accept`]. All traffic is encrypted via TLS 1.3.
///
/// [`ObjectsEndpoint::connect`]: crate::ObjectsEndpoint::connect
/// [`ObjectsEndpoint::accept`]: crate::ObjectsEndpoint::accept
pub struct Connection {
    inner: IrohConnection,
}

impl Connection {
    /// Create a new Connection wrapper.
    pub(crate) fn new(inner: IrohConnection) -> Self {
        Self { inner }
    }

    /// The remote peer's NodeId (public key).
    ///
    /// This is cryptographically verified during the TLS handshake.
    pub fn remote_node_id(&self) -> NodeId {
        self.inner.remote_id()
    }

    /// Open a new bidirectional stream.
    ///
    /// Returns a pair of (send, receive) streams for exchanging data.
    ///
    /// # Note
    ///
    /// Per QUIC semantics, the peer will only see the stream after you
    /// write to the send stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.inner
            .open_bi()
            .await
            .map_err(|e| crate::Error::Iroh(e.into()))
    }

    /// Accept an incoming bidirectional stream.
    ///
    /// Returns a pair of (send, receive) streams.
    ///
    /// # Note
    ///
    /// The peer must write to their send stream before this returns.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.inner
            .accept_bi()
            .await
            .map_err(|e| crate::Error::Iroh(e.into()))
    }

    /// Open a new unidirectional stream for sending.
    ///
    /// Returns a send stream. The peer will receive this via `accept_uni`.
    pub async fn open_uni(&self) -> Result<SendStream> {
        self.inner
            .open_uni()
            .await
            .map_err(|e| crate::Error::Iroh(e.into()))
    }

    /// Accept an incoming unidirectional stream.
    ///
    /// Returns a receive stream.
    pub async fn accept_uni(&self) -> Result<RecvStream> {
        self.inner
            .accept_uni()
            .await
            .map_err(|e| crate::Error::Iroh(e.into()))
    }

    /// Close the connection with an error code and reason.
    ///
    /// The error code is application-defined. OBJECTS reserves codes
    /// 0x4F42 through 0x4F5A per RFC-002 §6.3.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code.into(), reason);
    }

    /// Wait for the connection to be closed.
    ///
    /// Returns when the peer closes the connection or an error occurs.
    pub async fn closed(&self) {
        self.inner.closed().await;
    }

    /// Get the underlying Iroh connection.
    ///
    /// Useful for advanced operations.
    pub fn inner(&self) -> &IrohConnection {
        &self.inner
    }
}
