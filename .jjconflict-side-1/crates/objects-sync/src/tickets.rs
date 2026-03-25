//! Ticket creation and redemption utilities.
//!
//! Tickets are share-able tokens encoding:
//! - What data to sync (blob hash or replica ID)
//! - Where to fetch it (peer addresses)
//!
//! Tickets use Iroh's Base32 encoding with human-readable prefixes.
//!
//! # Example
//!
//! ```rust,no_run
//! use objects_sync::tickets::parse_ticket;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Parse a ticket string
//! match parse_ticket("blobaaaa...")? {
//!     objects_sync::tickets::Ticket::Blob(blob_ticket) => {
//!         println!("Blob hash: {}", blob_ticket.hash());
//!     }
//!     objects_sync::tickets::Ticket::Doc(doc_ticket) => {
//!         println!("Replica ID: {}", doc_ticket.capability.id());
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use iroh_blobs::ticket::BlobTicket;
use iroh_blobs::{BlobFormat, Hash};
use iroh_docs::{Capability, DocTicket, NamespaceId};
use objects_transport::NodeAddr;

use crate::{Error, Result};

/// A ticket for sharing data.
///
/// Automatically distinguishes between blob and doc tickets based on prefix.
#[derive(Debug, Clone)]
pub enum Ticket {
    /// Blob ticket (single content-addressed blob).
    Blob(BlobTicket),
    /// Doc ticket (replica with metadata entries).
    Doc(DocTicket),
}

impl std::fmt::Display for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ticket::Blob(t) => write!(f, "{}", t),
            Ticket::Doc(t) => write!(f, "{}", t),
        }
    }
}

/// Parses a ticket string (blob or doc).
///
/// Automatically detects ticket type from prefix:
/// - `blob...` → BlobTicket
/// - `doc...` → DocTicket
///
/// # Example
///
/// ```rust,no_run
/// use objects_sync::tickets::{parse_ticket, Ticket};
///
/// # fn example() -> anyhow::Result<()> {
/// match parse_ticket("blobaaaa...")? {
///     Ticket::Blob(blob_ticket) => {
///         println!("Downloading blob: {}", blob_ticket.hash());
///     }
///     Ticket::Doc(doc_ticket) => {
///         println!("Syncing replica: {}", doc_ticket.capability.id());
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_ticket(ticket_str: &str) -> Result<Ticket> {
    if ticket_str.starts_with("blob") {
        let blob_ticket = ticket_str
            .parse::<BlobTicket>()
            .map_err(|e| Error::InvalidTicket(e.to_string()))?;
        Ok(Ticket::Blob(blob_ticket))
    } else if ticket_str.starts_with("doc") {
        let doc_ticket = ticket_str
            .parse::<DocTicket>()
            .map_err(|e| Error::InvalidTicket(e.to_string()))?;
        Ok(Ticket::Doc(doc_ticket))
    } else {
        Err(Error::InvalidTicket(
            "ticket must start with 'blob' or 'doc'".to_string(),
        ))
    }
}

/// Helper to create a blob ticket.
///
/// # Example
///
/// ```rust,no_run
/// use objects_sync::tickets::create_blob_ticket;
/// use iroh_blobs::Hash;
/// use objects_transport::NodeAddr;
///
/// # fn example(hash: Hash, node_addr: objects_transport::NodeAddr) {
/// let ticket = create_blob_ticket(hash, node_addr);
/// println!("Share: {}", ticket);
/// # }
/// ```
pub fn create_blob_ticket(hash: Hash, node_addr: NodeAddr) -> BlobTicket {
    BlobTicket::new(node_addr, hash, BlobFormat::Raw)
}

/// Helper to create a read-only doc ticket.
///
/// # Example
///
/// ```rust,no_run
/// use objects_sync::tickets::create_doc_ticket;
/// use iroh_docs::NamespaceId;
/// use objects_transport::NodeAddr;
///
/// # fn example(replica_id: NamespaceId, nodes: Vec<objects_transport::NodeAddr>) {
/// let ticket = create_doc_ticket(replica_id, nodes);
/// println!("Share: {}", ticket);
/// # }
/// ```
pub fn create_doc_ticket(replica_id: NamespaceId, nodes: Vec<NodeAddr>) -> DocTicket {
    DocTicket {
        capability: Capability::Read(replica_id),
        nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_ticket_prefix() {
        let result = parse_ticket("invalid_prefix");
        assert!(result.is_err());
        match result {
            Err(Error::InvalidTicket(msg)) => {
                assert!(msg.contains("blob") || msg.contains("doc"));
            }
            _ => panic!("Expected InvalidTicket error"),
        }
    }

    #[test]
    fn test_empty_ticket() {
        let result = parse_ticket("");
        assert!(result.is_err());
    }

    // Note: Full integration tests with real tickets are in tests/integration_tests.rs
}
