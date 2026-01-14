//! Project types for OBJECTS Protocol.

use objects_identity::IdentityId;
use serde::{Deserialize, Serialize};

/// A project representing an organizational grouping of assets.
///
/// A Project maps 1:1 with a Sync layer Replica (RFC-003).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Unique identifier (derived from ReplicaId).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Project description.
    pub description: Option<String>,
    /// Identity ID of the project owner (RFC-001).
    pub owner_id: IdentityId,
    /// Unix timestamp (seconds) when project was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when project was last updated.
    pub updated_at: u64,
}
