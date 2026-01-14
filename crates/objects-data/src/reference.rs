//! Reference types for OBJECTS Protocol.

use serde::{Deserialize, Serialize};

use crate::asset::ContentHash;

/// Type of relationship between assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ReferenceType {
    /// Unknown relationship.
    Unspecified = 0,
    /// Source contains target (assembly → part).
    Contains = 1,
    /// Source depends on target.
    DependsOn = 2,
    /// Source is derived from target (version chain).
    DerivedFrom = 3,
    /// Generic reference.
    References = 4,
}

/// A typed link between assets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// Unique identifier within the project.
    pub id: String,
    /// ID of the source asset.
    pub source_asset_id: String,
    /// ID of the target asset.
    pub target_asset_id: String,
    /// Specific version of target (optional).
    pub target_content_hash: Option<ContentHash>,
    /// Type of relationship.
    pub reference_type: ReferenceType,
    /// Unix timestamp (seconds) when reference was created.
    pub created_at: u64,
}

/// A reference to an asset in another project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProjectReference {
    /// Unique identifier within the project.
    pub id: String,
    /// ID of the source asset (in this project).
    pub source_asset_id: String,
    /// ID of the target project.
    pub target_project_id: String,
    /// ID of the target asset in the target project.
    pub target_asset_id: String,
    /// Specific version of target (optional).
    pub target_content_hash: Option<ContentHash>,
    /// Type of relationship.
    pub reference_type: ReferenceType,
    /// Unix timestamp (seconds) when reference was created.
    pub created_at: u64,
}
