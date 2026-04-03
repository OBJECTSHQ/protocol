//! FFI-safe types exposed to Kotlin and Swift.
//!
//! These mirror the proto-generated API types but use only primitives
//! that uniffi can represent: String, u32, u64, Vec<u8>, Option, bool.
//! No prost, irpc, or iroh types cross the FFI boundary.

use objects_core::api::types::{
    AssetInfo as ProtoAssetInfo, HealthResponse, IdentityInfo as ProtoIdentityInfo,
    ListAssetsResponse, ListProjectsResponse, ListVaultResponse, PeerInfo as ProtoPeerInfo,
    ProjectInfo as ProtoProjectInfo, StatusResponse, VaultEntry as ProtoVaultEntry,
};
use objects_core::rpc::proto::ListPeersResponse;

/// Node health status.
#[derive(uniffi::Record)]
pub struct HealthInfo {
    pub status: String,
}

/// Node status including identity and network info.
#[derive(uniffi::Record)]
pub struct StatusInfo {
    pub node_id: String,
    pub relay_url: String,
    pub peer_count: u32,
    pub identity: Option<IdentityInfo>,
}

/// Registered identity information.
#[derive(uniffi::Record)]
pub struct IdentityInfo {
    pub id: String,
    pub handle: String,
    /// Raw 8-byte nonce used in ID derivation.
    pub nonce: Vec<u8>,
}

/// Discovered peer connection info.
#[derive(uniffi::Record)]
pub struct PeerConnectionInfo {
    pub node_id: String,
    pub relay_url: Option<String>,
    pub last_seen_ago: String,
    pub connection_type: String,
}

/// Project metadata.
#[derive(uniffi::Record)]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Asset metadata.
#[derive(uniffi::Record)]
pub struct AssetInfo {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    /// Raw BLAKE3 content hash (32 bytes).
    pub content_hash: Vec<u8>,
    pub created_at: u64,
}

/// Raw asset content with its MIME type.
#[derive(uniffi::Record)]
pub struct AssetContent {
    pub content_type: String,
    pub data: Vec<u8>,
}

/// Vault catalog entry.
#[derive(uniffi::Record)]
pub struct VaultEntryInfo {
    pub project_id: String,
    pub name: String,
    pub created_at: u64,
    pub local: bool,
}

// =========================================================================
// From conversions: proto types -> FFI types
// =========================================================================

impl From<HealthResponse> for HealthInfo {
    fn from(r: HealthResponse) -> Self {
        Self { status: r.status }
    }
}

impl From<StatusResponse> for StatusInfo {
    fn from(r: StatusResponse) -> Self {
        Self {
            node_id: r.node_id,
            relay_url: r.relay_url,
            peer_count: r.peer_count,
            identity: r.identity.map(IdentityInfo::from),
        }
    }
}

impl From<ProtoIdentityInfo> for IdentityInfo {
    fn from(r: ProtoIdentityInfo) -> Self {
        Self {
            id: r.id,
            handle: r.handle,
            nonce: r.nonce,
        }
    }
}

impl From<ProtoPeerInfo> for PeerConnectionInfo {
    fn from(p: ProtoPeerInfo) -> Self {
        Self {
            node_id: p.node_id,
            relay_url: p.relay_url,
            last_seen_ago: p.last_seen_ago,
            connection_type: p.connection_type,
        }
    }
}

impl From<ProtoProjectInfo> for ProjectInfo {
    fn from(r: ProtoProjectInfo) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            owner_id: r.owner_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

impl From<ProtoAssetInfo> for AssetInfo {
    fn from(r: ProtoAssetInfo) -> Self {
        Self {
            id: r.id,
            filename: r.filename,
            content_type: r.content_type,
            size: r.size,
            content_hash: r.content_hash,
            created_at: r.created_at,
        }
    }
}

impl From<ProtoVaultEntry> for VaultEntryInfo {
    fn from(e: ProtoVaultEntry) -> Self {
        Self {
            project_id: e.project_id,
            name: e.name,
            created_at: e.created_at,
            local: e.local,
        }
    }
}

// =========================================================================
// Aggregate response conversions (free functions to avoid orphan rules)
// =========================================================================

pub fn projects_from(r: ListProjectsResponse) -> Vec<ProjectInfo> {
    r.projects.into_iter().map(ProjectInfo::from).collect()
}

pub fn assets_from(r: ListAssetsResponse) -> Vec<AssetInfo> {
    r.assets.into_iter().map(AssetInfo::from).collect()
}

pub fn peers_from(r: ListPeersResponse) -> Vec<PeerConnectionInfo> {
    r.peers.into_iter().map(PeerConnectionInfo::from).collect()
}

pub fn vault_entries_from(r: ListVaultResponse) -> Vec<VaultEntryInfo> {
    r.entries.into_iter().map(VaultEntryInfo::from).collect()
}
