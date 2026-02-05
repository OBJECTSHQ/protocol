//! API request and response types.

use objects_data::{Asset, Project};
use objects_transport::NodeAddr;
use serde::{Deserialize, Serialize};

/// Response for the health check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    /// Status of the node ("ok" if healthy).
    pub status: String,
}

/// Response for the node status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node ID as a string.
    pub node_id: String,
    /// Node address with relay information.
    pub node_addr: NodeAddr,
    /// Number of currently discovered peers.
    pub peer_count: usize,
    /// Identity information if registered.
    pub identity: Option<IdentityResponse>,
    /// Relay URL the node is connected to.
    pub relay_url: String,
}

/// Identity information response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityResponse {
    /// Identity ID (e.g., "obj_2dMiYc8RhnYkorPc5pVh9").
    pub id: String,
    /// Handle (e.g., "@alice").
    pub handle: String,
    /// 8-byte nonce encoded as hex.
    pub nonce: String,
    /// Signer type ("passkey" or "wallet").
    pub signer_type: String,
}

/// Peer information for listing discovered peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's node ID.
    pub node_id: String,
    /// Peer's relay URL if known.
    pub relay_url: Option<String>,
    /// Human-readable time since last seen (e.g., "2m ago").
    pub last_seen_ago: String,
}

// =============================================================================
// Project Types
// =============================================================================

/// Request to create a new project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectRequest {
    /// Human-readable name for the project (1-256 characters).
    pub name: String,
    /// Optional description (max 4096 characters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CreateProjectRequest {
    /// Validates the request fields.
    ///
    /// # Errors
    ///
    /// Returns an error message if validation fails:
    /// - Name must be 1-256 characters
    /// - Description must be at most 4096 characters
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Name is required".to_string());
        }
        if self.name.len() > 256 {
            return Err("Name must be at most 256 characters".to_string());
        }
        if let Some(ref desc) = self.description
            && desc.len() > 4096
        {
            return Err("Description must be at most 4096 characters".to_string());
        }
        Ok(())
    }
}

/// Response containing project information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectResponse {
    /// Project ID (32 hex characters derived from ReplicaId).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Owner identity ID (e.g., "obj_2dMiYc8RhnYkorPc5pVh9").
    pub owner_id: String,
    /// Unix timestamp when project was created.
    pub created_at: u64,
    /// Unix timestamp when project was last updated.
    pub updated_at: u64,
}

impl From<&Project> for ProjectResponse {
    fn from(project: &Project) -> Self {
        Self {
            id: project.id().to_string(),
            name: project.name().to_string(),
            description: project.description().map(String::from),
            owner_id: project.owner_id().to_string(),
            created_at: project.created_at(),
            updated_at: project.updated_at(),
        }
    }
}

impl From<Project> for ProjectResponse {
    fn from(project: Project) -> Self {
        Self::from(&project)
    }
}

/// Response containing a list of projects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectListResponse {
    /// List of projects.
    pub projects: Vec<ProjectResponse>,
}

// =============================================================================
// Asset Types
// =============================================================================

/// Response containing asset information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetResponse {
    /// Asset ID (alphanumeric + hyphens, 1-64 characters).
    pub id: String,
    /// Human-readable filename.
    pub filename: String,
    /// MIME type (e.g., "image/png", "model/step").
    pub content_type: String,
    /// Size of the content in bytes.
    pub size: u64,
    /// BLAKE3 hash of the content (hex-encoded).
    pub content_hash: String,
    /// Unix timestamp when asset was created.
    pub created_at: u64,
}

impl From<&Asset> for AssetResponse {
    fn from(asset: &Asset) -> Self {
        Self {
            id: asset.id().to_string(),
            filename: asset.name().to_string(),
            content_type: asset
                .format()
                .unwrap_or("application/octet-stream")
                .to_string(),
            size: asset.content_size(),
            content_hash: asset.content_hash().to_hex(),
            created_at: asset.created_at(),
        }
    }
}

impl From<Asset> for AssetResponse {
    fn from(asset: Asset) -> Self {
        Self::from(&asset)
    }
}

/// Response containing a list of assets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetListResponse {
    /// List of assets.
    pub assets: Vec<AssetResponse>,
}

// =============================================================================
// Ticket Types
// =============================================================================

/// Request to create a project share ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTicketRequest {
    /// Project ID to create ticket for.
    pub project_id: String,
}

/// Response containing the ticket string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketResponse {
    /// Serialized ticket string for sharing.
    pub ticket: String,
}

/// Request to redeem a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemTicketRequest {
    /// Ticket string to redeem.
    pub ticket: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "ok".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"status":"ok"}"#);

        let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_identity_response_serialization() {
        let response = IdentityResponse {
            id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
            handle: "@alice".to_string(),
            nonce: "0102030405060708".to_string(),
            signer_type: "passkey".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: IdentityResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_peer_info_serialization() {
        let peer = PeerInfo {
            node_id: "abc123".to_string(),
            relay_url: Some("https://relay.example.com".to_string()),
            last_seen_ago: "5m ago".to_string(),
        };

        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.node_id, peer.node_id);
    }

    // =========================================================================
    // Project Type Tests
    // =========================================================================

    #[test]
    fn test_create_project_request_validation_valid() {
        let req = CreateProjectRequest {
            name: "My Project".to_string(),
            description: Some("A test project".to_string()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_create_project_request_validation_empty_name() {
        let req = CreateProjectRequest {
            name: "".to_string(),
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert_eq!(err, "Name is required");
    }

    #[test]
    fn test_create_project_request_validation_name_too_long() {
        let req = CreateProjectRequest {
            name: "a".repeat(257),
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert_eq!(err, "Name must be at most 256 characters");
    }

    #[test]
    fn test_create_project_request_validation_description_too_long() {
        let req = CreateProjectRequest {
            name: "Test Project".to_string(),
            description: Some("a".repeat(4097)),
        };
        let err = req.validate().unwrap_err();
        assert_eq!(err, "Description must be at most 4096 characters");
    }

    #[test]
    fn test_project_response_serialization() {
        let response = ProjectResponse {
            id: "a".repeat(32),
            name: "Test Project".to_string(),
            description: Some("A test project".to_string()),
            owner_id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
            created_at: 1704542400,
            updated_at: 1704542500,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ProjectResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_project_response_from_project() {
        use objects_identity::IdentityId;

        let owner_id = IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap();
        let project = Project::new(
            "a".repeat(32),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            owner_id,
            1704542400,
            1704542500,
        )
        .unwrap();

        let response = ProjectResponse::from(&project);
        assert_eq!(response.id, "a".repeat(32));
        assert_eq!(response.name, "Test Project");
        assert_eq!(response.description, Some("A test project".to_string()));
        assert_eq!(response.owner_id, "obj_2dMiYc8RhnYkorPc5pVh9");
        assert_eq!(response.created_at, 1704542400);
        assert_eq!(response.updated_at, 1704542500);
    }

    #[test]
    fn test_project_list_response_serialization() {
        let response = ProjectListResponse {
            projects: vec![ProjectResponse {
                id: "a".repeat(32),
                name: "Test Project".to_string(),
                description: None,
                owner_id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
                created_at: 1704542400,
                updated_at: 1704542500,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Test Project"));
        let deserialized: ProjectListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.projects.len(), 1);
    }

    // =========================================================================
    // Asset Type Tests
    // =========================================================================

    #[test]
    fn test_asset_response_serialization() {
        let response = AssetResponse {
            id: "motor-mount-v1".to_string(),
            filename: "motor_mount.step".to_string(),
            content_type: "model/step".to_string(),
            size: 1024,
            content_hash: "ab".repeat(32),
            created_at: 1704542400,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: AssetResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_asset_response_from_asset() {
        use objects_data::ContentHash;
        use objects_identity::IdentityId;

        let author_id = IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap();
        let content_hash = ContentHash::new([0xab; 32]);
        let asset = Asset::new(
            "motor-mount-v1".to_string(),
            "motor_mount.step".to_string(),
            author_id,
            content_hash,
            1024,
            Some("model/step".to_string()),
            1704542400,
            1704542500,
        )
        .unwrap();

        let response = AssetResponse::from(&asset);
        assert_eq!(response.id, "motor-mount-v1");
        assert_eq!(response.filename, "motor_mount.step");
        assert_eq!(response.content_type, "model/step");
        assert_eq!(response.size, 1024);
        assert_eq!(response.content_hash, "ab".repeat(32));
        assert_eq!(response.created_at, 1704542400);
    }

    #[test]
    fn test_asset_response_default_content_type() {
        use objects_data::ContentHash;
        use objects_identity::IdentityId;

        let author_id = IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap();
        let content_hash = ContentHash::new([0xab; 32]);
        let asset = Asset::new(
            "data-file".to_string(),
            "data.bin".to_string(),
            author_id,
            content_hash,
            512,
            None, // No format specified
            1704542400,
            1704542400,
        )
        .unwrap();

        let response = AssetResponse::from(&asset);
        assert_eq!(response.content_type, "application/octet-stream");
    }

    #[test]
    fn test_asset_list_response_serialization() {
        let response = AssetListResponse {
            assets: vec![AssetResponse {
                id: "motor-mount-v1".to_string(),
                filename: "motor_mount.step".to_string(),
                content_type: "model/step".to_string(),
                size: 1024,
                content_hash: "ab".repeat(32),
                created_at: 1704542400,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("motor-mount-v1"));
        let deserialized: AssetListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.assets.len(), 1);
    }
}
