//! API request and response types.
//!
//! Types are generated from `proto/objects/node/v1/node.proto` via prost-build.
//! This module re-exports them and provides `From` impls for domain types
//! (objects-data Asset, Project) and validation logic.

use objects_data::{Asset, Project};

// Re-export proto-generated types used by the API layer.
pub use crate::proto_gen::{
    AssetInfo, CreateProjectRequest, GetAssetContentResponse, HealthResponse, IdentityInfo,
    ListAssetsResponse, ListProjectsResponse, ListVaultResponse, NodeAddress, PeerInfo,
    ProjectInfo, StatusResponse, VaultEntry,
};

// =============================================================================
// Domain → Proto conversions
// =============================================================================

impl From<&crate::state::IdentityInfo> for IdentityInfo {
    fn from(info: &crate::state::IdentityInfo) -> Self {
        Self {
            id: info.identity_id().to_string(),
            handle: info.handle().to_string(),
            nonce: info.nonce().to_vec(),
        }
    }
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

impl From<&Project> for ProjectInfo {
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

impl From<Project> for ProjectInfo {
    fn from(project: Project) -> Self {
        Self::from(&project)
    }
}

impl From<&Asset> for AssetInfo {
    fn from(asset: &Asset) -> Self {
        Self {
            id: asset.id().to_string(),
            filename: asset.name().to_string(),
            content_type: asset
                .format()
                .unwrap_or("application/octet-stream")
                .to_string(),
            size: asset.content_size(),
            content_hash: asset.content_hash().0.to_vec(),
            created_at: asset.created_at(),
        }
    }
}

impl From<Asset> for AssetInfo {
    fn from(asset: Asset) -> Self {
        Self::from(&asset)
    }
}

// =============================================================================
// NodeAddress ↔ NodeAddr conversions
// =============================================================================

impl From<&objects_transport::NodeAddr> for NodeAddress {
    fn from(addr: &objects_transport::NodeAddr) -> Self {
        Self {
            node_id: addr.id.to_string(),
            relay_url: addr.relay_urls().next().map(|u| u.to_string()),
            direct_addresses: addr.ip_addrs().map(|a| a.to_string()).collect(),
        }
    }
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
        let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, response);
    }

    #[test]
    fn test_identity_info_serialization() {
        let info = IdentityInfo {
            id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
            handle: "@alice".to_string(),
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: IdentityInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, info);
    }

    #[test]
    fn test_peer_info_serialization() {
        let peer = PeerInfo {
            node_id: "abc123".to_string(),
            relay_url: Some("https://relay.example.com".to_string()),
            last_seen_ago: "5m ago".to_string(),
            connection_type: "none".to_string(),
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
    fn test_project_info_serialization() {
        let info = ProjectInfo {
            id: "a".repeat(32),
            name: "Test Project".to_string(),
            description: Some("A test project".to_string()),
            owner_id: "obj_2dMiYc8RhnYkorPc5pVh9".to_string(),
            created_at: 1704542400,
            updated_at: 1704542500,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ProjectInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, info);
    }

    #[test]
    fn test_project_info_from_project() {
        use objects_identity::IdentityId;

        let owner_id = IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap();
        let project = Project::new(
            "a".repeat(64), // Full NamespaceId hex (64 chars)
            "Test Project".to_string(),
            Some("A test project".to_string()),
            owner_id,
            1704542400,
            1704542500,
        )
        .unwrap();

        let info = ProjectInfo::from(&project);
        assert_eq!(info.id, "a".repeat(64));
        assert_eq!(info.name, "Test Project");
        assert_eq!(info.description, Some("A test project".to_string()));
        assert_eq!(info.owner_id, "obj_2dMiYc8RhnYkorPc5pVh9");
        assert_eq!(info.created_at, 1704542400);
        assert_eq!(info.updated_at, 1704542500);
    }

    #[test]
    fn test_list_projects_response_serialization() {
        let response = ListProjectsResponse {
            projects: vec![ProjectInfo {
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
        let deserialized: ListProjectsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.projects.len(), 1);
    }

    // =========================================================================
    // Asset Type Tests
    // =========================================================================

    #[test]
    fn test_asset_info_serialization() {
        let info = AssetInfo {
            id: "motor-mount-v1".to_string(),
            filename: "motor_mount.step".to_string(),
            content_type: "model/step".to_string(),
            size: 1024,
            content_hash: objects_test_utils::crypto::deterministic_bytes(42).to_vec(),
            created_at: 1704542400,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: AssetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, info);
    }

    #[test]
    fn test_asset_info_from_asset() {
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

        let info = AssetInfo::from(&asset);
        assert_eq!(info.id, "motor-mount-v1");
        assert_eq!(info.filename, "motor_mount.step");
        assert_eq!(info.content_type, "model/step");
        assert_eq!(info.size, 1024);
        assert_eq!(info.content_hash, [0xab; 32].to_vec());
        assert_eq!(info.created_at, 1704542400);
    }

    #[test]
    fn test_asset_info_default_content_type() {
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

        let info = AssetInfo::from(&asset);
        assert_eq!(info.content_type, "application/octet-stream");
    }

    #[test]
    fn test_list_assets_response_serialization() {
        let response = ListAssetsResponse {
            assets: vec![AssetInfo {
                id: "motor-mount-v1".to_string(),
                filename: "motor_mount.step".to_string(),
                content_type: "model/step".to_string(),
                size: 1024,
                content_hash: objects_test_utils::crypto::deterministic_bytes(42).to_vec(),
                created_at: 1704542400,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("motor-mount-v1"));
        let deserialized: ListAssetsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.assets.len(), 1);
    }
}
