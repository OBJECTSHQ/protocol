//! Project types for OBJECTS Protocol.

use objects_identity::IdentityId;
use serde::{Deserialize, Serialize};

use crate::Error;

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

impl Project {
    /// Validates the project according to RFC-004 rules.
    ///
    /// Checks:
    /// - `id`: 32 hex characters (16 bytes from ReplicaId)
    /// - `created_at <= updated_at`
    pub fn validate(&self) -> Result<(), Error> {
        // Validate id: hex-encoded first 16 bytes of ReplicaId (32 hex chars)
        if self.id.len() != 32 {
            return Err(Error::InvalidProject(
                "id must be 32 hex characters (16 bytes)".to_string(),
            ));
        }
        if !self.id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidProject(
                "id must be hex characters only".to_string(),
            ));
        }

        // Validate name is not empty
        if self.name.is_empty() {
            return Err(Error::InvalidProject("name is required".to_string()));
        }

        // Validate timestamps
        if self.created_at > self.updated_at {
            return Err(Error::InvalidProject(
                "created_at must not be greater than updated_at".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_owner_id() -> IdentityId {
        IdentityId::parse("obj_2dMiYc8RhnYkorPc5pVh9").unwrap()
    }

    fn valid_project() -> Project {
        Project {
            id: "a".repeat(32), // 32 hex chars
            name: "Test Project".to_string(),
            description: Some("A test project".to_string()),
            owner_id: test_owner_id(),
            created_at: 1704542400,
            updated_at: 1704542500,
        }
    }

    #[test]
    fn test_project_validate_valid() {
        let project = valid_project();
        assert!(project.validate().is_ok());
    }

    #[test]
    fn test_project_validate_invalid_id_length_short() {
        let mut project = valid_project();
        project.id = "abc".to_string(); // too short
        assert!(project.validate().is_err());
    }

    #[test]
    fn test_project_validate_invalid_id_length_long() {
        let mut project = valid_project();
        project.id = "a".repeat(33); // too long
        assert!(project.validate().is_err());
    }

    #[test]
    fn test_project_validate_invalid_id_chars() {
        let mut project = valid_project();
        project.id = "g".repeat(32); // 'g' is not hex
        assert!(project.validate().is_err());
    }

    #[test]
    fn test_project_validate_valid_hex_id() {
        let mut project = valid_project();
        project.id = "0123456789abcdef0123456789abcdef".to_string();
        assert!(project.validate().is_ok());
    }

    #[test]
    fn test_project_validate_empty_name() {
        let mut project = valid_project();
        project.name = "".to_string();
        assert!(project.validate().is_err());
    }

    #[test]
    fn test_project_validate_timestamps() {
        let mut project = valid_project();
        project.created_at = 200;
        project.updated_at = 100; // created_at > updated_at
        assert!(project.validate().is_err());
    }
}
