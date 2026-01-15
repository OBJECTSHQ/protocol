//! Project types for OBJECTS Protocol.

use objects_identity::IdentityId;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Derives a Project ID from a ReplicaId per RFC-004.
///
/// Project ID is the hex encoding of the first 16 bytes of the ReplicaId (32 hex characters).
pub fn project_id_from_replica(replica_id: &[u8; 32]) -> String {
    hex::encode(&replica_id[..16])
}

/// A project representing an organizational grouping of assets.
///
/// A Project maps 1:1 with a Sync layer Replica (RFC-003).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Unique identifier (derived from ReplicaId).
    id: String,
    /// Human-readable name.
    name: String,
    /// Project description.
    description: Option<String>,
    /// Identity ID of the project owner (RFC-001).
    owner_id: IdentityId,
    /// Unix timestamp (seconds) when project was created.
    created_at: u64,
    /// Unix timestamp (seconds) when project was last updated.
    updated_at: u64,
}

impl Project {
    /// Creates a new Project with validated fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProject`] if validation fails:
    /// - `id`: must be 32 hex characters
    /// - `name`: must be non-empty
    /// - `created_at <= updated_at`
    pub fn new(
        id: String,
        name: String,
        description: Option<String>,
        owner_id: IdentityId,
        created_at: u64,
        updated_at: u64,
    ) -> Result<Self, Error> {
        let project = Self {
            id,
            name,
            description,
            owner_id,
            created_at,
            updated_at,
        };
        project.validate()?;
        Ok(project)
    }

    /// Derives a project ID from a ReplicaId.
    ///
    /// Per RFC-004 Section 3.2: Project ID is the first 16 bytes
    /// of the ReplicaId, hex-encoded (32 hex characters).
    ///
    /// # Example
    ///
    /// ```rust
    /// use objects_data::Project;
    ///
    /// let replica_id: [u8; 32] = [0xab; 32];
    /// let project_id = Project::project_id_from_replica(&replica_id);
    /// assert_eq!(project_id.len(), 32); // 16 bytes = 32 hex chars
    /// assert_eq!(project_id, "ab".repeat(16));
    /// ```
    pub fn project_id_from_replica(replica_id: &[u8; 32]) -> String {
        hex::encode(&replica_id[..16])
    }

    /// Returns the project ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the project name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the project description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the owner identity ID.
    pub fn owner_id(&self) -> &IdentityId {
        &self.owner_id
    }

    /// Returns the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the last update timestamp.
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Validates the project according to RFC-004 rules.
    ///
    /// Checks:
    /// - `id`: 32 hex characters (first 16 bytes of ReplicaId, hex-encoded)
    /// - `name`: non-empty
    /// - `created_at <= updated_at`
    ///
    /// Note: This validation only checks format. It does not verify that the ID
    /// was actually derived from a valid ReplicaId - that must be checked elsewhere.
    fn validate(&self) -> Result<(), Error> {
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
        Project::new(
            "a".repeat(32),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            1704542400,
            1704542500,
        )
        .unwrap()
    }

    #[test]
    fn test_project_validate_valid() {
        let project = valid_project();
        assert_eq!(project.id(), &"a".repeat(32));
    }

    #[test]
    fn test_project_validate_invalid_id_length_short() {
        let result = Project::new(
            "abc".to_string(),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_project_validate_invalid_id_length_long() {
        let result = Project::new(
            "a".repeat(33),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_project_validate_invalid_id_chars() {
        let result = Project::new(
            "g".repeat(32),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_project_validate_valid_hex_id() {
        let result = Project::new(
            "0123456789abcdef0123456789abcdef".to_string(),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            1704542400,
            1704542500,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_project_validate_empty_name() {
        let result = Project::new(
            "a".repeat(32),
            "".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            1704542400,
            1704542500,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_project_validate_timestamps() {
        let result = Project::new(
            "a".repeat(32),
            "Test Project".to_string(),
            Some("A test project".to_string()),
            test_owner_id(),
            200,
            100,
        );
        assert!(result.is_err());
    }
}
