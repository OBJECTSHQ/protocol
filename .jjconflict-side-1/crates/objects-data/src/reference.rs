//! Reference types for OBJECTS Protocol.

use serde::{Deserialize, Serialize};

use crate::Error;
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

impl Reference {
    /// Validates the reference according to RFC-004 rules.
    ///
    /// Checks:
    /// - `id`: non-empty
    /// - `source_asset_id`: non-empty
    /// - `target_asset_id`: non-empty
    pub fn validate(&self) -> Result<(), Error> {
        if self.id.is_empty() {
            return Err(Error::InvalidReference("id is required".to_string()));
        }
        if self.source_asset_id.is_empty() {
            return Err(Error::InvalidReference(
                "source_asset_id is required".to_string(),
            ));
        }
        if self.target_asset_id.is_empty() {
            return Err(Error::InvalidReference(
                "target_asset_id is required".to_string(),
            ));
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_reference() -> Reference {
        Reference {
            id: "ref-1".to_string(),
            source_asset_id: "motor-mount".to_string(),
            target_asset_id: "gear-assembly".to_string(),
            target_content_hash: None,
            reference_type: ReferenceType::Contains,
            created_at: 1704542400,
        }
    }

    #[test]
    fn test_reference_validate_valid() {
        let reference = valid_reference();
        assert!(reference.validate().is_ok());
    }

    #[test]
    fn test_reference_validate_empty_id() {
        let mut reference = valid_reference();
        reference.id = "".to_string();
        assert!(reference.validate().is_err());
    }

    #[test]
    fn test_reference_validate_empty_source() {
        let mut reference = valid_reference();
        reference.source_asset_id = "".to_string();
        assert!(reference.validate().is_err());
    }

    #[test]
    fn test_reference_validate_empty_target() {
        let mut reference = valid_reference();
        reference.target_asset_id = "".to_string();
        assert!(reference.validate().is_err());
    }

    #[test]
    fn test_reference_type_values() {
        assert_eq!(ReferenceType::Unspecified as u32, 0);
        assert_eq!(ReferenceType::Contains as u32, 1);
        assert_eq!(ReferenceType::DependsOn as u32, 2);
        assert_eq!(ReferenceType::DerivedFrom as u32, 3);
        assert_eq!(ReferenceType::References as u32, 4);
    }

    #[test]
    fn test_reference_with_content_hash() {
        let mut reference = valid_reference();
        reference.target_content_hash = Some(ContentHash::new([0xab; 32]));
        assert!(reference.validate().is_ok());
    }
}
