//! Storage key helpers for Sync layer integration.
//!
//! Entry key format per RFC-004 Section 4.1:
//! - `/project`              -> Project metadata
//! - `/assets/{id}`          -> Asset record
//! - `/refs/{id}`            -> Reference record

/// Key for project metadata.
pub const PROJECT_KEY: &str = "/project";

/// Prefix for asset entries.
pub const ASSETS_PREFIX: &str = "/assets/";

/// Prefix for reference entries.
pub const REFS_PREFIX: &str = "/refs/";

/// Returns the storage key for an asset.
pub fn asset_key(id: &str) -> String {
    format!("{}{}", ASSETS_PREFIX, id)
}

/// Returns the storage key for a reference.
pub fn reference_key(id: &str) -> String {
    format!("{}{}", REFS_PREFIX, id)
}

/// Parsed key type from a storage key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    /// Project metadata key.
    Project,
    /// Asset key with ID.
    Asset(String),
    /// Reference key with ID.
    Reference(String),
    /// Unknown key format.
    Unknown,
}

/// Parses a storage key into its type and ID.
pub fn parse_key(key: &str) -> KeyType {
    if key == PROJECT_KEY {
        KeyType::Project
    } else if let Some(id) = key.strip_prefix(ASSETS_PREFIX) {
        KeyType::Asset(id.to_string())
    } else if let Some(id) = key.strip_prefix(REFS_PREFIX) {
        KeyType::Reference(id.to_string())
    } else {
        KeyType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_key() {
        assert_eq!(asset_key("motor-mount"), "/assets/motor-mount");
        assert_eq!(asset_key("gear-assembly"), "/assets/gear-assembly");
    }

    #[test]
    fn test_reference_key() {
        assert_eq!(
            reference_key("assembly-to-part-1"),
            "/refs/assembly-to-part-1"
        );
    }

    #[test]
    fn test_parse_key_project() {
        assert_eq!(parse_key("/project"), KeyType::Project);
    }

    #[test]
    fn test_parse_key_asset() {
        assert_eq!(
            parse_key("/assets/motor-mount"),
            KeyType::Asset("motor-mount".to_string())
        );
    }

    #[test]
    fn test_parse_key_reference() {
        assert_eq!(
            parse_key("/refs/link-1"),
            KeyType::Reference("link-1".to_string())
        );
    }

    #[test]
    fn test_parse_key_unknown() {
        assert_eq!(parse_key("/unknown/path"), KeyType::Unknown);
        assert_eq!(parse_key(""), KeyType::Unknown);
    }
}
