//! Handle validation and formatting.
//!
//! Handles are human-readable aliases for identities.
//! Format: 1-30 chars, lowercase alphanumeric + underscore + period.

use crate::Error;

/// Maximum length of a handle.
pub const HANDLE_MAX_LEN: usize = 30;

/// Reserved handles that cannot be assigned.
const RESERVED_HANDLES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "system",
    "objects",
    "protocol",
    "support",
    "help",
    "info",
    "contact",
    "api",
    "www",
    "mail",
    "ftp",
];

/// A validated OBJECTS handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle(String);

impl Handle {
    /// Parses and validates a handle string.
    ///
    /// # Rules
    /// - 1-30 characters
    /// - Lowercase alphanumeric, underscore, period only
    /// - Cannot start with period or underscore
    /// - Cannot end with period
    /// - Cannot contain consecutive periods
    /// - Cannot be a reserved word
    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(Error::InvalidHandle("handle cannot be empty".to_string()));
        }

        if s.len() > HANDLE_MAX_LEN {
            return Err(Error::InvalidHandle(format!(
                "handle cannot exceed {} characters",
                HANDLE_MAX_LEN
            )));
        }

        // Check for valid characters
        for c in s.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '.' {
                return Err(Error::InvalidHandle(format!(
                    "invalid character '{}': only lowercase letters, digits, underscore, and period allowed",
                    c
                )));
            }
        }

        // Cannot start with period or underscore
        if s.starts_with('.') || s.starts_with('_') {
            return Err(Error::InvalidHandle(
                "handle cannot start with period or underscore".to_string(),
            ));
        }

        // Cannot end with period
        if s.ends_with('.') {
            return Err(Error::InvalidHandle(
                "handle cannot end with period".to_string(),
            ));
        }

        // Cannot contain consecutive periods
        if s.contains("..") {
            return Err(Error::InvalidHandle(
                "handle cannot contain consecutive periods".to_string(),
            ));
        }

        // Cannot be a reserved word
        if RESERVED_HANDLES.contains(&s) {
            return Err(Error::InvalidHandle(format!(
                "'{}' is a reserved handle",
                s
            )));
        }

        Ok(Self(s.to_string()))
    }

    /// Returns the handle as a string (without @ prefix).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the handle with @ prefix for display.
    pub fn display(&self) -> String {
        format!("@{}", self.0)
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_handles() {
        // Test vectors from RFC-001 Appendix B
        assert!(Handle::parse("montez").is_ok());
        assert!(Handle::parse("alice_123").is_ok());
        assert!(Handle::parse("montez.studio").is_ok());
        assert!(Handle::parse("design.co_lab").is_ok());
    }

    #[test]
    fn test_invalid_handles() {
        // Test vectors from RFC-001 Appendix B
        assert!(Handle::parse("_alice").is_err()); // starts with underscore
        assert!(Handle::parse(".alice").is_err()); // starts with period
        assert!(Handle::parse("alice.").is_err()); // ends with period
        assert!(Handle::parse("alice..bob").is_err()); // consecutive periods
        assert!(Handle::parse("Alice").is_err()); // contains uppercase
        assert!(Handle::parse("admin").is_err()); // reserved word
        assert!(Handle::parse("hello world").is_err()); // contains space
    }

    #[test]
    fn test_handle_too_long() {
        let long_handle = "a".repeat(31);
        assert!(Handle::parse(&long_handle).is_err());
    }

    #[test]
    fn test_display_with_at() {
        let handle = Handle::parse("montez").unwrap();
        assert_eq!(handle.display(), "@montez");
    }
}
