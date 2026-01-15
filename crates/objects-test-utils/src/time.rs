//! Timestamp utilities for testing.
//!
//! Provides consistent timestamp functions across all OBJECTS Protocol tests.
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::time;
//!
//! // Get current timestamp
//! let timestamp = time::now();
//!
//! // Use fixed test timestamp for deterministic tests
//! let fixed_ts = time::TEST_TIMESTAMP;
//!
//! // Generate future timestamp
//! let future = time::future_timestamp(3600); // 1 hour from now
//! assert!(future > timestamp);
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current Unix timestamp in seconds.
///
/// # Panics
///
/// Panics if the system clock is set before the Unix epoch (January 1, 1970).
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::time::now;
///
/// let timestamp = now();
/// assert!(timestamp > 1_700_000_000); // After November 2023
/// ```
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Fixed test timestamp constant (2024-01-06 12:00:00 UTC).
///
/// Use this for deterministic tests that need a consistent timestamp value.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::time::TEST_TIMESTAMP;
///
/// assert_eq!(TEST_TIMESTAMP, 1704542400);
/// ```
pub const TEST_TIMESTAMP: u64 = 1704542400;

/// Generate a future timestamp offset by the specified number of seconds.
///
/// # Arguments
///
/// * `offset_secs` - Number of seconds to add to the current timestamp
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::time::{now, future_timestamp};
///
/// let current = now();
/// let future = future_timestamp(100);
/// assert!(future >= current + 100);
/// ```
pub fn future_timestamp(offset_secs: u64) -> u64 {
    now() + offset_secs
}

/// Deprecated alias for `now()`.
///
/// This function exists for backward compatibility during migration.
/// Use `now()` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use now() instead for consistent naming across test utilities"
)]
pub fn current_timestamp() -> u64 {
    now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_returns_reasonable_timestamp() {
        let timestamp = now();
        // Should be after 2024-01-01
        assert!(timestamp > 1704067200);
        // Should be before 2030-01-01
        assert!(timestamp < 1893456000);
    }

    #[test]
    fn test_future_timestamp_adds_offset() {
        let current = now();
        let future = future_timestamp(100);
        assert!(future >= current + 100);
        assert!(future <= current + 101); // Allow for 1 second of test execution time
    }

    #[test]
    fn test_timestamp_constant() {
        assert_eq!(TEST_TIMESTAMP, 1704542400);
    }
}
