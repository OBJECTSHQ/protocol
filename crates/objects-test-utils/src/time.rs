//! Time utilities for testing.
//!
//! Provides standardized timestamp functions to ensure consistency across tests.
//!
//! ## Examples
//!
//! ```rust
//! use objects_test_utils::time;
//!
//! // Get current Unix timestamp
//! let timestamp = time::now();
//!
//! // Use canonical test timestamp (2024-01-06 12:00:00 UTC)
//! let test_ts = time::TEST_TIMESTAMP;
//!
//! // Generate future timestamp
//! let future = time::future_timestamp(3600); // 1 hour from now
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical test timestamp: 2024-01-06 12:00:00 UTC.
///
/// Use this for deterministic tests that need a fixed timestamp.
pub const TEST_TIMESTAMP: u64 = 1704542400;

/// Get the current Unix timestamp in seconds.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::time::now;
///
/// let timestamp = now();
/// assert!(timestamp > 1704067200); // After 2024-01-01
/// ```
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Generate a timestamp offset from now by the given number of seconds.
///
/// Useful for creating future expiry times in tests.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::time::future_timestamp;
///
/// let one_hour_from_now = future_timestamp(3600);
/// ```
pub fn future_timestamp(offset_secs: u64) -> u64 {
    now() + offset_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_returns_reasonable_timestamp() {
        let timestamp = now();

        // Should be after 2024-01-01 (1704067200)
        assert!(
            timestamp > 1704067200,
            "timestamp should be after 2024-01-01"
        );

        // Should be before 2030-01-01 (1893456000)
        assert!(
            timestamp < 1893456000,
            "timestamp should be before 2030-01-01"
        );
    }

    #[test]
    fn test_future_timestamp_adds_offset() {
        let current = now();
        let future = future_timestamp(100);

        assert!(
            future >= current + 100,
            "future timestamp should be at least offset seconds ahead"
        );
        assert!(
            future <= current + 101,
            "future timestamp should not exceed offset + 1 second (for test execution time)"
        );
    }

    #[test]
    fn test_timestamp_constant_is_correct() {
        // 2024-01-06 12:00:00 UTC
        assert_eq!(TEST_TIMESTAMP, 1704542400);
    }
}
