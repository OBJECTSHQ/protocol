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
/// # Panics
///
/// Panics if `now() + offset_secs` would overflow `u64::MAX`.
///
/// # Examples
///
/// ```rust
/// use objects_test_utils::time::future_timestamp;
///
/// let one_hour_from_now = future_timestamp(3600);
/// ```
pub fn future_timestamp(offset_secs: u64) -> u64 {
    now()
        .checked_add(offset_secs)
        .expect("timestamp overflow: offset too large")
}

// Unit tests live in tests/self_test.rs to avoid duplication.
