//! Property-based tests for objects-identity crate.
//!
//! Tests cryptographic and validation invariants using proptest.

mod common;

use common::{reserved_handles, test_passkey_key};
use objects_identity::{Handle, IdentityId};
use proptest::prelude::*;

proptest! {
    // ========================================================================
    // Identity ID Properties
    // ========================================================================

    /// Property: All derived identity IDs must have "obj_" prefix
    #[test]
    fn identity_id_always_has_obj_prefix(nonce in prop::array::uniform8(any::<u8>())) {
        let key = test_passkey_key();
        let public_key = key.verifying_key();
        let public_key_point = public_key.to_encoded_point(true);
        let public_key_bytes: [u8; 33] = public_key_point.as_bytes()
            .try_into()
            .expect("compressed P-256 public key is 33 bytes");

        let id = IdentityId::derive(&public_key_bytes, &nonce);

        prop_assert!(
            id.as_str().starts_with("obj_"),
            "Identity ID '{}' must start with 'obj_' prefix",
            id.as_str()
        );
    }

    /// Property: Identity ID length must be within RFC-001 bounds (23-25 chars)
    #[test]
    fn identity_id_length_within_bounds(nonce in prop::array::uniform8(any::<u8>())) {
        let key = test_passkey_key();
        let public_key = key.verifying_key();
        let public_key_point = public_key.to_encoded_point(true);
        let public_key_bytes: [u8; 33] = public_key_point.as_bytes()
            .try_into()
            .expect("33 bytes");

        let id = IdentityId::derive(&public_key_bytes, &nonce);
        let len = id.as_str().len();

        prop_assert!(
            len >= 23 && len <= 25,
            "Identity ID length {} not in valid range [23, 25]",
            len
        );
    }

    /// Property: Identity derivation is deterministic (same inputs = same output)
    #[test]
    fn identity_id_deterministic(nonce in prop::array::uniform8(any::<u8>())) {
        let key = test_passkey_key();
        let public_key = key.verifying_key();
        let public_key_point = public_key.to_encoded_point(true);
        let public_key_bytes: [u8; 33] = public_key_point.as_bytes()
            .try_into()
            .expect("33 bytes");

        let id1 = IdentityId::derive(&public_key_bytes, &nonce);
        let id2 = IdentityId::derive(&public_key_bytes, &nonce);

        prop_assert_eq!(id1, id2, "Identity derivation must be deterministic");
    }

    /// Property: Identity ID parsing is lossless (derive → to_string → parse = identity)
    #[test]
    fn identity_id_parse_roundtrip(nonce in prop::array::uniform8(any::<u8>())) {
        let key = test_passkey_key();
        let public_key = key.verifying_key();
        let public_key_point = public_key.to_encoded_point(true);
        let public_key_bytes: [u8; 33] = public_key_point.as_bytes()
            .try_into()
            .expect("33 bytes");

        let id = IdentityId::derive(&public_key_bytes, &nonce);
        let id_str = id.as_str();

        let parsed = IdentityId::parse(id_str)
            .expect("valid identity ID must parse successfully");

        prop_assert_eq!(id, parsed, "Parse roundtrip must be lossless");
    }

    // ========================================================================
    // Handle Validation Properties
    // ========================================================================

    /// Property: Valid handle pattern always accepted (lowercase alphanumeric + _ + .)
    /// Pattern: [a-z][a-z0-9_.]{0,28}[a-z0-9]
    #[test]
    fn valid_handle_pattern_accepted(handle in "[a-z][a-z0-9_.]{0,28}[a-z0-9]") {
        // Filter out invalid edge cases that the regex doesn't catch
        let is_valid = !reserved_handles().contains(&handle.as_str())
            && !handle.contains("..")       // No consecutive periods
            && !handle.starts_with('_')     // No leading underscore
            && !handle.starts_with('.')     // No leading period
            && !handle.ends_with('.')       // No trailing period
            && handle.len() <= 30;          // Length constraint

        if is_valid {
            let result = Handle::parse(&handle);
            prop_assert!(
                result.is_ok(),
                "Valid handle '{}' should be accepted",
                handle
            );
        }
    }

    /// Property: Handles with uppercase letters always rejected
    #[test]
    fn handle_with_uppercase_rejected(
        base in "[a-z][a-z0-9_.]{0,20}",
        uppercase_pos in 0usize..5
    ) {
        let handle = format!(
            "{}{}test",
            &base[..base.len().min(20)],
            (b'A' + (uppercase_pos as u8 % 26)) as char
        );

        if handle.len() <= 30 {
            let result = Handle::parse(&handle);
            prop_assert!(
                result.is_err(),
                "Handle with uppercase '{}' must be rejected",
                handle
            );
        }
    }

    /// Property: Handles with leading underscore always rejected
    #[test]
    fn handle_leading_underscore_rejected(suffix in "[a-z0-9_.]{1,29}") {
        let handle = format!("_{}", suffix);
        let result = Handle::parse(&handle);

        prop_assert!(
            result.is_err(),
            "Handle with leading underscore '{}' must be rejected",
            handle
        );
    }

    /// Property: Handles with trailing period always rejected
    #[test]
    fn handle_trailing_period_rejected(base in "[a-z][a-z0-9_]{0,28}") {
        let handle = format!("{}.", base);

        if handle.len() <= 30 {
            let result = Handle::parse(&handle);
            prop_assert!(
                result.is_err(),
                "Handle with trailing period '{}' must be rejected",
                handle
            );
        }
    }

    /// Property: Handles longer than 30 characters always rejected
    #[test]
    fn handle_too_long_rejected(extra_chars in 1usize..20) {
        let handle = "a".repeat(31 + extra_chars);
        let result = Handle::parse(&handle);

        prop_assert!(
            result.is_err(),
            "Handle longer than 30 chars (len={}) must be rejected",
            handle.len()
        );
    }

    /// Property: Display representation matches original valid input
    #[test]
    fn handle_display_matches_original(handle in "[a-z][a-z0-9_.]{0,28}[a-z0-9]") {
        let is_valid = !reserved_handles().contains(&handle.as_str())
            && !handle.contains("..")
            && !handle.starts_with('_')
            && !handle.starts_with('.')
            && !handle.ends_with('.')
            && handle.len() <= 30;

        if is_valid {
            if let Ok(h) = Handle::parse(&handle) {
                prop_assert_eq!(
                    h.as_str(),
                    &handle,
                    "Display representation must match original input"
                );
            }
        }
    }

    /// Property: Reserved handles always rejected
    #[test]
    fn reserved_handles_rejected(
        reserved in prop::sample::select(vec![
            "admin", "administrator", "root", "system", "objects", "protocol",
            "support", "help", "info", "contact", "api", "www", "mail", "ftp"
        ])
    ) {
        let result = Handle::parse(reserved);
        prop_assert!(
            result.is_err(),
            "Reserved handle '{}' must be rejected",
            reserved
        );
    }
}
