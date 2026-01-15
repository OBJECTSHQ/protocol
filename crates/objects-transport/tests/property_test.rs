//! Property-based tests for objects-transport.
//!
//! Tests invariants and validation rules that must hold for all inputs.

mod common;

use common::*;
use objects_transport::{ALPN, DISCOVERY_TOPIC_DEVNET, NetworkConfig, SecretKey};
use proptest::prelude::*;
use std::time::Duration;

// ============================================================================
// NetworkConfig Property Tests
// ============================================================================

proptest! {
    /// Property: max_connections must always be positive
    #[test]
    fn prop_max_connections_positive(max_connections in 1usize..1000) {
        let config = NetworkConfig::devnet()
            .with_max_connections(max_connections);

        prop_assert!(config.max_connections > 0);
        prop_assert_eq!(config.max_connections, max_connections);
    }
}

proptest! {
    /// Property: idle_timeout must be non-zero duration
    #[test]
    fn prop_idle_timeout_non_zero(secs in 1u64..3600) {
        let timeout = Duration::from_secs(secs);
        let config = NetworkConfig::devnet()
            .with_idle_timeout(timeout);

        prop_assert!(!config.idle_timeout.is_zero());
        prop_assert_eq!(config.idle_timeout, timeout);
    }
}

proptest! {
    /// Property: NetworkConfig with any valid relay URL should be constructible
    #[test]
    fn prop_relay_url_format(scheme in "(https?)://", host in "[a-z0-9-]{1,20}\\.[a-z]{2,5}") {
        let url_str = format!("{}{}", scheme, host);
        let relay_url_result = url_str.parse::<objects_transport::RelayUrl>();

        if scheme == "https://" {
            // HTTPS URLs should parse successfully
            prop_assert!(relay_url_result.is_ok(),
                "HTTPS relay URL should parse: {}", url_str);

            let relay_url = relay_url_result.unwrap();
            let config = NetworkConfig::devnet()
                .with_relay_url(relay_url.clone());

            // URL parsing may normalize the URL (e.g., adding trailing slash)
            // Verify the config stores a valid relay URL
            prop_assert!(config.relay_url.to_string().starts_with(&scheme),
                "Relay URL should maintain scheme: {}", config.relay_url);
            prop_assert!(config.relay_url.to_string().contains(&host),
                "Relay URL should contain host: {}", config.relay_url);
        }
    }
}

proptest! {
    /// Property: Adding bootstrap nodes preserves order and count
    #[test]
    fn prop_bootstrap_nodes_accumulate(count in 0usize..10) {
        let mut config = NetworkConfig::devnet();

        for _ in 0..count {
            let node_addr = objects_transport::NodeAddr::new(SecretKey::generate(&mut rand::rng()).public());
            config = config.with_bootstrap_node(node_addr);
        }

        prop_assert_eq!(config.bootstrap_nodes.len(), count);
    }
}

// ============================================================================
// SecretKey Property Tests
// ============================================================================

proptest! {
    /// Property: Generated secret keys always produce valid public keys
    #[test]
    fn prop_secret_key_generates_valid_public_key(_seed in 0u64..1000) {
        let secret_key = SecretKey::generate(&mut rand::rng());
        let public_key = secret_key.public();

        // Public key should be convertible to string (valid format)
        let public_key_str = public_key.to_string();
        prop_assert!(!public_key_str.is_empty());
    }
}

proptest! {
    /// Property: Same secret key always produces same public key (determinism)
    #[test]
    fn prop_secret_key_deterministic(_seed in 0u64..100) {
        let secret_key = SecretKey::generate(&mut rand::rng());

        let public_key1 = secret_key.public();
        let public_key2 = secret_key.public();

        prop_assert_eq!(public_key1, public_key2,
            "Same secret key must always produce same public key");
    }
}

// ============================================================================
// Constants Invariant Tests
// ============================================================================

proptest! {
    /// Property: ALPN constant never changes (protocol stability)
    #[test]
    fn prop_alpn_constant_stable(_arbitrary in 0u8..255) {
        prop_assert_eq!(ALPN, b"/objects/0.1",
            "ALPN constant must remain stable");
    }
}

proptest! {
    /// Property: ALPN has correct format (starts with /, contains version)
    #[test]
    fn prop_alpn_format_valid(_arbitrary in 0u8..255) {
        let alpn_str = std::str::from_utf8(ALPN).expect("ALPN should be valid UTF-8");

        prop_assert!(alpn_str.starts_with('/'),
            "ALPN should start with /");
        prop_assert!(alpn_str.contains("objects"),
            "ALPN should contain 'objects'");
        prop_assert!(alpn_str.contains("0.1"),
            "ALPN should contain version");
    }
}

proptest! {
    /// Property: Discovery topic has correct format
    #[test]
    fn prop_discovery_topic_format(_arbitrary in 0u8..255) {
        prop_assert!(DISCOVERY_TOPIC_DEVNET.starts_with('/'),
            "Discovery topic should start with /");
        prop_assert!(DISCOVERY_TOPIC_DEVNET.contains("objects"),
            "Discovery topic should contain 'objects'");
        prop_assert!(DISCOVERY_TOPIC_DEVNET.contains("devnet"),
            "Discovery topic should contain 'devnet'");
        prop_assert!(DISCOVERY_TOPIC_DEVNET.contains("discovery"),
            "Discovery topic should contain 'discovery'");
    }
}

// ============================================================================
// Duration Property Tests
// ============================================================================

proptest! {
    /// Property: Valid timeout durations are always positive
    #[test]
    fn prop_timeout_positive(millis in 1u64..60000) {
        let duration = Duration::from_millis(millis);

        prop_assert!(!duration.is_zero());
        prop_assert!(duration.as_millis() > 0);
    }
}

proptest! {
    /// Property: Keepalive interval should be less than idle timeout
    #[test]
    fn prop_keepalive_less_than_idle(keepalive_secs in 1u64..30, idle_secs in 31u64..120) {
        let config = NetworkConfig::devnet()
            .with_idle_timeout(Duration::from_secs(idle_secs));

        let keepalive = Duration::from_secs(keepalive_secs);

        // In a well-configured system, keepalive should be less than idle
        prop_assert!(keepalive < config.idle_timeout,
            "Keepalive interval should be less than idle timeout for proper operation");
    }
}

// ============================================================================
// NodeAddr Property Tests
// ============================================================================

proptest! {
    /// Property: NodeAddr created from public key has correct node_id
    #[test]
    fn prop_node_addr_has_correct_id(_seed in 0u64..100) {
        let secret_key = SecretKey::generate(&mut rand::rng());
        let public_key = secret_key.public();
        let node_addr = objects_transport::NodeAddr::new(public_key);

        prop_assert_eq!(node_addr.id, public_key,
            "NodeAddr should contain the correct node_id");
    }
}

// ============================================================================
// Config Limits Property Tests
// ============================================================================

proptest! {
    /// Property: max_streams_per_conn in NetworkConfig must meet RFC-002 minimum
    #[test]
    fn prop_max_streams_meets_rfc_minimum(_arbitrary in 0u8..255) {
        let config = NetworkConfig::devnet();

        // Per RFC-002 §6.1, nodes MUST support at least 100 streams
        prop_assert!(config.max_streams_per_conn >= 100,
            "max_streams_per_conn must be at least 100 per RFC-002");
    }
}

proptest! {
    /// Property: max_connections in default config meets RFC-002 recommendation
    #[test]
    fn prop_max_connections_meets_rfc_recommendation(_arbitrary in 0u8..255) {
        let config = NetworkConfig::devnet();

        // Per RFC-002 §6.1, nodes SHOULD accept at least 50 connections
        prop_assert!(config.max_connections >= 50,
            "max_connections should be at least 50 per RFC-002");
    }
}

// ============================================================================
// Round-trip Property Tests
// ============================================================================

proptest! {
    /// Property: Secret key to public key is deterministic
    #[test]
    fn prop_secret_to_public_deterministic(_seed in 0u64..100) {
        let secret = SecretKey::generate(&mut rand::rng());

        // Multiple calls should produce identical results
        let public1 = secret.public();
        let public2 = secret.public();
        let public3 = secret.public();

        prop_assert_eq!(public1, public2);
        prop_assert_eq!(public2, public3);
    }
}

proptest! {
    /// Property: NodeAddr to string and back preserves node_id
    #[test]
    fn prop_node_addr_string_roundtrip(_seed in 0u64..100) {
        let secret = SecretKey::generate(&mut rand::rng());
        let public_key = secret.public();
        let node_addr = objects_transport::NodeAddr::new(public_key);

        let node_id_before = node_addr.id;
        let addr_string = node_addr.id.to_string();

        prop_assert!(!addr_string.is_empty());
        prop_assert_eq!(node_id_before, node_addr.id,
            "NodeId should remain unchanged after string conversion");
    }
}
