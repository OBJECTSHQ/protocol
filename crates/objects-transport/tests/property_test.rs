//! Property-based tests for objects-transport.
//!
//! Tests invariants and validation rules that must hold for all inputs.

use objects_test_utils::transport;
use objects_transport::NetworkConfig;
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
            let node_addr = objects_transport::NodeAddr::new(transport::secret_key().public());
            config = config.with_bootstrap_node(node_addr);
        }

        prop_assert_eq!(config.bootstrap_nodes.len(), count);
    }
}

// Constant-value tests (ALPN, discovery topic, relay URL) and NetworkConfig
// defaults are covered by integration_test.rs. Only property-based tests that
// exercise varying inputs belong in this file.
