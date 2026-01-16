//! Transport-layer test utilities for OBJECTS Protocol.
//!
//! This module provides standardized test utilities for creating and managing
//! transport endpoints, network configurations, and connection testing.
//!
//! # Quick Start
//!
//! ```rust
//! use objects_test_utils::transport;
//!
//! #[tokio::test]
//! async fn my_test() {
//!     // Create a test endpoint with defaults
//!     let endpoint = transport::endpoint().await;
//!
//!     // Create endpoint with custom config
//!     let config = transport::network_config()
//!         .with_max_connections(10);
//!     let endpoint = transport::endpoint_with_config(config).await;
//! }
//! ```

use objects_transport::{NetworkConfig, NodeAddr, ObjectsEndpoint, SecretKey};
use std::time::Duration;

// ============================================================================
// Network Configuration
// ============================================================================

/// Create a network configuration with sensible defaults for testing.
///
/// Uses devnet settings with reduced connection limits and timeouts
/// suitable for unit and integration tests.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// let config = transport::network_config()
///     .with_max_connections(10)
///     .with_idle_timeout(Duration::from_secs(5));
/// ```
pub fn network_config() -> NetworkConfig {
    NetworkConfig::devnet()
        .with_max_connections(10)
        .with_idle_timeout(Duration::from_secs(5))
}

/// Create a network configuration with a custom relay URL.
///
/// # Arguments
///
/// * `relay_url` - The relay URL to use (must be valid URL string)
///
/// # Panics
///
/// Panics if the relay URL is invalid.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// let config = transport::network_config_with_relay("https://custom-relay.example.com");
/// ```
pub fn network_config_with_relay(relay_url: &str) -> NetworkConfig {
    let relay = relay_url
        .parse()
        .unwrap_or_else(|_| panic!("Invalid relay URL: {}", relay_url));
    network_config().with_relay_url(relay)
}

// ============================================================================
// Endpoint Creation
// ============================================================================

/// Create a test endpoint with default configuration.
///
/// This is the primary factory for creating endpoints in tests.
/// Uses `OsRng` for cryptographic randomness per CLAUDE.md.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_endpoint() {
///     let endpoint = transport::endpoint().await;
///     assert!(!endpoint.node_id().to_string().is_empty());
/// }
/// ```
pub async fn endpoint() -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .config(network_config())
        .bind()
        .await
        .expect("failed to create test endpoint")
}

/// Create a test endpoint with a specific secret key.
///
/// Useful when you need deterministic node IDs or want to test
/// endpoint behavior with specific keys.
///
/// # Arguments
///
/// * `secret_key` - The secret key to use for the endpoint
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_with_key() {
///     let key = transport::secret_key();
///     let endpoint = transport::endpoint_with_key(key).await;
/// }
/// ```
pub async fn endpoint_with_key(secret_key: SecretKey) -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .config(network_config())
        .secret_key(secret_key)
        .bind()
        .await
        .expect("failed to create test endpoint with key")
}

/// Create a test endpoint with a specific configuration.
///
/// Useful when you need to test specific network configurations
/// or connection parameters.
///
/// # Arguments
///
/// * `config` - The network configuration to use
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
/// use std::time::Duration;
///
/// #[tokio::test]
/// async fn test_with_config() {
///     let config = transport::network_config()
///         .with_idle_timeout(Duration::from_secs(60));
///     let endpoint = transport::endpoint_with_config(config).await;
/// }
/// ```
pub async fn endpoint_with_config(config: NetworkConfig) -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .config(config)
        .bind()
        .await
        .expect("failed to create test endpoint with config")
}

// ============================================================================
// Cryptographic Primitives
// ============================================================================

/// Generate a random secret key for testing.
///
/// Uses cryptographically secure randomness per CLAUDE.md.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// let key = transport::secret_key();
/// let node_id = key.public();
/// ```
pub fn secret_key() -> SecretKey {
    SecretKey::generate(&mut rand::rng())
}

// ============================================================================
// Node Addressing
// ============================================================================

/// Create a node address from an endpoint.
///
/// Convenience function for extracting node addresses in tests.
///
/// # Arguments
///
/// * `endpoint` - The endpoint to get the node address from
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_node_addr() {
///     let endpoint = transport::endpoint().await;
///     let addr = transport::node_addr(&endpoint);
///     assert_eq!(addr.id, endpoint.node_id());
/// }
/// ```
pub fn node_addr(endpoint: &ObjectsEndpoint) -> NodeAddr {
    endpoint.node_addr()
}

// ============================================================================
// Async Test Helpers
// ============================================================================

/// Wait for a short duration (100ms).
///
/// Useful for giving async operations time to complete in tests,
/// such as waiting for connection establishment or discovery propagation.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_with_wait() {
///     let endpoint = transport::endpoint().await;
///     transport::wait_short().await;
///     // Endpoint is now ready
/// }
/// ```
pub async fn wait_short() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Wait for a medium duration (500ms).
///
/// Useful for discovery propagation, relay connection establishment,
/// or other operations that need more time to settle.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_discovery() {
///     let endpoint1 = transport::endpoint().await;
///     let endpoint2 = transport::endpoint().await;
///     transport::wait_medium().await;
///     // Discovery should have propagated
/// }
/// ```
pub async fn wait_medium() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Wait for a longer duration (1 second).
///
/// Useful for integration tests that need to wait for complex
/// multi-step operations or network propagation.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_integration() {
///     // ... complex setup
///     transport::wait_long().await;
///     // All operations should have completed
/// }
/// ```
pub async fn wait_long() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

// ============================================================================
// Assertions
// ============================================================================

/// Assert that two node IDs match.
///
/// Provides better error messages than raw `assert_eq!` by including
/// the node IDs in the panic message.
///
/// Uses `#[track_caller]` to report the correct source location.
///
/// # Arguments
///
/// * `expected` - The expected node ID
/// * `actual` - The actual node ID
///
/// # Panics
///
/// Panics if the node IDs don't match.
///
/// # Example
///
/// ```rust
/// use objects_test_utils::transport;
///
/// #[tokio::test]
/// async fn test_node_id() {
///     let key = transport::secret_key();
///     let expected_id = key.public();
///     let endpoint = transport::endpoint_with_key(key).await;
///     transport::assert_node_ids_match(&expected_id, &endpoint.node_id());
/// }
/// ```
#[track_caller]
pub fn assert_node_ids_match(
    expected: &objects_transport::NodeId,
    actual: &objects_transport::NodeId,
) {
    assert_eq!(
        expected, actual,
        "NodeId mismatch: expected {:?}, got {:?}",
        expected, actual
    );
}
