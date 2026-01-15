//! Shared test utilities for objects-transport tests.

use objects_transport::{NetworkConfig, NodeAddr, ObjectsEndpoint, SecretKey};
use std::time::Duration;

/// Create a test network configuration with sensible defaults for testing.
pub fn test_config() -> NetworkConfig {
    NetworkConfig::devnet()
        .with_max_connections(10)
        .with_idle_timeout(Duration::from_secs(5))
}

/// Create a test network configuration with a custom relay URL.
pub fn test_config_with_relay(relay_url: &str) -> NetworkConfig {
    let relay = relay_url.parse().expect("valid relay URL");
    test_config().with_relay_url(relay)
}

/// Create a test endpoint with default configuration.
pub async fn test_endpoint() -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .config(test_config())
        .bind()
        .await
        .expect("failed to create test endpoint")
}

/// Create a test endpoint with a specific secret key.
pub async fn test_endpoint_with_key(secret_key: SecretKey) -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .config(test_config())
        .secret_key(secret_key)
        .bind()
        .await
        .expect("failed to create test endpoint with key")
}

/// Create a test endpoint with a specific configuration.
pub async fn test_endpoint_with_config(config: NetworkConfig) -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .config(config)
        .bind()
        .await
        .expect("failed to create test endpoint with config")
}

/// Generate a random secret key for testing.
pub fn random_secret_key() -> SecretKey {
    SecretKey::generate(&mut rand::rng())
}

/// Create a node address from an endpoint for testing.
pub fn node_addr_from_endpoint(endpoint: &ObjectsEndpoint) -> NodeAddr {
    endpoint.node_addr()
}

/// Wait for a short duration (useful in async tests).
pub async fn short_wait() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Wait for a medium duration (useful for discovery propagation).
pub async fn medium_wait() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Wait for a longer duration (useful for integration tests).
pub async fn long_wait() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Assert that two node IDs match.
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
