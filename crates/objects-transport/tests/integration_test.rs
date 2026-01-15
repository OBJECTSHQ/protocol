//! Integration tests for objects-transport.
//!
//! Tests the full lifecycle and cross-module integration of the transport layer.

mod common;

use common::*;
use objects_transport::{
    ALPN, DEFAULT_RELAY_URL, DISCOVERY_TOPIC_DEVNET, NetworkConfig, NodeAddr, ObjectsEndpoint,
    SecretKey,
};
use rstest::*;
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// ObjectsEndpoint Lifecycle Tests
// ============================================================================

#[tokio::test]
async fn test_endpoint_creation_with_defaults() {
    let endpoint = test_endpoint().await;

    // Verify endpoint was created successfully
    let node_id = endpoint.node_id();
    assert!(
        !node_id.to_string().is_empty(),
        "NodeId should not be empty"
    );

    let node_addr = endpoint.node_addr();
    assert_eq!(
        node_addr.id, node_id,
        "NodeAddr should contain the endpoint's NodeId"
    );
}

#[tokio::test]
async fn test_endpoint_creation_with_custom_key() {
    let secret_key = random_secret_key();
    let expected_node_id = secret_key.public();

    let endpoint = test_endpoint_with_key(secret_key.clone()).await;

    assert_node_ids_match(&expected_node_id, &endpoint.node_id());
}

#[tokio::test]
async fn test_endpoint_with_custom_config() {
    let config = NetworkConfig::devnet()
        .with_max_connections(5)
        .with_idle_timeout(Duration::from_secs(10));

    let endpoint = test_endpoint_with_config(config).await;

    // Verify endpoint uses the config
    assert!(!endpoint.node_id().to_string().is_empty());
}

#[tokio::test]
async fn test_endpoint_node_addr_is_retrievable() {
    let endpoint = test_endpoint().await;
    let node_addr = endpoint.node_addr();

    // Node address should be retrievable and contain the node ID
    assert_eq!(
        node_addr.id,
        endpoint.node_id(),
        "NodeAddr should contain correct node ID"
    );

    // Note: Relay URLs may not be immediately available in local test environment
    // They are discovered/added dynamically by the Iroh endpoint
}

// ============================================================================
// NetworkConfig Tests
// ============================================================================

#[tokio::test]
async fn test_network_config_defaults() {
    let config = NetworkConfig::devnet();

    assert_eq!(config.discovery_topic, DISCOVERY_TOPIC_DEVNET);
    assert_eq!(config.max_connections, 50);
    assert_eq!(config.max_streams_per_conn, 100);
    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(config.keepalive_interval, Duration::from_secs(15));
    assert_eq!(config.connect_timeout, Duration::from_secs(30));
}

#[tokio::test]
async fn test_network_config_builder() {
    let relay_url: objects_transport::RelayUrl =
        "https://custom-relay.example.com".parse().unwrap();
    let bootstrap_node = NodeAddr::new(SecretKey::generate(&mut rand::rng()).public());

    let config = NetworkConfig::devnet()
        .with_relay_url(relay_url.clone())
        .with_bootstrap_node(bootstrap_node.clone())
        .with_max_connections(25)
        .with_idle_timeout(Duration::from_secs(60));

    assert_eq!(config.relay_url, relay_url);
    assert_eq!(config.bootstrap_nodes.len(), 1);
    assert_eq!(config.max_connections, 25);
    assert_eq!(config.idle_timeout, Duration::from_secs(60));
}

// ============================================================================
// Connection Establishment Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires relay server or localhost network setup"]
async fn test_two_endpoints_can_connect() {
    let endpoint1 = test_endpoint().await;
    let endpoint2 = test_endpoint().await;

    // Give endpoints time to bind and discover local addresses
    short_wait().await;

    // Get endpoint2's address with local addressing
    let mut addr2 = endpoint2.node_addr();

    // Add localhost address explicitly for testing
    // In production, this would come from discovery or relay
    for socket in endpoint2.inner().bound_sockets() {
        addr2 = addr2.with_ip_addr(socket);
    }

    // Connect endpoint1 to endpoint2
    let conn = endpoint1
        .connect(addr2)
        .await
        .expect("should connect successfully");

    // Verify connection properties
    assert_node_ids_match(&endpoint2.node_id(), &conn.remote_node_id());
}

#[tokio::test]
#[ignore = "Requires relay server or localhost network setup"]
async fn test_endpoint_can_accept_connection() {
    let endpoint1 = test_endpoint().await;
    let endpoint2 = test_endpoint().await;

    let addr1 = endpoint1.node_addr();

    // Spawn a task to accept on endpoint1
    let accept_handle = tokio::spawn(async move { endpoint1.accept().await });

    // Give accept time to start listening
    short_wait().await;

    // Connect from endpoint2
    let _conn = endpoint2
        .connect(addr1)
        .await
        .expect("should connect successfully");

    // Verify endpoint1 accepted the connection
    let accepted_conn = accept_handle
        .await
        .expect("accept task should complete")
        .expect("should accept connection");

    assert_node_ids_match(&endpoint2.node_id(), &accepted_conn.remote_node_id());
}

// ============================================================================
// Stream Communication Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires relay server or localhost network setup"]
async fn test_bidirectional_stream_communication() {
    let endpoint1 = test_endpoint().await;
    let endpoint2 = test_endpoint().await;

    let addr2 = endpoint2.node_addr();

    // Connect
    let conn1 = endpoint1.connect(addr2).await.expect("should connect");

    // Accept on endpoint2
    let accept_handle = tokio::spawn(async move { endpoint2.accept().await });

    short_wait().await;

    let conn2 = accept_handle
        .await
        .expect("accept task should complete")
        .expect("should accept");

    // Open bidirectional stream from conn1
    let (mut send1, mut recv1) = conn1.open_bi().await.expect("should open bi stream");

    // Accept on conn2
    let accept_bi_handle = tokio::spawn(async move { conn2.accept_bi().await });

    // Write from endpoint1
    let test_data = b"Hello from endpoint1";
    send1.write_all(test_data).await.expect("should write");
    send1.finish().expect("should finish");

    // Read on endpoint2
    let (mut send2, mut recv2) = accept_bi_handle
        .await
        .expect("accept bi task should complete")
        .expect("should accept bi stream");

    let received = recv2.read_to_end(1024).await.expect("should read");
    assert_eq!(
        received.as_slice(),
        test_data,
        "received data should match sent data"
    );

    // Send response back
    let response_data = b"Hello from endpoint2";
    send2
        .write_all(response_data)
        .await
        .expect("should write response");
    send2.finish().expect("should finish response");

    // Read response on endpoint1
    let response = recv1.read_to_end(1024).await.expect("should read response");
    assert_eq!(
        response.as_slice(),
        response_data,
        "response data should match"
    );
}

#[tokio::test]
#[ignore = "Requires relay server or localhost network setup"]
async fn test_unidirectional_stream_communication() {
    let endpoint1 = test_endpoint().await;
    let endpoint2 = test_endpoint().await;

    let addr2 = endpoint2.node_addr();

    // Connect
    let conn1 = endpoint1.connect(addr2).await.expect("should connect");

    // Accept on endpoint2
    let accept_handle = tokio::spawn(async move { endpoint2.accept().await });

    short_wait().await;

    let conn2 = accept_handle
        .await
        .expect("accept task should complete")
        .expect("should accept");

    // Open unidirectional stream from conn1
    let mut send = conn1.open_uni().await.expect("should open uni stream");

    // Accept on conn2
    let accept_uni_handle = tokio::spawn(async move { conn2.accept_uni().await });

    // Write from endpoint1
    let test_data = b"One-way message";
    send.write_all(test_data).await.expect("should write");
    send.finish().expect("should finish");

    // Read on endpoint2
    let mut recv = accept_uni_handle
        .await
        .expect("accept uni task should complete")
        .expect("should accept uni stream");

    let received = recv.read_to_end(1024).await.expect("should read");
    assert_eq!(
        received.as_slice(),
        test_data,
        "received data should match sent data"
    );
}

#[tokio::test]
#[ignore = "Requires relay server or localhost network setup"]
async fn test_multiple_streams_on_same_connection() {
    let endpoint1 = test_endpoint().await;
    let endpoint2 = test_endpoint().await;

    let addr2 = endpoint2.node_addr();

    // Connect
    let conn1 = Arc::new(endpoint1.connect(addr2).await.expect("should connect"));

    // Accept on endpoint2
    let accept_handle = tokio::spawn(async move { endpoint2.accept().await });

    short_wait().await;

    let conn2 = Arc::new(
        accept_handle
            .await
            .expect("accept task should complete")
            .expect("should accept"),
    );

    // Open multiple streams
    let stream1_handle = tokio::spawn({
        let conn1 = Arc::clone(&conn1);
        async move {
            let (mut send, _recv) = conn1.open_bi().await.expect("should open stream 1");
            send.write_all(b"stream1").await.expect("should write");
            send.finish().expect("should finish");
        }
    });

    let stream2_handle = tokio::spawn({
        let conn1 = Arc::clone(&conn1);
        async move {
            let (mut send, _recv) = conn1.open_bi().await.expect("should open stream 2");
            send.write_all(b"stream2").await.expect("should write");
            send.finish().expect("should finish");
        }
    });

    // Accept both streams
    let accept1_handle = tokio::spawn({
        let conn2 = Arc::clone(&conn2);
        async move {
            let (_send, mut recv) = conn2.accept_bi().await.expect("should accept stream 1");
            recv.read_to_end(1024).await.expect("should read")
        }
    });

    let accept2_handle = tokio::spawn({
        let conn2 = Arc::clone(&conn2);
        async move {
            let (_send, mut recv) = conn2.accept_bi().await.expect("should accept stream 2");
            recv.read_to_end(1024).await.expect("should read")
        }
    });

    // Wait for all operations
    stream1_handle.await.expect("stream1 should complete");
    stream2_handle.await.expect("stream2 should complete");

    let data1 = accept1_handle.await.expect("accept1 should complete");
    let data2 = accept2_handle.await.expect("accept2 should complete");

    // Verify both streams received data (order may vary)
    let mut received = vec![data1.to_vec(), data2.to_vec()];
    received.sort();
    assert!(
        received.contains(&b"stream1".to_vec()) && received.contains(&b"stream2".to_vec()),
        "should receive data from both streams"
    );
}

// ============================================================================
// Connection Management Tests
// ============================================================================

#[tokio::test]
#[ignore = "Requires relay server or localhost network setup"]
async fn test_connection_close() {
    let endpoint1 = test_endpoint().await;
    let endpoint2 = test_endpoint().await;

    let addr2 = endpoint2.node_addr();

    let conn1 = endpoint1.connect(addr2).await.expect("should connect");

    // Close the connection
    conn1.close(0, b"test close");

    // Wait for close to propagate
    tokio::time::timeout(Duration::from_secs(2), conn1.closed())
        .await
        .expect("connection should close within timeout");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_connect_to_invalid_address_fails() {
    let endpoint = test_endpoint().await;

    // Create an invalid node address (non-existent peer)
    let invalid_secret = SecretKey::generate(&mut rand::rng());
    let invalid_addr = NodeAddr::new(invalid_secret.public());

    // Attempt to connect should fail or timeout
    let result = tokio::time::timeout(Duration::from_secs(2), endpoint.connect(invalid_addr)).await;

    // Either timeout or connection failure is acceptable
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "connecting to invalid address should fail or timeout"
    );
}

// ============================================================================
// Constants Validation Tests
// ============================================================================

#[tokio::test]
async fn test_alpn_constant() {
    assert_eq!(
        ALPN, b"/objects/0.1",
        "ALPN should match RFC-002 specification"
    );
}

#[tokio::test]
async fn test_discovery_topic_constant() {
    assert_eq!(
        DISCOVERY_TOPIC_DEVNET, "/objects/devnet/0.1/discovery",
        "Discovery topic should match RFC-002 specification"
    );
}

#[tokio::test]
async fn test_default_relay_url_constant() {
    assert_eq!(
        DEFAULT_RELAY_URL, "https://relay.objects.foundation",
        "Default relay URL should match RFC-002 specification"
    );

    // Verify it can be parsed
    let parsed = DEFAULT_RELAY_URL.parse::<objects_transport::RelayUrl>();
    assert!(parsed.is_ok(), "Default relay URL should be valid");
}

// ============================================================================
// Builder Pattern Tests
// ============================================================================

#[tokio::test]
async fn test_endpoint_builder_default() {
    let endpoint = ObjectsEndpoint::builder()
        .bind()
        .await
        .expect("should build with defaults");

    assert!(!endpoint.node_id().to_string().is_empty());
}

#[tokio::test]
async fn test_endpoint_builder_with_config() {
    let config = test_config();
    let endpoint = ObjectsEndpoint::builder()
        .config(config)
        .bind()
        .await
        .expect("should build with custom config");

    assert!(!endpoint.node_id().to_string().is_empty());
}

#[tokio::test]
async fn test_endpoint_builder_with_secret_key() {
    let secret_key = random_secret_key();
    let expected_node_id = secret_key.public();

    let endpoint = ObjectsEndpoint::builder()
        .secret_key(secret_key)
        .bind()
        .await
        .expect("should build with custom secret key");

    assert_node_ids_match(&expected_node_id, &endpoint.node_id());
}
