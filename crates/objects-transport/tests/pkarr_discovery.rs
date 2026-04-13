//! Pkarr/DNS discovery integration tests.
//!
//! These tests verify that iroh's built-in PkarrPublisher and DnsDiscovery
//! work end-to-end: a node publishes its addressing info to dns.iroh.link,
//! and another node can resolve and connect using only the NodeId.
//!
//! All tests are `#[ignore]` because they require internet access.
//! Run with: `cargo test -p objects-transport pkarr_discovery -- --ignored`

use objects_transport::{NodeAddr, ObjectsEndpoint};
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;

/// Build an endpoint with relay enabled (N0 preset with Pkarr + DNS discovery).
///
/// Uses the default relay mode which, without an explicit config, falls back
/// to iroh's N0 defaults (including `PkarrPublisher` and `DnsDiscovery`).
async fn relay_endpoint() -> ObjectsEndpoint {
    ObjectsEndpoint::builder()
        .bind()
        .await
        .expect("should bind with relay defaults")
}

/// Wait for the endpoint to connect to a relay and publish its pkarr record.
///
/// `online()` resolves once the endpoint has a relay connection, which is a
/// prerequisite for pkarr publishing (the signed record includes the relay URL).
async fn wait_for_pkarr_publish(endpoint: &ObjectsEndpoint) {
    endpoint.inner().online().await;

    // Allow time for the pkarr record to propagate to dns.iroh.link.
    // PkarrPublisher publishes shortly after the relay handshake completes,
    // but DNS propagation adds latency.
    tokio::time::sleep(Duration::from_secs(5)).await;
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_pkarr_node_id_only_connect() {
    // Node A: start and publish addressing info via pkarr
    let node_a = Arc::new(relay_endpoint().await);
    wait_for_pkarr_publish(&node_a).await;

    let node_a_id = node_a.node_id();

    // Node B: start with relay (gets its own pkarr + DNS discovery)
    let node_b = relay_endpoint().await;
    node_b.inner().online().await;

    // Connect using ONLY NodeId — no relay URL, no direct addresses.
    // DnsDiscovery must resolve node_a_id via dns.iroh.link to get the
    // relay URL and direct addresses that PkarrPublisher published.
    let node_a_addr = NodeAddr::new(node_a_id);

    let ep_a = node_a.clone();
    let accept_handle = tokio::spawn(async move { ep_a.accept().await });

    let conn = tokio::time::timeout(Duration::from_secs(30), node_b.connect(node_a_addr))
        .await
        .expect("connect should not timeout — pkarr resolution failed")
        .expect("connect should succeed");

    assert_eq!(
        conn.remote_node_id(),
        node_a_id,
        "should connect to the correct peer"
    );

    let _ = accept_handle.await.expect("accept task panicked");
}

#[tokio::test]
#[ignore]
#[serial]
async fn test_pkarr_bidirectional_after_discovery() {
    // Both nodes start with relay, publishing pkarr records
    let node_a = Arc::new(relay_endpoint().await);
    let node_b = Arc::new(relay_endpoint().await);

    wait_for_pkarr_publish(&node_a).await;
    wait_for_pkarr_publish(&node_b).await;

    let node_a_id = node_a.node_id();
    let node_b_id = node_b.node_id();

    // Node B connects to Node A using only NodeId
    let ep_a = node_a.clone();
    let accept_handle = tokio::spawn(async move { ep_a.accept().await });

    let conn_b = tokio::time::timeout(
        Duration::from_secs(30),
        node_b.connect(NodeAddr::new(node_a_id)),
    )
    .await
    .expect("connect should not timeout")
    .expect("connect should succeed");

    let conn_a = accept_handle
        .await
        .expect("accept task panicked")
        .expect("should accept connection");

    assert_eq!(conn_b.remote_node_id(), node_a_id);
    assert_eq!(conn_a.remote_node_id(), node_b_id);

    // Verify bidirectional data transfer over pkarr-discovered connection
    let (mut send_b, mut recv_b) = conn_b.open_bi().await.expect("should open bi stream");

    let accept_bi = tokio::spawn(async move { conn_a.accept_bi().await });

    let payload = b"pkarr discovery works";
    send_b.write_all(payload).await.expect("should write");
    send_b.finish().expect("should finish");

    let (mut send_a, mut recv_a) = accept_bi
        .await
        .expect("accept_bi task panicked")
        .expect("should accept bi stream");

    let received = recv_a.read_to_end(1024).await.expect("should read");
    assert_eq!(received.as_slice(), payload);

    // Send response back
    let response = b"confirmed";
    send_a.write_all(response).await.expect("should write back");
    send_a.finish().expect("should finish response");

    let resp_data = recv_b.read_to_end(1024).await.expect("should read back");
    assert_eq!(resp_data.as_slice(), response);
}
