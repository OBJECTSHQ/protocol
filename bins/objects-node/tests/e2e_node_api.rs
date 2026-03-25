//! E2E tests for Node REST API endpoints.
//!
//! Tests Node HTTP API with real in-process node and registry.

mod harness;

use harness::TestHarness;
use reqwest::StatusCode;

macro_rules! require_docker {
    () => {
        if !harness::registry::docker_available() {
            eprintln!("Skipping: Docker registry image not available");
            return;
        }
    };
}

#[tokio::test]
async fn test_health_endpoint() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_status_endpoint() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/status", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["node_id"].is_string());
    assert!(body["relay_url"].is_string());
}

#[tokio::test]
async fn test_identity_not_found_initially() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/identity", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// Ignored: GossipDiscovery requires bootstrap peers or a rendezvous point
// for two isolated nodes to find each other. With just two nodes and no
// shared bootstrap, gossip topic subscription never propagates.
// Re-enable once we add bootstrap peer support or a discovery relay.
#[tokio::test]
#[ignore = "gossip discovery needs bootstrap peers — two isolated nodes cannot discover each other"]
async fn test_peer_discovery_between_nodes() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();

    // Poll until node A discovers node B via gossip.
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    loop {
        let response = client
            .get(format!("{}/peers", harness.node_a_url()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        let peers = body["peers"].as_array().expect("peers should be an array");

        if !peers.is_empty() {
            break; // Discovery worked
        }

        if tokio::time::Instant::now() > deadline {
            panic!("Timed out waiting for peer discovery — node A never found node B");
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn test_projects_list_empty_initially() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/projects", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["projects"].is_array());
    assert_eq!(body["projects"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_invalid_endpoint_returns_404() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nonexistent", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_cors_headers() {
    require_docker!();
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    // Should have CORS headers for web clients
    assert_eq!(response.status(), StatusCode::OK);
}
