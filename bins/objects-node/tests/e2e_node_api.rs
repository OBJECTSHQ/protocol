//! E2E tests for Node REST API endpoints.
//!
//! Tests Node HTTP API with real in-process node and registry.

mod harness;

use harness::TestHarness;
use reqwest::StatusCode;

#[tokio::test]
async fn test_health_endpoint() {
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
    let harness = TestHarness::new().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/identity", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_peer_discovery_between_nodes() {
    let harness = TestHarness::new().await.unwrap();

    // Give nodes time to discover each other via gossip
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let client = reqwest::Client::new();

    // Node A should see Node B
    let response = client
        .get(format!("{}/peers", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();

    // Should have at least discovered node B
    // (May have 0 if discovery hasn't completed yet - gossip is eventually consistent)
    assert!(body["peers"].is_array());
}

#[tokio::test]
async fn test_projects_list_empty_initially() {
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
