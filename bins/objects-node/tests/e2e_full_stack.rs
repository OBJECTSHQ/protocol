//! Full stack E2E tests.
//!
//! Tests complete workflows using CLI + Node + Registry + Sync.

mod harness;

use harness::TestHarness;
use reqwest::StatusCode;
use sqlx::PgPool;

#[tokio::test]
async fn test_health_check_all_components() {
    let harness = TestHarness::new().await.unwrap();
    let client = reqwest::Client::new();

    // Check registry health
    let registry_health = client
        .get(format!("{}/health", harness.registry_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(registry_health.status(), StatusCode::OK);

    // Check node A health
    let node_a_health = client
        .get(format!("{}/health", harness.node_a_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(node_a_health.status(), StatusCode::OK);

    // Check node B health
    let node_b_health = client
        .get(format!("{}/health", harness.node_b_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(node_b_health.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_node_status_includes_network_info() {
    let harness = TestHarness::new().await.unwrap();
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/status", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();

    // Verify node_id is present and non-empty
    assert!(body["node_id"].is_string());
    let node_id = body["node_id"].as_str().unwrap();
    assert!(!node_id.is_empty());

    // Verify relay_url is present
    assert!(body["relay_url"].is_string());
}

#[sqlx::test]
async fn test_projects_lifecycle(pool: PgPool) {
    let harness = TestHarness::with_pool(pool).await.unwrap();

    // Register identities before creating projects
    harness.register_test_identities().await.unwrap();

    let client = reqwest::Client::new();

    // Create a project via Node A
    let create_response = client
        .post(format!("{}/projects", harness.node_a_url()))
        .json(&serde_json::json!({
            "name": "E2E Test Project",
            "description": "Created via E2E test"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::CREATED);

    let project: serde_json::Value = create_response.json().await.unwrap();
    let project_id = project["id"].as_str().unwrap();

    // List projects - should include our new project
    let list_response = client
        .get(format!("{}/projects", harness.node_a_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(list_response.status(), StatusCode::OK);

    let projects: serde_json::Value = list_response.json().await.unwrap();
    assert!(projects["projects"].is_array());
    assert!(projects["projects"].as_array().unwrap().len() >= 1);

    // Get specific project
    let get_response = client
        .get(format!("{}/projects/{}", harness.node_a_url(), project_id))
        .send()
        .await
        .unwrap();

    assert_eq!(get_response.status(), StatusCode::OK);

    let fetched_project: serde_json::Value = get_response.json().await.unwrap();
    assert_eq!(fetched_project["id"], project_id);
    assert_eq!(fetched_project["name"], "E2E Test Project");
}

#[tokio::test]
async fn test_cli_client_can_communicate() {
    let harness = TestHarness::new().await.unwrap();

    let client_a = harness.cli_client_a();
    let client_b = harness.cli_client_b();

    // Both clients should be able to check health
    let health_a = client_a.health().await;
    let health_b = client_b.health().await;

    assert!(health_a.is_ok());
    assert!(health_b.is_ok());

    assert_eq!(health_a.unwrap().status, "ok");
    assert_eq!(health_b.unwrap().status, "ok");
}

#[sqlx::test]
async fn test_two_nodes_independent_operations(pool: PgPool) {
    let harness = TestHarness::with_pool(pool).await.unwrap();

    // Register identities before creating projects
    harness.register_test_identities().await.unwrap();

    // Node A creates a project
    let client_a = reqwest::Client::new();
    let project_a = client_a
        .post(format!("{}/projects", harness.node_a_url()))
        .json(&serde_json::json!({
            "name": "Node A Project",
            "description": "Created on Node A"
        }))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    // Node B creates a different project
    let client_b = reqwest::Client::new();
    let project_b = client_b
        .post(format!("{}/projects", harness.node_b_url()))
        .json(&serde_json::json!({
            "name": "Node B Project",
            "description": "Created on Node B"
        }))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    // Projects should have different IDs
    assert_ne!(project_a["id"], project_b["id"]);

    // Node A should only see its project
    let list_a = client_a
        .get(format!("{}/projects", harness.node_a_url()))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let projects_a = list_a["projects"].as_array().unwrap();
    assert!(projects_a.iter().any(|p| p["id"] == project_a["id"]));

    // Node B should only see its project (before any sync)
    let list_b = client_b
        .get(format!("{}/projects", harness.node_b_url()))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let projects_b = list_b["projects"].as_array().unwrap();
    assert!(projects_b.iter().any(|p| p["id"] == project_b["id"]));
}

#[tokio::test]
async fn test_registry_integration() {
    let harness = TestHarness::new().await.unwrap();

    // Registry should be accessible
    let client = reqwest::Client::new();
    let health = client
        .get(format!("{}/health", harness.registry_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(health.status(), StatusCode::OK);

    let body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}
