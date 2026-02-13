use objects_cli::client::NodeClient;
use objects_cli::commands;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_project_create_success() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "proj_123",
            "name": "My Project",
            "description": "Test project",
            "owner_id": "obj_user1",
            "created_at": 1704067200,
            "updated_at": 1704067200
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::project::create(
        "My Project".to_string(),
        Some("Test project".to_string()),
        &client,
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_project_create_without_description() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "proj_456",
            "name": "Simple Project",
            "description": null,
            "owner_id": "obj_user1",
            "created_at": 1704067200,
            "updated_at": 1704067200
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::project::create("Simple Project".to_string(), None, &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_project_list_empty() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": []
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::project::list(&client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_project_list_with_projects() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [
                {
                    "id": "proj_1",
                    "name": "Project One",
                    "description": "First project",
                    "owner_id": "obj_user1",
                    "created_at": 1704067200,
                    "updated_at": 1704067200
                },
                {
                    "id": "proj_2",
                    "name": "Project Two",
                    "description": null,
                    "owner_id": "obj_user1",
                    "created_at": 1704153600,
                    "updated_at": 1704153600
                }
            ]
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::project::list(&client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_project_get_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/proj_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "proj_123",
            "name": "Test Project",
            "description": "A test project",
            "owner_id": "obj_user1",
            "created_at": 1704067200,
            "updated_at": 1704067200
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::project::get("proj_123".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_project_get_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/nonexistent"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::project::get("nonexistent".to_string(), &client).await;
    assert!(result.is_err());
}
