use objects_cli::client::NodeClient;
use objects_cli::commands;
use serde_json::json;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_asset_add_success() {
    let mock = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let test_file = tmp.path().join("test.txt");
    fs::write(&test_file, b"test content").unwrap();

    Mock::given(method("POST"))
        .and(path("/projects/proj_123/assets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "asset_456",
            "filename": "test.txt",
            "content_type": "text/plain",
            "size": 12,
            "content_hash": "abc123def456",
            "created_at": 1704067200
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::asset::add(
        "proj_123".to_string(),
        test_file.to_str().unwrap().to_string(),
        &client,
    )
    .await;
    if let Err(e) = &result {
        eprintln!("Error: {:?}", e);
    }
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_asset_add_file_not_found() {
    let mock = MockServer::start().await;
    let client = NodeClient::new(mock.uri());

    let result = commands::asset::add(
        "proj_123".to_string(),
        "/nonexistent/file.txt".to_string(),
        &client,
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("File not found"));
}

#[tokio::test]
async fn test_asset_list_empty() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/proj_123/assets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "assets": []
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::asset::list("proj_123".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_asset_list_with_assets() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/proj_123/assets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "assets": [
                {
                    "id": "asset_1",
                    "filename": "file1.txt",
                    "content_type": "text/plain",
                    "size": 100,
                    "content_hash": "hash1",
                    "created_at": 1704067200
                },
                {
                    "id": "asset_2",
                    "filename": "image.png",
                    "content_type": "image/png",
                    "size": 2048,
                    "content_hash": "hash2",
                    "created_at": 1704067300
                }
            ]
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::asset::list("proj_123".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_asset_list_project_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/nonexistent/assets"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::asset::list("nonexistent".to_string(), &client).await;
    assert!(result.is_err());
}
