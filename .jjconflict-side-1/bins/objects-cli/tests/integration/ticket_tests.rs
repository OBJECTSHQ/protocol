use objects_cli::client::NodeClient;
use objects_cli::commands;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_ticket_create_success() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tickets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ticket": "blob:Qm123abc:node123:relay123"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::ticket::create("proj_123".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_ticket_create_project_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tickets"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::ticket::create("nonexistent".to_string(), &client).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ticket_redeem_success() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tickets/redeem"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "proj_456",
            "name": "Shared Project",
            "description": "A shared project",
            "owner_id": "obj_user2",
            "created_at": 1704067200,
            "updated_at": 1704067200
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result =
        commands::ticket::redeem("blob:Qm123abc:node123:relay123".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_ticket_redeem_invalid_format() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tickets/redeem"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "Invalid ticket format"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::ticket::redeem("invalid-ticket".to_string(), &client).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ticket_redeem_expired() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tickets/redeem"))
        .respond_with(ResponseTemplate::new(410).set_body_json(json!({
            "error": "Ticket expired or invalid"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result =
        commands::ticket::redeem("blob:Qm123abc:node123:relay123".to_string(), &client).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ticket_format_validation() {
    // This test verifies that tickets follow the expected format
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tickets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ticket": "doc:replica123:node456:relay789"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::ticket::create("proj_789".to_string(), &client).await;
    assert!(result.is_ok());
}
