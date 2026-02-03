use objects_cli::client::NodeClient;
use objects_cli::commands;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_identity_create() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "obj_test123",
            "handle": "@alice",
            "nonce": "0102030405060708",
            "signer_type": "passkey"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::identity::create("alice".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_identity_create_with_at_prefix() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "obj_test456",
            "handle": "@bob",
            "nonce": "0102030405060708",
            "signer_type": "wallet"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::identity::create("@bob".to_string(), &client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_identity_show_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "obj_test789",
            "handle": "@charlie",
            "nonce": "0102030405060708",
            "signer_type": "passkey"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::identity::show(&client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_identity_show_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::identity::show(&client).await;
    assert!(result.is_ok()); // Should not error, just print message
}
