use objects_cli::client::NodeClient;
use objects_cli::commands;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_status_node_running() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "node_id": "test_node_123",
            "relay_url": "https://relay.objects.foundation",
            "peer_count": 2,
            "identity": {
                "id": "obj_test123",
                "handle": "@alice",
                "nonce": "0102030405060708",
                "signer_type": "passkey"
            }
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::status::run(&client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_status_no_identity() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "node_id": "test_node_456",
            "relay_url": "https://relay.objects.foundation",
            "peer_count": 0,
            "identity": null
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::status::run(&client).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_status_node_down() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = commands::status::run(&client).await;
    assert!(result.is_ok()); // Should not error, just print message
}
