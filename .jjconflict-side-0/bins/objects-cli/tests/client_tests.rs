use base64::Engine as _;
use objects_cli::client::NodeClient;
use objects_cli::error::CliError;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_health_success() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = client.health().await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.status, "ok");
}

#[tokio::test]
async fn test_health_server_error() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = client.health().await;
    assert!(result.is_err());

    match result.unwrap_err() {
        CliError::NodeError { status, .. } => {
            assert_eq!(status, 500);
        }
        _ => panic!("Expected NodeError"),
    }
}

#[tokio::test]
async fn test_status_success() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "node_id": "test_node_123",
            "peer_count": 2,
            "identity": {
                "id": "obj_test123",
                "handle": "@alice",
                "nonce": "0102030405060708",
                "signer_type": "passkey"
            },
            "relay_url": "https://relay.objects.foundation"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = client.status().await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.node_id, "test_node_123");
    assert_eq!(response.peer_count, 2);
    assert!(response.identity.is_some());
}

#[tokio::test]
async fn test_get_identity_success() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "obj_test123",
            "handle": "@alice",
            "nonce": "0102030405060708",
            "signer_type": "passkey"
        })))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = client.get_identity().await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.handle, "@alice");
}

#[tokio::test]
async fn test_get_identity_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let result = client.get_identity().await;
    assert!(result.is_err());

    match result.unwrap_err() {
        CliError::NotFound(_) => {}
        _ => panic!("Expected NotFound error"),
    }
}

#[tokio::test]
async fn test_create_identity_success() {
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
    let request = objects_cli::types::CreateIdentityRequest {
        handle: "@alice".to_string(),
        signer_type: "PASSKEY".to_string(),
        signer_public_key: base64::engine::general_purpose::STANDARD
            .encode(b"test_public_key_33_bytes_long_0123456"),
        nonce: base64::engine::general_purpose::STANDARD.encode(b"testnonce"),
        timestamp: 1234567890,
        signature: objects_cli::types::SignatureData {
            signature: base64::engine::general_purpose::STANDARD.encode(b"test_signature"),
            public_key: Some(base64::engine::general_purpose::STANDARD.encode(b"test_pk")),
            address: None,
            authenticator_data: Some(
                base64::engine::general_purpose::STANDARD.encode(b"test_auth"),
            ),
            client_data_json: Some(
                base64::engine::general_purpose::STANDARD.encode(b"{\"type\":\"webauthn.get\"}"),
            ),
        },
    };

    let result = client.create_identity(request).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.id, "obj_test123");
    assert_eq!(response.handle, "@alice");
}

#[tokio::test]
async fn test_create_identity_conflict() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity"))
        .respond_with(ResponseTemplate::new(409).set_body_string("Handle already taken"))
        .mount(&mock)
        .await;

    let client = NodeClient::new(mock.uri());
    let request = objects_cli::types::CreateIdentityRequest {
        handle: "@alice".to_string(),
        signer_type: "PASSKEY".to_string(),
        signer_public_key: base64::engine::general_purpose::STANDARD
            .encode(b"test_public_key_33_bytes_long_0123456"),
        nonce: base64::engine::general_purpose::STANDARD.encode(b"testnonce"),
        timestamp: 1234567890,
        signature: objects_cli::types::SignatureData {
            signature: base64::engine::general_purpose::STANDARD.encode(b"test_signature"),
            public_key: Some(base64::engine::general_purpose::STANDARD.encode(b"test_pk")),
            address: None,
            authenticator_data: Some(
                base64::engine::general_purpose::STANDARD.encode(b"test_auth"),
            ),
            client_data_json: Some(
                base64::engine::general_purpose::STANDARD.encode(b"{\"type\":\"webauthn.get\"}"),
            ),
        },
    };

    let result = client.create_identity(request).await;
    assert!(result.is_err());

    match result.unwrap_err() {
        CliError::NodeError { status, .. } => {
            assert_eq!(status, 409);
        }
        _ => panic!("Expected NodeError"),
    }
}
