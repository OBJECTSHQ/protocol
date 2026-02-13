//! Integration tests for OBJECTS Registry REST API.
//!
//! These tests use sqlx::test to run against a real PostgreSQL database.

use alloy_primitives::keccak256;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::ecdsa::signature::Signer as _;
use objects_identity::IdentityId;
use objects_registry::api::rest::handlers::AppState;
use objects_registry::api::rest::routes::create_router;
use objects_registry::api::rest::types::*;
use objects_registry::config::Config;
use objects_test_utils::{crypto, time};
use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions, PgPool};
use tower::ServiceExt;

/// Helper: Create passkey signature for create identity message
fn sign_create_identity_passkey(
    signing_key: &P256SigningKey,
    identity_id: &str,
    handle: &str,
    timestamp: u64,
) -> SignatureRequest {
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes: [u8; 33] = verifying_key
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    // Create message per verification.rs
    let message =
        objects_identity::message::create_identity_message(identity_id, handle, timestamp);

    // Create minimal WebAuthn data
    let rp_id_hash = Sha256::digest(b"example.com");
    let flags = 0x05u8;
    let counter = 0u32.to_be_bytes();
    let mut authenticator_data = rp_id_hash.to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&counter);

    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(message.as_bytes())
    )
    .into_bytes();

    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = authenticator_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let signature_der: p256::ecdsa::Signature = signing_key.sign(&signed_data);

    SignatureRequest {
        signature: BASE64.encode(signature_der.to_der().to_bytes()),
        public_key: Some(BASE64.encode(public_key_bytes)),
        authenticator_data: Some(BASE64.encode(authenticator_data)),
        client_data_json: Some(BASE64.encode(client_data_json)),
        address: None,
    }
}

/// Helper: Create wallet signature for create identity message
fn sign_create_identity_wallet(
    signing_key: &K256SigningKey,
    identity_id: &str,
    handle: &str,
    timestamp: u64,
) -> (SignatureRequest, String) {
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key_point.as_bytes();

    // Derive Ethereum address
    let pub_key_hash = keccak256(&public_key_bytes[1..]);
    let address = format!("0x{}", hex::encode(&pub_key_hash[12..]));

    // Create message
    let message =
        objects_identity::message::create_identity_message(identity_id, handle, timestamp);

    // EIP-191 prefix
    let eip191_prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut prefixed = eip191_prefix.as_bytes().to_vec();
    prefixed.extend_from_slice(message.as_bytes());
    let message_hash = keccak256(&prefixed);

    // Sign with recovery
    let (signature_der, recovery_id) = signing_key
        .sign_prehash_recoverable(message_hash.as_slice())
        .unwrap();
    let mut signature_bytes = signature_der.to_bytes().to_vec();
    signature_bytes.push(recovery_id.to_byte());

    let sig = SignatureRequest {
        signature: BASE64.encode(signature_bytes),
        public_key: None,
        authenticator_data: None,
        client_data_json: None,
        address: Some(address.clone()),
    };

    (sig, address)
}

async fn setup_test_app(pool: PgPool) -> axum::Router {
    let config = Config {
        database_url: pool.connect_options().to_url_lossy().to_string(),
        rest_port: 8080,
        grpc_port: 9090,
        timestamp_future_max: std::time::Duration::from_secs(5 * 60),
        timestamp_past_max: std::time::Duration::from_secs(24 * 60 * 60),
    };
    let state = AppState { pool, config };
    create_router(state)
}

#[sqlx::test]
async fn test_create_identity_with_passkey(pool: PgPool) {
    let app = setup_test_app(pool).await;

    // Generate passkey and derive identity
    let nonce = rand::random::<[u8; 8]>();
    let signing_key = crypto::passkey_keypair().signing_key;
    let public_key: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let identity_id = IdentityId::derive(&public_key, &nonce);

    let handle = "alice";
    let timestamp = time::now();
    let signature =
        sign_create_identity_passkey(&signing_key, identity_id.as_str(), handle, timestamp);

    let request_body = serde_json::json!({
        "handle": handle,
        "signer_type": "PASSKEY",
        "signer_public_key": BASE64.encode(public_key),
        "nonce": BASE64.encode(nonce),
        "timestamp": timestamp,
        "signature": signature,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/identities")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let identity: IdentityResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(identity.id, identity_id.as_str());
    assert_eq!(identity.handle, handle);
    assert_eq!(identity.signer_type, "PASSKEY");
}

#[sqlx::test]
async fn test_create_identity_with_wallet(pool: PgPool) {
    let app = setup_test_app(pool).await;

    // Generate wallet and derive identity
    let nonce = rand::random::<[u8; 8]>();
    let signing_key = crypto::wallet_keypair().signing_key;
    let public_key: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let identity_id = IdentityId::derive(&public_key, &nonce);

    let handle = "bob";
    let timestamp = time::now();
    let (signature, _address) =
        sign_create_identity_wallet(&signing_key, identity_id.as_str(), handle, timestamp);

    let request_body = serde_json::json!({
        "handle": handle,
        "signer_type": "WALLET",
        "signer_public_key": BASE64.encode(public_key),
        "nonce": BASE64.encode(nonce),
        "timestamp": timestamp,
        "signature": signature,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/identities")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let identity: IdentityResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(identity.id, identity_id.as_str());
    assert_eq!(identity.handle, handle);
    assert_eq!(identity.signer_type, "WALLET");
}

#[sqlx::test]
async fn test_create_identity_duplicate_handle(pool: PgPool) {
    let app = setup_test_app(pool.clone()).await;

    // Create first identity with handle "alice"
    let nonce1 = rand::random::<[u8; 8]>();
    let signing_key1 = crypto::passkey_keypair().signing_key;
    let public_key1: [u8; 33] = signing_key1
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let identity_id1 = IdentityId::derive(&public_key1, &nonce1);

    let handle = "alice";
    let timestamp = time::now();
    let signature1 =
        sign_create_identity_passkey(&signing_key1, identity_id1.as_str(), handle, timestamp);

    let request_body1 = serde_json::json!({
        "handle": handle,
        "signer_type": "PASSKEY",
        "signer_public_key": BASE64.encode(public_key1),
        "nonce": BASE64.encode(nonce1),
        "timestamp": timestamp,
        "signature": signature1,
    });

    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/identities")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::CREATED);

    // Try to create second identity with same handle "alice"
    let nonce2 = rand::random::<[u8; 8]>();
    let signing_key2 = crypto::passkey_keypair().signing_key;
    let public_key2: [u8; 33] = signing_key2
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let identity_id2 = IdentityId::derive(&public_key2, &nonce2);

    let signature2 =
        sign_create_identity_passkey(&signing_key2, identity_id2.as_str(), handle, timestamp);

    let request_body2 = serde_json::json!({
        "handle": handle,
        "signer_type": "PASSKEY",
        "signer_public_key": BASE64.encode(public_key2),
        "nonce": BASE64.encode(nonce2),
        "timestamp": timestamp,
        "signature": signature2,
    });

    let response2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/identities")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 409 CONFLICT
    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn test_resolve_identity_by_handle(pool: PgPool) {
    let app = setup_test_app(pool.clone()).await;

    // Create identity with handle "alice"
    let nonce = rand::random::<[u8; 8]>();
    let signing_key = crypto::passkey_keypair().signing_key;
    let public_key: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let identity_id = IdentityId::derive(&public_key, &nonce);

    let handle = "alice";
    let timestamp = time::now();
    let signature =
        sign_create_identity_passkey(&signing_key, identity_id.as_str(), handle, timestamp);

    let request_body = serde_json::json!({
        "handle": handle,
        "signer_type": "PASSKEY",
        "signer_public_key": BASE64.encode(public_key),
        "nonce": BASE64.encode(nonce),
        "timestamp": timestamp,
        "signature": signature,
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/identities")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Resolve by handle
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/identities?handle=alice")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let identity: IdentityResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(identity.id, identity_id.as_str());
    assert_eq!(identity.handle, handle);
}
