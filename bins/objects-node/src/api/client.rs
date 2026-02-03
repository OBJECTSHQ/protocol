//! HTTP client for communicating with the registry service.

use crate::NodeConfig;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

/// HTTP client for registry operations.
#[derive(Clone)]
pub struct RegistryClient {
    client: Client,
    base_url: String,
}

/// Request to create a new identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityRequest {
    pub handle: String,
    pub signer_type: String,
    pub signer_public_key: String,
    pub nonce: String,
    pub timestamp: i64,
    pub signature: SignatureData,
}

/// Signature data for identity creation.
/// Matches the registry's SignatureRequest format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureData {
    /// Base64-encoded signature bytes
    pub signature: String,
    /// Base64-encoded public key (required for passkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Wallet address (required for wallet signatures)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Base64-encoded authenticator data (required for passkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_data: Option<String>,
    /// Base64-encoded client data JSON (required for passkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_data_json: Option<String>,
}

/// Identity response from registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub id: String,
    pub handle: String,
    pub nonce: String,
    pub signer_type: String,
}

/// Error response from registry.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorDetail {
    pub message: String,
}

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Registry error: {0}")]
    Registry(StatusCode),

    #[error("Handle already taken: {0}")]
    HandleTaken(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
}

impl RegistryClient {
    /// Create a new registry client from node configuration.
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            client: Client::new(),
            base_url: config.identity.registry_url.clone(),
        }
    }

    /// Create identity in the registry.
    pub async fn create_identity(
        &self,
        req: CreateIdentityRequest,
    ) -> Result<IdentityResponse, ClientError> {
        let url = format!("{}/v1/identities", self.base_url);
        let response = self.client.post(&url).json(&req).send().await?;

        match response.status() {
            StatusCode::CREATED => Ok(response.json().await?),
            StatusCode::CONFLICT => {
                let err: ErrorResponse = response.json().await?;
                Err(ClientError::HandleTaken(err.error.message))
            }
            status => Err(ClientError::Registry(status)),
        }
    }

    /// Get identity from the registry by ID.
    pub async fn get_identity(&self, id: &str) -> Result<IdentityResponse, ClientError> {
        let url = format!("{}/v1/identities/{}", self.base_url, id);
        let response = self.client.get(&url).send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json().await?),
            status => Err(ClientError::Registry(status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_create_identity_success() {
        let mock_server = MockServer::start().await;

        let mock_response = IdentityResponse {
            id: "obj_test123".to_string(),
            handle: "@alice".to_string(),
            nonce: "0102030405060708".to_string(),
            signer_type: "passkey".to_string(),
        };

        Mock::given(method("POST"))
            .and(path("/v1/identities"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&mock_response))
            .mount(&mock_server)
            .await;

        let mut config = NodeConfig::default();
        config.identity.registry_url = mock_server.uri();
        let client = RegistryClient::new(&config);

        let request = CreateIdentityRequest {
            handle: "@alice".to_string(),
            signer_type: "passkey".to_string(),
            signer_public_key: "pubkey".to_string(),
            nonce: "0102030405060708".to_string(),
            timestamp: 1234567890,
            signature: SignatureData {
                r: "r_value".to_string(),
                s: "s_value".to_string(),
                v: None,
            },
        };

        let result = client.create_identity(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.handle, "@alice");
        assert_eq!(response.id, "obj_test123");
    }

    #[tokio::test]
    async fn test_create_identity_handle_taken() {
        let mock_server = MockServer::start().await;

        let error_response = serde_json::json!({
            "error": {
                "message": "Handle @alice is already taken"
            }
        });

        Mock::given(method("POST"))
            .and(path("/v1/identities"))
            .respond_with(ResponseTemplate::new(409).set_body_json(error_response))
            .mount(&mock_server)
            .await;

        let mut config = NodeConfig::default();
        config.identity.registry_url = mock_server.uri();
        let client = RegistryClient::new(&config);

        let request = CreateIdentityRequest {
            handle: "@alice".to_string(),
            signer_type: "passkey".to_string(),
            signer_public_key: "pubkey".to_string(),
            nonce: "0102030405060708".to_string(),
            timestamp: 1234567890,
            signature: SignatureData {
                r: "r_value".to_string(),
                s: "s_value".to_string(),
                v: None,
            },
        };

        let result = client.create_identity(request).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            ClientError::HandleTaken(msg) => {
                assert!(msg.contains("@alice"));
            }
            _ => panic!("Expected HandleTaken error"),
        }
    }

    #[tokio::test]
    async fn test_get_identity_success() {
        let mock_server = MockServer::start().await;

        let mock_response = IdentityResponse {
            id: "obj_test123".to_string(),
            handle: "@bob".to_string(),
            nonce: "0102030405060708".to_string(),
            signer_type: "wallet".to_string(),
        };

        Mock::given(method("GET"))
            .and(path("/v1/identities/obj_test123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&mock_response))
            .mount(&mock_server)
            .await;

        let mut config = NodeConfig::default();
        config.identity.registry_url = mock_server.uri();
        let client = RegistryClient::new(&config);

        let result = client.get_identity("obj_test123").await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.handle, "@bob");
        assert_eq!(response.id, "obj_test123");
    }
}
