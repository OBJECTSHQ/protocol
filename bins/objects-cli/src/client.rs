use crate::error::CliError;
use crate::types::*;
use reqwest::{Client, StatusCode};

/// HTTP client for node API.
#[derive(Clone, Debug)]
pub struct NodeClient {
    client: Client,
    base_url: String,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into(),
        }
    }

    pub async fn health(&self) -> Result<HealthResponse, CliError> {
        let url = format!("{}/health", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::OK {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
        }
    }

    pub async fn status(&self) -> Result<StatusResponse, CliError> {
        let url = format!("{}/status", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::OK {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
        }
    }

    pub async fn get_identity(&self) -> Result<IdentityResponse, CliError> {
        let url = format!("{}/identity", self.base_url);
        let response = self.client.get(&url).send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json().await?),
            StatusCode::NOT_FOUND => Err(CliError::NotFound("No identity registered".to_string())),
            _ => Err(self.error_from_response(response).await),
        }
    }

    pub async fn create_identity(
        &self,
        req: CreateIdentityRequest,
    ) -> Result<IdentityResponse, CliError> {
        let url = format!("{}/identity", self.base_url);
        let response = self.client.post(&url).json(&req).send().await?;

        if response.status() == StatusCode::CREATED {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
        }
    }

    // =========================================================================
    // Project Operations
    // =========================================================================

    pub async fn create_project(
        &self,
        req: CreateProjectRequest,
    ) -> Result<ProjectResponse, CliError> {
        let url = format!("{}/projects", self.base_url);
        let response = self.client.post(&url).json(&req).send().await?;

        if response.status() == StatusCode::CREATED {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
        }
    }

    pub async fn list_projects(&self) -> Result<ProjectListResponse, CliError> {
        let url = format!("{}/projects", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::OK {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
        }
    }

    pub async fn get_project(&self, id: &str) -> Result<ProjectResponse, CliError> {
        let url = format!("{}/projects/{}", self.base_url, id);
        let response = self.client.get(&url).send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json().await?),
            StatusCode::NOT_FOUND => Err(CliError::NotFound(format!("Project not found: {}", id))),
            _ => Err(self.error_from_response(response).await),
        }
    }

    async fn error_from_response(&self, response: reqwest::Response) -> CliError {
        let status = response.status().as_u16();
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        CliError::NodeError { status, message }
    }
}
