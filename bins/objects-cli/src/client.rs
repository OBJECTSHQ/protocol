use crate::error::CliError;
use crate::types::*;
use reqwest::{Client, StatusCode, multipart};
use std::path::Path;

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

    // =========================================================================
    // Asset Operations
    // =========================================================================

    /// Add an asset to a project (multipart upload).
    pub async fn add_asset(
        &self,
        project_id: &str,
        file_path: &Path,
    ) -> Result<AssetResponse, CliError> {
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        let content_type = mime_guess::from_path(file_path)
            .first_or_octet_stream()
            .to_string();

        let data = tokio::fs::read(file_path).await?;

        let part = multipart::Part::bytes(data)
            .file_name(file_name)
            .mime_str(&content_type)
            .map_err(|e| CliError::Config(format!("Invalid MIME type: {}", e)))?;

        let form = multipart::Form::new().part("file", part);

        let url = format!("{}/projects/{}/assets", self.base_url, project_id);
        let response = self.client.post(&url).multipart(form).send().await?;

        if response.status() == StatusCode::CREATED {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
        }
    }

    /// List assets in a project.
    pub async fn list_assets(&self, project_id: &str) -> Result<AssetListResponse, CliError> {
        let url = format!("{}/projects/{}/assets", self.base_url, project_id);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::OK {
            Ok(response.json().await?)
        } else {
            Err(self.error_from_response(response).await)
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
