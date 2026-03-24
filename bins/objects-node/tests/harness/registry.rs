//! Docker-based test registry harness.
//!
//! Spawns the registry container via Docker Compose and exposes
//! the base URL for E2E tests.

use anyhow::{Context, Result};
use std::process::Command;
use std::time::Duration;

/// Path to the test Docker Compose file, relative to the workspace root.
const COMPOSE_FILE: &str = "docker/test-compose.yml";

/// Docker-based registry for testing.
///
/// Starts the registry container on creation and stops it on drop.
/// The container uses SQLite on tmpfs — no external database needed.
pub struct TestRegistry {
    pub base_url: String,
    compose_file: String,
}

impl TestRegistry {
    /// Start a new test registry container.
    ///
    /// This:
    /// 1. Starts the registry via `docker compose up -d`
    /// 2. Discovers the mapped port
    /// 3. Polls `/health` until the registry is ready (timeout 30s)
    pub async fn new() -> Result<Self> {
        let compose_file = workspace_compose_path()?;

        // Start the container
        let status = Command::new("docker")
            .args(["compose", "-f", &compose_file, "up", "-d", "--wait"])
            .status()
            .context("Failed to start docker compose")?;

        anyhow::ensure!(status.success(), "docker compose up failed");

        // Discover the mapped port
        let output = Command::new("docker")
            .args(["compose", "-f", &compose_file, "port", "registry", "8080"])
            .output()
            .context("Failed to get registry port")?;

        let port_mapping = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let base_url = format!("http://{port_mapping}");

        let registry = Self {
            base_url,
            compose_file,
        };

        // Wait for health
        registry.wait_for_health(Duration::from_secs(30)).await?;

        Ok(registry)
    }

    /// Poll the registry's `/health` endpoint until it returns 200.
    async fn wait_for_health(&self, timeout: Duration) -> Result<()> {
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!(
                    "Registry did not become healthy within {}s",
                    timeout.as_secs()
                );
            }

            match client.get(format!("{}/health", self.base_url)).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }
}

impl Drop for TestRegistry {
    fn drop(&mut self) {
        // Stop and remove the container
        let _ = Command::new("docker")
            .args(["compose", "-f", &self.compose_file, "down"])
            .status();
    }
}

/// Resolve the compose file path relative to the workspace root.
///
/// Walks up from CARGO_MANIFEST_DIR to find the workspace root
/// (where the top-level Cargo.toml with [workspace] lives).
fn workspace_compose_path() -> Result<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut dir = std::path::PathBuf::from(&manifest_dir);

    // Walk up to find workspace root (has docker/ directory)
    loop {
        if dir.join(COMPOSE_FILE).exists() {
            return Ok(dir.join(COMPOSE_FILE).to_string_lossy().to_string());
        }
        if !dir.pop() {
            break;
        }
    }

    // Fallback: assume we're in the workspace root
    Ok(COMPOSE_FILE.to_string())
}
