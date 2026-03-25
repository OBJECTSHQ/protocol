//! Docker-based test registry harness.
//!
//! Spawns the registry container via Docker Compose and exposes
//! the base URL for E2E tests. Detects if compose is already running
//! (e.g., started by CI) and reuses it without tearing down on drop.

use anyhow::{Context, Result};
use std::process::Command;
use std::time::Duration;

/// Path to the test Docker Compose file, relative to the workspace root.
const COMPOSE_FILE: &str = "docker/test-compose.yml";

/// Check if Docker and the registry image are available for E2E tests.
pub fn docker_available() -> bool {
    Command::new("docker")
        .args(["image", "inspect", "objects-registry:latest"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Docker-based registry for testing.
///
/// If compose is already running (CI started it), reuses the existing
/// container. If not, starts compose and tears it down on drop.
pub struct TestRegistry {
    pub base_url: String,
    compose_file: String,
    owns_lifecycle: bool,
}

impl TestRegistry {
    /// Connect to or start a test registry container.
    ///
    /// 1. Checks if compose is already running (CI workflow starts it)
    /// 2. If running: discovers port and reuses it (no teardown on drop)
    /// 3. If not: starts compose, discovers port, tears down on drop
    pub async fn new() -> Result<Self> {
        let compose_file = workspace_compose_path()?;

        // Check if the registry container is already running
        let ps_output = Command::new("docker")
            .args(["compose", "-f", &compose_file, "ps", "-q", "registry"])
            .output()
            .context("Failed to check docker compose status")?;

        let already_running = !String::from_utf8_lossy(&ps_output.stdout).trim().is_empty();

        if !already_running {
            // Start compose ourselves — we own the lifecycle
            let status = Command::new("docker")
                .args(["compose", "-f", &compose_file, "up", "-d", "--wait"])
                .status()
                .context("Failed to start docker compose")?;

            anyhow::ensure!(status.success(), "docker compose up failed");
        }

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
            owns_lifecycle: !already_running,
        };

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
        // Only tear down compose if we started it ourselves.
        // If CI started it, leave it running for other tests.
        if self.owns_lifecycle {
            let _ = Command::new("docker")
                .args(["compose", "-f", &self.compose_file, "down"])
                .status();
        }
    }
}

/// Resolve the compose file path relative to the workspace root.
fn workspace_compose_path() -> Result<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut dir = std::path::PathBuf::from(&manifest_dir);

    loop {
        if dir.join(COMPOSE_FILE).exists() {
            return Ok(dir.join(COMPOSE_FILE).to_string_lossy().to_string());
        }
        if !dir.pop() {
            break;
        }
    }

    Ok(COMPOSE_FILE.to_string())
}
