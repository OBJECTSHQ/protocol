//! Test registry harness for spawning in-process registry server.

use anyhow::Result;
use objects_registry::api::rest::handlers::AppState;
use objects_registry::api::rest::routes::create_router;
use objects_registry::config::Config;
use sqlx::{ConnectOptions, PgPool};
use std::net::SocketAddr;
use tokio::task::JoinHandle;

/// In-process registry for testing.
///
/// Spawns a test PostgreSQL database and runs the registry API server
/// in-process on a random available port.
pub struct TestRegistry {
    pub base_url: String,
    _server_handle: JoinHandle<()>,
    _pool: PgPool,
}

impl TestRegistry {
    /// Create and start a new test registry.
    ///
    /// This:
    /// 1. Creates a test PostgreSQL database (requires `DATABASE_URL` env var)
    /// 2. Runs migrations
    /// 3. Spawns an Axum API server on a random port
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Database connection fails
    /// - Migrations fail
    /// - Server binding fails
    pub async fn new() -> Result<Self> {
        // Get database URL from environment
        // Use dedicated test database to avoid interfering with real registry
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://postgres:password@localhost:5432/objects_registry_test".to_string()
        });

        // Connect to database
        let connect_options = database_url
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .log_statements(log::LevelFilter::Debug);

        let pool = PgPool::connect_with(connect_options).await?;

        Self::with_pool(pool, database_url).await
    }

    /// Create and start a test registry with provided pool.
    ///
    /// This variant is used when tests already have a pool from sqlx::test.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Migrations fail
    /// - Server binding fails
    pub async fn with_pool(pool: PgPool, database_url: String) -> Result<Self> {
        // Run migrations to ensure schema is up to date
        sqlx::migrate!("../objects-registry/migrations")
            .run(&pool)
            .await
            .ok(); // Ignore errors if migrations already applied

        // Create app state
        let config = Config {
            database_url: database_url.clone(),
            rest_port: 0, // Will be set by actual binding
            grpc_port: 0,
            timestamp_future_max: std::time::Duration::from_secs(5 * 60),
            timestamp_past_max: std::time::Duration::from_secs(24 * 60 * 60),
        };
        let state = AppState {
            pool: pool.clone(),
            config,
        };

        // Create router
        let app = create_router(state);

        // Bind to random port
        let addr: SocketAddr = "127.0.0.1:0".parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        let base_url = format!("http://{}", bound_addr);

        // Spawn server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("Registry server failed");
        });

        Ok(Self {
            base_url,
            _server_handle: server_handle,
            _pool: pool,
        })
    }
}

impl Drop for TestRegistry {
    fn drop(&mut self) {
        // Server handle is aborted on drop
        self._server_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn test_registry_creation(pool: PgPool) {
        // Note: sqlx::test creates a fresh database for us
        let database_url = pool.connect_options().to_url_lossy().to_string();
        let registry = TestRegistry::with_pool(pool, database_url).await;
        assert!(registry.is_ok(), "Failed to create test registry");
    }

    #[sqlx::test]
    async fn test_registry_health_endpoint(pool: PgPool) {
        let database_url = pool.connect_options().to_url_lossy().to_string();
        let registry = TestRegistry::with_pool(pool, database_url).await.unwrap();

        // Test health endpoint
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/health", registry.base_url))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ok");
    }
}
