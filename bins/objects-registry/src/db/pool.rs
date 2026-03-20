//! Database connection pool setup.

use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tracing::info;

/// Create a SQLite connection pool and run migrations.
///
/// Migrations are embedded at compile time and run automatically on startup.
/// This is appropriate for the 0.1 prototype stage.
///
/// TODO(0.2): Add explicit migration command for production deployments.
pub async fn create_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    info!("Connecting to database...");

    // Ensure parent directory exists for the SQLite database file.
    if let Some(path) = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        && let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;

    info!("Running migrations...");
    sqlx::migrate!("./migrations").run(&pool).await?;

    info!("Database ready");
    Ok(pool)
}
