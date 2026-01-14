//! Database connection pool setup.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

/// Create a PostgreSQL connection pool and run migrations.
///
/// Migrations are embedded at compile time and run automatically on startup.
/// This is appropriate for the 0.1 prototype stage.
///
/// TODO(0.2): Add explicit migration command for production deployments.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    info!("Connecting to database...");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;

    info!("Running migrations...");
    sqlx::migrate!("./migrations").run(&pool).await?;

    info!("Database ready");
    Ok(pool)
}
