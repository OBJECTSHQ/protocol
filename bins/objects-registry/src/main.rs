//! Identity registry service for OBJECTS Protocol.

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting OBJECTS Registry...");

    // TODO: Initialize registry
    // 1. Connect to PostgreSQL database
    // 2. Run migrations
    // 3. Start REST API server (Axum)
    // 4. Start gRPC server (Tonic)

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    info!("Registry listening on port {}", port);

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    Ok(())
}
