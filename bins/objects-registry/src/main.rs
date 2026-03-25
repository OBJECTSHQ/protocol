//! Identity registry service for OBJECTS Protocol.
//!
//! This binary implements RFC-001 Section 5-6: Identity Registry.

mod api;
mod config;
mod db;
mod error;
mod verification;

use tracing::{error, info};

use crate::api::rest::{self, handlers::AppState};
use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting OBJECTS Registry...");

    // Load configuration
    let config = Config::from_env().map_err(|e| {
        error!("Configuration error: {}", e);
        e
    })?;

    info!(
        "Configuration loaded: REST port {}, gRPC port {}",
        config.rest_port, config.grpc_port
    );

    // Connect to database and run migrations
    let pool = db::create_pool(&config.database_url).await?;

    // Create shared state
    let state = AppState {
        pool,
        config: config.clone(),
    };

    // Create REST API router
    let app = rest::create_router(state);

    // Start REST server
    let rest_addr = config.rest_addr();
    info!("REST API listening on http://{}", rest_addr);

    let listener = tokio::net::TcpListener::bind(rest_addr).await?;

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Registry shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down..."),
        _ = terminate => info!("Received SIGTERM, shutting down..."),
    }
}
