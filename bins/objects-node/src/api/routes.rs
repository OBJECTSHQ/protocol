//! API routes and router configuration.

use super::handlers::{
    AppState, create_identity, get_identity, health_check, list_peers, node_status,
};
use axum::{Router, routing::get};

/// Create the API router with all routes.
///
/// # Routes
///
/// - `GET /health` - Health check endpoint
/// - `GET /status` - Node status endpoint
/// - `GET /identity` - Get registered identity
/// - `POST /identity` - Create new identity
/// - `GET /peers` - List discovered peers
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/status", get(node_status))
        .route("/identity", get(get_identity).post(create_identity))
        .route("/peers", get(list_peers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeConfig, NodeState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use objects_transport::discovery::{DiscoveryConfig, GossipDiscovery};
    use objects_transport::{NetworkConfig, ObjectsEndpoint, RelayUrl};
    use std::str::FromStr;
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    use super::super::client::RegistryClient;
    use super::super::handlers::NodeInfo;
    use super::super::types::HealthResponse;

    /// Create a test AppState with a real GossipDiscovery.
    ///
    /// This sets up the full transport layer for integration testing.
    async fn create_test_app_state() -> (AppState, TempDir) {
        let temp = TempDir::new().unwrap();
        let mut config = NodeConfig::default();
        config.node.data_dir = temp.path().to_string_lossy().to_string();

        let state_path = temp.path().join("node.key");
        let node_state = NodeState::load_or_create(&state_path).unwrap();

        // Create endpoint
        let relay_url = RelayUrl::from_str(&config.network.relay_url).unwrap();
        let network_config = NetworkConfig::devnet()
            .with_relay_url(relay_url)
            .with_max_connections(50);

        let endpoint = ObjectsEndpoint::builder()
            .config(network_config)
            .secret_key(node_state.node_key().clone())
            .bind()
            .await
            .unwrap();

        let endpoint_arc = Arc::new(endpoint);

        // Create gossip and discovery
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint_arc.inner().clone());
        let discovery = GossipDiscovery::new(
            gossip,
            endpoint_arc.clone(),
            vec![],
            DiscoveryConfig::devnet(),
        )
        .await
        .unwrap();

        let node_info = Arc::new(NodeInfo {
            node_id: endpoint_arc.node_id(),
            node_addr: endpoint_arc.node_addr(),
        });

        let app_state = AppState {
            node_info,
            discovery: Arc::new(Mutex::new(discovery)),
            node_state: Arc::new(RwLock::new(node_state)),
            config: config.clone(),
            registry_client: RegistryClient::new(&config),
        };

        (app_state, temp)
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_ok() {
        let (state, _temp) = create_test_app_state().await;
        let router = create_router(state);

        let response = router
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "ok");
    }

    #[tokio::test]
    async fn test_status_endpoint_returns_node_info() {
        let (state, _temp) = create_test_app_state().await;
        let expected_node_id = state.node_info.node_id.to_string();
        let router = create_router(state);

        let response = router
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let status: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status["node_id"], expected_node_id);
        assert_eq!(status["peer_count"], 0);
        assert!(status["identity"].is_null());
        assert!(status["relay_url"].is_string());
    }

    #[tokio::test]
    async fn test_peers_endpoint_returns_empty_list() {
        let (state, _temp) = create_test_app_state().await;
        let router = create_router(state);

        let response = router
            .oneshot(Request::get("/peers").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let peers: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(peers["peers"].is_array());
        assert_eq!(peers["peers"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let (state, _temp) = create_test_app_state().await;
        let router = create_router(state);

        let response = router
            .oneshot(Request::get("/unknown").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
