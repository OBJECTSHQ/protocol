//! Health probe for OBJECTS Protocol node.
//!
//! Connects to the running node via irpc and calls `health()`.
//! Exits 0 if healthy, 1 otherwise.
//!
//! Same pattern as [grpc-health-probe](https://github.com/grpc-ecosystem/grpc-health-probe):
//! a tiny binary bundled in the container image, invoked by Docker HEALTHCHECK.

use objects_core::node_api::NodeApi;
use objects_core::rpc::proto::{NODE_RPC_ALPN, NodeProtocol};
use objects_transport::NodeAddr;
use std::path::Path;
use std::process;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let data_dir = std::env::var("OBJECTS_DATA_DIR").unwrap_or_else(|_| "/data".into());
    let api_path = Path::new(&data_dir).join("node.api");

    let Ok(contents) = std::fs::read_to_string(&api_path) else {
        eprintln!("node.api not found — node not started");
        process::exit(1);
    };

    let Ok(info) = serde_json::from_str::<serde_json::Value>(&contents) else {
        eprintln!("node.api malformed");
        process::exit(1);
    };

    let Some(addr) = info
        .get("node_addr")
        .and_then(|v| serde_json::from_value::<NodeAddr>(v.clone()).ok())
    else {
        eprintln!("node.api missing node_addr");
        process::exit(1);
    };

    let Ok(endpoint) = iroh::Endpoint::empty_builder().bind().await else {
        eprintln!("failed to create endpoint");
        process::exit(1);
    };

    let client = irpc_iroh::client::<NodeProtocol>(endpoint, addr, NODE_RPC_ALPN);
    let api = NodeApi::from_client(client);

    match tokio::time::timeout(Duration::from_secs(3), api.health()).await {
        Ok(Ok(resp)) if resp.status == "ok" => process::exit(0),
        Ok(Ok(resp)) => {
            eprintln!("unhealthy: {}", resp.status);
            process::exit(1);
        }
        Ok(Err(e)) => {
            eprintln!("health check failed: {e}");
            process::exit(1);
        }
        Err(_) => {
            eprintln!("health check timed out");
            process::exit(1);
        }
    }
}
