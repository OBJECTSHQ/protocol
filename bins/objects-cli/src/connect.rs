//! Connect to a running OBJECTS node via irpc.

use crate::config::Config;
use objects_core::node_api::NodeApi;
use objects_core::rpc::proto::NODE_RPC_ALPN;
use objects_transport::NodeAddr;
use std::path::Path;

/// Read node.api file and connect to the node via irpc over QUIC.
pub async fn connect_to_node(config: &Config) -> anyhow::Result<NodeApi> {
    let api_path = Path::new(&config.data_dir()).join("node.api");

    let api_info: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&api_path).map_err(|e| {
            anyhow::anyhow!(
                "Cannot read node.api at {}: {}. Is the node running?",
                api_path.display(),
                e
            )
        })?)?;

    let node_addr: NodeAddr = serde_json::from_value(
        api_info
            .get("node_addr")
            .ok_or_else(|| anyhow::anyhow!("node.api missing node_addr field"))?
            .clone(),
    )?;

    // Create a lightweight iroh endpoint for the CLI (no relay, no discovery)
    let endpoint = iroh::Endpoint::empty_builder()
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create endpoint: {e}"))?;

    let client = irpc_iroh::client::<objects_core::rpc::proto::NodeProtocol>(
        endpoint,
        node_addr,
        NODE_RPC_ALPN,
    );

    Ok(NodeApi::from_client(client))
}
