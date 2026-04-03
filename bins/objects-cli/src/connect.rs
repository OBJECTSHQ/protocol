//! Connect to a running OBJECTS node via irpc.

use crate::config::Config;
use objects_core::node_api::NodeApi;
use objects_core::rpc::proto::NODE_RPC_ALPN;
use objects_transport::{NetworkConfig, NodeAddr, ObjectsEndpoint, RelayUrl};
use std::path::Path;
use std::str::FromStr;

/// Read node.api file and connect to the node via irpc over QUIC.
///
/// Uses the relay URL from config so the CLI can reach remote nodes
/// via relay when direct connections aren't possible.
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

    // Create endpoint with relay configured for remote node communication
    let relay_url = RelayUrl::from_str(&config.network.relay_url)?;
    let network_config = NetworkConfig::devnet().with_relay_url(relay_url);

    let endpoint = ObjectsEndpoint::builder()
        .config(network_config)
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create endpoint: {e}"))?;

    let client = irpc_iroh::client::<objects_core::rpc::proto::NodeProtocol>(
        endpoint.inner().clone(),
        node_addr,
        NODE_RPC_ALPN,
    );

    Ok(NodeApi::from_client(client))
}
