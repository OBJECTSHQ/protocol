//! Default network infrastructure for the OBJECTS devnet.

/// Relay server URL for NAT traversal.
pub const RELAY_URL: &str = "https://relay.objects.foundation";

/// Registry service URL.
pub const REGISTRY_URL: &str = "https://registry.objects.foundation";

/// Gossip discovery topic.
pub const DISCOVERY_TOPIC: &str = "/objects/devnet/0.1/discovery";

/// DNS hostname for bootstrap node discovery.
///
/// TXT records at this hostname contain `node=<hex_node_id> region=<region>`.
/// Nodes resolve this on startup and periodically to discover bootstrap peers.
pub const BOOTSTRAP_DNS: &str = "_objects-bootstrap.objects.foundation";

/// Hardcoded bootstrap node IDs (fallback when DNS resolution fails).
///
/// These are well-known devnet bootstrap peers. Override via
/// `OBJECTS_BOOTSTRAP_NODES` env var (comma-separated node IDs).
pub const BOOTSTRAP_NODES: &[&str] = &[
    // US (us-central1)
    "e1b52711c11d3bda3e4a280cce6068b411800bec8faea4bf60a3a3a23e1e2145",
    // Asia (asia-northeast1)
    "3709827d11224e34929f21411174e0538766c4770989b0611305b0e319db5dd3",
];
