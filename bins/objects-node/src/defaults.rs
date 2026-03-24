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
    "2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc",
    // Asia (asia-northeast1)
    "cfb922a8c9217d440cd0cd4d7842b2a8b9fd23116c45be607375c336b2a6022b",
];
