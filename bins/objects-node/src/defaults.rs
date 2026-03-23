//! Default network infrastructure for the OBJECTS devnet.

/// Relay server URL for NAT traversal.
pub const RELAY_URL: &str = "https://relay.objects.foundation";

/// Registry service URL.
pub const REGISTRY_URL: &str = "https://registry.objects.foundation";

/// Gossip discovery topic.
pub const DISCOVERY_TOPIC: &str = "/objects/devnet/0.1/discovery";

/// DNS domain for bootstrap node discovery.
///
/// TXT records at this domain contain `node=<hex-node-id>` entries.
/// Adding/removing a bootstrap node = adding/removing a TXT record.
pub const BOOTSTRAP_DNS_DOMAIN: &str = "bootstrap.objects.foundation";

/// Resolve bootstrap node IDs from DNS TXT records.
///
/// Queries TXT records at [`BOOTSTRAP_DNS_DOMAIN`]. Each record should contain
/// `node=<64-hex-char-node-id>` and optionally `region=<region>` (logged but
/// not used for routing).
///
/// Returns an empty vec on DNS failure — the node will still work via relay
/// and Iroh's pkarr discovery, just without gossip bootstrap peers.
pub async fn resolve_bootstrap_nodes() -> Vec<String> {
    use hickory_resolver::TokioResolver;

    let resolver = match TokioResolver::builder_tokio() {
        Ok(builder) => builder.build(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create DNS resolver, starting without bootstrap peers");
            return Vec::new();
        }
    };

    let lookup = match resolver.txt_lookup(BOOTSTRAP_DNS_DOMAIN).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                domain = BOOTSTRAP_DNS_DOMAIN,
                error = %e,
                "DNS bootstrap lookup failed, starting without bootstrap peers"
            );
            return Vec::new();
        }
    };

    let mut node_ids = Vec::new();
    for record in lookup.iter() {
        let txt = record.to_string();
        for node_id in parse_bootstrap_txt(&txt) {
            node_ids.push(node_id);
        }
    }

    if node_ids.is_empty() {
        tracing::warn!(
            domain = BOOTSTRAP_DNS_DOMAIN,
            "DNS lookup returned records but no valid node= entries"
        );
    } else {
        tracing::info!(
            domain = BOOTSTRAP_DNS_DOMAIN,
            count = node_ids.len(),
            "Resolved bootstrap nodes from DNS"
        );
    }

    node_ids
}

/// Parse a TXT record string and extract node IDs from `node=<hex>` entries.
///
/// Each TXT record may contain multiple space-separated key=value pairs.
/// Only `node=` entries with valid 64-character hex strings are extracted.
fn parse_bootstrap_txt(txt: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for part in txt.split_whitespace() {
        if let Some(id) = part.strip_prefix("node=") {
            if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                ids.push(id.to_string());
            } else {
                tracing::warn!(
                    node_id = id,
                    "Ignoring invalid node ID in DNS TXT record (expected 64 hex chars)"
                );
            }
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootstrap_txt_valid() {
        let txt = "node=2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc region=us-central1";
        let ids = parse_bootstrap_txt(txt);
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids[0],
            "2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc"
        );
    }

    #[test]
    fn test_parse_bootstrap_txt_multiple_entries() {
        // A single TXT record with multiple node entries (unlikely but valid)
        let txt = "node=2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc node=cfb922a8c9217d440cd0cd4d7842b2a8b9fd23116c45be607375c336b2a6022b";
        let ids = parse_bootstrap_txt(txt);
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_parse_bootstrap_txt_no_node_prefix() {
        let txt = "region=us-central1 role=bootstrap";
        let ids = parse_bootstrap_txt(txt);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_parse_bootstrap_txt_invalid_hex() {
        let txt = "node=not-a-valid-hex-string";
        let ids = parse_bootstrap_txt(txt);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_parse_bootstrap_txt_wrong_length() {
        let txt = "node=2e0a658732832de5"; // Too short
        let ids = parse_bootstrap_txt(txt);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_parse_bootstrap_txt_empty() {
        let ids = parse_bootstrap_txt("");
        assert!(ids.is_empty());
    }

    #[test]
    fn test_bootstrap_dns_domain() {
        assert_eq!(BOOTSTRAP_DNS_DOMAIN, "bootstrap.objects.foundation");
    }
}
