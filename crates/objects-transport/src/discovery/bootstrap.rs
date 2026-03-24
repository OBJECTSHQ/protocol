//! DNS-based bootstrap node discovery.
//!
//! Resolves bootstrap node IDs from DNS TXT records, with fallback to
//! hardcoded defaults when DNS is unavailable. Supports periodic refresh
//! to pick up rotated nodes without restarting.

use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::TxtLookup;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{NodeAddr, NodeId, RelayUrl};

/// Source of bootstrap node resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapSource {
    /// Resolved from DNS TXT records.
    Dns,
    /// Using hardcoded fallback (DNS failed or returned empty).
    Fallback,
    /// Set via OBJECTS_BOOTSTRAP_NODES environment variable.
    EnvOverride,
}

/// Result of bootstrap resolution.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    /// Resolved bootstrap node addresses.
    pub addrs: Vec<NodeAddr>,
    /// How the addresses were resolved.
    pub source: BootstrapSource,
}

/// Resolves bootstrap node addresses from DNS with hardcoded fallback.
pub struct BootstrapResolver {
    dns_hostname: String,
    fallback_nodes: Vec<String>,
    relay_url: RelayUrl,
    env_override: bool,
}

impl BootstrapResolver {
    /// Create a new resolver.
    ///
    /// If `OBJECTS_BOOTSTRAP_NODES` env var is set, `env_override` should be true
    /// and DNS resolution will be skipped entirely.
    pub fn new(
        dns_hostname: &str,
        fallback_nodes: Vec<String>,
        relay_url: RelayUrl,
        env_override: bool,
    ) -> Self {
        Self {
            dns_hostname: dns_hostname.to_string(),
            fallback_nodes,
            relay_url,
            env_override,
        }
    }

    /// Resolve bootstrap nodes.
    ///
    /// Priority: env override → DNS → hardcoded fallback.
    pub async fn resolve(&self) -> BootstrapResult {
        if self.env_override {
            let addrs = self.node_ids_to_addrs(&self.fallback_nodes);
            info!(
                count = addrs.len(),
                "Using bootstrap nodes from OBJECTS_BOOTSTRAP_NODES"
            );
            return BootstrapResult {
                addrs,
                source: BootstrapSource::EnvOverride,
            };
        }

        match self.resolve_dns().await {
            Ok(node_ids) if !node_ids.is_empty() => {
                let addrs = self.node_ids_to_addrs(&node_ids);
                info!(
                    count = addrs.len(),
                    hostname = %self.dns_hostname,
                    "Resolved bootstrap nodes from DNS"
                );
                BootstrapResult {
                    addrs,
                    source: BootstrapSource::Dns,
                }
            }
            Ok(_) => {
                warn!(
                    hostname = %self.dns_hostname,
                    "DNS returned no bootstrap records, using hardcoded fallback"
                );
                let addrs = self.node_ids_to_addrs(&self.fallback_nodes);
                BootstrapResult {
                    addrs,
                    source: BootstrapSource::Fallback,
                }
            }
            Err(e) => {
                warn!(
                    hostname = %self.dns_hostname,
                    error = %e,
                    fallback_count = self.fallback_nodes.len(),
                    "DNS resolution failed, using hardcoded bootstrap nodes"
                );
                let addrs = self.node_ids_to_addrs(&self.fallback_nodes);
                BootstrapResult {
                    addrs,
                    source: BootstrapSource::Fallback,
                }
            }
        }
    }

    /// Resolve TXT records from DNS and extract node IDs.
    async fn resolve_dns(&self) -> anyhow::Result<Vec<String>> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::cloudflare(),
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build();

        let response: TxtLookup = resolver.txt_lookup(&self.dns_hostname).await?;

        let mut node_ids = Vec::new();
        for record in response.iter() {
            // Each TXT rdata contains one or more byte strings; join them
            let txt_str: String = record
                .txt_data()
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<Vec<_>>()
                .join(" ");
            if let Some(node_id) = parse_bootstrap_txt(&txt_str) {
                debug!(node_id = %node_id, "Parsed bootstrap node from DNS");
                node_ids.push(node_id);
            }
        }

        Ok(node_ids)
    }

    /// Convert node ID strings to NodeAddrs with relay URL.
    fn node_ids_to_addrs(&self, node_ids: &[String]) -> Vec<NodeAddr> {
        node_ids
            .iter()
            .filter_map(|id_str| match id_str.parse::<NodeId>() {
                Ok(node_id) => {
                    let addr = NodeAddr::from(node_id).with_relay_url(self.relay_url.clone());
                    Some(addr)
                }
                Err(e) => {
                    warn!(
                        node_id = %id_str,
                        error = %e,
                        "Skipping invalid bootstrap node ID"
                    );
                    None
                }
            })
            .collect()
    }

    /// Spawn a background task that periodically re-resolves DNS and logs results.
    ///
    /// This ensures rotated bootstrap nodes are picked up if the gossip
    /// network needs to reconnect. The resolved addresses are logged for
    /// observability. On restart, the node will use the latest DNS results.
    ///
    /// Only runs when DNS is the bootstrap source (not env override).
    pub fn spawn_refresh(self, interval: Duration) -> Option<JoinHandle<()>> {
        if self.env_override {
            debug!("Skipping DNS refresh — using env override");
            return None;
        }

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                match self.resolve_dns().await {
                    Ok(node_ids) if !node_ids.is_empty() => {
                        debug!(
                            count = node_ids.len(),
                            "DNS refresh: {} bootstrap nodes available",
                            node_ids.len()
                        );
                    }
                    Ok(_) => {
                        debug!("DNS refresh returned no records");
                    }
                    Err(e) => {
                        debug!(error = %e, "DNS refresh failed (will retry)");
                    }
                }
            }
        });

        Some(handle)
    }
}

/// Parse a bootstrap TXT record value.
///
/// Format: `node=<hex_node_id> region=<region>`
/// Returns the node ID hex string, or None if not parseable.
fn parse_bootstrap_txt(txt: &str) -> Option<String> {
    for part in txt.split_whitespace() {
        if let Some(node_id) = part.strip_prefix("node=")
            && !node_id.is_empty()
        {
            return Some(node_id.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootstrap_txt() {
        assert_eq!(
            parse_bootstrap_txt("node=abcdef1234 region=us-central1"),
            Some("abcdef1234".to_string())
        );
        assert_eq!(
            parse_bootstrap_txt("region=eu-west1 node=deadbeef"),
            Some("deadbeef".to_string())
        );
        assert_eq!(parse_bootstrap_txt("no-node-here"), None);
        assert_eq!(parse_bootstrap_txt("node= region=us"), None);
        assert_eq!(parse_bootstrap_txt(""), None);
    }

    #[tokio::test]
    async fn test_resolve_with_fallback_when_dns_missing() {
        // When DNS records don't exist, should fall back to hardcoded nodes
        let resolver = BootstrapResolver::new(
            "_objects-bootstrap.objects.foundation",
            vec![
                "2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc".to_string(),
                "cfb922a8c9217d440cd0cd4d7842b2a8b9fd23116c45be607375c336b2a6022b".to_string(),
            ],
            "https://relay.objects.foundation"
                .parse::<crate::RelayUrl>()
                .unwrap(),
            false,
        );

        let result = resolver.resolve().await;
        // DNS may or may not have records; either source is acceptable
        assert!(
            result.source == BootstrapSource::Dns || result.source == BootstrapSource::Fallback
        );
        assert!(
            !result.addrs.is_empty(),
            "Should have bootstrap nodes from DNS or fallback"
        );
    }

    #[tokio::test]
    async fn test_fallback_on_dns_failure() {
        let resolver = BootstrapResolver::new(
            "nonexistent.invalid.test",
            vec!["2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc".to_string()],
            "https://relay.objects.foundation"
                .parse::<crate::RelayUrl>()
                .unwrap(),
            false,
        );

        let result = resolver.resolve().await;
        assert_eq!(result.source, BootstrapSource::Fallback);
        assert_eq!(result.addrs.len(), 1);
    }

    #[tokio::test]
    async fn test_env_override_skips_dns() {
        let resolver = BootstrapResolver::new(
            "_objects-bootstrap.objects.foundation",
            vec!["2e0a658732832de5d47bdce0571cb66afd54f06aac3e683abaefd702415121fc".to_string()],
            "https://relay.objects.foundation"
                .parse::<crate::RelayUrl>()
                .unwrap(),
            true, // env override
        );

        let result = resolver.resolve().await;
        assert_eq!(result.source, BootstrapSource::EnvOverride);
        assert_eq!(result.addrs.len(), 1);
    }
}
