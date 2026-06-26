//! Bootstrap discovery: connect to seed nodes to join the network.

use aafp_core::Multiaddr;
use aafp_identity::AgentRecord;
use std::time::Duration;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("no seed nodes configured")]
    NoSeeds,
    #[error("failed to connect to seed: {0}")]
    ConnectionFailed(String),
    #[error("timeout waiting for bootstrap")]
    Timeout,
}

/// Configuration for bootstrap discovery.
#[derive(Clone)]
pub struct BootstrapConfig {
    /// Seed node multiaddrs (e.g., ["quic://seed1.aafp.io:4433", ...]).
    pub seed_nodes: Vec<Multiaddr>,
    /// Maximum time to wait for bootstrap to complete.
    pub timeout: Duration,
    /// Number of peers to discover before considering bootstrap complete.
    pub min_peers: usize,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            seed_nodes: vec![],
            timeout: Duration::from_secs(30),
            min_peers: 3,
        }
    }
}

/// Bootstrap discovery driver.
///
/// For MVP, this is a stub that returns the configured seed addresses.
/// A production version would connect to seeds, exchange peer lists,
/// and verify AgentRecords.
pub struct BootstrapDiscovery {
    config: BootstrapConfig,
    discovered: Vec<AgentRecord>,
}

impl BootstrapDiscovery {
    /// Create a new bootstrap discovery with the given config.
    pub fn new(config: BootstrapConfig) -> Self {
        Self {
            config,
            discovered: Vec::new(),
        }
    }

    /// Get the configured seed addresses.
    pub fn seed_nodes(&self) -> &[Multiaddr] {
        &self.config.seed_nodes
    }

    /// Add a discovered agent record.
    pub fn add_discovered(&mut self, record: AgentRecord) {
        if record.verify() {
            self.discovered.push(record);
        }
    }

    /// Get all discovered agent records.
    pub fn discovered(&self) -> &[AgentRecord] {
        &self.discovered
    }

    /// Check if bootstrap is complete (enough peers discovered).
    pub fn is_complete(&self) -> bool {
        self.discovered.len() >= self.config.min_peers
    }

    /// Get the bootstrap configuration.
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    /// Add default seed nodes (for testing).
    pub fn add_default_seeds(&mut self) {
        if self.config.seed_nodes.is_empty() {
            self.config.seed_nodes.push("quic://seed1.aafp.io:4433".into());
            self.config.seed_nodes.push("quic://seed2.aafp.io:4433".into());
            self.config.seed_nodes.push("quic://seed3.aafp.io:4433".into());
            info!("Added 3 default seed nodes");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_identity::AgentKeypair;

    #[test]
    fn default_config() {
        let config = BootstrapConfig::default();
        assert_eq!(config.min_peers, 3);
        assert!(config.seed_nodes.is_empty());
    }

    #[test]
    fn add_default_seeds() {
        let mut bs = BootstrapDiscovery::new(BootstrapConfig::default());
        assert!(bs.seed_nodes().is_empty());
        bs.add_default_seeds();
        assert_eq!(bs.seed_nodes().len(), 3);
    }

    #[test]
    fn add_valid_record() {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(&kp, vec!["inference".into()], vec!["quic://1.2.3.4:4433".into()]);
        let mut bs = BootstrapDiscovery::new(BootstrapConfig::default());
        bs.add_discovered(record);
        assert_eq!(bs.discovered().len(), 1);
    }

    #[test]
    fn rejects_invalid_record() {
        let kp = AgentKeypair::generate();
        let mut record = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        record.capabilities.push("forged".into()); // breaks signature
        let mut bs = BootstrapDiscovery::new(BootstrapConfig::default());
        bs.add_discovered(record);
        assert_eq!(bs.discovered().len(), 0);
    }

    #[test]
    fn is_complete_check() {
        let config = BootstrapConfig {
            min_peers: 2,
            ..Default::default()
        };
        let mut bs = BootstrapDiscovery::new(config);
        assert!(!bs.is_complete());

        let kp1 = AgentKeypair::generate();
        let r1 = AgentRecord::new(&kp1, vec!["cap".into()], vec![]);
        bs.add_discovered(r1);
        assert!(!bs.is_complete());

        let kp2 = AgentKeypair::generate();
        let r2 = AgentRecord::new(&kp2, vec!["cap".into()], vec![]);
        bs.add_discovered(r2);
        assert!(bs.is_complete());
    }
}
