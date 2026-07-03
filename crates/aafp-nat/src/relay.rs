//! Circuit relay: relay nodes forward traffic for agents behind NAT.
//!
//! For MVP, this is a stub that tracks relay assignments. A production
//! version would implement libp2p circuit relay v2 over QUIC streams.

use aafp_core::Multiaddr;
use aafp_identity::AgentId;
use std::collections::HashMap;
use thiserror::Error;

/// Errors returned by relay operations.
#[derive(Debug, Error)]
pub enum RelayError {
    /// No relay node is available to use.
    #[error("no relay available")]
    NoRelay,
    /// A relay reservation request failed with the given reason.
    #[error("relay reservation failed: {0}")]
    ReservationFailed(String),
    /// The agent is not relayed through this node.
    #[error("not relayed through this node")]
    NotRelayed,
}

/// Relay node configuration.
#[derive(Clone, Debug)]
pub struct RelayNode {
    /// Relay node's AgentId.
    pub agent_id: AgentId,
    /// Relay node's multiaddr.
    pub addr: Multiaddr,
    /// Maximum bytes per second (0 = unlimited).
    pub max_bps: u64,
    /// Maximum duration of a relayed connection (seconds).
    pub max_duration_secs: u64,
}

/// Relay service configuration.
#[derive(Clone)]
pub struct RelayConfig {
    /// Known relay nodes.
    pub relays: Vec<RelayNode>,
    /// Whether this node acts as a relay.
    pub is_relay: bool,
    /// Maximum concurrent relayed connections.
    pub max_connections: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relays: vec![],
            is_relay: false,
            max_connections: 100,
        }
    }
}

/// Relay service: manages relay reservations and connections.
pub struct RelayService {
    config: RelayConfig,
    /// Agents currently relayed through this node (if this node is a relay).
    relayed: HashMap<AgentId, Multiaddr>,
    /// The relay this agent is using (if behind NAT).
    my_relay: Option<RelayNode>,
}

impl RelayService {
    /// Create a new relay service.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            relayed: HashMap::new(),
            my_relay: None,
        }
    }

    /// Add a known relay node.
    pub fn add_relay(&mut self, relay: RelayNode) {
        self.config.relays.push(relay);
    }

    /// Get all known relay nodes.
    pub fn relays(&self) -> &[RelayNode] {
        &self.config.relays
    }

    /// Select the best relay (first available for MVP).
    pub fn select_relay(&self) -> Option<&RelayNode> {
        self.config.relays.first()
    }

    /// Set this agent's relay (when behind NAT).
    pub fn set_my_relay(&mut self, relay: RelayNode) {
        self.my_relay = Some(relay);
    }

    /// Get this agent's relay.
    pub fn my_relay(&self) -> Option<&RelayNode> {
        self.my_relay.as_ref()
    }

    /// Check if this agent is using a relay.
    pub fn is_relayed(&self) -> bool {
        self.my_relay.is_some()
    }

    /// Add a relayed agent (when this node is a relay).
    pub fn add_relayed_agent(&mut self, agent: AgentId, addr: Multiaddr) {
        if self.relayed.len() < self.config.max_connections {
            self.relayed.insert(agent, addr);
        }
    }

    /// Remove a relayed agent.
    pub fn remove_relayed_agent(&mut self, agent: &AgentId) {
        self.relayed.remove(agent);
    }

    /// Get all agents currently relayed through this node.
    pub fn relayed_agents(&self) -> &HashMap<AgentId, Multiaddr> {
        &self.relayed
    }

    /// Check if this node is a relay.
    pub fn is_relay(&self) -> bool {
        self.config.is_relay
    }

    /// Construct a relay multiaddr for an agent.
    /// Format: "quic://relay_addr/p2p/relay_agent_id/p2p-circuit/target_agent_id"
    pub fn relay_multiaddr(&self, target: &AgentId) -> Option<String> {
        self.my_relay.as_ref().map(|relay| {
            format!(
                "quic://{}/p2p/{}/p2p-circuit/{}",
                relay.addr.strip_prefix("quic://").unwrap_or(&relay.addr),
                hex::encode(relay.agent_id),
                hex::encode(target),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relay(id: u8) -> RelayNode {
        RelayNode {
            agent_id: [id; 32],
            addr: format!("quic://relay{}.aafp.io:4433", id),
            max_bps: 1_000_000,
            max_duration_secs: 3600,
        }
    }

    #[test]
    fn add_and_select_relay() {
        let mut service = RelayService::new(RelayConfig::default());
        assert!(service.select_relay().is_none());
        service.add_relay(make_relay(1));
        service.add_relay(make_relay(2));
        assert_eq!(service.relays().len(), 2);
        assert!(service.select_relay().is_some());
    }

    #[test]
    fn set_my_relay() {
        let mut service = RelayService::new(RelayConfig::default());
        assert!(!service.is_relayed());
        service.set_my_relay(make_relay(1));
        assert!(service.is_relayed());
        assert!(service.my_relay().is_some());
    }

    #[test]
    fn relay_multiaddr() {
        let mut service = RelayService::new(RelayConfig::default());
        service.set_my_relay(make_relay(1));
        let target = [0xab; 32];
        let addr = service.relay_multiaddr(&target).unwrap();
        assert!(addr.contains("p2p-circuit"));
        assert!(addr.contains("abababab"));
    }

    #[test]
    fn relayed_agents() {
        let config = RelayConfig {
            is_relay: true,
            max_connections: 2,
            ..Default::default()
        };
        let mut service = RelayService::new(config);
        service.add_relayed_agent([1; 32], "quic://1.2.3.4:4433".into());
        service.add_relayed_agent([2; 32], "quic://5.6.7.8:4433".into());
        assert_eq!(service.relayed_agents().len(), 2);

        // Max connections reached.
        service.add_relayed_agent([3; 32], "quic://9.10.11.12:4433".into());
        assert_eq!(service.relayed_agents().len(), 2);

        // Remove one.
        service.remove_relayed_agent(&[1; 32]);
        assert_eq!(service.relayed_agents().len(), 1);
    }
}
