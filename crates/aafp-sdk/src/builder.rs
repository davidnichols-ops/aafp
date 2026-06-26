//! Agent builder: fluent API for constructing an AAFP agent.

use crate::{Agent, SdkError};
use aafp_discovery::{BootstrapConfig, BootstrapDiscovery, CapabilityDht, RegionalDiscovery};
use aafp_identity::{derive_agent_id, AgentKeypair, AgentRecord};
use aafp_messaging::PubSub;
use aafp_nat::{AutoNat, RelayConfig, RelayService};
use aafp_transport_quic::QuicConfig;
use std::net::SocketAddr;

/// Builder for creating an AAFP agent.
pub struct AgentBuilder {
    keypair: Option<AgentKeypair>,
    capabilities: Vec<String>,
    bind_addr: SocketAddr,
    seed_nodes: Vec<String>,
    is_relay: bool,
    enable_pq: bool,
}

impl AgentBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self {
            keypair: None,
            capabilities: vec![],
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            seed_nodes: vec![],
            is_relay: false,
            enable_pq: true,
        }
    }

    /// Use an existing keypair (for persistent identity).
    pub fn with_keypair(mut self, keypair: AgentKeypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set the agent's capabilities.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the bind address.
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set seed nodes for bootstrap.
    pub fn with_seeds(mut self, seeds: Vec<String>) -> Self {
        self.seed_nodes = seeds;
        self
    }

    /// Enable relay mode (this agent acts as a relay).
    pub fn as_relay(mut self) -> Self {
        self.is_relay = true;
        self
    }

    /// Enable or disable post-quantum KEX.
    pub fn with_pq(mut self, enable: bool) -> Self {
        self.enable_pq = enable;
        self
    }

    /// Build the agent.
    pub async fn build(self) -> Result<Agent, SdkError> {
        let keypair = self.keypair.unwrap_or_else(AgentKeypair::generate);
        let agent_id = derive_agent_id(&keypair.public_key);

        // Create QUIC transport.
        let quic_config = QuicConfig {
            bind_addr: self.bind_addr,
            enable_pq: self.enable_pq,
            ..Default::default()
        };
        let transport = aafp_transport_quic::QuicTransport::new(quic_config)
            .map_err(|e| SdkError::Transport(e.to_string()))?;

        let local_addr = transport.local_multiaddr()?;

        // Create agent record.
        let record = AgentRecord::new(
            &keypair,
            self.capabilities.clone(),
            vec![local_addr],
        );

        // Create discovery components.
        let bootstrap_config = BootstrapConfig {
            seed_nodes: self.seed_nodes,
            ..Default::default()
        };
        let bootstrap = BootstrapDiscovery::new(bootstrap_config);
        let dht = CapabilityDht::new();
        let regional = RegionalDiscovery::new();

        // Put our own record in the DHT.
        let mut dht = dht;
        dht.put(record.clone()).map_err(|e| SdkError::Discovery(e.to_string()))?;

        // Create NAT components.
        let auto_nat = AutoNat::new();
        let relay_config = RelayConfig {
            is_relay: self.is_relay,
            ..Default::default()
        };
        let relay = RelayService::new(relay_config);

        // Create pubsub.
        let pubsub = PubSub::new();

        Ok(Agent {
            keypair,
            agent_id,
            transport,
            record,
            dht,
            regional,
            bootstrap,
            auto_nat,
            relay,
            pubsub,
            running: false,
        })
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_agent() {
        let agent = AgentBuilder::new()
            .with_capabilities(vec!["inference".into()])
            .build()
            .await
            .unwrap();

        assert_eq!(agent.capabilities(), &["inference"]);
        assert!(!agent.is_running());
        assert_eq!(agent.nat_status(), aafp_nat::NatStatus::Unknown);
        // Agent's own record is in the DHT.
        let inference = agent.find_by_capability("inference");
        assert_eq!(inference.len(), 1);
    }

    #[tokio::test]
    async fn build_with_keypair() {
        let kp = AgentKeypair::generate();
        let expected_id = derive_agent_id(&kp.public_key);
        let agent = AgentBuilder::new()
            .with_keypair(kp)
            .build()
            .await
            .unwrap();
        assert_eq!(*agent.id(), expected_id);
    }

    #[tokio::test]
    async fn build_relay() {
        let agent = AgentBuilder::new()
            .as_relay()
            .build()
            .await
            .unwrap();
        assert!(agent.relay.is_relay());
    }

    #[tokio::test]
    async fn build_with_seeds() {
        let agent = AgentBuilder::new()
            .with_seeds(vec!["quic://seed1:4433".into()])
            .build()
            .await
            .unwrap();
        assert_eq!(agent.bootstrap.seed_nodes().len(), 1);
    }

    #[tokio::test]
    async fn find_self_in_dht() {
        let agent = AgentBuilder::new()
            .with_capabilities(vec!["inference".into(), "translation".into()])
            .build()
            .await
            .unwrap();

        let inference = agent.find_by_capability("inference");
        assert_eq!(inference.len(), 1);
        assert_eq!(inference[0].agent_id, *agent.id());

        let translation = agent.find_by_capability("translation");
        assert_eq!(translation.len(), 1);
    }
}
