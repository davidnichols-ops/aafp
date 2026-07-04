//! Agent builder: fluent API for constructing an AAFP agent.

use crate::{Agent, RuntimeConfig, SdkError};
use aafp_discovery::capability_dht::CapabilityDht;
use aafp_discovery::{BootstrapConfig, BootstrapDiscovery, RegionalDiscovery};
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::{derive_agent_id, AgentKeypair};
use aafp_messaging::{KeepAliveConfig, PubSub};
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
    keepalive_config: KeepAliveConfig,
    runtime_config: RuntimeConfig,
    /// Bootstrap relay addresses for NAT traversal (Track N5).
    bootstrap_relays: Vec<String>,
    /// Whether to enable DCuTR hole punching (Track N5).
    enable_dcutr: bool,
    /// Whether to enable AutoNAT dial-back (Track N5).
    enable_autonat: bool,
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
            keepalive_config: KeepAliveConfig::default(),
            runtime_config: RuntimeConfig::default(),
            bootstrap_relays: vec![],
            enable_dcutr: true,
            enable_autonat: true,
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

    /// Set the keep-alive configuration (RFC-0002 §4.7-4.8).
    ///
    /// Controls PING/PONG behavior for connection liveness checks.
    /// Default: interval 30s, timeout 10s, max_missed 3.
    pub fn with_keepalive(mut self, config: KeepAliveConfig) -> Self {
        self.keepalive_config = config;
        self
    }

    /// Disable keep-alive entirely.
    pub fn disable_keepalive(self) -> Self {
        self.with_keepalive(KeepAliveConfig::disabled())
    }

    /// Set the Tokio runtime configuration (Track L5).
    ///
    /// Controls whether the agent uses a `current_thread` or `multi_thread`
    /// runtime. For localhost RPC, `current_thread` eliminates cross-core
    /// scheduling overhead (84% of time per L1 profiling).
    ///
    /// Default: `RuntimeConfig::default()` (multi_thread, auto worker count).
    /// Low-latency: `RuntimeConfig::low_latency()` (current_thread, 2MB stack).
    pub fn with_runtime_config(mut self, config: RuntimeConfig) -> Self {
        self.runtime_config = config;
        self
    }

    /// Use the low-latency runtime preset (Track L5).
    ///
    /// Equivalent to `.with_runtime_config(RuntimeConfig::low_latency())`.
    /// Uses `current_thread` runtime with 2MB stack — best for localhost RPC.
    pub fn with_low_latency_runtime(self) -> Self {
        self.with_runtime_config(RuntimeConfig::low_latency())
    }

    /// Add bootstrap relay addresses for NAT traversal (Track N5).
    ///
    /// These relays are used when the agent detects it is behind NAT.
    /// The agent will health-check these relays and use the best one
    /// for relayed connections.
    pub fn with_bootstrap_relays(mut self, relays: Vec<String>) -> Self {
        self.bootstrap_relays = relays;
        self
    }

    /// Enable or disable DCuTR hole punching (Track N5).
    ///
    /// When enabled (default), the agent will attempt to upgrade relayed
    /// connections to direct connections via simultaneous open.
    pub fn with_dcutr(mut self, enable: bool) -> Self {
        self.enable_dcutr = enable;
        self
    }

    /// Enable or disable AutoNAT dial-back (Track N5).
    ///
    /// When enabled (default), the agent will attempt to detect if it is
    /// behind NAT by requesting dial-back checks from peers.
    pub fn with_autonat(mut self, enable: bool) -> Self {
        self.enable_autonat = enable;
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
        let record = AgentRecord::new(&keypair, self.capabilities.clone(), vec![local_addr]);

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
        dht.put(record.clone())
            .map_err(|e| SdkError::Discovery(e.to_string()))?;

        // Create NAT components (legacy stubs).
        let auto_nat = AutoNat::new();
        let relay_config = RelayConfig {
            is_relay: self.is_relay,
            ..Default::default()
        };
        let relay = RelayService::new(relay_config);

        // Create NAT v1 components (Track N5).
        let auto_nat_v1 = aafp_nat::AutoNatV1DialBack::new();
        let mut relay_discovery = aafp_nat::RelayDiscovery::new();
        for relay_addr in &self.bootstrap_relays {
            relay_discovery.add_bootstrap_relay(relay_addr.clone());
        }
        let mut dcutr_v1 = aafp_nat::DcutrV1::new();
        if !self.enable_dcutr {
            dcutr_v1.set_enabled(false);
        }

        // Create pubsub.
        let pubsub = PubSub::new();

        // Create metrics (Track S4).
        let metrics = crate::AgentMetrics::new();

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
            keepalive_config: self.keepalive_config,
            running: false,
            auto_nat_v1,
            relay_discovery,
            dcutr_v1,
            metrics,
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
    use std::time::Duration;

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
        let agent = AgentBuilder::new().with_keypair(kp).build().await.unwrap();
        assert_eq!(*agent.id(), expected_id);
    }

    #[tokio::test]
    async fn build_relay() {
        let agent = AgentBuilder::new().as_relay().build().await.unwrap();
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

    #[tokio::test]
    async fn build_with_keepalive() {
        let config = KeepAliveConfig {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            max_missed: 5,
        };
        let agent = AgentBuilder::new()
            .with_keepalive(config.clone())
            .build()
            .await
            .unwrap();
        assert_eq!(agent.keepalive_config.interval, Duration::from_secs(5));
        assert_eq!(agent.keepalive_config.timeout, Duration::from_secs(2));
        assert_eq!(agent.keepalive_config.max_missed, 5);
    }

    #[tokio::test]
    async fn build_with_keepalive_disabled() {
        let agent = AgentBuilder::new()
            .disable_keepalive()
            .build()
            .await
            .unwrap();
        assert!(!agent.keepalive_config.is_enabled());
    }

    #[tokio::test]
    async fn build_default_keepalive() {
        let agent = AgentBuilder::new().build().await.unwrap();
        assert!(agent.keepalive_config.is_enabled());
        assert_eq!(agent.keepalive_config.interval, Duration::from_secs(30));
    }

    #[test]
    fn builder_with_runtime_config() {
        let builder = AgentBuilder::new().with_low_latency_runtime();
        assert_eq!(
            builder.runtime_config.flavor,
            crate::RuntimeFlavor::CurrentThread
        );
    }

    #[test]
    fn builder_default_runtime_is_multi_thread() {
        let builder = AgentBuilder::new();
        assert_eq!(
            builder.runtime_config.flavor,
            crate::RuntimeFlavor::MultiThread
        );
    }

    #[tokio::test]
    async fn build_with_bootstrap_relays() {
        let agent = AgentBuilder::new()
            .with_bootstrap_relays(vec![
                "quic://relay1:4433".into(),
                "quic://relay2:4433".into(),
            ])
            .build()
            .await
            .unwrap();
        assert_eq!(agent.relay_discovery().bootstrap_relays().len(), 2);
    }

    #[tokio::test]
    async fn build_with_dcutr_disabled() {
        let agent = AgentBuilder::new().with_dcutr(false).build().await.unwrap();
        assert!(!agent.dcutr_v1().is_enabled());
    }

    #[tokio::test]
    async fn build_with_dcutr_enabled() {
        let agent = AgentBuilder::new().with_dcutr(true).build().await.unwrap();
        assert!(agent.dcutr_v1().is_enabled());
    }

    #[tokio::test]
    async fn build_default_dcutr_enabled() {
        let agent = AgentBuilder::new().build().await.unwrap();
        assert!(agent.dcutr_v1().is_enabled());
    }

    #[tokio::test]
    async fn build_nat_v1_status_unknown() {
        let agent = AgentBuilder::new().build().await.unwrap();
        assert_eq!(
            *agent.nat_status_v1(),
            aafp_nat::auto_nat_v1::NatStatus::Unknown
        );
        assert!(!agent.is_behind_nat());
        assert!(!agent.is_publicly_reachable());
    }

    #[tokio::test]
    async fn build_select_best_relay_none() {
        let agent = AgentBuilder::new().build().await.unwrap();
        // No relays discovered yet
        assert!(agent.select_best_relay().is_none());
    }

    #[tokio::test]
    async fn build_agent_has_metrics() {
        let agent = AgentBuilder::new().build().await.unwrap();
        let metrics = agent.metrics();
        assert_eq!(metrics.connections_active, 0);
        assert_eq!(metrics.connections_total, 0);
        assert_eq!(metrics.messages_sent, 0);
        assert_eq!(metrics.messages_received, 0);
        assert_eq!(metrics.uptime_seconds, 0); // just created
    }

    #[tokio::test]
    async fn build_agent_health_check_warmup() {
        let agent = AgentBuilder::new().build().await.unwrap();
        // During warmup (uptime < 60s), health should be Healthy
        let health = agent.health_check();
        assert_eq!(health, crate::HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn build_agent_metrics_record_and_check() {
        let agent = AgentBuilder::new().build().await.unwrap();
        // Record some activity
        agent.metrics.record_connection();
        agent.metrics.record_sent(1024);
        agent.metrics.record_received(512);
        agent.metrics.record_handshake();

        let metrics = agent.metrics();
        assert_eq!(metrics.connections_active, 1);
        assert_eq!(metrics.connections_total, 1);
        assert_eq!(metrics.messages_sent, 1);
        assert_eq!(metrics.messages_received, 1);
        assert_eq!(metrics.bytes_sent, 1024);
        assert_eq!(metrics.bytes_received, 512);
        assert_eq!(metrics.handshakes_completed, 1);

        // Health should be healthy (low error rate, has connections)
        let health = agent.health_check();
        assert_eq!(health, crate::HealthStatus::Healthy);
    }
}
