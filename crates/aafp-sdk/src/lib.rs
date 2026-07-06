//! AAFP SDK: high-level API for building agent-to-agent networking applications.
//!
//! The SDK wraps all lower-level crates into a simple builder-pattern API:
//!
//! ```ignore
//! use aafp_sdk::AgentBuilder;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let agent = AgentBuilder::new()
//!     .with_capabilities(vec!["inference".into()])
//!     .bind("127.0.0.1:4433".parse()?)
//!     .build()
//!     .await?;
//!
//! agent.start().await?;
//! agent.discover().await?;
//!
//! let peer = agent.connect("quic://peer:4433").await?;
//! agent.send(&peer, b"hello").await?;
//! # Ok(())
//! # }
//! ```

// The SDK uses legacy AgentRecord and CapabilityDht for local in-memory state.
// These are NOT used for wire serialization (v1 types are used for that).
#![allow(deprecated)]

pub mod builder;
pub mod client;
pub mod connection_pool;
pub mod cpu_affinity;
pub mod handshake_driver;
pub mod metrics;
pub mod prometheus;
pub mod protocol_frames;
pub mod pubsub;
pub mod runtime_config;
pub mod server;
pub mod simple;
pub mod transport_binding;

#[cfg(feature = "adaptive-routing")]
pub mod routing;

pub use builder::AgentBuilder;
pub use client::AgentClient;
pub use connection_pool::{
    ConnectionPool, PoolConfig, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_POOL_SIZE, HEALTH_CHECK_THRESHOLD,
};
pub use cpu_affinity::{num_cores, pin_current_thread_to_core, set_high_priority};
pub use handshake_driver::{drive_client_handshake, drive_server_handshake, PeerInfo};
pub use metrics::{AgentMetrics, HealthStatus, MetricsRpcResponse, MetricsSnapshot};
pub use prometheus::PrometheusExporter;
pub use protocol_frames::{parse_control_frame, send_close_frame, send_error_frame, ControlFrame};
pub use runtime_config::{RuntimeConfig, RuntimeFlavor};
pub use server::{
    AgentServer, HandshakeRateLimiter, ServerConfig, DEFAULT_HANDSHAKE_RATE_LIMIT,
    DEFAULT_MAX_CONNECTIONS,
};
pub use transport_binding::establish_session;

pub use simple::{
    Backchannel, BackchannelHandlerFn, ConnectBuilder, ConnectedAgent, DiscoveryBuilder,
    ProgressStream, Request, Response, ServeBuilder, ServingAgent,
};

pub use pubsub::{Event, PubSubBridge, SubscriptionStream, TopicMatcher};

use aafp_identity::agent_record::AgentRecord;
use aafp_identity::{AgentId, AgentKeypair};
use thiserror::Error;

/// Errors returned by the AAFP SDK.
#[derive(Debug, Error)]
pub enum SdkError {
    /// A transport-layer error.
    #[error("transport error: {0}")]
    Transport(String),
    /// A discovery-layer error.
    #[error("discovery error: {0}")]
    Discovery(String),
    /// A handshake protocol error.
    #[error("handshake error: {0}")]
    Handshake(String),
    /// A messaging-layer error.
    #[error("messaging error: {0}")]
    Messaging(String),
    /// A frame encoding or decoding error.
    #[error("frame error: {0}")]
    Frame(#[from] aafp_messaging::FrameError),
    /// No connection to the peer exists.
    #[error("not connected to peer")]
    NotConnected,
    /// The peer has not completed the handshake (session not in `MessagingEnabled` state).
    #[error("peer not authenticated — session not in MessagingEnabled state")]
    NotAuthenticated,
    /// The agent has not been started.
    #[error("agent not started")]
    NotStarted,
    /// An identity-layer error.
    #[error("identity error: {0}")]
    Identity(#[from] aafp_identity::IdentityError),
    /// A cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] aafp_crypto::CryptoError),
    /// A core crate error.
    #[error("core error: {0}")]
    Core(#[from] aafp_core::Error),
    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Circuit breaker is open for the peer.
    #[error("circuit open")]
    CircuitOpen(aafp_identity::identity_v1::AgentId),
    /// Bulkhead concurrency limit reached for the peer.
    #[error("concurrency limit reached")]
    ConcurrencyLimit(aafp_identity::identity_v1::AgentId),
    /// Operation timed out.
    #[error("timeout")]
    Timeout,
    /// No viable candidate found after filtering and scoring.
    #[error("no viable candidate")]
    NoViableCandidate,
}

/// A running AAFP agent instance.
pub struct Agent {
    /// Agent keypair (identity).
    pub keypair: AgentKeypair,
    /// Agent ID (SHA-256 of public key).
    pub agent_id: AgentId,
    /// QUIC transport.
    pub transport: aafp_transport_quic::QuicTransport,
    /// Agent record (self-signed).
    pub record: AgentRecord,
    /// Capability DHT.
    pub dht: aafp_discovery::capability_dht::CapabilityDht,
    /// Regional discovery.
    pub regional: aafp_discovery::RegionalDiscovery,
    /// Bootstrap discovery.
    pub bootstrap: aafp_discovery::BootstrapDiscovery,
    /// AutoNAT (legacy stub).
    pub auto_nat: aafp_nat::AutoNat,
    /// Relay service (legacy stub).
    pub relay: aafp_nat::RelayService,
    /// PubSub.
    pub pubsub: aafp_messaging::PubSub,
    /// Keep-alive configuration (RFC-0002 §4.7-4.8).
    pub keepalive_config: aafp_messaging::KeepAliveConfig,
    /// Whether the agent is running.
    pub running: bool,
    /// AutoNAT v1 dial-back (RFC 0010 §6) — real NAT detection.
    pub auto_nat_v1: aafp_nat::AutoNatV1DialBack,
    /// Relay discovery (RFC 0010 §9) — find relay nodes.
    pub relay_discovery: aafp_nat::RelayDiscovery,
    /// DCuTR v1 (RFC 0010 §7) — hole punching driver.
    pub dcutr_v1: aafp_nat::DcutrV1,
    /// Agent metrics (lock-free atomic counters, Track S4).
    pub metrics: std::sync::Arc<AgentMetrics>,
}

impl Agent {
    /// Get the agent's ID.
    pub fn id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Get the agent's capabilities.
    pub fn capabilities(&self) -> &[String] {
        &self.record.capabilities
    }

    /// Get the agent's multiaddr.
    pub fn multiaddr(&self) -> Result<String, SdkError> {
        Ok(self.transport.local_multiaddr()?)
    }

    /// Check if the agent is running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get the NAT status (legacy).
    pub fn nat_status(&self) -> aafp_nat::NatStatus {
        self.auto_nat.status()
    }

    /// Get the v1 NAT status (RFC 0010 §6) — real NAT detection.
    pub fn nat_status_v1(&self) -> &aafp_nat::auto_nat_v1::NatStatus {
        self.auto_nat_v1.status()
    }

    /// Check if behind NAT (v1).
    pub fn is_behind_nat(&self) -> bool {
        self.auto_nat_v1.is_behind_nat()
    }

    /// Check if publicly reachable (v1).
    pub fn is_publicly_reachable(&self) -> bool {
        self.auto_nat_v1.is_public()
    }

    /// Get the relay discovery service.
    pub fn relay_discovery(&self) -> &aafp_nat::RelayDiscovery {
        &self.relay_discovery
    }

    /// Get the DCuTR v1 driver.
    pub fn dcutr_v1(&self) -> &aafp_nat::DcutrV1 {
        &self.dcutr_v1
    }

    /// Select the best relay for a new connection.
    pub fn select_best_relay(&self) -> Option<&aafp_nat::RelayNodeInfo> {
        self.relay_discovery.select_best_relay()
    }

    /// Get all discovered agents.
    pub fn discovered_agents(&self) -> Vec<&AgentRecord> {
        self.bootstrap.discovered().iter().collect()
    }

    /// Find agents by capability.
    pub fn find_by_capability(&self, capability: &str) -> Vec<&AgentRecord> {
        self.dht.get(capability)
    }

    /// Get active pubsub topics.
    pub fn pubsub_topics(&self) -> Vec<String> {
        self.pubsub.topics().into_iter().map(String::from).collect()
    }

    /// Get a metrics snapshot (Track S4).
    ///
    /// Returns a point-in-time view of all agent metrics counters.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Check the agent's health status (Track S4).
    ///
    /// Returns `Healthy`, `Degraded`, or `Unhealthy` based on connection
    /// count, error rate, and handshake failure rate.
    pub fn health_check(&self) -> HealthStatus {
        HealthStatus::from_metrics(&self.metrics.snapshot())
    }
}
