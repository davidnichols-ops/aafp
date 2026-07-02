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
pub mod handshake_driver;
pub mod protocol_frames;
pub mod server;
pub mod transport_binding;

pub use builder::AgentBuilder;
pub use client::AgentClient;
pub use handshake_driver::{drive_client_handshake, drive_server_handshake, PeerInfo};
pub use protocol_frames::{parse_control_frame, send_close_frame, send_error_frame, ControlFrame};
pub use server::AgentServer;
pub use transport_binding::establish_session;

use aafp_identity::agent_record::AgentRecord;
use aafp_identity::{AgentId, AgentKeypair};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("discovery error: {0}")]
    Discovery(String),
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("messaging error: {0}")]
    Messaging(String),
    #[error("frame error: {0}")]
    Frame(#[from] aafp_messaging::FrameError),
    #[error("not connected to peer")]
    NotConnected,
    #[error("peer not authenticated — session not in MessagingEnabled state")]
    NotAuthenticated,
    #[error("agent not started")]
    NotStarted,
    #[error("identity error: {0}")]
    Identity(#[from] aafp_identity::IdentityError),
    #[error("crypto error: {0}")]
    Crypto(#[from] aafp_crypto::CryptoError),
    #[error("core error: {0}")]
    Core(#[from] aafp_core::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
    /// AutoNAT.
    pub auto_nat: aafp_nat::AutoNat,
    /// Relay service.
    pub relay: aafp_nat::RelayService,
    /// PubSub.
    pub pubsub: aafp_messaging::PubSub,
    /// Whether the agent is running.
    pub running: bool,
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

    /// Get the NAT status.
    pub fn nat_status(&self) -> aafp_nat::NatStatus {
        self.auto_nat.status()
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
    pub fn pubsub_topics(&self) -> Vec<&str> {
        self.pubsub.topics()
    }
}
