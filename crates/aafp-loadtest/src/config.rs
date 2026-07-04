//! Configuration for load tests (Track S1).
//!
//! `LoadTestConfig` controls the number of agents, messages per agent,
//! message size, test duration, and network topology.

use std::time::Duration;

/// Network topology for connecting agents.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Topology {
    /// Every agent connects to every other (capped at `max_connections_per_agent`).
    #[default]
    Mesh,
    /// All agents connect to a single central hub agent.
    Star,
    /// Each agent connects to its neighbor in a ring (N connections).
    Ring,
    /// Each agent connects to K random peers.
    Random,
}

impl std::fmt::Display for Topology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mesh => write!(f, "mesh"),
            Self::Star => write!(f, "star"),
            Self::Ring => write!(f, "ring"),
            Self::Random => write!(f, "random"),
        }
    }
}

/// Configuration for a load test run.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LoadTestConfig {
    /// Number of agents to create.
    pub num_agents: usize,
    /// Messages each agent sends to each peer (per edge).
    pub messages_per_agent: usize,
    /// Payload size in bytes for each message.
    pub message_size: usize,
    /// Maximum test duration (the test stops early if all messages are sent).
    pub duration: Duration,
    /// Network topology.
    pub topology: Topology,
    /// Maximum connections per agent (for mesh topology, caps N² to this).
    pub max_connections_per_agent: usize,
    /// Number of random peers per agent (only used by `Random` topology).
    pub random_degree: usize,
    /// Concurrency: how many messages are in-flight per agent at once.
    pub concurrency: usize,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            num_agents: 10,
            messages_per_agent: 100,
            message_size: 1024,
            duration: Duration::from_secs(60),
            topology: Topology::Mesh,
            max_connections_per_agent: 10,
            random_degree: 5,
            concurrency: 8,
        }
    }
}

impl LoadTestConfig {
    /// Create a config for a small smoke test (10 agents, 10 messages, 256B).
    pub fn smoke() -> Self {
        Self {
            num_agents: 10,
            messages_per_agent: 10,
            message_size: 256,
            duration: Duration::from_secs(30),
            topology: Topology::Mesh,
            max_connections_per_agent: 10,
            random_degree: 3,
            concurrency: 4,
        }
    }

    /// Create a config for the 100-agent load test (Track S2).
    pub fn agents_100() -> Self {
        Self {
            num_agents: 100,
            messages_per_agent: 100,
            message_size: 1024,
            duration: Duration::from_secs(120),
            topology: Topology::Star,
            max_connections_per_agent: 10,
            random_degree: 5,
            concurrency: 16,
        }
    }
}
