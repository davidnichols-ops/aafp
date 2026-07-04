//! Topology edge generation (Track S1).
//!
//! Given N agents, produce the list of directed edges `(from, to)` that
//! define which agents connect to which. Each edge represents a client
//! connection from agent `from` to agent `to`.

use crate::config::{LoadTestConfig, Topology};

/// A directed edge: agent `from` connects to agent `to`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
}

/// Generate the list of edges for the given topology.
///
/// Edges are directed: `(from, to)` means agent `from` dials agent `to`.
/// Self-loops are never included.
pub fn generate_edges(config: &LoadTestConfig) -> Vec<Edge> {
    let n = config.num_agents;
    match config.topology {
        Topology::Mesh => generate_mesh(n, config.max_connections_per_agent),
        Topology::Star => generate_star(n),
        Topology::Ring => generate_ring(n),
        Topology::Random => generate_random(n, config.random_degree),
    }
}

/// Mesh: every agent connects to every other, capped at `max_per_agent`.
///
/// Agent `i` connects to agents `i+1, i+2, ..., i+max` (mod N). This gives
/// each agent exactly `min(max_per_agent, N-1)` outgoing connections and
/// keeps the total edge count at `N * min(max, N-1)` rather than N².
fn generate_mesh(n: usize, max_per_agent: usize) -> Vec<Edge> {
    let mut edges = Vec::new();
    for i in 0..n {
        let limit = max_per_agent.min(n.saturating_sub(1));
        for k in 1..=limit {
            let j = (i + k) % n;
            edges.push(Edge { from: i, to: j });
        }
    }
    edges
}

/// Star: all agents connect to agent 0 (the hub).
fn generate_star(n: usize) -> Vec<Edge> {
    let mut edges = Vec::new();
    for i in 1..n {
        edges.push(Edge { from: i, to: 0 });
    }
    edges
}

/// Ring: each agent connects to its neighbor (i → i+1 mod N).
fn generate_ring(n: usize) -> Vec<Edge> {
    let mut edges = Vec::new();
    for i in 0..n {
        let j = (i + 1) % n;
        edges.push(Edge { from: i, to: j });
    }
    edges
}

/// Random: each agent connects to K random peers (deterministic seed).
///
/// Uses a simple LCG (linear congruential generator) with a fixed seed so
/// that the topology is reproducible across runs.
fn generate_random(n: usize, k: usize) -> Vec<Edge> {
    let mut edges = Vec::new();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15; // fixed seed
    for i in 0..n {
        let mut connected = std::collections::HashSet::new();
        let target = k.min(n.saturating_sub(1));
        while connected.len() < target {
            // LCG step
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (state >> 33) as usize % n;
            if j != i {
                connected.insert(j);
            }
        }
        let mut sorted: Vec<_> = connected.into_iter().collect();
        sorted.sort();
        for j in sorted {
            edges.push(Edge { from: i, to: j });
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(n: usize, topo: Topology) -> LoadTestConfig {
        LoadTestConfig {
            num_agents: n,
            topology: topo,
            ..Default::default()
        }
    }

    #[test]
    fn mesh_no_self_loops() {
        let edges = generate_edges(&config(10, Topology::Mesh));
        for e in &edges {
            assert_ne!(e.from, e.to, "no self-loops");
        }
    }

    #[test]
    fn mesh_caps_connections() {
        let cfg = LoadTestConfig {
            num_agents: 20,
            max_connections_per_agent: 5,
            topology: Topology::Mesh,
            ..Default::default()
        };
        let edges = generate_edges(&cfg);
        // Each agent has exactly 5 outgoing edges
        for i in 0..20 {
            let count = edges.iter().filter(|e| e.from == i).count();
            assert_eq!(count, 5, "agent {i} should have 5 outgoing edges");
        }
    }

    #[test]
    fn star_all_connect_to_hub() {
        let edges = generate_edges(&config(10, Topology::Star));
        assert_eq!(edges.len(), 9, "9 edges for 10-agent star");
        for e in &edges {
            assert_eq!(e.to, 0, "all edges point to hub (agent 0)");
            assert_ne!(e.from, 0);
        }
    }

    #[test]
    fn ring_n_edges() {
        let edges = generate_edges(&config(10, Topology::Ring));
        assert_eq!(edges.len(), 10, "ring has N edges");
        for i in 0..10 {
            assert!(
                edges.iter().any(|e| e.from == i && e.to == (i + 1) % 10),
                "agent {i} connects to next"
            );
        }
    }

    #[test]
    fn random_no_self_loops() {
        let edges = generate_edges(&config(20, Topology::Random));
        for e in &edges {
            assert_ne!(e.from, e.to, "no self-loops in random");
        }
    }

    #[test]
    fn random_respects_degree() {
        let cfg = LoadTestConfig {
            num_agents: 20,
            random_degree: 5,
            topology: Topology::Random,
            ..Default::default()
        };
        let edges = generate_edges(&cfg);
        for i in 0..20 {
            let count = edges.iter().filter(|e| e.from == i).count();
            assert_eq!(count, 5, "agent {i} should have degree 5");
        }
    }

    #[test]
    fn random_is_deterministic() {
        let cfg = config(20, Topology::Random);
        let e1 = generate_edges(&cfg);
        let e2 = generate_edges(&cfg);
        assert_eq!(e1, e2, "random topology must be deterministic");
    }

    #[test]
    fn single_agent_has_no_edges() {
        let edges = generate_edges(&config(1, Topology::Mesh));
        assert!(edges.is_empty());
    }
}
