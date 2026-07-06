//! Directed graph of capabilities and their composition edges (D4).
//!
//! Nodes are [`SemanticCapability`] records offered by specific agents; edges
//! are [`CapabilityEdge`] (directed and typed). This graph is the substrate for
//! pipeline assembly.
//!
//! This is a pre-build scaffold: method bodies are `todo!()` and will be
//! implemented by the D4 builder.

use crate::semantic::{CapabilityEdge, EdgeType, SemanticCapability};
use aafp_identity::AgentId;
use std::collections::HashMap;

/// A node in the capability graph: a capability offered by a specific agent.
#[derive(Clone, Debug)]
pub struct CapabilityNode {
    /// The semantic capability descriptor.
    pub capability: SemanticCapability,
    /// The agent offering this capability.
    pub agent_id: AgentId,
}

/// The capability graph.
///
/// Nodes are keyed by capability name (multiple agents may offer the same
/// capability → multiple nodes per name). Edges are stored as an adjacency
/// list keyed by source capability name. A reverse adjacency map supports
/// requirement resolution and topological sort.
pub struct CapabilityGraph {
    /// capability name → nodes (one per provider).
    nodes: HashMap<String, Vec<CapabilityNode>>,
    /// source capability name → outgoing edges (adjacency list).
    adjacency: HashMap<String, Vec<CapabilityEdge>>,
    /// target capability name → incoming source names (reverse adjacency).
    reverse_adjacency: HashMap<String, Vec<String>>,
}

impl Default for CapabilityGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityGraph {
    /// Create an empty capability graph.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
        }
    }

    /// Add a capability node (a provider of `name`).
    pub fn add_node(&mut self, node: CapabilityNode) {
        todo!("D4: insert node into nodes[capability.name]")
    }

    /// Add an outgoing edge from `source` capability. Updates
    /// [`reverse_adjacency`](Self::reverse_adjacency).
    pub fn add_edge(&mut self, source: &str, edge: CapabilityEdge) {
        todo!("D4: push edge into adjacency[source]; push source into reverse_adjacency[edge.target]")
    }

    /// All nodes (providers) for a capability name.
    pub fn get_providers(&self, name: &str) -> &[CapabilityNode] {
        todo!("D4: return nodes.get(name) slice or empty")
    }

    /// Outgoing edges of a capability.
    pub fn get_edges(&self, name: &str) -> &[CapabilityEdge] {
        todo!("D4: return adjacency.get(name) slice or empty")
    }

    /// Edges of a specific type from a capability (e.g., all `Requires`).
    pub fn edges_of_type(&self, name: &str, et: EdgeType) -> Vec<&CapabilityEdge> {
        todo!("D4: filter adjacency[name] by edge.edge_type == et")
    }

    /// Total node count (sum across all capability names).
    pub fn node_count(&self) -> usize {
        todo!("D4: sum of nodes vec lengths")
    }

    /// Total edge count (sum across all adjacency entries).
    pub fn edge_count(&self) -> usize {
        todo!("D4: sum of adjacency vec lengths")
    }
}
