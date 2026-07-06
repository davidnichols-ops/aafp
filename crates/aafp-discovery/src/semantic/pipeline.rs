//! Assemble execution pipelines from the capability graph (D4).
//!
//! The assembler takes a goal expressed as a [`CapabilityQuery`] and returns
//! an ordered [`Pipeline`] by traversing the [`CapabilityGraph`]: find
//! candidates, recursively resolve `Requires` edges, topologically sort using
//! `Requires` + `Precedes` edges (Kahn's algorithm), and materialize steps
//! with `depends_on` indices.
//!
//! This is a pre-build scaffold: method bodies are `todo!()` and will be
//! implemented by the D4 builder.

use crate::semantic::graph::{CapabilityGraph, CapabilityNode};
use crate::semantic::index::CapabilityIndex;
use crate::semantic::{CapabilityQuery, EdgeType};
use aafp_identity::AgentId;
use std::collections::{HashMap, HashSet, VecDeque};

/// A single step in an assembled pipeline.
#[derive(Clone, Debug)]
pub struct PipelineStep {
    /// The capability to invoke at this step.
    pub capability_name: String,
    /// The agent that will execute this step.
    pub agent_id: AgentId,
    /// Indices of prior steps this step depends on (from `Requires`/`Precedes`).
    pub depends_on: Vec<usize>,
    /// Position in the pipeline (0-based, topologically ordered).
    pub order: usize,
}

/// An assembled pipeline: ordered steps with dependency links.
#[derive(Clone, Debug)]
pub struct Pipeline {
    /// Topologically ordered steps.
    pub steps: Vec<PipelineStep>,
    /// Sum of `avg_latency_ms` across steps (rough estimate).
    pub estimated_latency_ms: f64,
}

/// Errors that can occur during pipeline assembly.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// No capability satisfies the goal query.
    #[error("no capability satisfies the goal: {0}")]
    NoCandidate(String),
    /// A required capability has no providers in the graph.
    #[error("requirement not satisfiable: capability '{0}' has no providers")]
    UnresolvedRequirement(String),
    /// A cycle was detected in the capability graph.
    #[error("cycle detected in capability graph at '{0}'")]
    CycleDetected(String),
    /// Requirement resolution exceeded the configured recursion depth.
    #[error("recursion depth exceeded ({0})")]
    DepthExceeded(usize),
}

/// Assembles execution pipelines from a [`CapabilityGraph`] + [`CapabilityIndex`].
pub struct PipelineAssembler {
    graph: CapabilityGraph,
    index: CapabilityIndex,
    /// Maximum recursion depth for requirement resolution (default 16).
    max_depth: usize,
}

impl PipelineAssembler {
    /// Create a new assembler over the given graph and index.
    pub fn new(graph: CapabilityGraph, index: CapabilityIndex) -> Self {
        Self {
            graph,
            index,
            max_depth: 16,
        }
    }

    /// Set the maximum requirement-resolution recursion depth.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Assemble a pipeline that satisfies `goal`.
    ///
    /// Algorithm:
    ///  1. Query the graph for goal candidates.
    ///  2. Recursively resolve `Requires` edges (BFS, visited set for cycles).
    ///  3. Build a combined precedence relation from `Requires` + `Precedes`.
    ///  4. Topologically sort (Kahn's algorithm); detect cycles.
    ///  5. Pick a provider (node) for each capability (highest trust first).
    ///  6. Materialize [`PipelineStep`]s with `depends_on` indices.
    pub fn assemble(&self, goal: &CapabilityQuery) -> Result<Pipeline, PipelineError> {
        todo!("D4: find_pipeline — candidates, requirement BFS, topological sort, materialize steps")
    }
}

/// Topologically sort `capabilities` using `Requires` + `Precedes` edges from
/// `graph` (Kahn's algorithm). Returns capability names in execution order.
/// Deterministic: the ready queue is sorted by capability name on each
/// iteration. Returns [`PipelineError::CycleDetected`] if a cycle exists.
pub fn topological_sort(
    graph: &CapabilityGraph,
    capabilities: &HashSet<String>,
) -> Result<Vec<String>, PipelineError> {
    let _ = (graph, capabilities);
    todo!("D4: build in-degree map from Requires/Precedes edges among `capabilities`; Kahn's algorithm with name-sorted ready queue; detect cycle via order.len() != capabilities.len()")
}

/// Resolve the full set of required capabilities for `goal_node` by BFS over
/// `Requires` edges. Returns the collected capability names and chosen
/// [`CapabilityNode`]s. Detects cycles and enforces `max_depth`.
fn resolve_requirements(
    graph: &CapabilityGraph,
    goal_node: &CapabilityNode,
    max_depth: usize,
) -> Result<HashMap<String, &CapabilityNode>, PipelineError> {
    let _ = (graph, goal_node, max_depth);
    todo!("D4: BFS over Requires edges with visited set; pick highest-trust provider per required capability; enforce max_depth")
}

// Silence unused-import warnings for scaffolding symbols referenced by the
// todo!() bodies once implemented.
#[allow(dead_code)]
fn _ensure_imports_used() {
    let _ = VecDeque::<(String, usize)>::new();
    let _ = EdgeType::Requires;
}
