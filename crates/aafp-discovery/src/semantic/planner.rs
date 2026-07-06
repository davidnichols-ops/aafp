//! Capability planning (SCG §10 — Discovery as Planning).
//!
//! A planner turns a goal query into an ordered [`ExecutionPlan`] by searching
//! the capability graph. The planning domain is modelled as:
//! - **States**: the set of satisfied [`Effect`]s (symbolic predicates over the
//!   execution state).
//! - **Actions**: capability invocations ([`PlannedStep`]), each with
//!   [`Precondition`]s (derived from `Requirement`s) and [`Effect`]s (derived
//!   from `provides`).
//! - **Goals**: the desired outputs expressed as a [`CapabilityQuery`].
//!
//! The default implementation, [`HeuristicPlanner`], runs greedy forward
//! chaining to find a feasible plan, then A* refinement to optimize total
//! latency/cost subject to complexity and cost budgets.
//!
//! > **Status:** Pre-build scaffolding (D5). All method bodies are `todo!()`.
//! > Types and signatures are final; implementation follows in the build phase.

use aafp_identity::AgentId;
use aafp_routing::RoutingMetrics;

use super::capability::SemanticError;
use super::{CapabilityQuery, SemanticCapability};

/// A planner turns a goal query into an ordered execution plan by searching
/// the capability graph. Implementations may use different search strategies
/// (greedy, A*, symbolic). The trait is async-aware because graph traversal
/// may need to issue follow-up discovery queries for unsatisfied requirements.
#[async_trait::async_trait]
pub trait CapabilityPlanner: Send + Sync {
    /// Find an execution plan that achieves the goal.
    ///
    /// `available` is the set of capabilities the calling agent currently
    /// knows about (from local index + recent DHT discovery). The planner
    /// may return [`PlanningError::MissingCapability`] if a required
    /// precondition cannot be satisfied by any available capability.
    async fn plan(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
    ) -> Result<ExecutionPlan, PlanningError>;

    /// Same as [`plan`](CapabilityPlanner::plan) but with live routing metrics
    /// so the planner can prefer healthy providers. The default impl falls
    /// back to [`plan`](CapabilityPlanner::plan).
    async fn plan_with_metrics(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
        metrics: &[(AgentId, RoutingMetrics)],
    ) -> Result<ExecutionPlan, PlanningError> {
        let _ = metrics;
        self.plan(goal, available).await
    }
}

/// An ordered execution plan produced by a [`CapabilityPlanner`].
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// Ordered steps. Step `i` may depend on steps `0..i` (see `depends_on`).
    pub steps: Vec<PlannedStep>,
    /// Sum of `avg_latency_ms` across all steps (serial estimate).
    /// Parallel branches are maxed, not summed.
    pub estimated_total_latency_ms: f64,
    /// Sum of `per_invocation_micro_usd` across all steps.
    pub estimated_total_cost_micro_usd: u64,
    /// Number of distinct agents involved (for fan-out analysis).
    pub agent_count: usize,
    /// Whether the plan is fully satisfied (all preconditions met) or
    /// partial (some preconditions open, requiring further discovery).
    pub complete: bool,
}

/// One step in an [`ExecutionPlan`]. Maps to a single capability invocation
/// against a specific agent, with explicit preconditions and effects drawn
/// from the [`SemanticCapability`] requirements/provides fields.
#[derive(Debug, Clone)]
pub struct PlannedStep {
    /// Index into the plan's `steps` vector (also the topological order).
    pub index: usize,
    /// The capability to invoke.
    pub capability: SemanticCapability,
    /// The agent that provides this capability (chosen by the planner).
    pub agent_id: AgentId,
    /// Indices of prior steps whose outputs feed into this step.
    pub depends_on: Vec<usize>,
    /// Preconditions that must hold before this step runs. Each is derived
    /// from a `Requirement` on the capability and is either satisfied by a
    /// prior step's effect or by the initial state.
    pub preconditions: Vec<Precondition>,
    /// Effects produced by this step (outputs that become available to
    /// later steps). Derived from `SemanticCapability.provides`.
    pub effects: Vec<Effect>,
    /// Estimated latency for this step alone (ms).
    pub estimated_latency_ms: f64,
    /// Estimated cost for this step alone (micro-USD).
    pub estimated_cost_micro_usd: u64,
}

/// A precondition is a symbolic predicate over the execution state.
/// The planner matches preconditions against [`Effect`]s of prior steps.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Precondition {
    /// The kind of thing required (e.g., "document-text", "image-bytes").
    pub kind: String,
    /// Optional attribute constraints (e.g., language=en, format=pdf).
    pub attributes: Vec<(String, String)>,
}

/// An effect is a symbolic assertion of what a step produces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Effect {
    /// The kind of thing produced (e.g., "search-results", "web-content").
    pub kind: String,
    /// Optional attributes describing the output (e.g., format=markdown).
    pub attributes: Vec<(String, String)>,
}

/// Errors that can arise during capability planning.
#[derive(Debug, thiserror::Error)]
pub enum PlanningError {
    /// No capability chain satisfies the goal.
    #[error("no capability satisfies goal: {0}")]
    NoSolution(String),
    /// A required capability is not available in the provided set.
    #[error("required capability not available: {0}")]
    MissingCapability(String),
    /// The plan exceeds the maximum number of steps (complexity budget).
    #[error("plan exceeds complexity budget (max {max_steps} steps)")]
    ComplexityExceeded { max_steps: usize },
    /// The plan exceeds the total cost budget.
    #[error("plan exceeds cost budget ({budget_micro_usd} micro-USD)")]
    CostExceeded { budget_micro_usd: u64 },
    /// A cycle was detected in the capability dependency graph.
    #[error("cycle detected in capability graph at {node}")]
    CycleDetected { node: String },
    /// An underlying index/graph error.
    #[error("index error: {0}")]
    Index(#[from] SemanticError),
}

/// The default [`CapabilityPlanner`]. Combines greedy forward chaining with
/// A* search refinement.
///
/// # Phases
/// 1. **Greedy forward chaining** — starting from the goal, find capabilities
///    whose `provides` match the goal. For each unsatisfied `Requirement`,
///    recurse to find a capability that produces the required effect. This
///    builds a dependency DAG quickly.
/// 2. **A\* refinement** — if greedy finds a plan, run A* over the graph to
///    optimize total latency/cost, using a heuristic of `remaining_steps *
///    min_step_latency`. A* prunes plans that exceed the complexity or cost
///    budget.
///
/// # Budgets
/// - [`max_steps`](HeuristicPlanner::max_steps): complexity budget.
/// - [`max_cost_micro_usd`](HeuristicPlanner::max_cost_micro_usd): cost budget.
/// Plans exceeding either are rejected with the appropriate
/// [`PlanningError`] variant.
pub struct HeuristicPlanner {
    /// Maximum steps in any plan (complexity budget).
    pub max_steps: usize,
    /// Maximum total cost in micro-USD (cost budget).
    pub max_cost_micro_usd: u64,
    /// Weight for latency vs cost in the A* objective.
    /// `0.0` = cost-only, `1.0` = latency-only.
    pub latency_weight: f64,
}

impl Default for HeuristicPlanner {
    fn default() -> Self {
        Self {
            max_steps: 16,
            max_cost_micro_usd: 1_000_000, // $1.00
            latency_weight: 0.7,
        }
    }
}

#[async_trait::async_trait]
impl CapabilityPlanner for HeuristicPlanner {
    async fn plan(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
    ) -> Result<ExecutionPlan, PlanningError> {
        let _ = (goal, available);
        todo!("D5: greedy forward chaining + A* refinement")
    }
}

impl HeuristicPlanner {
    /// Greedy forward chaining: pick the cheapest capability that satisfies
    /// each open precondition, recursing on its requirements. Detects cycles.
    fn greedy_plan(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
    ) -> Result<ExecutionPlan, PlanningError> {
        let _ = (goal, available);
        todo!("D5: greedy forward chaining phase")
    }

    /// Recursively satisfy an effect by finding a candidate capability,
    /// recursing on its requirements, and appending the resulting step.
    fn satisfy(
        &self,
        effect: &Effect,
        available: &[SemanticCapability],
        steps: &mut Vec<PlannedStep>,
        satisfied: &mut std::collections::HashSet<Effect>,
        visiting: &mut std::collections::HashSet<String>,
    ) -> Result<(), PlanningError> {
        let _ = (effect, available, steps, satisfied, visiting);
        todo!("D5: satisfy a single effect recursively")
    }

    /// A* over the graph to optimize the greedy plan. Explores alternative
    /// orderings and alternative capabilities for each step.
    fn astar_refine(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
        greedy: ExecutionPlan,
    ) -> Result<ExecutionPlan, PlanningError> {
        let _ = (goal, available, greedy);
        todo!("D5: A* refinement phase")
    }

    /// Heuristic estimate to goal: `remaining_goal_effects * min_step_latency`.
    fn heuristic(&self, goal: &[Effect], available: &[SemanticCapability]) -> f64 {
        let _ = (goal, available);
        todo!("D5: A* heuristic function")
    }

    /// The A* objective: weighted sum of latency and cost.
    fn objective(&self, plan: &ExecutionPlan) -> f64 {
        let _ = plan;
        todo!("D5: A* objective function")
    }

    /// Finalize a step list into an [`ExecutionPlan`] by computing totals.
    fn finalize(&self, steps: Vec<PlannedStep>) -> ExecutionPlan {
        let _ = steps;
        todo!("D5: finalize execution plan from steps")
    }
}
