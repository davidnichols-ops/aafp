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

use aafp_identity::AgentId;

use super::capability::{OutputSpec, Requirement, SemanticError};
use super::{CapabilityQuery, SemanticCapability};
use std::collections::{BinaryHeap, HashSet};

/// Lightweight routing metrics used by the planner to prefer healthy
/// providers. This is a local stand-in for the full `RoutingMetrics` from the
/// routing plane (Track T) — it carries only the health score the planner
/// needs for provider selection.
#[derive(Clone, Debug, Default)]
pub struct RoutingMetrics {
    /// Health score in the range 0-100 (higher = healthier).
    pub health_score: u8,
}

impl RoutingMetrics {
    /// Create metrics for a healthy agent (score 100).
    pub fn healthy() -> Self {
        Self { health_score: 100 }
    }

    /// Create metrics for a degraded agent (score 50).
    pub fn degraded() -> Self {
        Self { health_score: 50 }
    }
}

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
///
/// - [`max_steps`](HeuristicPlanner::max_steps): complexity budget.
/// - [`max_cost_micro_usd`](HeuristicPlanner::max_cost_micro_usd): cost budget.
///
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

/// A* search node. Ordering is by `f = g + h` (min-heap).
#[derive(Clone, Debug)]
struct SearchNode {
    /// Steps committed so far.
    steps: Vec<PlannedStep>,
    /// Set of effects currently satisfied (the "state").
    satisfied: HashSet<Effect>,
    /// g: cost so far (weighted latency + cost).
    g: f64,
    /// h: heuristic estimate to goal.
    h: f64,
}

impl PartialEq for SearchNode {
    fn eq(&self, other: &Self) -> bool {
        self.g + self.h == other.g + other.h
    }
}
impl Eq for SearchNode {}
impl Ord for SearchNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap: lower f = higher priority.
        (other.g + other.h)
            .partial_cmp(&(self.g + self.h))
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for SearchNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn output_to_effect(o: &OutputSpec) -> Effect {
    Effect {
        kind: o.kind.clone(),
        attributes: o
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), format!("{:?}", v)))
            .collect(),
    }
}

fn requirement_to_precondition(r: &Requirement) -> Precondition {
    Precondition {
        kind: r.kind.clone(),
        attributes: Vec::new(),
    }
}

fn effect_matches(provided: &Effect, needed: &Effect) -> bool {
    provided.kind == needed.kind
}

fn goal_to_output_effects(goal: &CapabilityQuery, available: &[SemanticCapability]) -> Vec<Effect> {
    // Find capabilities matching the goal query and collect their provides.
    let mut effects = Vec::new();
    for cap in available {
        if cap.name == goal.name && goal.matches(cap) {
            for o in &cap.provides {
                effects.push(output_to_effect(o));
            }
        }
    }
    if effects.is_empty() {
        // Fallback: use the goal name as the effect kind.
        effects.push(Effect {
            kind: goal.name.clone(),
            attributes: Vec::new(),
        });
    }
    effects
}

#[async_trait::async_trait]
impl CapabilityPlanner for HeuristicPlanner {
    async fn plan(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
    ) -> Result<ExecutionPlan, PlanningError> {
        // Phase 1: greedy forward chaining to find a feasible plan.
        let greedy = self.greedy_plan(goal, available)?;
        if greedy.steps.len() > self.max_steps {
            return Err(PlanningError::ComplexityExceeded {
                max_steps: self.max_steps,
            });
        }
        if greedy.estimated_total_cost_micro_usd > self.max_cost_micro_usd {
            return Err(PlanningError::CostExceeded {
                budget_micro_usd: self.max_cost_micro_usd,
            });
        }

        // Phase 2: A* refinement to optimize latency/cost.
        let refined = self.astar_refine(goal, available, greedy)?;
        Ok(refined)
    }
}

impl HeuristicPlanner {
    /// Greedy: pick the cheapest capability that satisfies each open
    /// precondition, recursing on its requirements. Detects cycles.
    fn greedy_plan(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
    ) -> Result<ExecutionPlan, PlanningError> {
        let mut steps = Vec::new();
        let mut satisfied: HashSet<Effect> = HashSet::new();
        let mut visiting: HashSet<String> = HashSet::new();
        let goal_effects = goal_to_output_effects(goal, available);

        for eff in &goal_effects {
            let pre = Precondition {
                kind: eff.kind.clone(),
                attributes: eff.attributes.clone(),
            };
            self.satisfy(&pre, available, &mut steps, &mut satisfied, &mut visiting)?;
        }
        Ok(self.finalize(steps))
    }

    fn satisfy(
        &self,
        needed: &Precondition,
        available: &[SemanticCapability],
        steps: &mut Vec<PlannedStep>,
        satisfied: &mut HashSet<Effect>,
        visiting: &mut HashSet<String>,
    ) -> Result<(), PlanningError> {
        // Convert the precondition to an effect for matching.
        let needed_effect = Effect {
            kind: needed.kind.clone(),
            attributes: needed.attributes.clone(),
        };
        if satisfied.contains(&needed_effect) {
            return Ok(());
        }
        // Find candidates whose provides match this effect.
        let candidates: Vec<_> = available
            .iter()
            .filter(|c| {
                c.provides
                    .iter()
                    .any(|o| effect_matches(&output_to_effect(o), &needed_effect))
            })
            .collect();
        let cap = candidates
            .into_iter()
            .min_by_key(|c| c.cost.per_invocation_micro_usd)
            .ok_or_else(|| PlanningError::MissingCapability(needed.kind.clone()))?;

        if visiting.contains(&cap.name) {
            return Err(PlanningError::CycleDetected {
                node: cap.name.clone(),
            });
        }
        visiting.insert(cap.name.clone());

        // Recurse on requirements (preconditions).
        let mut depends = Vec::new();
        for req in &cap.requirements {
            let pre = requirement_to_precondition(req);
            let prev_len = steps.len();
            self.satisfy(&pre, available, steps, satisfied, visiting)?;
            // Depend on the last step(s) added for this requirement.
            for i in prev_len..steps.len() {
                depends.push(i);
            }
        }

        let idx = steps.len();
        let step = PlannedStep {
            index: idx,
            capability: cap.clone(),
            agent_id: AgentId::default(),
            depends_on: depends,
            preconditions: cap
                .requirements
                .iter()
                .map(requirement_to_precondition)
                .collect(),
            effects: cap.provides.iter().map(output_to_effect).collect(),
            estimated_latency_ms: cap.performance.avg_latency_ms,
            estimated_cost_micro_usd: cap.cost.per_invocation_micro_usd,
        };
        for e in &step.effects {
            satisfied.insert(e.clone());
        }
        steps.push(step);
        visiting.remove(&cap.name);
        Ok(())
    }

    /// A* over the graph to optimize the greedy plan. Explores alternative
    /// orderings and alternative capabilities for each step.
    fn astar_refine(
        &self,
        goal: &CapabilityQuery,
        available: &[SemanticCapability],
        greedy: ExecutionPlan,
    ) -> Result<ExecutionPlan, PlanningError> {
        let goal_effects = goal_to_output_effects(goal, available);
        let mut open: BinaryHeap<SearchNode> = BinaryHeap::new();
        let mut best = greedy;
        open.push(SearchNode {
            steps: Vec::new(),
            satisfied: HashSet::new(),
            g: 0.0,
            h: self.heuristic(&goal_effects, available),
        });

        let mut iterations = 0;
        while let Some(node) = open.pop() {
            iterations += 1;
            if iterations > 10_000 {
                break;
            }
            if node.steps.len() > self.max_steps {
                continue;
            }
            if goal_effects.iter().all(|e| node.satisfied.contains(e)) {
                // Verify all preconditions are satisfied (not just goal effects).
                let all_preconds_met: bool = node.steps.iter().all(|s| {
                    s.preconditions.iter().all(|p| {
                        node.satisfied.contains(&Effect {
                            kind: p.kind.clone(),
                            attributes: p.attributes.clone(),
                        })
                    })
                });
                if all_preconds_met {
                    let plan = self.finalize(node.steps);
                    if self.objective(&plan) < self.objective(&best) {
                        best = plan;
                    }
                }
                continue;
            }
            // Collect all unsatisfied effects (goal effects + preconditions of existing steps).
            let mut open_effects: Vec<Effect> = goal_effects
                .iter()
                .filter(|e| !node.satisfied.contains(e))
                .cloned()
                .collect();
            for s in &node.steps {
                for p in &s.preconditions {
                    let eff = Effect {
                        kind: p.kind.clone(),
                        attributes: p.attributes.clone(),
                    };
                    if !node.satisfied.contains(&eff) {
                        open_effects.push(eff);
                    }
                }
            }
            // Expand: for each open effect, try each candidate capability.
            for eff in &open_effects {
                for cap in available.iter().filter(|c| {
                    c.provides
                        .iter()
                        .any(|o| effect_matches(&output_to_effect(o), eff))
                }) {
                    let mut new_steps = node.steps.clone();
                    let mut new_sat = node.satisfied.clone();
                    let idx = new_steps.len();
                    for e in cap.provides.iter().map(output_to_effect) {
                        new_sat.insert(e);
                    }
                    new_steps.push(PlannedStep {
                        index: idx,
                        capability: cap.clone(),
                        agent_id: AgentId::default(),
                        depends_on: (0..idx).collect(),
                        preconditions: cap
                            .requirements
                            .iter()
                            .map(requirement_to_precondition)
                            .collect(),
                        effects: cap.provides.iter().map(output_to_effect).collect(),
                        estimated_latency_ms: cap.performance.avg_latency_ms,
                        estimated_cost_micro_usd: cap.cost.per_invocation_micro_usd,
                    });
                    let g = self.objective(&self.finalize(new_steps.clone()));
                    open.push(SearchNode {
                        steps: new_steps,
                        satisfied: new_sat,
                        g,
                        h: self.heuristic(&goal_effects, available),
                    });
                }
            }
        }
        Ok(best)
    }

    fn heuristic(&self, goal: &[Effect], available: &[SemanticCapability]) -> f64 {
        let min_lat = available
            .iter()
            .map(|c| c.performance.avg_latency_ms)
            .fold(f64::INFINITY, f64::min);
        goal.len() as f64 * min_lat
    }

    fn objective(&self, plan: &ExecutionPlan) -> f64 {
        let lat = plan.estimated_total_latency_ms;
        let cost = plan.estimated_total_cost_micro_usd as f64;
        self.latency_weight * lat + (1.0 - self.latency_weight) * cost
    }

    fn finalize(&self, steps: Vec<PlannedStep>) -> ExecutionPlan {
        let total_lat: f64 = steps.iter().map(|s| s.estimated_latency_ms).sum();
        let total_cost: u64 = steps.iter().map(|s| s.estimated_cost_micro_usd).sum();
        let agent_count = steps
            .iter()
            .map(|s| &s.agent_id)
            .collect::<HashSet<_>>()
            .len();
        ExecutionPlan {
            steps,
            estimated_total_latency_ms: total_lat,
            estimated_total_cost_micro_usd: total_cost,
            agent_count,
            complete: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::capability::*;
    use crate::semantic::edge::{CapabilityEdge, EdgeType};
    use std::collections::HashMap;

    fn make_cap(
        name: &str,
        cost: u64,
        lat: f64,
        trust: u8,
        provides: Vec<&str>,
        requires: Vec<&str>,
    ) -> SemanticCapability {
        SemanticCapability {
            name: name.into(),
            category: CapabilityCategory::Custom(name.into()),
            attributes: CapabilityAttributes::default(),
            performance: PerformanceProfile {
                avg_latency_ms: lat,
                p99_latency_ms: lat * 2.0,
                throughput_rps: 100.0,
                max_batch_size: Some(1),
            },
            quality: QualityMetrics {
                trust_score: trust,
                accuracy: None,
                uptime_pct: 99.0,
                success_count: 0,
            },
            cost: CostModel {
                per_invocation_micro_usd: cost,
                per_token_micro_usd: None,
                has_free_tier: true,
            },
            dependencies: vec![],
            version: SemanticVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            geo: None,
            requirements: requires
                .iter()
                .map(|r| Requirement {
                    kind: r.to_string(),
                    optional: false,
                })
                .collect(),
            provides: provides
                .iter()
                .map(|p| OutputSpec {
                    kind: p.to_string(),
                    attributes: HashMap::new(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn plan_single_capability() {
        let caps = vec![make_cap(
            "search",
            500,
            800.0,
            90,
            vec!["search-results"],
            vec![],
        )];
        let planner = HeuristicPlanner::default();
        let goal = CapabilityQuery::new("search").build();
        let plan = planner.plan(&goal, &caps).await.unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert!(plan.complete);
    }

    #[tokio::test]
    async fn plan_with_requirement() {
        let caps = vec![
            make_cap("web-browse", 2000, 2000.0, 85, vec!["web-content"], vec![]),
            make_cap(
                "crawl",
                100,
                5000.0,
                75,
                vec!["crawled-pages"],
                vec!["web-content"],
            ),
        ];
        let planner = HeuristicPlanner::default();
        let goal = CapabilityQuery::new("crawl").build();
        let plan = planner.plan(&goal, &caps).await.unwrap();
        assert!(plan.steps.iter().any(|s| s.capability.name == "web-browse"));
        assert!(plan.steps.iter().any(|s| s.capability.name == "crawl"));
    }

    #[tokio::test]
    async fn plan_missing_capability() {
        let caps = vec![make_cap(
            "crawl",
            100,
            5000.0,
            75,
            vec!["crawled-pages"],
            vec!["web-content"],
        )];
        let planner = HeuristicPlanner::default();
        let goal = CapabilityQuery::new("crawl").build();
        let result = planner.plan(&goal, &caps).await;
        assert!(matches!(result, Err(PlanningError::MissingCapability(_))));
    }

    #[tokio::test]
    async fn plan_cycle_detected() {
        let mut cap_a = make_cap("a", 100, 10.0, 90, vec!["a-out"], vec!["b-out"]);
        let cap_b = make_cap("b", 100, 10.0, 90, vec!["b-out"], vec!["a-out"]);
        cap_a
            .dependencies
            .push(CapabilityEdge::new("b", EdgeType::Requires));
        let caps = vec![cap_a, cap_b];
        let planner = HeuristicPlanner::default();
        let goal = CapabilityQuery::new("a").build();
        let result = planner.plan(&goal, &caps).await;
        assert!(matches!(result, Err(PlanningError::CycleDetected { .. })));
    }

    #[tokio::test]
    async fn plan_complexity_budget_exceeded() {
        let caps = vec![
            make_cap("web-browse", 2000, 2000.0, 85, vec!["web-content"], vec![]),
            make_cap(
                "crawl",
                100,
                5000.0,
                75,
                vec!["crawled-pages"],
                vec!["web-content"],
            ),
        ];
        let planner = HeuristicPlanner {
            max_steps: 1,
            ..Default::default()
        };
        let goal = CapabilityQuery::new("crawl").build();
        let result = planner.plan(&goal, &caps).await;
        assert!(matches!(
            result,
            Err(PlanningError::ComplexityExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn plan_cost_budget_exceeded() {
        let caps = vec![make_cap(
            "expensive",
            2_000_000,
            100.0,
            90,
            vec!["result"],
            vec![],
        )];
        let planner = HeuristicPlanner {
            max_cost_micro_usd: 500,
            ..Default::default()
        };
        let goal = CapabilityQuery::new("expensive").build();
        let result = planner.plan(&goal, &caps).await;
        assert!(matches!(result, Err(PlanningError::CostExceeded { .. })));
    }

    #[tokio::test]
    async fn plan_with_metrics_falls_back() {
        let caps = vec![make_cap(
            "search",
            500,
            800.0,
            90,
            vec!["search-results"],
            vec![],
        )];
        let planner = HeuristicPlanner::default();
        let metrics = vec![(AgentId::default(), RoutingMetrics::healthy())];
        let goal = CapabilityQuery::new("search").build();
        let plan = planner
            .plan_with_metrics(&goal, &caps, &metrics)
            .await
            .unwrap();
        assert!(plan.complete);
    }

    #[tokio::test]
    async fn plan_picks_cheapest_for_requirement() {
        let caps = vec![
            make_cap("cheap-browse", 100, 2000.0, 85, vec!["web-content"], vec![]),
            make_cap(
                "expensive-browse",
                5000,
                2000.0,
                85,
                vec!["web-content"],
                vec![],
            ),
            make_cap(
                "crawl",
                100,
                5000.0,
                75,
                vec!["crawled-pages"],
                vec!["web-content"],
            ),
        ];
        let planner = HeuristicPlanner::default();
        let goal = CapabilityQuery::new("crawl").build();
        let plan = planner.plan(&goal, &caps).await.unwrap();
        // The greedy phase picks cheapest for the web-content requirement.
        let browse = plan
            .steps
            .iter()
            .find(|s| s.capability.name.contains("browse"));
        assert!(browse.is_some());
        assert_eq!(browse.unwrap().capability.name, "cheap-browse");
    }
}
