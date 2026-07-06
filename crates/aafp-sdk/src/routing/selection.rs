//! Selection strategies for the adaptive routing plane.
//!
//! Given a set of scored candidates, pick one according to the
//! configured strategy. The default is Power-of-Two Choices (P2C),
//! which provides good load distribution with minimal overhead.
//!
//! This is a pre-build scaffolding stub. Function bodies are `todo!()`
//! and will be implemented in the T1-T2 build phase.

use aafp_identity::AgentId;
use rand::Rng;

// ──────────────────────────────────────────────────────────────────────
// SelectionCandidate
// ──────────────────────────────────────────────────────────────────────

/// A scored candidate ready for selection.
#[derive(Clone, Debug)]
pub struct SelectionCandidate {
    pub agent_id: AgentId,
    pub score: f64,
    pub in_flight: u32,
    pub latency_ewma_ms: f64,
    pub latency_initialized: bool,
    pub success_rate: f64,
}

// ──────────────────────────────────────────────────────────────────────
// RoutingStrategy
// ──────────────────────────────────────────────────────────────────────

/// Routing strategy selector.
///
/// Each variant dispatches to a corresponding `select_*` function via
/// the `select()` method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Power-of-two choices (default). Best general-purpose strategy.
    P2C,
    /// Weighted random by score.
    WeightedRandom,
    /// Least in-flight connections.
    LeastConnections,
    /// Lowest EWMA latency.
    LowestLatency,
    /// Epsilon-greedy exploration. The `epsilon` value (0.0–1.0)
    /// controls the probability of a random exploration step.
    EpsilonGreedy { epsilon: f64 },
}

impl RoutingStrategy {
    /// Dispatch to the selection function for this strategy.
    pub fn select(
        &self,
        candidates: &[SelectionCandidate],
        rng: &mut impl Rng,
    ) -> Option<AgentId> {
        match self {
            RoutingStrategy::P2C => select_power_of_two(candidates, rng),
            RoutingStrategy::WeightedRandom => select_weighted_random(candidates, rng),
            RoutingStrategy::LeastConnections => select_least_connections(candidates),
            RoutingStrategy::LowestLatency => select_lowest_latency(candidates),
            RoutingStrategy::EpsilonGreedy { epsilon } => {
                select_epsilon_greedy(candidates, *epsilon, rng)
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Strategy 1: Power-of-Two Choices (P2C) — Default
// ──────────────────────────────────────────────────────────────────────

/// Pick two candidates at random, return the one with the higher score.
/// With <4 candidates, falls back to weighted random.
pub fn select_power_of_two(
    candidates: &[SelectionCandidate],
    rng: &mut impl Rng,
) -> Option<AgentId> {
    todo!()
}

// ──────────────────────────────────────────────────────────────────────
// Strategy 2: Weighted Random
// ──────────────────────────────────────────────────────────────────────

/// Pick a candidate with probability proportional to its score.
/// If all scores are zero, falls back to uniform random.
pub fn select_weighted_random(
    candidates: &[SelectionCandidate],
    rng: &mut impl Rng,
) -> Option<AgentId> {
    todo!()
}

// ──────────────────────────────────────────────────────────────────────
// Strategy 3: Least-Connections
// ──────────────────────────────────────────────────────────────────────

/// Pick the candidate with the lowest `in_flight` count.
/// Ties broken by score (higher wins).
pub fn select_least_connections(candidates: &[SelectionCandidate]) -> Option<AgentId> {
    todo!()
}

// ──────────────────────────────────────────────────────────────────────
// Strategy 4: Lowest-Latency (EWMA)
// ──────────────────────────────────────────────────────────────────────

/// Pick the candidate with the lowest EWMA latency.
/// Only considers candidates with initialized latency.
/// Ties broken by success rate (higher wins).
/// Falls back to highest score if no candidate has initialized latency.
pub fn select_lowest_latency(candidates: &[SelectionCandidate]) -> Option<AgentId> {
    todo!()
}

// ──────────────────────────────────────────────────────────────────────
// Strategy 5: Epsilon-Greedy
// ──────────────────────────────────────────────────────────────────────

/// With probability `epsilon`, pick uniformly at random (explore);
/// otherwise pick the highest score (exploit).
pub fn select_epsilon_greedy(
    candidates: &[SelectionCandidate],
    epsilon: f64,
    rng: &mut impl Rng,
) -> Option<AgentId> {
    todo!()
}
