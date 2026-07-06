//! Track U integration: combined static + dynamic scoring and the
//! three-stage routing pipeline (Track T6).
//!
//! This is a pre-build scaffold: function bodies are `todo!()` stubs to be
//! filled in during T6 implementation. The signatures track
//! `AR_T5_T7_INTEGRATION_API.md` §1 and §3.

use std::time::{Duration, Instant};

use aafp_discovery::semantic::{CapabilityQuery, SemanticCapability};
use aafp_identity::AgentId;

use crate::routing::config::RoutingConfig;
use crate::routing::metrics::{CircuitState, PeerMetrics, PeerMetricsRegistry};
use crate::routing::scoring::{dynamic_score, DynamicScoreConfig};

/// A single scored candidate, carrying both sub-scores for observability.
#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    pub agent_id: AgentId,
    pub static_score: f64,
    pub dynamic_score: f64,
    pub total_score: f64,
    pub circuit: CircuitState,
}

/// Fuse static (Track U) and dynamic (Track T) scores for one candidate.
///
/// Pre-conditions:
/// - `static_score` is already computed by `CapabilityQuery::match_score()`.
/// - The candidate has already passed all hard-constraint filters (see
///   [`passes_static_constraints`] / [`passes_dynamic_constraints`]).
/// - The caller holds no lock on `registry`; this function acquires it
///   internally where needed.
///
/// `total_score = w_static * static_score + w_dynamic * dynamic_score`,
/// clamped to `[0, 1]`.
pub fn score_candidate(
    capability: &SemanticCapability,
    metrics: &PeerMetrics,
    query: &CapabilityQuery,
    dyn_config: &DynamicScoreConfig,
    static_weight: f64,
    dynamic_weight: f64,
    now: Instant,
    staleness_threshold: Duration,
) -> ScoredCandidate {
    let static_score = query.match_score(capability); // [0, 1]
    let dynamic_score_val = dynamic_score(metrics, dyn_config, now, staleness_threshold);

    let total = (static_weight * static_score + dynamic_weight * dynamic_score_val).clamp(0.0, 1.0);

    ScoredCandidate {
        agent_id: metrics.agent_id.clone(),
        static_score,
        dynamic_score: dynamic_score_val,
        total_score: total,
        circuit: metrics.circuit,
    }
}

/// Static hard-constraint filter: returns `true` if the *advertised*
/// [`SemanticCapability`] satisfies all hard constraints in `query`.
///
/// Hard constraints are applied *before* scoring; a candidate that fails is
/// eliminated, not penalized. Examples: `max_avg_latency_ms`,
/// `min_throughput_rps`, `max_per_invocation_micro_usd`, and attribute
/// filters (`Equality`, `In`, `Exists`).
pub fn passes_static_constraints(
    capability: &SemanticCapability,
    query: &CapabilityQuery,
) -> bool {
    // TODO(T6): implement per AR_T5_T7_INTEGRATION_API.md §2.2.
    //   - performance: max_avg_latency_ms, min_throughput_rps
    //   - cost: max_per_invocation_micro_usd
    //   - attribute filters (Equality, In, Exists) are always hard
    let _ = (capability, query);
    todo!("passes_static_constraints: implement static hard-constraint filtering (§2.2)")
}

/// Dynamic hard-constraint filter: reject peers whose *observed* metrics
/// violate the query's hard constraints by a configurable margin.
///
/// The margin is 2x for latency: a peer advertising "<40ms" is pruned only
/// if its observed EWMA exceeds 80ms. This avoids flapping under transient
/// latency spikes while catching sustained degradation. A peer whose
/// circuit is [`CircuitState::Open`] is always rejected. Stale metrics
/// combined with hard performance constraints also trigger pruning.
pub fn passes_dynamic_constraints(
    metrics: &PeerMetrics,
    query: &CapabilityQuery,
    registry: &PeerMetricsRegistry,
) -> bool {
    // TODO(T6): implement per AR_T5_T7_INTEGRATION_API.md §3.2.
    //   - circuit-open is always a hard reject
    //   - observed latency vs. max_avg_latency_ms (2x margin)
    //   - staleness + hard performance constraints → prune
    let _ = (metrics, query, registry);
    todo!("passes_dynamic_constraints: implement dynamic hard-constraint filtering (§3.2)")
}

/// The complete routing pipeline: filter then score.
///
/// Three-stage funnel:
///   1. **Static filter** — advertised capability vs. hard constraints.
///   2. **Dynamic filter** — observed metrics vs. hard constraints.
///   3. **Score** — fuse static + dynamic scores for survivors.
///
/// Returns scored survivors, best-first (descending `total_score`). An empty
/// `Vec` means *no* candidate can meet the query's hard constraints — neither
/// advertised nor observed — and the caller should surface
/// `SdkError::NoViableCandidate` rather than falling back to `candidates[0]`.
pub fn route_candidates(
    candidates: &[(SemanticCapability, AgentId)],
    query: &CapabilityQuery,
    registry: &PeerMetricsRegistry,
    config: &RoutingConfig,
    now: Instant,
) -> Vec<ScoredCandidate> {
    // TODO(T6): implement per AR_T5_T7_INTEGRATION_API.md §3.3.
    //   Stage 1: static hard constraints (advertised data).
    //   Stage 2: dynamic hard constraints (observed data).
    //   Stage 3: score survivors via score_candidate().
    //   Sort descending by total_score.
    let _ = (candidates, query, registry, config, now);
    todo!("route_candidates: implement 3-stage filter-then-score pipeline (§3.3)")
}
