//! Composite scoring function for the adaptive routing plane.
//!
//! Combines static scores (capability match quality) with dynamic
//! per-peer scores (latency, success, load, availability, cost) into
//! a single ranking value used by the selection strategies.
//!
//! This is a pre-build scaffolding stub. Function bodies are `todo!()`
//! and will be implemented in the T1-T2 build phase.

use crate::routing::circuit::CircuitState;
use crate::routing::metrics::{HealthProbeResult, PeerMetrics, PeerMetricsRegistry};
use aafp_identity::AgentId;
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────
// DynamicScoreConfig
// ──────────────────────────────────────────────────────────────────────

/// Configuration for dynamic scoring weights.
///
/// The five weights control the relative influence of each sub-score
/// in the composite dynamic score. They need not sum to 1.0 — the
/// final score is normalized by the total weight.
#[derive(Clone, Debug)]
pub struct DynamicScoreConfig {
    /// Weight for the latency sub-score.
    pub weight_latency: f64,
    /// Weight for the success-rate sub-score.
    pub weight_success: f64,
    /// Weight for the load (in-flight + queue) sub-score.
    pub weight_load: f64,
    /// Weight for the availability (health probe) sub-score.
    pub weight_availability: f64,
    /// Weight for the cost sub-score.
    pub weight_cost: f64,
    /// Reference latency (ms) for normalization. Latency at or below
    /// this scores 1.0; latency at 5x scores ~0.
    pub latency_ref_ms: f64,
    /// Cost reference (micro-USD) for normalization.
    pub cost_ref_micro_usd: f64,
}

impl Default for DynamicScoreConfig {
    fn default() -> Self {
        Self {
            weight_latency: 0.35,
            weight_success: 0.30,
            weight_load: 0.15,
            weight_availability: 0.15,
            weight_cost: 0.05,
            latency_ref_ms: 50.0,
            cost_ref_micro_usd: 100,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// ScoredCandidate
// ──────────────────────────────────────────────────────────────────────

/// A candidate agent with its computed composite score.
#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    pub agent_id: AgentId,
    pub total_score: f64,
    pub static_score: f64,
    pub dynamic_score: f64,
}

// ──────────────────────────────────────────────────────────────────────
// dynamic_score
// ──────────────────────────────────────────────────────────────────────

/// Compute the dynamic sub-score for a single peer.
///
/// Rules (from ADAPTIVE_ROUTING_PLANE.md §4.2):
/// - Circuit Open → return 0.0 (hard gate).
/// - Circuit HalfOpen → return 0.1 (allow trial but deprioritize).
/// - Stale (>staleness_threshold since last_seen) → return 0.5
///   (neutral default, don't starve unknown peers).
/// - Latency score: `(1.0 - (latency / (5.0 * latency_ref_ms))).max(0.0)`.
///   If EWMA not initialized, use 0.5.
/// - Success score: directly from `success_window.success_rate()`.
/// - Load score: `1.0 / (1.0 + in_flight + queue_depth)`.
/// - Availability score: Healthy=1.0, Degraded=0.5, Unhealthy=0.1,
///   Unreachable=0.0, None=0.7.
/// - Cost score: `(1.0 - (cost / (5.0 * cost_ref))).max(0.0)`.
///   If no cost data, use 0.8.
/// - Weighted sum divided by total weight, clamped to [0.0, 1.0].
pub fn dynamic_score(
    metrics: &PeerMetrics,
    config: &DynamicScoreConfig,
    now: Instant,
    staleness_threshold: Duration,
) -> f64 {
    todo!()
}

// ──────────────────────────────────────────────────────────────────────
// score_candidates
// ──────────────────────────────────────────────────────────────────────

/// Filter candidates by circuit state and compute composite scores.
///
/// Returns `(AgentId, total_score)` pairs. Circuit-Open peers are
/// hard-skipped (excluded entirely). HalfOpen peers are included
/// with a heavy penalty so the trial request can go through if no
/// better option exists.
///
/// The total score is:
/// `static_weight * static_score + dynamic_weight * dynamic_score`.
pub fn score_candidates(
    candidates: &[aafp_identity::agent_record::AgentRecord],
    registry: &PeerMetricsRegistry,
    static_scores: &[f64],
    dyn_config: &DynamicScoreConfig,
    static_weight: f64,
    dynamic_weight: f64,
) -> Vec<(AgentId, f64)> {
    todo!()
}
