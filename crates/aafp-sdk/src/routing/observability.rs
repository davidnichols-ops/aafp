//! Routing observability: decision logging and Prometheus metrics (Track T5).
//!
//! Every routing decision produces a [`RoutingDecision`] record, stored in a
//! thread-safe ring buffer ([`DecisionLog`], last 1024 by default) and emitted
//! to the `tracing` span. [`RoutingMetrics`] exposes 10 Prometheus counters /
//! histograms / gauges for the routing plane.
//!
//! This is a pre-build scaffold: `record_decision()` and metric registration
//! are `todo!()` stubs to be filled in during T5 implementation.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use aafp_identity::AgentId;

use crate::routing::config::RoutingStrategy;

/// A routing decision record, for logging and debugging.
#[derive(Clone, Debug)]
pub struct RoutingDecision {
    /// Capability tag that was discovered (e.g. `"ocr"`).
    pub capability: String,
    /// Human-readable query digest.
    pub query_summary: String,
    /// Total candidates considered before filtering.
    pub candidates_total: usize,
    /// Candidates surviving the static hard-constraint filter.
    pub candidates_passed_static: usize,
    /// Candidates surviving the dynamic hard-constraint filter.
    pub candidates_passed_dynamic: usize,
    /// Candidates eliminated because their circuit was open.
    pub candidates_filtered_circuit: usize,
    /// The agent ultimately selected, if any.
    pub selected: Option<AgentId>,
    pub selected_static_score: Option<f64>,
    pub selected_dynamic_score: Option<f64>,
    pub selected_total_score: Option<f64>,
    pub selected_latency_ewma_ms: Option<f64>,
    pub selected_success_rate: Option<f64>,
    /// Strategy used for this decision.
    pub strategy: RoutingStrategy,
    /// Whether this call was hedged.
    pub hedged: bool,
    /// Time spent making the routing decision, in microseconds.
    pub elapsed_us: u64,
}

/// Thread-safe ring buffer of recent routing decisions.
pub struct DecisionLog {
    buffer: Mutex<VecDeque<RoutingDecision>>,
    capacity: usize,
}

impl DecisionLog {
    /// Create a new ring buffer holding the last `capacity` decisions,
    /// wrapped in an [`Arc`] for shared ownership across the routing plane.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        })
    }

    /// Append a decision to the ring buffer, evicting the oldest entry when
    /// full, and emit a structured `tracing` event.
    pub fn record(&self, decision: RoutingDecision) {
        // TODO(T5): implement per AR_T5_T7_INTEGRATION_API.md §6.1.
        //   - lock buffer, pop_front if at capacity, push_back
        //   - emit tracing::debug!(capability, selected, score, "routing decision")
        let _ = decision;
        todo!("DecisionLog::record: implement ring-buffer append + tracing emit (§6.1)")
    }

    /// Return a snapshot of the buffered decisions in insertion order.
    pub fn snapshot(&self) -> Vec<RoutingDecision> {
        // TODO(T5): implement — lock and clone.
        todo!("DecisionLog::snapshot: implement buffered-decision snapshot (§6.1)")
    }
}

/// Prometheus metrics for the routing plane (10 metrics).
///
/// Counters:
///   - `aafp_routing_decisions_total`
///   - `aafp_routing_circuit_open_total`
///   - `aafp_routing_hedge_total`
///   - `aafp_routing_hedge_won_total`
///   - `aafp_routing_no_viable_total`
/// Histogram:
///   - `aafp_routing_decision_us`
/// Gauges (label: `agent_id`):
///   - `aafp_peer_latency_ewma_ms`
///   - `aafp_peer_success_rate`
///   - `aafp_peer_in_flight`
///   - `aafp_peer_circuit_state` (0=closed, 1=open, 2=half)
pub struct RoutingMetrics {
    // TODO(T5): replace placeholders with prometheus::{IntCounter, Histogram, GaugeVec}
    // once the prometheus dependency is wired in.
    pub decisions_total: (),
    pub circuit_open_total: (),
    pub hedge_total: (),
    pub hedge_won_total: (),
    pub no_viable_candidate_total: (),
    pub decision_latency_us: (),
    pub peer_latency_ewma_ms: (),
    pub peer_success_rate: (),
    pub peer_in_flight: (),
    pub peer_circuit_state: (),
}

impl RoutingMetrics {
    /// Register all routing metrics on the given Prometheus registry.
    pub fn register(_registry: &()) -> Result<Self, ()> {
        // TODO(T5): implement per AR_T5_T7_INTEGRATION_API.md §6.2.
        //   Construct IntCounter/Histogram/GaugeVec instances and register
        //   each on the provided prometheus::Registry.
        todo!("RoutingMetrics::register: implement Prometheus metric registration (§6.2)")
    }
}

/// Record a routing decision: update counters/histograms and append to the
/// decision log. This is the single observability hook invoked on every
/// `discover().call()`.
pub fn record_decision(
    _metrics: &RoutingMetrics,
    _log: &DecisionLog,
    _decision: RoutingDecision,
) {
    // TODO(T5): implement per AR_T5_T7_INTEGRATION_API.md §6.
    //   - increment decisions_total
    //   - observe decision_latency_us
    //   - increment circuit_open_total / no_viable_candidate_total as appropriate
    //   - log.record(decision)
    todo!("record_decision: wire metrics + decision log (§6)")
}
