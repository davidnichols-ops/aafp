//! Per-peer dynamic metrics: EWMA latency, rolling success window,
//! circuit breaker state, and a thread-safe `PeerMetricsRegistry`.
//!
//! This is a pre-build scaffolding stub. Method bodies are `todo!()`
//! and will be implemented in the T1-T2 build phase.

use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────
// Ewma
// ──────────────────────────────────────────────────────────────────────

/// EWMA (exponentially weighted moving average) estimator.
///
/// `alpha` controls how quickly the estimate adapts to new samples.
/// A common choice is `alpha = 2 / (N + 1)` where N is the effective
/// window size in samples. For N=20, alpha ≈ 0.095.
#[derive(Clone, Debug)]
pub struct Ewma {
    value: f64,
    alpha: f64,
    initialized: bool,
}

impl Ewma {
    /// Create a new EWMA with the given alpha (must be in [0.0, 1.0]).
    pub fn new(alpha: f64) -> Self {
        todo!()
    }

    /// Update with a new sample and return the updated estimate.
    /// The first sample sets the value directly (no blending).
    pub fn update(&mut self, sample: f64) -> f64 {
        todo!()
    }

    /// Current EWMA estimate. Returns 0.0 if never updated.
    pub fn value(&self) -> f64 {
        todo!()
    }

    /// Whether at least one sample has been recorded.
    pub fn is_initialized(&self) -> bool {
        todo!()
    }

    /// Reset to uninitialized state (e.g., after long disconnection).
    pub fn reset(&mut self) {
        todo!()
    }
}

// ──────────────────────────────────────────────────────────────────────
// RollingWindow
// ──────────────────────────────────────────────────────────────────────

/// A fixed-capacity rolling window for success/failure tracking.
///
/// Uses a bitset: 1 = success, 0 = failure. Capacity is at most 64
/// (one u64). Default capacity: 64 samples. Wraps around via modulo.
#[derive(Clone, Debug)]
pub struct RollingWindow {
    bits: u64,
    index: u8,
    capacity: u8,
    count: u8,
}

impl RollingWindow {
    /// Create a new window with the given capacity (must be ≤ 64).
    pub fn new(capacity: u8) -> Self {
        todo!()
    }

    /// Record a success (true) or failure (false) in the window.
    pub fn record(&mut self, success: bool) {
        todo!()
    }

    /// Success rate over the window in [0.0, 1.0].
    /// Returns 1.0 for an empty window (optimistic default).
    pub fn success_rate(&self) -> f64 {
        todo!()
    }

    /// Number of samples currently in the window.
    pub fn sample_count(&self) -> u8 {
        todo!()
    }

    /// Reset the window (clear all samples).
    pub fn reset(&mut self) {
        todo!()
    }
}

// ──────────────────────────────────────────────────────────────────────
// CircuitState
// ──────────────────────────────────────────────────────────────────────

/// Circuit breaker state machine.
///
/// Transitions:
/// - Closed → Open: when consecutive_failures >= failure_threshold
/// - Open → HalfOpen: when cooldown elapses (checked in check_circuit)
/// - HalfOpen → Closed: when a trial request succeeds
/// - HalfOpen → Open: when a trial request fails
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation. Requests flow.
    Closed,
    /// Tripped. Requests are short-circuited (rejected immediately).
    Open,
    /// Trial period after cooldown. One request is allowed through;
    /// success → Closed, failure → Open.
    HalfOpen,
}

impl CircuitState {
    /// Whether requests should be allowed through (not short-circuited).
    pub fn allows_request(&self) -> bool {
        matches!(self, CircuitState::Closed | CircuitState::HalfOpen)
    }
}

impl Default for CircuitState {
    fn default() -> Self {
        CircuitState::Closed
    }
}

// ──────────────────────────────────────────────────────────────────────
// HealthProbeResult
// ──────────────────────────────────────────────────────────────────────

/// Result of an active health probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthProbeResult {
    Healthy,
    Degraded,
    Unhealthy,
    Unreachable,
}

// ──────────────────────────────────────────────────────────────────────
// PeerMetrics
// ──────────────────────────────────────────────────────────────────────

/// Dynamic metrics tracked per remote agent (peer).
#[derive(Clone, Debug)]
pub struct PeerMetrics {
    pub agent_id: AgentId,

    // ── Latency ──────────────────────────────────────────────
    /// EWMA of round-trip latency in milliseconds.
    pub latency_ewma_ms: Ewma,
    /// Minimum observed latency (cold-cache lower bound).
    pub latency_min_ms: f64,

    // ── Success / Failure ────────────────────────────────────
    /// Rolling success/failure window.
    pub success_window: RollingWindow,
    /// Consecutive failures (for circuit breaker).
    pub consecutive_failures: u32,
    /// Consecutive successes (for half-open recovery).
    pub consecutive_successes: u32,

    // ── Load ─────────────────────────────────────────────────
    /// Active in-flight requests to this peer.
    pub in_flight: u32,
    /// Last reported queue depth (from active probe or gossip).
    pub queue_depth: Option<u32>,
    /// Last reported active connections (from aafp.metrics RPC).
    pub reported_active_conns: Option<u64>,

    // ── Cost ─────────────────────────────────────────────────
    /// Last reported cost per invocation in micro-USD.
    pub cost_micro_usd: Option<u64>,

    // ── Availability ─────────────────────────────────────────
    /// Last time we successfully communicated with this peer.
    pub last_seen: Instant,
    /// Last active health-probe result.
    pub last_health: Option<HealthProbeResult>,

    // ── Circuit Breaker ──────────────────────────────────────
    pub circuit: CircuitState,
}

// ──────────────────────────────────────────────────────────────────────
// PeerMetricsRegistry
// ──────────────────────────────────────────────────────────────────────

/// Thread-safe registry of per-peer metrics.
pub struct PeerMetricsRegistry {
    peers: Mutex<HashMap<AgentId, PeerMetrics>>,
    /// Config: EWMA alpha for latency.
    pub latency_alpha: f64,
    /// Config: rolling window capacity.
    pub window_capacity: u8,
    /// Config: consecutive failures to trip the circuit.
    pub failure_threshold: u32,
    /// Config: cooldown before half-open attempt.
    pub cooldown: Duration,
    /// Config: how long before metrics are considered "stale".
    pub staleness_threshold: Duration,
}

impl PeerMetricsRegistry {
    /// Create a new registry with defaults:
    /// alpha=0.1, capacity=64, threshold=5, cooldown=10s, staleness=60s.
    pub fn new() -> Self {
        todo!()
    }

    /// Returns a clone of existing metrics for `agent_id`, or creates
    /// a fresh entry with default values.
    pub fn get_or_create(&self, agent_id: &AgentId) -> PeerMetrics {
        todo!()
    }

    /// Record the outcome of a call to `agent_id`.
    ///
    /// Updates EWMA latency, min latency, success window, last_seen,
    /// and drives circuit breaker transitions:
    /// - success resets consecutive_failures, increments consecutive_successes;
    ///   HalfOpen → Closed on success.
    /// - failure increments consecutive_failures; Open when threshold reached.
    pub fn record_outcome(&self, agent_id: &AgentId, latency_ms: f64, success: bool) {
        todo!()
    }

    /// Saturating increment of in-flight count for `agent_id`.
    pub fn inflight_inc(&self, agent_id: &AgentId) {
        todo!()
    }

    /// Saturating decrement of in-flight count for `agent_id`.
    pub fn inflight_dec(&self, agent_id: &AgentId) {
        todo!()
    }

    /// Check and advance the circuit breaker for `agent_id`.
    ///
    /// If Open and cooldown has elapsed, transitions to HalfOpen.
    /// Returns the current state. Unknown peers return `Closed`
    /// (optimistic).
    pub fn check_circuit(&self, agent_id: &AgentId) -> CircuitState {
        todo!()
    }

    /// Whether metrics for `agent_id` are stale (last_seen elapsed
    /// >= staleness_threshold). Returns `true` for unknown peers.
    pub fn is_stale(&self, agent_id: &AgentId) -> bool {
        todo!()
    }

    /// Clone all peer metrics for observability/debugging.
    pub fn snapshot_all(&self) -> Vec<PeerMetrics> {
        todo!()
    }
}
