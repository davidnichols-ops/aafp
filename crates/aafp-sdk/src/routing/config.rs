//! Routing configuration and per-call overrides (Track T5).
//!
//! `RoutingConfig` is the single entry point for tuning the adaptive routing
//! plane. `RoutingOptions` is a lightweight per-call overlay that merges into
//! an agent-wide config via [`RoutingOptions::resolve`].
//!
//! This is a pre-build scaffold: method bodies are `todo!()` stubs to be
//! filled in during T5 implementation.

use std::time::Duration;

// NOTE: `DynamicScoreConfig` will live in `crate::routing::scoring` (Track T2).
// It is re-exported here as a placeholder alias so the config struct can be
// defined without pulling in the not-yet-landed scoring module.
use crate::routing::scoring::DynamicScoreConfig;

/// Routing strategy selector.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RoutingStrategy {
    /// Power-of-two-choices (default). Sample two random candidates and pick
    /// the one with the higher combined score.
    PowerOfTwo,
    /// Weighted random sampling by combined score.
    WeightedRandom,
    /// Least-connections: route to the peer with the fewest in-flight calls.
    LeastConnections,
    /// Lowest-latency: route to the peer with the lowest observed EWMA.
    LowestLatency,
    /// Epsilon-greedy: explore with probability `epsilon`, exploit otherwise.
    EpsilonGreedy { epsilon: f64 },
}

/// Circuit breaker configuration.
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures required to trip the circuit open.
    pub failure_threshold: u32,
    /// Open → HalfOpen wait duration.
    pub cooldown: Duration,
    /// Maximum concurrent trial requests permitted in the HalfOpen state.
    pub half_open_max_trials: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown: Duration::from_secs(10),
            half_open_max_trials: 1,
        }
    }
}

/// Hedging policy.
#[derive(Clone, Debug)]
pub struct HedgePolicy {
    /// Whether request hedging is enabled.
    pub enabled: bool,
    /// Delay before sending a secondary (hedge) request.
    pub delay: Duration,
    /// Only hedge if the primary is predicted to miss the deadline.
    pub adaptive: bool,
    /// Upper bound on concurrent duplicate (hedge) requests.
    pub max_concurrent_hedges: u32,
}

impl Default for HedgePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            delay: Duration::from_millis(50),
            adaptive: true,
            max_concurrent_hedges: 4,
        }
    }
}

/// Static/dynamic score fusion weights. `static_weight + dynamic_weight == 1`.
#[derive(Clone, Copy, Debug)]
pub struct Weights {
    pub static_weight: f64,
    pub dynamic_weight: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            static_weight: 0.5,
            dynamic_weight: 0.5,
        }
    }
}

/// Top-level routing configuration.
///
/// This is the single knob callers turn via `ConnectBuilder::with_routing()`.
/// Without it, [`RoutingConfig::default`] applies (P2C strategy, equal
/// static/dynamic weighting, circuit breaker with 5-failure threshold,
/// hedging off).
#[derive(Clone, Debug)]
pub struct RoutingConfig {
    /// Selection strategy applied after scoring.
    pub strategy: RoutingStrategy,
    /// Circuit breaker thresholds and cooldown.
    pub circuit_breaker_config: CircuitBreakerConfig,
    /// Request hedging policy.
    pub hedge_policy: HedgePolicy,
    /// Dynamic (observed-health) scoring configuration (Track T2).
    pub dynamic_score_config: DynamicScoreConfig,
    /// Static/dynamic score fusion weights.
    pub weights: Weights,
    /// Metrics older than this are considered stale and pruned from
    /// dynamic-constraint filtering.
    pub staleness_threshold: Duration,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::PowerOfTwo,
            circuit_breaker_config: CircuitBreakerConfig::default(),
            hedge_policy: HedgePolicy::default(),
            dynamic_score_config: DynamicScoreConfig::default(),
            weights: Weights::default(),
            staleness_threshold: Duration::from_secs(60),
        }
    }
}

/// Per-call routing overrides. Fields that are `None` inherit the
/// agent-wide [`RoutingConfig`] value.
#[derive(Clone, Debug, Default)]
pub struct RoutingOptions {
    pub strategy: Option<RoutingStrategy>,
    pub hedge: Option<bool>,
    pub hedge_delay: Option<Duration>,
    pub static_weight: Option<f64>,
    pub dynamic_weight: Option<f64>,
    /// Per-call deadline (ms) used for adaptive hedging decisions.
    pub deadline_ms: Option<f64>,
    /// Bypass the circuit breaker (dangerous; reserved for admin calls).
    pub skip_circuit: Option<bool>,
}

impl RoutingOptions {
    /// Merge per-call overrides into an agent-wide config, producing the
    /// effective config for this one call.
    pub fn resolve(&self, base: &RoutingConfig) -> RoutingConfig {
        let mut effective = base.clone();
        if let Some(s) = self.strategy {
            effective.strategy = s;
        }
        if let Some(enabled) = self.hedge {
            effective.hedge_policy.enabled = enabled;
        }
        if let Some(d) = self.hedge_delay {
            effective.hedge_policy.delay = d;
        }
        if let Some(w) = self.static_weight {
            effective.weights.static_weight = w;
        }
        if let Some(w) = self.dynamic_weight {
            effective.weights.dynamic_weight = w;
        }
        // TODO(T5): honor deadline_ms and skip_circuit once hedging and
        // circuit-breaker call paths are wired in.
        effective
    }
}
