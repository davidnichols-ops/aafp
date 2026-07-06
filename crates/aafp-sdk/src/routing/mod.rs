//! Adaptive Routing Plane — dynamic metrics, quality-aware routing,
//! and resilience (circuit breakers, bulkheads, hedging, retries).
//!
//! Implements Track T (Phases T1-T7):
//! - T1-T2: per-peer metrics collection, circuit breaker state,
//!   composite scoring, and selection strategies.
//! - T3-T4: circuit breaker registry, bulkhead concurrency limits,
//!   hedged requests, and retry with backoff.
//! - T5-T7: unified configuration, observability/export, and the
//!   `AdaptiveRouter` integration that ties everything together.

pub mod bulkhead;
pub mod circuit;
pub mod config;
pub mod hedging;
pub mod integration;
pub mod metrics;
pub mod observability;
pub mod retry;
pub mod scoring;
pub mod selection;

pub use bulkhead::{try_acquire as bulkhead_try_acquire, BulkheadConfig, ConcurrencyGuard};
pub use circuit::{
    BulkheadRegistry, CircuitBreakerConfig, CircuitBreakerRegistry, CircuitState,
};
pub use config::{AdaptiveRoutingConfig, AdaptiveRoutingConfigBuilder};
pub use hedging::{
    call_with_hedging, call_with_hedging_boxed, should_hedge_adaptive, BoxedHedgeFuture,
    HedgeConfig,
};
pub use integration::{AdaptiveRouter, RoutingSlot};
pub use metrics::{Ewma, HealthProbeResult, PeerMetrics, PeerMetricsRegistry, RollingWindow};
pub use observability::{
    export_snapshot, export_stats, PeerSnapshot, RoutingObserver, RoutingSnapshot, RoutingStats,
};
pub use retry::{is_retryable, retry_delay, with_retry, RetryConfig};
pub use scoring::{dynamic_score, score_candidates, DynamicScoreConfig, ScoredCandidate};
pub use selection::{
    select_epsilon_greedy, select_least_connections, select_lowest_latency, select_power_of_two,
    select_weighted_random, RoutingStrategy, SelectionCandidate,
};
