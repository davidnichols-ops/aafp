//! Unified configuration for the adaptive routing plane.
//!
//! Combines all T1-T4 configuration into a single `AdaptiveRoutingConfig`
//! with sensible defaults and builder-style customization.

use crate::routing::circuit::CircuitBreakerConfig;
use crate::routing::hedging::HedgeConfig;
use crate::routing::retry::RetryConfig;
use crate::routing::scoring::DynamicScoreConfig;
use crate::routing::selection::RoutingStrategy;
use std::time::Duration;

/// Top-level configuration for the adaptive routing plane.
#[derive(Clone, Debug)]
pub struct AdaptiveRoutingConfig {
    /// Composite scoring weights and reference points.
    pub scoring: DynamicScoreConfig,
    /// Circuit breaker thresholds and cooldown.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Bulkhead per-peer concurrency limit.
    pub bulkhead_max_per_peer: u32,
    /// Hedged request configuration.
    pub hedge: HedgeConfig,
    /// Retry with backoff configuration.
    pub retry: RetryConfig,
    /// Default selection strategy.
    pub strategy: RoutingStrategy,
    /// Weight of static score in final candidate ranking (0.0–1.0).
    pub static_weight: f64,
    /// Weight of dynamic score in final candidate ranking (0.0–1.0).
    pub dynamic_weight: f64,
    /// EWMA alpha for latency estimation (0.0–1.0).
    pub latency_alpha: f64,
    /// Rolling success window capacity (1–64).
    pub window_capacity: u8,
    /// Staleness threshold for peer metrics.
    pub staleness_threshold: Duration,
}

impl Default for AdaptiveRoutingConfig {
    fn default() -> Self {
        Self {
            scoring: DynamicScoreConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            bulkhead_max_per_peer: 8,
            hedge: HedgeConfig::default(),
            retry: RetryConfig::default(),
            strategy: RoutingStrategy::P2C,
            static_weight: 0.3,
            dynamic_weight: 0.7,
            latency_alpha: 0.1,
            window_capacity: 64,
            staleness_threshold: Duration::from_secs(60),
        }
    }
}

impl AdaptiveRoutingConfig {
    /// Create a builder for customizing the configuration.
    pub fn builder() -> AdaptiveRoutingConfigBuilder {
        AdaptiveRoutingConfigBuilder::default()
    }
}

/// Builder for `AdaptiveRoutingConfig`.
#[derive(Default)]
pub struct AdaptiveRoutingConfigBuilder {
    config: AdaptiveRoutingConfig,
}

impl AdaptiveRoutingConfigBuilder {
    pub fn scoring(mut self, scoring: DynamicScoreConfig) -> Self {
        self.config.scoring = scoring;
        self
    }
    pub fn circuit_breaker(mut self, cb: CircuitBreakerConfig) -> Self {
        self.config.circuit_breaker = cb;
        self
    }
    pub fn bulkhead_max_per_peer(mut self, max: u32) -> Self {
        self.config.bulkhead_max_per_peer = max;
        self
    }
    pub fn hedge(mut self, hedge: HedgeConfig) -> Self {
        self.config.hedge = hedge;
        self
    }
    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.config.retry = retry;
        self
    }
    pub fn strategy(mut self, strategy: RoutingStrategy) -> Self {
        self.config.strategy = strategy;
        self
    }
    pub fn static_weight(mut self, w: f64) -> Self {
        self.config.static_weight = w;
        self
    }
    pub fn dynamic_weight(mut self, w: f64) -> Self {
        self.config.dynamic_weight = w;
        self
    }
    pub fn latency_alpha(mut self, alpha: f64) -> Self {
        self.config.latency_alpha = alpha;
        self
    }
    pub fn window_capacity(mut self, cap: u8) -> Self {
        self.config.window_capacity = cap;
        self
    }
    pub fn staleness_threshold(mut self, threshold: Duration) -> Self {
        self.config.staleness_threshold = threshold;
        self
    }
    pub fn build(self) -> AdaptiveRoutingConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AdaptiveRoutingConfig::default();
        assert_eq!(config.bulkhead_max_per_peer, 8);
        assert_eq!(config.static_weight, 0.3);
        assert_eq!(config.dynamic_weight, 0.7);
        assert_eq!(config.latency_alpha, 0.1);
        assert_eq!(config.window_capacity, 64);
        assert_eq!(config.staleness_threshold, Duration::from_secs(60));
        assert_eq!(config.strategy, RoutingStrategy::P2C);
    }

    #[test]
    fn test_builder_customization() {
        let config = AdaptiveRoutingConfig::builder()
            .bulkhead_max_per_peer(16)
            .static_weight(0.5)
            .dynamic_weight(0.5)
            .latency_alpha(0.2)
            .window_capacity(32)
            .staleness_threshold(Duration::from_secs(30))
            .strategy(RoutingStrategy::LeastConnections)
            .build();
        assert_eq!(config.bulkhead_max_per_peer, 16);
        assert_eq!(config.static_weight, 0.5);
        assert_eq!(config.dynamic_weight, 0.5);
        assert_eq!(config.latency_alpha, 0.2);
        assert_eq!(config.window_capacity, 32);
        assert_eq!(config.staleness_threshold, Duration::from_secs(30));
        assert_eq!(config.strategy, RoutingStrategy::LeastConnections);
    }

    #[test]
    fn test_builder_preserves_defaults_for_unset() {
        let config = AdaptiveRoutingConfig::builder()
            .bulkhead_max_per_peer(4)
            .build();
        assert_eq!(config.bulkhead_max_per_peer, 4);
        assert_eq!(config.static_weight, 0.3);
        assert_eq!(config.retry.max_attempts, 3);
    }
}
