//! Integration: `AdaptiveRouter` ties together all routing plane components.
//!
//! Combines metrics registry, circuit breaker registry, bulkhead registry,
//! scoring, selection, hedging, retry, and observability into a single
//! cohesive routing engine.

use crate::routing::circuit::{BulkheadRegistry, CircuitBreakerRegistry, CircuitState};
use crate::routing::config::AdaptiveRoutingConfig;
use crate::routing::hedging::should_hedge_adaptive;
use crate::routing::metrics::PeerMetricsRegistry;
use crate::routing::observability::{RoutingObserver, RoutingSnapshot, RoutingStats};
use crate::routing::scoring::score_candidates;
use crate::routing::selection::SelectionCandidate;
use crate::routing::bulkhead;
use crate::SdkError;

#[cfg(test)]
use crate::routing::selection::RoutingStrategy;

use aafp_identity::agent_record::AgentRecord;
use aafp_identity::identity_v1::AgentId;
use rand::rngs::ThreadRng;
use std::time::Duration;

/// The main adaptive routing engine.
///
/// Holds all registries and configuration needed to:
/// 1. Score and select the best peer for a request.
/// 2. Enforce circuit breaker and bulkhead limits.
/// 3. Provide hedging and retry guidance.
/// 4. Export observability data.
pub struct AdaptiveRouter {
    pub metrics: PeerMetricsRegistry,
    pub circuits: CircuitBreakerRegistry,
    pub bulkhead: BulkheadRegistry,
    pub observer: RoutingObserver,
    config: AdaptiveRoutingConfig,
    rng: ThreadRng,
}

impl AdaptiveRouter {
    /// Create a new router with the given configuration.
    pub fn new(config: AdaptiveRoutingConfig) -> Self {
        Self {
            metrics: PeerMetricsRegistry::new(),
            circuits: CircuitBreakerRegistry::new(config.circuit_breaker.clone()),
            bulkhead: BulkheadRegistry::new(config.bulkhead_max_per_peer),
            observer: RoutingObserver::new(),
            config,
            rng: rand::thread_rng(),
        }
    }

    /// Create a router with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AdaptiveRoutingConfig::default())
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &AdaptiveRoutingConfig {
        &self.config
    }

    /// Score and select the best candidate from a list of agent records.
    ///
    /// Filters out peers with open circuits, scores the remaining candidates
    /// using both static and dynamic scores, and selects using the configured
    /// strategy.
    pub fn select(
        &mut self,
        candidates: &[AgentRecord],
        static_scores: &[f64],
    ) -> Result<AgentId, SdkError> {
        if candidates.len() != static_scores.len() {
            return Err(SdkError::Messaging(format!(
                "candidates len {} != static_scores len {}",
                candidates.len(),
                static_scores.len()
            )));
        }
        // Filter out candidates with open circuits in the CircuitBreakerRegistry.
        let filtered: Vec<(AgentRecord, f64)> = candidates
            .iter()
            .zip(static_scores.iter())
            .filter(|(record, _)| {
                let agent_id = AgentId(record.agent_id);
                self.circuits.state(&agent_id) != CircuitState::Open
            })
            .map(|(r, &s)| (r.clone(), s))
            .collect();
        if filtered.is_empty() {
            self.observer.record_failure();
            return Err(SdkError::NoViableCandidate);
        }
        let filtered_candidates: Vec<AgentRecord> = filtered.iter().map(|(r, _)| r.clone()).collect();
        let filtered_scores: Vec<f64> = filtered.iter().map(|(_, s)| *s).collect();
        let scored = score_candidates(
            &filtered_candidates,
            &self.metrics,
            &filtered_scores,
            &self.config.scoring,
            self.config.static_weight,
            self.config.dynamic_weight,
        );
        if scored.is_empty() {
            self.observer.record_failure();
            return Err(SdkError::NoViableCandidate);
        }
        let selection_candidates: Vec<SelectionCandidate> = scored
            .iter()
            .map(|(agent_id, score)| {
                let m = self.metrics.get_or_create(agent_id);
                SelectionCandidate {
                    agent_id: *agent_id,
                    score: *score,
                    in_flight: m.in_flight,
                    latency_ewma_ms: m.latency_ewma_ms.value(),
                    latency_initialized: m.latency_ewma_ms.is_initialized(),
                    success_rate: m.success_window.success_rate(),
                }
            })
            .collect();
        let selected = self
            .config
            .strategy
            .select(&selection_candidates, &mut self.rng);
        match selected {
            Some(id) => Ok(id),
            None => Err(SdkError::NoViableCandidate),
        }
    }

    /// Acquire a routing slot for a peer.
    ///
    /// Checks the circuit breaker and bulkhead. Returns `Ok` if both pass,
    /// or an appropriate `SdkError` if the circuit is open or the bulkhead
    /// is full.
    pub fn acquire(&self, agent_id: &AgentId) -> Result<RoutingSlot<'_>, SdkError> {
        let (state, allowed) = self.circuits.acquire(agent_id);
        if !allowed {
            match state {
                CircuitState::Open => {
                    self.observer.record_circuit_open();
                    return Err(SdkError::CircuitOpen(*agent_id));
                }
                CircuitState::HalfOpen => {
                    self.observer.record_circuit_open();
                    return Err(SdkError::CircuitOpen(*agent_id));
                }
                CircuitState::Closed => {}
            }
        }
        let guard = bulkhead::try_acquire(&self.bulkhead, agent_id).ok_or_else(|| {
            self.observer.record_bulkhead_rejection();
            SdkError::ConcurrencyLimit(*agent_id)
        })?;
        self.metrics.inflight_inc(agent_id);
        Ok(RoutingSlot {
            router: self,
            agent_id: *agent_id,
            guard,
        })
    }

    /// Record a successful outcome for a peer.
    pub fn record_success(&self, agent_id: &AgentId, latency_ms: f64) {
        self.metrics.record_outcome(agent_id, latency_ms, true);
        self.circuits.record_success(agent_id);
        self.observer.record_success();
    }

    /// Record a failed outcome for a peer.
    pub fn record_failure(&self, agent_id: &AgentId, latency_ms: f64) {
        self.metrics.record_outcome(agent_id, latency_ms, false);
        self.circuits.record_failure(agent_id);
        self.observer.record_failure();
    }

    /// Record a timeout for a peer (counts as a failure).
    pub fn record_timeout(&self, agent_id: &AgentId) {
        self.metrics.record_outcome(agent_id, 0.0, false);
        self.circuits.record_failure(agent_id);
        self.observer.record_timeout();
    }

    /// Determine if a hedged request should be sent for this peer,
    /// and if so, what delay to use.
    pub fn hedge_delay(&self, agent_id: &AgentId) -> Option<Duration> {
        should_hedge_adaptive(&self.metrics, agent_id, &self.config.hedge)
    }

    /// Take a routing snapshot for observability.
    pub fn snapshot(&self) -> RoutingSnapshot {
        RoutingSnapshot::collect(&self.metrics, &self.circuits, &self.bulkhead)
    }

    /// Get aggregate routing stats.
    pub fn stats(&self) -> RoutingStats {
        self.observer.snapshot()
    }

    /// Record a retry event.
    pub fn record_retry(&self) {
        self.observer.record_retry();
    }

    /// Record a hedge event.
    pub fn record_hedge(&self) {
        self.observer.record_hedge();
    }
}

/// RAII slot representing an acquired routing permit (circuit + bulkhead).
///
/// Automatically releases the bulkhead slot and decrements in-flight count on drop.
/// Call `record_success` or `record_failure` on the router to update circuit state.
pub struct RoutingSlot<'a> {
    router: &'a AdaptiveRouter,
    agent_id: AgentId,
    /// RAII guard — released on drop. Field is never read directly.
    #[allow(dead_code)]
    guard: bulkhead::ConcurrencyGuard<'a>,
}

impl<'a> RoutingSlot<'a> {
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }
}

impl Drop for RoutingSlot<'_> {
    fn drop(&mut self) {
        self.router.metrics.inflight_dec(&self.agent_id);
        // guard is dropped here, releasing the bulkhead slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(id: AgentId) -> AgentRecord {
        AgentRecord {
            agent_id: id.0,
            public_key: vec![0u8; 1952],
            capabilities: vec!["test".to_string()],
            endpoints: vec!["127.0.0.1:0".to_string()],
            version: 1,
            timestamp: 0,
            signature: vec![],
        }
    }

    #[test]
    fn test_router_select_single_candidate() {
        let mut router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        let candidates = vec![make_record(id)];
        let selected = router.select(&candidates, &[1.0]);
        assert_eq!(selected.unwrap(), id);
    }

    #[test]
    fn test_router_select_filters_open_circuit() {
        let mut router = AdaptiveRouter::with_defaults();
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        // Open circuit for id1
        for _ in 0..router.config().circuit_breaker.failure_threshold {
            router.circuits.record_failure(&id1);
        }
        let candidates = vec![make_record(id1), make_record(id2)];
        let selected = router.select(&candidates, &[1.0, 1.0]);
        assert_eq!(selected.unwrap(), id2);
    }

    #[test]
    fn test_router_select_no_viable_candidate() {
        let mut router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        for _ in 0..router.config().circuit_breaker.failure_threshold {
            router.circuits.record_failure(&id);
        }
        let candidates = vec![make_record(id)];
        let result = router.select(&candidates, &[1.0]);
        assert!(matches!(result, Err(SdkError::NoViableCandidate)));
    }

    #[test]
    fn test_router_acquire_success() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        let slot = router.acquire(&id);
        assert!(slot.is_ok());
        assert_eq!(router.metrics.get_or_create(&id).in_flight, 1);
        drop(slot);
        assert_eq!(router.metrics.get_or_create(&id).in_flight, 0);
    }

    #[test]
    fn test_router_acquire_circuit_open() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        for _ in 0..router.config().circuit_breaker.failure_threshold {
            router.circuits.record_failure(&id);
        }
        let result = router.acquire(&id);
        assert!(matches!(result, Err(SdkError::CircuitOpen(_))));
    }

    #[test]
    fn test_router_acquire_bulkhead_full() {
        let config = AdaptiveRoutingConfig::builder()
            .bulkhead_max_per_peer(1)
            .build();
        let router = AdaptiveRouter::new(config);
        let id = AgentId([1u8; 32]);
        let slot = router.acquire(&id).unwrap();
        let result = router.acquire(&id);
        assert!(matches!(result, Err(SdkError::ConcurrencyLimit(_))));
        drop(slot);
        // After releasing, should succeed
        assert!(router.acquire(&id).is_ok());
    }

    #[test]
    fn test_router_record_success_updates_metrics() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        router.record_success(&id, 50.0);
        let m = router.metrics.get_or_create(&id);
        assert!(m.latency_ewma_ms.is_initialized());
        assert_eq!(m.consecutive_failures, 0);
        let stats = router.stats();
        assert_eq!(stats.total_successes, 1);
    }

    #[test]
    fn test_router_record_failure_updates_metrics() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        router.record_failure(&id, 100.0);
        let m = router.metrics.get_or_create(&id);
        assert_eq!(m.consecutive_failures, 1);
        let stats = router.stats();
        assert_eq!(stats.total_failures, 1);
    }

    #[test]
    fn test_router_record_timeout() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        router.record_timeout(&id);
        let stats = router.stats();
        assert_eq!(stats.total_timeouts, 1);
        assert_eq!(stats.total_failures, 1);
    }

    #[test]
    fn test_router_hedge_delay() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        let delay = router.hedge_delay(&id);
        assert!(delay.is_some());
    }

    #[test]
    fn test_router_snapshot() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        router.record_success(&id, 50.0);
        let snapshot = router.snapshot();
        assert_eq!(snapshot.total_peers, 1);
        assert_eq!(snapshot.closed_circuits, 1);
    }

    #[test]
    fn test_router_stats() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        router.record_success(&id, 50.0);
        router.record_failure(&id, 100.0);
        router.record_retry();
        router.record_hedge();
        let stats = router.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.total_retries, 1);
        assert_eq!(stats.total_hedges_sent, 1);
    }

    #[test]
    fn test_routing_slot_releases_on_drop() {
        let router = AdaptiveRouter::with_defaults();
        let id = AgentId([1u8; 32]);
        {
            let _slot = router.acquire(&id).unwrap();
            assert_eq!(router.bulkhead.in_flight(&id), 1);
            assert_eq!(router.metrics.get_or_create(&id).in_flight, 1);
        }
        assert_eq!(router.bulkhead.in_flight(&id), 0);
        assert_eq!(router.metrics.get_or_create(&id).in_flight, 0);
    }

    #[test]
    fn test_router_default_config() {
        let router = AdaptiveRouter::with_defaults();
        assert_eq!(router.config().bulkhead_max_per_peer, 8);
        assert_eq!(router.config().strategy, RoutingStrategy::P2C);
    }
}
