//! Observability for the adaptive routing plane.
//!
//! Provides `RoutingSnapshot` for point-in-time state export and
//! `RoutingStats` for aggregate statistics, along with a `RoutingObserver`
//! that collects events for logging/metrics export.

use crate::routing::circuit::{BulkheadRegistry, CircuitBreakerRegistry, CircuitState};
use crate::routing::metrics::PeerMetricsRegistry;
use aafp_identity::identity_v1::AgentId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Point-in-time snapshot of a single peer's routing state.
#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    pub agent_id: AgentId,
    pub circuit: CircuitState,
    pub latency_ewma_ms: f64,
    pub latency_initialized: bool,
    pub latency_min_ms: f64,
    pub success_rate: f64,
    pub sample_count: u8,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub in_flight: u32,
    pub bulkhead_in_flight: u32,
    pub stale: bool,
}

/// Point-in-time snapshot of the entire routing plane.
#[derive(Clone, Debug)]
pub struct RoutingSnapshot {
    pub peers: Vec<PeerSnapshot>,
    pub total_peers: usize,
    pub open_circuits: usize,
    pub half_open_circuits: usize,
    pub closed_circuits: usize,
    pub total_in_flight: u32,
}

impl RoutingSnapshot {
    /// Build a snapshot from the registries.
    pub fn collect(
        metrics: &PeerMetricsRegistry,
        circuits: &CircuitBreakerRegistry,
        bulkhead: &BulkheadRegistry,
    ) -> Self {
        let all_metrics = metrics.snapshot_all();
        let now = Instant::now();
        let mut peers = Vec::with_capacity(all_metrics.len());
        let mut open = 0;
        let mut half_open = 0;
        let mut closed = 0;
        let mut total_in_flight = 0u32;

        for m in all_metrics {
            let circuit = circuits.state(&m.agent_id);
            let bulkhead_in_flight = bulkhead.in_flight(&m.agent_id);
            let stale = now.duration_since(m.last_seen) >= metrics.staleness_threshold;
            match circuit {
                CircuitState::Open => open += 1,
                CircuitState::HalfOpen => half_open += 1,
                CircuitState::Closed => closed += 1,
            }
            total_in_flight = total_in_flight.saturating_add(m.in_flight);
            peers.push(PeerSnapshot {
                agent_id: m.agent_id,
                circuit,
                latency_ewma_ms: m.latency_ewma_ms.value(),
                latency_initialized: m.latency_ewma_ms.is_initialized(),
                latency_min_ms: if m.latency_min_ms == f64::MAX {
                    0.0
                } else {
                    m.latency_min_ms
                },
                success_rate: m.success_window.success_rate(),
                sample_count: m.success_window.sample_count(),
                consecutive_failures: m.consecutive_failures,
                consecutive_successes: m.consecutive_successes,
                in_flight: m.in_flight,
                bulkhead_in_flight,
                stale,
            });
        }

        Self {
            total_peers: peers.len(),
            open_circuits: open,
            half_open_circuits: half_open,
            closed_circuits: closed,
            total_in_flight,
            peers,
        }
    }

    /// Get peers with open circuits.
    pub fn open_circuit_peers(&self) -> Vec<&PeerSnapshot> {
        self.peers
            .iter()
            .filter(|p| p.circuit == CircuitState::Open)
            .collect()
    }

    /// Get healthy peers (closed circuit, not stale, success rate > 0.5).
    pub fn healthy_peers(&self) -> Vec<&PeerSnapshot> {
        self.peers
            .iter()
            .filter(|p| p.circuit == CircuitState::Closed && !p.stale && p.success_rate > 0.5)
            .collect()
    }
}

/// Aggregate routing statistics (cumulative counters).
#[derive(Clone, Debug, Default)]
pub struct RoutingStats {
    pub total_requests: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub total_timeouts: u64,
    pub total_circuit_opens: u64,
    pub total_hedges_sent: u64,
    pub total_retries: u64,
    pub total_bulkhead_rejections: u64,
}

impl RoutingStats {
    pub fn success_rate(&self) -> f64 {
        let total = self.total_successes + self.total_failures;
        if total == 0 {
            return 1.0;
        }
        self.total_successes as f64 / total as f64
    }

    pub fn record_success(&mut self) {
        self.total_requests += 1;
        self.total_successes += 1;
    }

    pub fn record_failure(&mut self) {
        self.total_requests += 1;
        self.total_failures += 1;
    }

    pub fn record_timeout(&mut self) {
        self.total_requests += 1;
        self.total_timeouts += 1;
        self.total_failures += 1;
    }

    pub fn record_circuit_open(&mut self) {
        self.total_circuit_opens += 1;
    }

    pub fn record_hedge(&mut self) {
        self.total_hedges_sent += 1;
    }

    pub fn record_retry(&mut self) {
        self.total_retries += 1;
    }

    pub fn record_bulkhead_rejection(&mut self) {
        self.total_bulkhead_rejections += 1;
    }
}

/// Thread-safe routing stats collector.
pub struct RoutingObserver {
    stats: Mutex<RoutingStats>,
}

impl RoutingObserver {
    pub fn new() -> Self {
        Self {
            stats: Mutex::new(RoutingStats::default()),
        }
    }

    pub fn record_success(&self) {
        self.stats.lock().unwrap().record_success();
    }
    pub fn record_failure(&self) {
        self.stats.lock().unwrap().record_failure();
    }
    pub fn record_timeout(&self) {
        self.stats.lock().unwrap().record_timeout();
    }
    pub fn record_circuit_open(&self) {
        self.stats.lock().unwrap().record_circuit_open();
    }
    pub fn record_hedge(&self) {
        self.stats.lock().unwrap().record_hedge();
    }
    pub fn record_retry(&self) {
        self.stats.lock().unwrap().record_retry();
    }
    pub fn record_bulkhead_rejection(&self) {
        self.stats.lock().unwrap().record_bulkhead_rejection();
    }

    pub fn snapshot(&self) -> RoutingStats {
        self.stats.lock().unwrap().clone()
    }
}

impl Default for RoutingObserver {
    fn default() -> Self {
        Self::new()
    }
}

/// Export routing stats as a flat key-value map (for Prometheus or similar).
pub fn export_stats(stats: &RoutingStats) -> HashMap<&'static str, f64> {
    let mut map = HashMap::new();
    map.insert("routing_requests_total", stats.total_requests as f64);
    map.insert("routing_successes_total", stats.total_successes as f64);
    map.insert("routing_failures_total", stats.total_failures as f64);
    map.insert("routing_timeouts_total", stats.total_timeouts as f64);
    map.insert(
        "routing_circuit_opens_total",
        stats.total_circuit_opens as f64,
    );
    map.insert("routing_hedges_sent_total", stats.total_hedges_sent as f64);
    map.insert("routing_retries_total", stats.total_retries as f64);
    map.insert(
        "routing_bulkhead_rejections_total",
        stats.total_bulkhead_rejections as f64,
    );
    map.insert("routing_success_rate", stats.success_rate());
    map
}

/// Export a routing snapshot as a flat key-value map.
pub fn export_snapshot(snapshot: &RoutingSnapshot) -> HashMap<&'static str, f64> {
    let mut map = HashMap::new();
    map.insert("routing_total_peers", snapshot.total_peers as f64);
    map.insert("routing_open_circuits", snapshot.open_circuits as f64);
    map.insert(
        "routing_half_open_circuits",
        snapshot.half_open_circuits as f64,
    );
    map.insert("routing_closed_circuits", snapshot.closed_circuits as f64);
    map.insert("routing_total_in_flight", snapshot.total_in_flight as f64);
    for p in &snapshot.peers {
        let prefix = format!("routing_peer_{:?}", p.agent_id);
        map.insert(
            leak_str(format!("{prefix}_latency_ewma_ms")),
            p.latency_ewma_ms,
        );
        map.insert(leak_str(format!("{prefix}_success_rate")), p.success_rate);
        map.insert(leak_str(format!("{prefix}_in_flight")), p.in_flight as f64);
    }
    map
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_stats_success_rate() {
        let mut stats = RoutingStats::default();
        assert_eq!(stats.success_rate(), 1.0);
        for _ in 0..8 {
            stats.record_success();
        }
        for _ in 0..2 {
            stats.record_failure();
        }
        assert!((stats.success_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_routing_stats_timeout_counts_as_failure() {
        let mut stats = RoutingStats::default();
        stats.record_timeout();
        assert_eq!(stats.total_timeouts, 1);
        assert_eq!(stats.total_failures, 1);
        assert_eq!(stats.total_requests, 1);
    }

    #[test]
    fn test_routing_observer_thread_safe() {
        let observer = RoutingObserver::new();
        observer.record_success();
        observer.record_success();
        observer.record_failure();
        observer.record_hedge();
        observer.record_retry();
        let stats = observer.snapshot();
        assert_eq!(stats.total_successes, 2);
        assert_eq!(stats.total_failures, 1);
        assert_eq!(stats.total_hedges_sent, 1);
        assert_eq!(stats.total_retries, 1);
    }

    #[test]
    fn test_export_stats_keys() {
        let mut stats = RoutingStats::default();
        stats.record_success();
        stats.record_failure();
        let map = export_stats(&stats);
        assert_eq!(map.get("routing_requests_total"), Some(&2.0));
        assert_eq!(map.get("routing_successes_total"), Some(&1.0));
        assert_eq!(map.get("routing_failures_total"), Some(&1.0));
        assert!(map.get("routing_success_rate").is_some());
    }

    #[test]
    fn test_snapshot_collect_empty() {
        let metrics = PeerMetricsRegistry::new();
        let circuits = CircuitBreakerRegistry::default();
        let bulkhead = BulkheadRegistry::default();
        let snapshot = RoutingSnapshot::collect(&metrics, &circuits, &bulkhead);
        assert_eq!(snapshot.total_peers, 0);
        assert_eq!(snapshot.open_circuits, 0);
    }

    #[test]
    fn test_snapshot_collect_with_peers() {
        let metrics = PeerMetricsRegistry::new();
        let circuits = CircuitBreakerRegistry::default();
        let bulkhead = BulkheadRegistry::default();
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        metrics.record_outcome(&id1, 50.0, true);
        metrics.record_outcome(&id2, 100.0, false);
        let snapshot = RoutingSnapshot::collect(&metrics, &circuits, &bulkhead);
        assert_eq!(snapshot.total_peers, 2);
        assert_eq!(snapshot.closed_circuits, 2);
        let healthy = snapshot.healthy_peers();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].agent_id, id1);
    }

    #[test]
    fn test_snapshot_open_circuit_peers() {
        let metrics = PeerMetricsRegistry::new();
        let circuits = CircuitBreakerRegistry::new(crate::routing::circuit::CircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        });
        let bulkhead = BulkheadRegistry::default();
        let id = AgentId([1u8; 32]);
        metrics.record_outcome(&id, 100.0, false);
        circuits.record_failure(&id);
        let snapshot = RoutingSnapshot::collect(&metrics, &circuits, &bulkhead);
        assert_eq!(snapshot.open_circuits, 1);
        assert_eq!(snapshot.open_circuit_peers().len(), 1);
    }

    #[test]
    fn test_export_snapshot() {
        let metrics = PeerMetricsRegistry::new();
        let circuits = CircuitBreakerRegistry::default();
        let bulkhead = BulkheadRegistry::default();
        let id = AgentId([1u8; 32]);
        metrics.record_outcome(&id, 50.0, true);
        let snapshot = RoutingSnapshot::collect(&metrics, &circuits, &bulkhead);
        let map = export_snapshot(&snapshot);
        assert_eq!(map.get("routing_total_peers"), Some(&1.0));
        assert_eq!(map.get("routing_closed_circuits"), Some(&1.0));
    }
}
