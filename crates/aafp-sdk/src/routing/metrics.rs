//! Per-peer dynamic metrics: EWMA latency, rolling success window,
//! circuit breaker state, and a thread-safe `PeerMetricsRegistry`.

use aafp_identity::identity_v1::AgentId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────
// Ewma
// ──────────────────────────────────────────────────────────────────────

/// EWMA (exponentially weighted moving average) estimator.
#[derive(Clone, Debug)]
pub struct Ewma {
    value: f64,
    alpha: f64,
    initialized: bool,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        assert!((0.0..=1.0).contains(&alpha), "alpha must be in [0,1]");
        Self {
            value: 0.0,
            alpha,
            initialized: false,
        }
    }

    pub fn update(&mut self, sample: f64) -> f64 {
        if !self.initialized {
            self.value = sample;
            self.initialized = true;
        } else {
            self.value = self.alpha * sample + (1.0 - self.alpha) * self.value;
        }
        self.value
    }

    pub fn value(&self) -> f64 {
        self.value
    }
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
    pub fn reset(&mut self) {
        self.value = 0.0;
        self.initialized = false;
    }
}

// ──────────────────────────────────────────────────────────────────────
// RollingWindow
// ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RollingWindow {
    bits: u64,
    index: u8,
    capacity: u8,
    count: u8,
}

impl RollingWindow {
    pub fn new(capacity: u8) -> Self {
        assert!(capacity <= 64, "capacity must be <= 64");
        assert!(capacity > 0, "capacity must be > 0");
        Self {
            bits: 0,
            index: 0,
            capacity,
            count: 0,
        }
    }

    pub fn record(&mut self, success: bool) {
        let mask = 1u64 << self.index;
        if success {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
        self.index = (self.index + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.count == 0 {
            return 1.0;
        }
        self.bits.count_ones() as f64 / self.count as f64
    }

    pub fn sample_count(&self) -> u8 {
        self.count
    }
    pub fn reset(&mut self) {
        self.bits = 0;
        self.index = 0;
        self.count = 0;
    }
}

// ──────────────────────────────────────────────────────────────────────
// CircuitState
// ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CircuitState {
    #[default]
    Closed,
    Open,
    HalfOpen,
}

impl CircuitState {
    pub fn allows_request(&self) -> bool {
        matches!(self, CircuitState::Closed | CircuitState::HalfOpen)
    }
}

// ──────────────────────────────────────────────────────────────────────
// HealthProbeResult
// ──────────────────────────────────────────────────────────────────────

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

#[derive(Clone, Debug)]
pub struct PeerMetrics {
    pub agent_id: AgentId,
    pub latency_ewma_ms: Ewma,
    pub latency_min_ms: f64,
    pub success_window: RollingWindow,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub in_flight: u32,
    pub queue_depth: Option<u32>,
    pub reported_active_conns: Option<u64>,
    pub cost_micro_usd: Option<u64>,
    pub last_seen: Instant,
    pub last_health: Option<HealthProbeResult>,
    pub circuit: CircuitState,
}

impl PeerMetrics {
    pub fn new(agent_id: AgentId) -> Self {
        Self {
            agent_id,
            latency_ewma_ms: Ewma::new(0.1),
            latency_min_ms: f64::MAX,
            success_window: RollingWindow::new(64),
            consecutive_failures: 0,
            consecutive_successes: 0,
            in_flight: 0,
            queue_depth: None,
            reported_active_conns: None,
            cost_micro_usd: None,
            last_seen: Instant::now(),
            last_health: None,
            circuit: CircuitState::Closed,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// PeerMetricsRegistry
// ──────────────────────────────────────────────────────────────────────

pub struct PeerMetricsRegistry {
    peers: Mutex<HashMap<AgentId, PeerMetrics>>,
    pub latency_alpha: f64,
    pub window_capacity: u8,
    pub failure_threshold: u32,
    pub cooldown: Duration,
    pub staleness_threshold: Duration,
}

impl PeerMetricsRegistry {
    pub fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            latency_alpha: 0.1,
            window_capacity: 64,
            failure_threshold: 5,
            cooldown: Duration::from_secs(10),
            staleness_threshold: Duration::from_secs(60),
        }
    }

    pub fn get_or_create(&self, agent_id: &AgentId) -> PeerMetrics {
        let mut peers = self.peers.lock().expect("peers lock poisoned");
        peers
            .entry(*agent_id)
            .or_insert_with(|| PeerMetrics::new(*agent_id))
            .clone()
    }

    pub fn record_outcome(&self, agent_id: &AgentId, latency_ms: f64, success: bool) {
        let mut peers = self.peers.lock().expect("peers lock poisoned");
        let metrics = peers
            .entry(*agent_id)
            .or_insert_with(|| PeerMetrics::new(*agent_id));
        metrics.latency_ewma_ms.update(latency_ms);
        if latency_ms < metrics.latency_min_ms {
            metrics.latency_min_ms = latency_ms;
        }
        metrics.success_window.record(success);
        metrics.last_seen = Instant::now();
        if success {
            metrics.consecutive_failures = 0;
            metrics.consecutive_successes += 1;
            if metrics.circuit == CircuitState::HalfOpen {
                metrics.circuit = CircuitState::Closed;
                metrics.consecutive_successes = 0;
            }
        } else {
            metrics.consecutive_successes = 0;
            metrics.consecutive_failures += 1;
            match metrics.circuit {
                CircuitState::HalfOpen => metrics.circuit = CircuitState::Open,
                CircuitState::Closed => {
                    if metrics.consecutive_failures >= self.failure_threshold {
                        metrics.circuit = CircuitState::Open;
                    }
                }
                CircuitState::Open => {}
            }
        }
    }

    pub fn inflight_inc(&self, agent_id: &AgentId) {
        let mut peers = self.peers.lock().expect("peers lock poisoned");
        let m = peers
            .entry(*agent_id)
            .or_insert_with(|| PeerMetrics::new(*agent_id));
        m.in_flight = m.in_flight.saturating_add(1);
    }

    pub fn inflight_dec(&self, agent_id: &AgentId) {
        let mut peers = self.peers.lock().expect("peers lock poisoned");
        if let Some(m) = peers.get_mut(agent_id) {
            m.in_flight = m.in_flight.saturating_sub(1);
        }
    }

    pub fn check_circuit(&self, agent_id: &AgentId) -> CircuitState {
        let mut peers = self.peers.lock().expect("peers lock poisoned");
        if let Some(m) = peers.get_mut(agent_id) {
            if m.circuit == CircuitState::Open && m.last_seen.elapsed() >= self.cooldown {
                m.circuit = CircuitState::HalfOpen;
            }
            m.circuit
        } else {
            CircuitState::Closed
        }
    }

    pub fn is_stale(&self, agent_id: &AgentId) -> bool {
        let peers = self.peers.lock().expect("peers lock poisoned");
        match peers.get(agent_id) {
            Some(m) => m.last_seen.elapsed() >= self.staleness_threshold,
            None => true,
        }
    }

    pub fn snapshot_all(&self) -> Vec<PeerMetrics> {
        self.peers.lock().expect("peers lock poisoned").values().cloned().collect()
    }
}

impl Default for PeerMetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ewma_first_sample_initializes() {
        let mut e = Ewma::new(0.1);
        assert!(!e.is_initialized());
        assert_eq!(e.value(), 0.0);
        e.update(100.0);
        assert!(e.is_initialized());
        assert_eq!(e.value(), 100.0);
    }

    #[test]
    fn test_ewma_convergence() {
        let mut e = Ewma::new(0.3);
        e.update(100.0);
        e.update(100.0);
        e.update(50.0);
        assert!((e.value() - 85.0).abs() < 0.001);
    }

    #[test]
    fn test_ewma_alpha_sensitivity() {
        let mut fast = Ewma::new(0.5);
        let mut slow = Ewma::new(0.05);
        // Start from 0, then step to 200 — fast should react more quickly.
        fast.update(0.0);
        slow.update(0.0);
        for _ in 0..20 {
            fast.update(200.0);
            slow.update(200.0);
        }
        assert!(fast.value() > slow.value());
        assert!((fast.value() - 200.0).abs() < 1.0);
    }

    #[test]
    fn test_ewma_reset() {
        let mut e = Ewma::new(0.1);
        e.update(100.0);
        assert!(e.is_initialized());
        e.reset();
        assert!(!e.is_initialized());
        assert_eq!(e.value(), 0.0);
    }

    #[test]
    fn test_rolling_window_empty() {
        let w = RollingWindow::new(64);
        assert_eq!(w.sample_count(), 0);
        assert_eq!(w.success_rate(), 1.0);
    }

    #[test]
    fn test_rolling_window_all_success() {
        let mut w = RollingWindow::new(8);
        for _ in 0..8 {
            w.record(true);
        }
        assert_eq!(w.sample_count(), 8);
        assert!((w.success_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_rolling_window_all_failure() {
        let mut w = RollingWindow::new(8);
        for _ in 0..8 {
            w.record(false);
        }
        assert_eq!(w.success_rate(), 0.0);
    }

    #[test]
    fn test_rolling_window_mixed() {
        let mut w = RollingWindow::new(8);
        w.record(true);
        w.record(true);
        w.record(true);
        w.record(false);
        w.record(false);
        assert!((w.success_rate() - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_rolling_window_wrap_around() {
        let mut w = RollingWindow::new(4);
        for _ in 0..4 {
            w.record(true);
        }
        assert!((w.success_rate() - 1.0).abs() < 0.001);
        for _ in 0..4 {
            w.record(false);
        }
        assert!((w.success_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_rolling_window_partial_wrap() {
        let mut w = RollingWindow::new(4);
        for _ in 0..4 {
            w.record(true);
        }
        w.record(false);
        assert!((w.success_rate() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_rolling_window_reset() {
        let mut w = RollingWindow::new(8);
        w.record(true);
        w.record(false);
        w.reset();
        assert_eq!(w.sample_count(), 0);
        assert_eq!(w.success_rate(), 1.0);
    }

    #[test]
    fn test_circuit_allows_request() {
        assert!(CircuitState::Closed.allows_request());
        assert!(CircuitState::HalfOpen.allows_request());
        assert!(!CircuitState::Open.allows_request());
    }

    #[test]
    fn test_circuit_default_is_closed() {
        assert_eq!(CircuitState::default(), CircuitState::Closed);
    }

    #[test]
    fn test_registry_record_outcome_updates_latency() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([1u8; 32]);
        registry.record_outcome(&id, 50.0, true);
        let m = registry.get_or_create(&id);
        assert!(m.latency_ewma_ms.is_initialized());
        assert_eq!(m.latency_ewma_ms.value(), 50.0);
        assert_eq!(m.latency_min_ms, 50.0);
    }

    #[test]
    fn test_registry_circuit_opens_on_failures() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([2u8; 32]);
        for _ in 0..5 {
            registry.record_outcome(&id, 100.0, false);
        }
        let m = registry.get_or_create(&id);
        assert_eq!(m.circuit, CircuitState::Open);
    }

    #[test]
    fn test_registry_circuit_stays_closed_below_threshold() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([3u8; 32]);
        for _ in 0..4 {
            registry.record_outcome(&id, 100.0, false);
        }
        let m = registry.get_or_create(&id);
        assert_eq!(m.circuit, CircuitState::Closed);
    }

    #[test]
    fn test_registry_success_resets_failures() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([4u8; 32]);
        for _ in 0..4 {
            registry.record_outcome(&id, 100.0, false);
        }
        registry.record_outcome(&id, 100.0, true);
        let m = registry.get_or_create(&id);
        assert_eq!(m.consecutive_failures, 0);
        assert_eq!(m.circuit, CircuitState::Closed);
    }

    #[test]
    fn test_registry_inflight_inc_dec() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([5u8; 32]);
        registry.get_or_create(&id);
        registry.inflight_inc(&id);
        registry.inflight_inc(&id);
        let m = registry.get_or_create(&id);
        assert_eq!(m.in_flight, 2);
        registry.inflight_dec(&id);
        let m = registry.get_or_create(&id);
        assert_eq!(m.in_flight, 1);
    }

    #[test]
    fn test_registry_check_circuit_unknown_peer() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([6u8; 32]);
        assert_eq!(registry.check_circuit(&id), CircuitState::Closed);
    }
}
