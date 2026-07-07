//! Circuit breaker state machine, registry, and bulkhead concurrency limits.
//!
//! `CircuitState` is defined in [`metrics`] and re-exported here.
//! `CircuitBreakerRegistry` provides per-peer circuit breaker management
//! with configurable thresholds, cooldown, and half-open probe limits.
//! `BulkheadRegistry` enforces per-peer concurrency limits (bulkhead pattern).

pub use crate::routing::metrics::CircuitState;

use aafp_identity::identity_v1::AgentId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────
// CircuitBreakerRegistry
// ──────────────────────────────────────────────────────────────────────

/// Configuration for a per-peer circuit breaker.
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub cooldown: Duration,
    pub half_open_max_probes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown: Duration::from_secs(10),
            half_open_max_probes: 1,
        }
    }
}

struct CircuitEntry {
    state: CircuitState,
    consecutive_failures: u32,
    opened_at: Instant,
    half_open_probes: u32,
}

impl Default for CircuitEntry {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            opened_at: Instant::now(),
            half_open_probes: 0,
        }
    }
}

/// Per-peer circuit breaker registry with configurable thresholds.
///
/// Tracks failure counts, transitions through Closed → Open → HalfOpen → Closed,
/// and limits the number of probe requests in HalfOpen state.
pub struct CircuitBreakerRegistry {
    circuits: Mutex<HashMap<AgentId, CircuitEntry>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            circuits: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Check the current circuit state for a peer, transitioning Open → HalfOpen
    /// if the cooldown has elapsed and probe slots are available.
    ///
    /// Returns `(state, allowed)` where `allowed` indicates whether a request
    /// may proceed (HalfOpen only allows up to `half_open_max_probes` concurrent probes).
    pub fn acquire(&self, agent_id: &AgentId) -> (CircuitState, bool) {
        let mut circuits = self.circuits.lock().expect("circuit lock poisoned");
        let entry = circuits.entry(*agent_id).or_default();
        Self::maybe_half_open(entry, &self.config);
        match entry.state {
            CircuitState::Closed => (CircuitState::Closed, true),
            CircuitState::Open => (CircuitState::Open, false),
            CircuitState::HalfOpen => {
                if entry.half_open_probes < self.config.half_open_max_probes {
                    entry.half_open_probes += 1;
                    (CircuitState::HalfOpen, true)
                } else {
                    (CircuitState::HalfOpen, false)
                }
            }
        }
    }

    /// Record a successful outcome for a peer.
    pub fn record_success(&self, agent_id: &AgentId) {
        let mut circuits = self.circuits.lock().expect("circuit lock poisoned");
        let entry = circuits.entry(*agent_id).or_default();
        entry.consecutive_failures = 0;
        if entry.state == CircuitState::HalfOpen {
            entry.state = CircuitState::Closed;
            entry.half_open_probes = 0;
        }
    }

    /// Record a failed outcome for a peer, potentially opening the circuit.
    pub fn record_failure(&self, agent_id: &AgentId) {
        let mut circuits = self.circuits.lock().expect("circuit lock poisoned");
        let entry = circuits.entry(*agent_id).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        match entry.state {
            CircuitState::HalfOpen => {
                entry.state = CircuitState::Open;
                entry.opened_at = Instant::now();
                entry.half_open_probes = 0;
            }
            CircuitState::Closed => {
                if entry.consecutive_failures >= self.config.failure_threshold {
                    entry.state = CircuitState::Open;
                    entry.opened_at = Instant::now();
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Get the current circuit state without side effects (no transition).
    pub fn state(&self, agent_id: &AgentId) -> CircuitState {
        let mut circuits = self.circuits.lock().expect("circuit lock poisoned");
        let entry = circuits.entry(*agent_id).or_default();
        Self::maybe_half_open(entry, &self.config);
        entry.state
    }

    /// Reset the circuit for a peer back to Closed.
    pub fn reset(&self, agent_id: &AgentId) {
        let mut circuits = self.circuits.lock().expect("circuit lock poisoned");
        circuits.insert(*agent_id, CircuitEntry::default());
    }

    fn maybe_half_open(entry: &mut CircuitEntry, config: &CircuitBreakerConfig) {
        if entry.state == CircuitState::Open && entry.opened_at.elapsed() >= config.cooldown {
            entry.state = CircuitState::HalfOpen;
            entry.half_open_probes = 0;
        }
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

// ──────────────────────────────────────────────────────────────────────
// BulkheadRegistry
// ──────────────────────────────────────────────────────────────────────

/// Per-peer concurrency limiter (bulkhead pattern).
///
/// Prevents a single slow peer from exhausting all in-flight slots.
/// Each peer gets an independent concurrency cap.
pub struct BulkheadRegistry {
    limits: Mutex<HashMap<AgentId, u32>>,
    max_per_peer: u32,
}

impl BulkheadRegistry {
    pub fn new(max_per_peer: u32) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            max_per_peer,
        }
    }

    /// Attempt to acquire a concurrency slot for a peer.
    /// Returns `true` if the slot was acquired, `false` if the limit is reached.
    pub fn try_acquire(&self, agent_id: &AgentId) -> bool {
        let mut limits = self.limits.lock().expect("circuit lock poisoned");
        let count = limits.entry(*agent_id).or_insert(0);
        if *count >= self.max_per_peer {
            return false;
        }
        *count += 1;
        true
    }

    /// Release a concurrency slot for a peer.
    pub fn release(&self, agent_id: &AgentId) {
        let mut limits = self.limits.lock().expect("circuit lock poisoned");
        if let Some(count) = limits.get_mut(agent_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Get the current in-flight count for a peer.
    pub fn in_flight(&self, agent_id: &AgentId) -> u32 {
        self.limits
            .lock()
            .expect("circuit lock poisoned")
            .get(agent_id)
            .copied()
            .unwrap_or(0)
    }

    /// Get the configured max concurrency per peer.
    pub fn max_per_peer(&self) -> u32 {
        self.max_per_peer
    }
}

impl Default for BulkheadRegistry {
    fn default() -> Self {
        Self::new(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_circuit_breaker_starts_closed() {
        let registry = CircuitBreakerRegistry::default();
        let id = AgentId([1u8; 32]);
        let (state, allowed) = registry.acquire(&id);
        assert_eq!(state, CircuitState::Closed);
        assert!(allowed);
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown: Duration::from_secs(60),
            half_open_max_probes: 1,
        });
        let id = AgentId([2u8; 32]);
        for _ in 0..3 {
            registry.record_failure(&id);
        }
        let (state, allowed) = registry.acquire(&id);
        assert_eq!(state, CircuitState::Open);
        assert!(!allowed);
    }

    #[test]
    fn test_circuit_breaker_stays_closed_below_threshold() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 5,
            cooldown: Duration::from_secs(60),
            half_open_max_probes: 1,
        });
        let id = AgentId([3u8; 32]);
        for _ in 0..4 {
            registry.record_failure(&id);
        }
        assert_eq!(registry.state(&id), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_success_resets() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown: Duration::from_secs(60),
            half_open_max_probes: 1,
        });
        let id = AgentId([4u8; 32]);
        for _ in 0..2 {
            registry.record_failure(&id);
        }
        registry.record_success(&id);
        assert_eq!(registry.state(&id), CircuitState::Closed);
        let (_, allowed) = registry.acquire(&id);
        assert!(allowed);
    }

    #[test]
    fn test_circuit_breaker_transitions_to_half_open_after_cooldown() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(50),
            half_open_max_probes: 1,
        });
        let id = AgentId([5u8; 32]);
        registry.record_failure(&id);
        assert_eq!(registry.state(&id), CircuitState::Open);
        thread::sleep(Duration::from_millis(60));
        let (state, allowed) = registry.acquire(&id);
        assert_eq!(state, CircuitState::HalfOpen);
        assert!(allowed);
    }

    #[test]
    fn test_circuit_breaker_half_open_limits_probes() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(50),
            half_open_max_probes: 1,
        });
        let id = AgentId([6u8; 32]);
        registry.record_failure(&id);
        thread::sleep(Duration::from_millis(60));
        let (state1, allowed1) = registry.acquire(&id);
        assert_eq!(state1, CircuitState::HalfOpen);
        assert!(allowed1);
        let (state2, allowed2) = registry.acquire(&id);
        assert_eq!(state2, CircuitState::HalfOpen);
        assert!(!allowed2);
    }

    #[test]
    fn test_circuit_breaker_half_open_success_closes() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(50),
            half_open_max_probes: 1,
        });
        let id = AgentId([7u8; 32]);
        registry.record_failure(&id);
        thread::sleep(Duration::from_millis(60));
        registry.acquire(&id);
        registry.record_success(&id);
        assert_eq!(registry.state(&id), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_failure_reopens() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(50),
            half_open_max_probes: 1,
        });
        let id = AgentId([8u8; 32]);
        registry.record_failure(&id);
        thread::sleep(Duration::from_millis(60));
        registry.acquire(&id);
        registry.record_failure(&id);
        assert_eq!(registry.state(&id), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let registry = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_secs(60),
            half_open_max_probes: 1,
        });
        let id = AgentId([9u8; 32]);
        registry.record_failure(&id);
        assert_eq!(registry.state(&id), CircuitState::Open);
        registry.reset(&id);
        assert_eq!(registry.state(&id), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_unknown_peer_is_closed() {
        let registry = CircuitBreakerRegistry::default();
        let id = AgentId([10u8; 32]);
        assert_eq!(registry.state(&id), CircuitState::Closed);
    }

    // ── BulkheadRegistry tests ──

    #[test]
    fn test_bulkhead_acquire_and_release() {
        let bulkhead = BulkheadRegistry::new(3);
        let id = AgentId([1u8; 32]);
        assert!(bulkhead.try_acquire(&id));
        assert!(bulkhead.try_acquire(&id));
        assert_eq!(bulkhead.in_flight(&id), 2);
        bulkhead.release(&id);
        assert_eq!(bulkhead.in_flight(&id), 1);
    }

    #[test]
    fn test_bulkhead_rejects_at_limit() {
        let bulkhead = BulkheadRegistry::new(2);
        let id = AgentId([2u8; 32]);
        assert!(bulkhead.try_acquire(&id));
        assert!(bulkhead.try_acquire(&id));
        assert!(!bulkhead.try_acquire(&id));
    }

    #[test]
    fn test_bulkhead_release_below_zero_saturates() {
        let bulkhead = BulkheadRegistry::new(2);
        let id = AgentId([3u8; 32]);
        bulkhead.release(&id);
        assert_eq!(bulkhead.in_flight(&id), 0);
    }

    #[test]
    fn test_bulkhead_independent_per_peer() {
        let bulkhead = BulkheadRegistry::new(1);
        let id1 = AgentId([4u8; 32]);
        let id2 = AgentId([5u8; 32]);
        assert!(bulkhead.try_acquire(&id1));
        assert!(!bulkhead.try_acquire(&id1));
        assert!(bulkhead.try_acquire(&id2));
    }

    #[test]
    fn test_bulkhead_default_max() {
        let bulkhead = BulkheadRegistry::default();
        assert_eq!(bulkhead.max_per_peer(), 8);
    }
}
