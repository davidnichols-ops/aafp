//! Bulkhead concurrency limiter for per-peer request isolation.
//!
//! Provides a `ConcurrencyLimit` guard that automatically releases on drop,
//! and a `with_bulkhead` helper that integrates with `BulkheadRegistry`.

use aafp_identity::identity_v1::AgentId;
use crate::routing::circuit::BulkheadRegistry;

/// RAII guard that releases a bulkhead slot on drop.
pub struct ConcurrencyGuard<'a> {
    registry: &'a BulkheadRegistry,
    agent_id: AgentId,
}

impl Drop for ConcurrencyGuard<'_> {
    fn drop(&mut self) {
        self.registry.release(&self.agent_id);
    }
}

/// Attempt to acquire a bulkhead slot for `agent_id`.
///
/// Returns `Some(guard)` if the slot was acquired, or `None` if the
/// per-peer concurrency limit has been reached.
pub fn try_acquire<'a>(
    registry: &'a BulkheadRegistry,
    agent_id: &AgentId,
) -> Option<ConcurrencyGuard<'a>> {
    if registry.try_acquire(agent_id) {
        Some(ConcurrencyGuard {
            registry,
            agent_id: *agent_id,
        })
    } else {
        None
    }
}

/// Configuration for bulkhead behavior.
#[derive(Clone, Debug)]
pub struct BulkheadConfig {
    pub max_per_peer: u32,
    pub timeout_ms: u64,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            max_per_peer: 8,
            timeout_ms: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_releases_on_drop() {
        let registry = BulkheadRegistry::new(2);
        let id = AgentId([1u8; 32]);
        {
            let _g1 = try_acquire(&registry, &id).unwrap();
            assert_eq!(registry.in_flight(&id), 1);
        }
        assert_eq!(registry.in_flight(&id), 0);
    }

    #[test]
    fn test_guard_releases_on_early_drop() {
        let registry = BulkheadRegistry::new(1);
        let id = AgentId([2u8; 32]);
        {
            let g = try_acquire(&registry, &id);
            assert!(g.is_some());
            assert_eq!(registry.in_flight(&id), 1);
            // second acquire fails
            assert!(try_acquire(&registry, &id).is_none());
        }
        // after scope, slot is released
        assert_eq!(registry.in_flight(&id), 0);
        assert!(try_acquire(&registry, &id).is_some());
    }

    #[test]
    fn test_try_acquire_returns_none_at_limit() {
        let registry = BulkheadRegistry::new(1);
        let id = AgentId([3u8; 32]);
        let _g = try_acquire(&registry, &id).unwrap();
        assert!(try_acquire(&registry, &id).is_none());
    }

    #[test]
    fn test_multiple_guards_release_correctly() {
        let registry = BulkheadRegistry::new(3);
        let id = AgentId([4u8; 32]);
        let g1 = try_acquire(&registry, &id).unwrap();
        let g2 = try_acquire(&registry, &id).unwrap();
        assert_eq!(registry.in_flight(&id), 2);
        drop(g1);
        assert_eq!(registry.in_flight(&id), 1);
        drop(g2);
        assert_eq!(registry.in_flight(&id), 0);
    }

    #[test]
    fn test_bulkhead_config_default() {
        let config = BulkheadConfig::default();
        assert_eq!(config.max_per_peer, 8);
        assert_eq!(config.timeout_ms, 100);
    }
}
