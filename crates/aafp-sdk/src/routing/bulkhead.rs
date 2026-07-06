//! Bulkhead — per-peer concurrency limits.
//!
//! Caps the number of concurrent in-flight requests per peer so a single
//! slow peer cannot exhaust the client's connection pool or task budget.
//! The counter uses `AtomicU32` for lock-free admission.
//!
//! See `AR_T3_T4_BREAKER_HEDGING.md` Part 2 (ADAPTIVE_ROUTING_PLANE.md §5.4).
//!
//! **Stub:** all method bodies are `todo!()` — to be implemented in the
//! T3-T4 build phase.

use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::Mutex;

/// Per-peer concurrency limit (bulkhead). Calls beyond `max_inflight`
/// are rejected so the router can skip to the next candidate.
pub struct ConcurrencyLimit {
    max_inflight: u32,
    current: AtomicU32,
}

impl ConcurrencyLimit {
    /// Create a new limit capped at `max_inflight` concurrent requests.
    pub fn new(max_inflight: u32) -> Self {
        Self {
            max_inflight,
            current: AtomicU32::new(0),
        }
    }

    /// Try to acquire a slot. Returns `true` if admitted, `false` if at
    /// capacity. Uses a compare-exchange CAS loop.
    pub fn acquire(&self) -> bool {
        todo!("implement try_acquire CAS loop per AR_T3_T4 §5.4")
    }

    /// Release a slot. Called on response or error.
    pub fn release(&self) {
        todo!("implement release per AR_T3_T4 §5.4")
    }

    /// Current number of in-flight requests.
    pub fn count(&self) -> u32 {
        todo!("implement current_inflight load per AR_T3_T4 §5.4")
    }

    /// The configured maximum.
    pub fn max_inflight(&self) -> u32 {
        self.max_inflight
    }
}

/// Registry of per-peer concurrency limits.
pub struct BulkheadRegistry {
    limits: Mutex<HashMap<AgentId, ConcurrencyLimit>>,
    default_max: u32,
}

impl BulkheadRegistry {
    /// Create a new registry; each peer gets a limit of `default_max`.
    pub fn new(default_max: u32) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            default_max,
        }
    }

    /// Try to acquire a slot for `agent_id`, creating the per-peer limit
    /// lazily on first use.
    pub fn acquire(&self, agent_id: &AgentId) -> bool {
        let _ = agent_id;
        todo!("implement per-peer try_acquire per AR_T3_T4 §5.4")
    }

    /// Release a slot for `agent_id`.
    pub fn release(&self, agent_id: &AgentId) {
        let _ = agent_id;
        todo!("implement per-peer release per AR_T3_T4 §5.4")
    }

    /// Current in-flight count for `agent_id` (0 if unknown).
    pub fn count(&self, agent_id: &AgentId) -> u32 {
        let _ = agent_id;
        todo!("implement per-peer count per AR_T3_T4 §5.4")
    }
}
