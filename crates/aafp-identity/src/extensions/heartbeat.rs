//! Heartbeat liveness updates for DHT-stored AgentRecords (Phase E5, §8.2.1).
//!
//! Agents with the HeartbeatExtension can send periodic heartbeat updates
//! to DHT nodes. The heartbeat is a lightweight signed message:
//!   ML-DSA-65(b"aafp-heartbeat" || agent_id || last_heartbeat)
//!
//! If the heartbeat is older than `interval_secs * 3`, the record is
//! considered *stale* (but not expired) and deprioritized in routing.
//!
//! This is a stub module — function bodies are `todo!()` and will be
//! implemented in a subsequent build phase.

use crate::AgentId;
use std::collections::HashMap;

/// Default heartbeat interval in seconds (5 minutes).
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u32 = 300;

/// Staleness multiplier: a record is stale if its heartbeat is older than
/// `interval_secs * STALENESS_MULTIPLIER`.
pub const STALENESS_MULTIPLIER: u64 = 3;

/// A heartbeat update message (separate from the full AgentRecord).
///
/// Carries only the agent ID, a timestamp, and a signature over
/// `b"aafp-heartbeat" || agent_id || timestamp`. This allows agents to
/// prove liveness without re-publishing the full record.
#[derive(Clone, Debug)]
pub struct HeartbeatUpdate {
    /// The agent this heartbeat belongs to.
    pub agent_id: AgentId,
    /// Unix timestamp (seconds) of this heartbeat.
    pub timestamp: u64,
    /// ML-DSA-65 signature over `b"aafp-heartbeat" || agent_id || timestamp`.
    pub signature: Vec<u8>,
}

impl HeartbeatUpdate {
    /// Create and sign a new heartbeat update.
    ///
    /// The signature is `ML-DSA-65(b"aafp-heartbeat" || agent_id || timestamp)`.
    ///
    /// # Stub
    /// This is a stub — signing logic will be implemented in a subsequent phase.
    pub fn sign_heartbeat(agent_id: &AgentId, timestamp: u64, secret_key: &[u8]) -> Self {
        let _ = secret_key;
        todo!("sign_heartbeat: implement ML-DSA-65 signing over b\"aafp-heartbeat\" || agent_id || timestamp")
    }

    /// Verify the heartbeat signature against the agent's public key.
    ///
    /// # Stub
    /// This is a stub — verification logic will be implemented in a subsequent phase.
    pub fn verify_heartbeat(&self, public_key: &[u8]) -> bool {
        let _ = public_key;
        todo!("verify_heartbeat: implement ML-DSA-65 verification")
    }
}

/// Tracks heartbeat freshness for DHT-stored records.
///
/// Maintains a map of `AgentId -> last_seen_timestamp` and provides
/// staleness checks based on a configurable interval. Records whose
/// heartbeat is older than `interval_secs * 3` are considered stale
/// and should be deprioritized in routing.
#[derive(Debug, Default)]
pub struct HeartbeatTracker {
    /// `AgentId -> last_seen` timestamp (Unix seconds).
    pub last_seen: HashMap<AgentId, u64>,
    /// Staleness threshold in seconds. A record is stale if
    /// `now - last_seen > staleness_threshold`.
    pub staleness_threshold_secs: u64,
}

impl HeartbeatTracker {
    /// Create a new tracker with the default staleness threshold.
    pub fn new() -> Self {
        Self {
            last_seen: HashMap::new(),
            staleness_threshold_secs: (DEFAULT_HEARTBEAT_INTERVAL_SECS as u64) * STALENESS_MULTIPLIER,
        }
    }

    /// Create a new tracker with a custom staleness threshold.
    pub fn with_threshold(staleness_threshold_secs: u64) -> Self {
        Self {
            last_seen: HashMap::new(),
            staleness_threshold_secs,
        }
    }

    /// Register a heartbeat update, returning `false` if the heartbeat
    /// is older than the last known one.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn update(&mut self, hb: &HeartbeatUpdate) -> bool {
        let _ = hb;
        todo!("update: register heartbeat, reject stale (older timestamp)")
    }

    /// Check if an agent's record is stale (heartbeat older than threshold).
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn is_stale(&self, agent_id: &AgentId, now: u64) -> bool {
        let _ = (agent_id, now);
        todo!("is_stale: check now - last_seen > staleness_threshold_secs")
    }

    /// Get the last heartbeat timestamp for an agent.
    pub fn last_heartbeat(&self, agent_id: &AgentId) -> Option<u64> {
        self.last_seen.get(agent_id).copied()
    }

    /// Evict heartbeat entries for agents that haven't heartbeaten in >24h.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn evict_stale(&mut self, now: u64) -> usize {
        let _ = now;
        todo!("evict_stale: remove entries older than 24h, return count")
    }
}

/// Compute the adaptive TTL for a record, considering heartbeat freshness
/// (Phase E5, §8.2.2).
///
/// Records with recent heartbeats (within `interval_secs`) get up to
/// `MAX_TTL_EXTENSION_SECS` of additional TTL. Records with stale heartbeats
/// (older than `3 * interval_secs`) get no extension. Records without
/// heartbeats use the base TTL from `expires_at - created_at`.
///
/// # Stub
/// This is a stub — the full adaptive TTL computation will be implemented
/// in a subsequent phase. The `record_expires_at`, `record_created_at`, and
/// `interval_secs` parameters provide the inputs needed for the computation.
pub fn adaptive_ttl(
    record_created_at: u64,
    record_expires_at: u64,
    heartbeat_tracker: &HeartbeatTracker,
    agent_id: &AgentId,
    interval_secs: u32,
    now: u64,
) -> u64 {
    let _ = (
        record_created_at,
        record_expires_at,
        heartbeat_tracker,
        agent_id,
        interval_secs,
        now,
    );
    todo!("adaptive_ttl: compute base TTL + heartbeat-based extension")
}
