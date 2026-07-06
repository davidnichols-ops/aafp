//! Local secondary indexes over AgentRecord extension data (Phase E5, §10.2).
//!
//! Built from DHT discovery results. The DHT itself remains keyed only by
//! capability name — all multi-dimensional filtering happens here, locally,
//! after retrieval.
//!
//! This is a stub module — function bodies are `todo!()` and will be
//! implemented in a subsequent build phase.

use aafp_identity::AgentId;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Local secondary index built from discovered AgentRecords.
///
/// Indexes are rebuilt (or incrementally updated) as records are discovered
/// via DHT lookups. They enable O(1) or O(log n) filtering by geo,
/// performance, and reputation without scanning all records.
#[derive(Debug, Default)]
pub struct ExtensionIndex {
    /// Country code -> AgentIds (exact match, O(1)).
    pub by_country: HashMap<String, HashSet<AgentId>>,
    /// Continent code -> AgentIds (exact match, O(1)).
    pub by_continent: HashMap<String, HashSet<AgentId>>,
    /// Latency (ms) -> AgentIds (range query via BTreeMap, O(log n)).
    pub by_latency_ms: BTreeMap<u16, HashSet<AgentId>>,
    /// Uptime (basis points) -> AgentIds (range query, O(log n)).
    pub by_uptime_bps: BTreeMap<u16, HashSet<AgentId>>,
    /// Self-claimed trust score (0-100) -> AgentIds (range query, O(log n)).
    pub by_reputation_score: BTreeMap<u8, HashSet<AgentId>>,
    /// AgentIds with heartbeat extensions (for liveness filtering).
    pub with_heartbeat: HashSet<AgentId>,
    /// Total indexed records.
    record_count: usize,
}

impl ExtensionIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build index from a set of discovered records.
    ///
    /// Records without extensions are counted but not indexed in any
    /// secondary index. They are still discoverable via the primary
    /// capability index.
    ///
    /// # Stub
    /// This is a stub — the full build logic iterating over records and
    /// populating each index map will be implemented in a subsequent phase.
    pub fn build_from_records(records: &[&aafp_identity::AgentRecordV1]) -> Self {
        let _ = records;
        todo!("build_from_records: iterate records, populate by_country/by_continent/by_latency_ms/by_uptime_bps/by_reputation_score/with_heartbeat")
    }

    /// Query agents by geographic location (country and/or continent).
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn query_by_geo(&self, country: Option<&str>, continent: Option<&str>) -> Vec<AgentId> {
        let _ = (country, continent);
        todo!("query_by_geo: intersect by_country and by_continent sets")
    }

    /// Query agents with avg latency <= `max_latency_ms`.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn query_by_latency(&self, max_latency_ms: u16) -> Vec<AgentId> {
        let _ = max_latency_ms;
        todo!("query_by_latency: range query on by_latency_ms BTreeMap (..=max_latency_ms)")
    }

    /// Query agents with reputation score >= `min_score`.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn query_by_reputation(&self, min_score: u8) -> Vec<AgentId> {
        let _ = min_score;
        todo!("query_by_reputation: range query on by_reputation_score BTreeMap (min_score..)")
    }

    /// Total indexed records.
    pub fn len(&self) -> usize {
        self.record_count
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.record_count == 0
    }
}
