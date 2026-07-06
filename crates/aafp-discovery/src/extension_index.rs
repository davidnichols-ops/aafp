//! Local secondary indexes over AgentRecord extension data.
//!
//! Built from DHT discovery results. The DHT itself remains keyed only by
//! capability name — all multi-dimensional filtering happens here, locally,
//! after records are retrieved from the DHT.
//!
//! See AGENT_RECORD_EXTENSIONS.md §10.2.

use aafp_identity::identity_v1::AgentId;
use aafp_identity::extensions::{
    GeoExtension, HeartbeatExtension, PerformanceExtension, ReputationExtension,
};
use aafp_identity::identity_v1::AgentRecord;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Local secondary index built from discovered AgentRecords.
///
/// Indexes are rebuilt (or incrementally updated) as records are discovered
/// via DHT lookups. They enable O(1) or O(log n) filtering by geo,
/// performance, and reputation without scanning all records.
#[derive(Debug, Default)]
pub struct ExtensionIndex {
    /// Country code → AgentIds (exact match, O(1))
    by_country: HashMap<String, HashSet<AgentId>>,
    /// Continent code → AgentIds (exact match, O(1))
    by_continent: HashMap<String, HashSet<AgentId>>,
    /// Latency (ms) → AgentIds (range query via BTreeMap, O(log n))
    by_latency_ms: BTreeMap<u16, HashSet<AgentId>>,
    /// Uptime (basis points) → AgentIds (range query, O(log n))
    by_uptime_bps: BTreeMap<u16, HashSet<AgentId>>,
    /// Self-claimed trust score (0-100) → AgentIds (range query, O(log n))
    by_reputation_score: BTreeMap<u8, HashSet<AgentId>>,
    /// AgentIds with heartbeat extensions (for liveness filtering)
    with_heartbeat: HashSet<AgentId>,
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
    /// secondary index. This is correct — they are still discoverable
    /// via the primary capability index.
    pub fn build(records: &[AgentRecord]) -> Self {
        let mut idx = Self::new();
        for r in records {
            idx.add_record(r);
        }
        idx
    }

    /// Add a single record to the index (incremental update).
    pub fn add_record(&mut self, record: &AgentRecord) {
        self.record_count += 1;
        let agent_id = record.agent_id;

        // Geo index
        if let Some(geo) = record.get_extension::<GeoExtension>() {
            if let Some(country) = &geo.country {
                self.by_country
                    .entry(country.clone())
                    .or_default()
                    .insert(agent_id);
            }
            if let Some(continent) = &geo.continent {
                self.by_continent
                    .entry(continent.clone())
                    .or_default()
                    .insert(agent_id);
            }
        }

        // Performance index
        if let Some(perf) = record.get_extension::<PerformanceExtension>() {
            if let Some(lat) = perf.avg_latency_ms {
                self.by_latency_ms.entry(lat).or_default().insert(agent_id);
            }
            if let Some(uptime) = perf.uptime_bps {
                self.by_uptime_bps
                    .entry(uptime)
                    .or_default()
                    .insert(agent_id);
            }
        }

        // Reputation index
        if let Some(rep) = record.get_extension::<ReputationExtension>() {
            if let Some(score) = rep.self_claimed_score {
                self.by_reputation_score
                    .entry(score)
                    .or_default()
                    .insert(agent_id);
            }
        }

        // Heartbeat tracking
        if record.get_extension::<HeartbeatExtension>().is_some() {
            self.with_heartbeat.insert(agent_id);
        }
    }

    /// Remove an agent from all indexes.
    pub fn remove_agent(&mut self, agent_id: &AgentId) {
        for set in self.by_country.values_mut() {
            set.remove(agent_id);
        }
        for set in self.by_continent.values_mut() {
            set.remove(agent_id);
        }
        for set in self.by_latency_ms.values_mut() {
            set.remove(agent_id);
        }
        for set in self.by_uptime_bps.values_mut() {
            set.remove(agent_id);
        }
        for set in self.by_reputation_score.values_mut() {
            set.remove(agent_id);
        }
        self.with_heartbeat.remove(agent_id);
        self.record_count = self.record_count.saturating_sub(1);
    }

    /// Find agents in a specific country.
    pub fn by_geo_country(&self, country: &str) -> Vec<AgentId> {
        self.by_country
            .get(country)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Find agents on a specific continent.
    pub fn by_geo_continent(&self, continent: &str) -> Vec<AgentId> {
        self.by_continent
            .get(continent)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Find agents with avg latency <= max_latency_ms.
    pub fn by_performance_latency(&self, max_latency_ms: u16) -> Vec<AgentId> {
        self.by_latency_ms
            .range(..=max_latency_ms)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect()
    }

    /// Find agents with uptime >= min_uptime_bps.
    pub fn by_performance_uptime(&self, min_uptime_bps: u16) -> Vec<AgentId> {
        self.by_uptime_bps
            .range(min_uptime_bps..)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect()
    }

    /// Find agents with reputation score >= min_score.
    pub fn by_reputation(&self, min_score: u8) -> Vec<AgentId> {
        self.by_reputation_score
            .range(min_score..)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect()
    }

    /// Find agents with heartbeat extensions (liveness-capable).
    pub fn with_heartbeat(&self) -> Vec<AgentId> {
        self.with_heartbeat.iter().copied().collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_identity::identity_v1::CapabilityDescriptor;
    use aafp_identity::extensions::{GeoExtension, PerformanceExtension, ReputationExtension};

    fn make_record(
        agent_id: AgentId,
        geo: Option<GeoExtension>,
        perf: Option<PerformanceExtension>,
        rep: Option<ReputationExtension>,
    ) -> AgentRecord {
        let mut record = AgentRecord::new(
            &[0u8; 1952],
            vec![CapabilityDescriptor::new("inference")],
            vec!["quic://1.2.3.4:4433".into()],
            1700000000,
            1700000000 + 86400,
            1,
        );
        record.agent_id = agent_id;
        if let Some(g) = geo {
            record.set_extension(g);
        }
        if let Some(p) = perf {
            record.set_extension(p);
        }
        if let Some(r) = rep {
            record.set_extension(r);
        }
        record
    }

    #[test]
    fn test_index_geo() {
        let mut idx = ExtensionIndex::new();
        idx.add_record(&make_record(
            AgentId([1u8; 32]),
            Some(GeoExtension {
                version: 1,
                country: Some("US".into()),
                continent: Some("NA".into()),
                ..Default::default()
            }),
            None,
            None,
        ));
        idx.add_record(&make_record(
            AgentId([2u8; 32]),
            Some(GeoExtension {
                version: 1,
                country: Some("DE".into()),
                continent: Some("EU".into()),
                ..Default::default()
            }),
            None,
            None,
        ));

        assert_eq!(idx.by_geo_country("US").len(), 1);
        assert_eq!(idx.by_geo_country("DE").len(), 1);
        assert_eq!(idx.by_geo_country("JP").len(), 0);
        assert_eq!(idx.by_geo_continent("NA").len(), 1);
        assert_eq!(idx.by_geo_continent("EU").len(), 1);
    }

    #[test]
    fn test_index_performance() {
        let mut idx = ExtensionIndex::new();
        idx.add_record(&make_record(
            AgentId([1u8; 32]),
            None,
            Some(PerformanceExtension {
                version: 1,
                avg_latency_ms: Some(10),
                uptime_bps: Some(9999),
                ..Default::default()
            }),
            None,
        ));
        idx.add_record(&make_record(
            AgentId([2u8; 32]),
            None,
            Some(PerformanceExtension {
                version: 1,
                avg_latency_ms: Some(200),
                uptime_bps: Some(9900),
                ..Default::default()
            }),
            None,
        ));

        assert_eq!(idx.by_performance_latency(50).len(), 1);
        assert_eq!(idx.by_performance_latency(500).len(), 2);
        assert_eq!(idx.by_performance_uptime(9990).len(), 1);
        assert_eq!(idx.by_performance_uptime(9800).len(), 2);
    }

    #[test]
    fn test_index_reputation() {
        let mut idx = ExtensionIndex::new();
        idx.add_record(&make_record(
            AgentId([1u8; 32]),
            None,
            None,
            Some(ReputationExtension {
                version: 1,
                self_claimed_score: Some(85),
                ..Default::default()
            }),
        ));
        idx.add_record(&make_record(
            AgentId([2u8; 32]),
            None,
            None,
            Some(ReputationExtension {
                version: 1,
                self_claimed_score: Some(30),
                ..Default::default()
            }),
        ));

        assert_eq!(idx.by_reputation(80).len(), 1);
        assert_eq!(idx.by_reputation(20).len(), 2);
    }

    #[test]
    fn test_index_remove_agent() {
        let mut idx = ExtensionIndex::new();
        idx.add_record(&make_record(
            AgentId([1u8; 32]),
            Some(GeoExtension {
                version: 1,
                country: Some("US".into()),
                ..Default::default()
            }),
            None,
            None,
        ));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.by_geo_country("US").len(), 1);

        idx.remove_agent(&AgentId([1u8; 32]));
        assert_eq!(idx.by_geo_country("US").len(), 0);
    }
}
