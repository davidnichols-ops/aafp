//! Local secondary indexes over discovered semantic capabilities (D3).
//!
//! Built from DHT lookup results; the DHT itself stays simple (keyed by
//! capability name). All multi-dimensional filtering happens here.
//!
//! This is a pre-build scaffold: method bodies are `todo!()` and will be
//! implemented by the D3 builder.

use crate::semantic::{CapabilityQuery, Modality, SemanticCapability};
use aafp_identity::AgentId;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

// NOTE: `ordered-float` is required for `by_latency` (BTreeMap key). The D3
// builder must add `ordered-float = "4"` to Cargo.toml. Until then this file
// will not compile; that is expected for this scaffolding stage.
use ordered_float::OrderedFloat;

/// A discovered capability record: the semantic descriptor plus the agent
/// that provides it and when the index entry was created (for TTL eviction).
#[derive(Clone, Debug)]
pub struct IndexedCapability {
    /// The semantic capability descriptor.
    pub capability: SemanticCapability,
    /// The agent providing this capability.
    pub agent_id: AgentId,
    /// When the record was inserted into the local index (for TTL eviction).
    pub inserted_at: Instant,
}

/// Eviction / sizing policy for the local index.
#[derive(Clone, Debug)]
pub struct IndexConfig {
    /// Records older than this are evicted on [`CapabilityIndex::evict_expired`].
    pub ttl: Duration,
    /// Hard cap on total records; `insert()` evicts oldest when exceeded.
    pub max_size: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300), // 5 minutes
            max_size: 10_000,
        }
    }
}

/// Local multi-dimensional index over discovered capabilities.
///
/// Primary index is by capability name (mirrors the DHT key). Secondary
/// indexes accelerate the common filter dimensions: language, modality,
/// latency (range queries via [`BTreeMap`]), and trust score (range queries
/// via [`BTreeMap`]). Each secondary index maps an attribute value to the set
/// of capability *names* that carry it; the names resolve back to records in
/// [`by_name`](Self::by_name), avoiding duplicated `SemanticCapability` storage.
pub struct CapabilityIndex {
    /// name → indexed records (one name may have multiple providers).
    by_name: HashMap<String, Vec<IndexedCapability>>,
    /// language → set of capability names that support it.
    by_language: HashMap<String, HashSet<String>>,
    /// modality → set of capability names that support it.
    by_modality: HashMap<Modality, HashSet<String>>,
    /// avg_latency_ms (ordered) → set of capability names.
    by_latency: BTreeMap<OrderedFloat<f64>, HashSet<String>>,
    /// trust_score → set of capability names.
    by_trust: BTreeMap<u8, HashSet<String>>,
    /// Total record count (sum of `by_name` vec lengths).
    len: usize,
    /// Eviction / sizing configuration.
    config: IndexConfig,
}

impl Default for CapabilityIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityIndex {
    /// Create an empty index with the default [`IndexConfig`].
    pub fn new() -> Self {
        Self::with_config(IndexConfig::default())
    }

    /// Create an empty index with a custom [`IndexConfig`].
    pub fn with_config(config: IndexConfig) -> Self {
        Self {
            by_name: HashMap::new(),
            by_language: HashMap::new(),
            by_modality: HashMap::new(),
            by_latency: BTreeMap::new(),
            by_trust: BTreeMap::new(),
            len: 0,
            config,
        }
    }

    /// Current configuration (read-only).
    pub fn config(&self) -> &IndexConfig {
        &self.config
    }

    /// Total number of indexed records across all capability names.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the index holds no records.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert a single discovered capability, updating all secondary indexes.
    /// If `max_size` is exceeded after insert, evict the oldest records.
    pub fn insert(&mut self, record: IndexedCapability) {
        todo!("D3: insert record into by_name and update by_language/by_modality/by_latency/by_trust; enforce max_size via evict_oldest()")
    }

    /// Bulk-insert from a DHT discovery round. More efficient than repeated
    /// [`insert`](Self::insert) because secondary indexes are rebuilt once at
    /// the end.
    pub fn insert_batch(&mut self, records: Vec<IndexedCapability>) {
        todo!("D3: bulk insert records and rebuild secondary indexes in one pass")
    }

    /// Look up all records for a capability name.
    pub fn get_by_name(&self, name: &str) -> &[IndexedCapability] {
        todo!("D3: return by_name.get(name) slice or empty")
    }

    /// All records supporting a given language.
    pub fn get_by_language(&self, lang: &str) -> Vec<&IndexedCapability> {
        todo!("D3: resolve by_language[lang] names back to records in by_name")
    }

    /// All records supporting a given modality.
    pub fn get_by_modality(&self, m: &Modality) -> Vec<&IndexedCapability> {
        todo!("D3: resolve by_modality[m] names back to records in by_name")
    }

    /// Records with `avg_latency_ms <= max_ms` (BTreeMap range scan).
    pub fn get_by_latency_max(&self, max_ms: f64) -> Vec<&IndexedCapability> {
        todo!("D3: BTreeMap range scan ..=OrderedFloat(max_ms) on by_latency")
    }

    /// Records with `trust_score >= min` (BTreeMap range scan).
    pub fn get_by_trust_min(&self, min: u8) -> Vec<&IndexedCapability> {
        todo!("D3: BTreeMap range scan min.. on by_trust")
    }

    /// Evaluate a [`CapabilityQuery`] against the index, using secondary
    /// indexes to prune candidates before applying full per-record filter
    /// evaluation. Returns matching records ranked by match score (descending).
    pub fn query(&self, q: &CapabilityQuery) -> Vec<&IndexedCapability> {
        todo!("D3: start from by_name[q.name], intersect secondary indexes per QueryFilter, apply per-record predicates, rank by match_score()")
    }

    /// Remove records older than `config.ttl`. Returns the count evicted.
    /// Prunes evicted names from every secondary index set.
    pub fn evict_expired(&mut self) -> usize {
        todo!("D3: walk by_name, drop entries where inserted_at + ttl < now; prune secondary indexes; return count")
    }

    /// Evict oldest records until `len <= config.max_size`. Tracks insertion
    /// order via `inserted_at`; ties broken by agent_id for determinism.
    fn evict_oldest(&mut self) {
        todo!("D3: remove globally-oldest IndexedCapability records until len <= max_size, updating all indexes")
    }

    /// Remove a specific `(agent_id, capability name)` entry and update indexes.
    pub fn remove(&mut self, agent_id: &AgentId, name: &str) {
        todo!("D3: remove the matching record from by_name and prune secondary indexes")
    }
}
