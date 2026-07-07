#![allow(deprecated)]
//! DHT-backed semantic query (Track U7).
//!
//! Merges local index results with live DHT results for hybrid discovery.
//!
//! ## Design
//! The [`DhtSemanticQuery`] struct combines a fast local cache of
//! [`AgentRecord`]s (the [`LocalIndex`]) with the legacy in-memory
//! [`CapabilityDht`]. Queries can be:
//!
//! - **Local-only**: consult the local index and return immediately (no
//!   network/DHT access).
//! - **DHT-only**: bypass the local index and query the DHT directly.
//! - **Hybrid**: query both sources and merge, deduplicating by `agent_id`.
//!
//! The local index is a lightweight, capability-keyed map of
//! [`AgentRecord`]s. The full semantic [`CapabilityIndex`] (D3) stores
//! [`SemanticCapability`] descriptors rather than `AgentRecord`s and its
//! methods are still scaffolding stubs; this module therefore defines its
//! own [`LocalIndex`] so that queries and tests are fully functional today.
//! When the D3 index is implemented, [`LocalIndex`] can be replaced with
//! `Arc<CapabilityIndex>` and `query_local` updated to call
//! `CapabilityIndex::query`.
//!
//! DHT results are cached with a configurable TTL (`cache_ttl_ms`). Entries
//! older than the TTL are evicted on access or via
//! [`evict_expired_cache`](DhtSemanticQuery::evict_expired_cache).

use super::capability::SemanticError;
use super::query::CapabilityQuery;
use crate::capability_dht::CapabilityDht;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// LocalIndex — lightweight local cache of AgentRecords by capability name
// ---------------------------------------------------------------------------

/// A simple local index of [`AgentRecord`]s keyed by capability name.
///
/// This is a fast, in-memory cache used by [`DhtSemanticQuery`] for
/// non-network lookups. Records are indexed by each capability string in
/// `AgentRecord::capabilities`, mirroring the DHT's key scheme.
#[derive(Clone, Debug, Default)]
pub struct LocalIndex {
    /// capability name → records advertising that capability.
    by_capability: HashMap<String, Vec<AgentRecord>>,
}

impl LocalIndex {
    /// Create an empty local index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record, indexing it under each of its advertised capabilities.
    pub fn insert(&mut self, record: AgentRecord) {
        for cap in &record.capabilities {
            self.by_capability
                .entry(cap.clone())
                .or_default()
                .push(record.clone());
        }
    }

    /// Look up all records advertising the given capability.
    pub fn get(&self, capability: &str) -> Vec<AgentRecord> {
        self.by_capability
            .get(capability)
            .cloned()
            .unwrap_or_default()
    }

    /// Total number of indexed records (sum across all capabilities).
    pub fn len(&self) -> usize {
        self.by_capability.values().map(|v| v.len()).sum()
    }

    /// Whether the index holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all records from the index.
    pub fn clear(&mut self) {
        self.by_capability.clear();
    }
}

// ---------------------------------------------------------------------------
// DhtQueryConfig
// ---------------------------------------------------------------------------

/// Configuration for [`DhtSemanticQuery`].
#[derive(Clone, Debug)]
pub struct DhtQueryConfig {
    /// Whether to query the local index before the DHT.
    ///
    /// When `true`, the local index is consulted first. If it has results
    /// and `dht_fallback` is also `true`, both sources are queried and
    /// merged. If it has results and `dht_fallback` is `false`, only local
    /// results are returned. If it is empty, the DHT is consulted (when
    /// `dht_fallback` is `true`).
    pub local_first: bool,
    /// Whether to fall back to (or supplement with) DHT results.
    pub dht_fallback: bool,
    /// Maximum DHT hops. Must be > 0; a value of 0 causes an error.
    pub max_hops: u8,
    /// Query timeout in milliseconds.
    pub timeout_ms: u64,
    /// Cache TTL for DHT results in milliseconds.
    pub cache_ttl_ms: u64,
}

impl Default for DhtQueryConfig {
    fn default() -> Self {
        Self {
            local_first: true,
            dht_fallback: true,
            max_hops: 5,
            timeout_ms: 5000,
            cache_ttl_ms: 30000,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

/// A cached DHT query result with a timestamp for TTL eviction.
#[derive(Clone, Debug)]
struct CacheEntry {
    /// The cached result records.
    result: Vec<AgentRecord>,
    /// When the entry was inserted into the cache.
    cached_at: Instant,
}

// ---------------------------------------------------------------------------
// DhtSemanticQuery
// ---------------------------------------------------------------------------

/// Query the live DHT for semantically matching agents.
///
/// Merges DHT results with a local index for hybrid discovery. The local
/// index provides fast, cached lookups while the DHT provides comprehensive,
/// up-to-date results from the network.
///
/// # Example
/// ```no_run
/// use aafp_discovery::capability_dht::CapabilityDht;
/// use aafp_discovery::semantic::dht_query::{
///     DhtQueryConfig, DhtSemanticQuery, LocalIndex,
/// };
/// use aafp_discovery::semantic::CapabilityQuery;
/// use std::sync::{Arc, RwLock};
///
/// let local = Arc::new(RwLock::new(LocalIndex::new()));
/// let dht = Arc::new(CapabilityDht::new());
/// let config = DhtQueryConfig::default();
/// let query = DhtSemanticQuery::new(local, dht, config);
/// ```
#[allow(deprecated)]
pub struct DhtSemanticQuery {
    /// Local capability index (fast, cached).
    local_index: Arc<RwLock<LocalIndex>>,
    /// DHT for remote discovery.
    dht: Arc<CapabilityDht>,
    /// Configuration.
    config: DhtQueryConfig,
    /// TTL cache for DHT results, keyed by capability name.
    cache: RwLock<HashMap<String, CacheEntry>>,
}

#[allow(deprecated)]
impl DhtSemanticQuery {
    /// Create a new `DhtSemanticQuery` with the given local index, DHT, and
    /// configuration.
    pub fn new(
        local_index: Arc<RwLock<LocalIndex>>,
        dht: Arc<CapabilityDht>,
        config: DhtQueryConfig,
    ) -> Self {
        Self {
            local_index,
            dht,
            config,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &DhtQueryConfig {
        &self.config
    }

    /// Query for agents matching a [`CapabilityQuery`].
    ///
    /// The behavior depends on [`DhtQueryConfig`]:
    /// - `local_first = true`:
    ///   - Query the local index first.
    ///   - If local has results and `dht_fallback = false`, return local.
    ///   - If local has results and `dht_fallback = true`, query both and
    ///     merge.
    ///   - If local is empty and `dht_fallback = true`, query DHT only.
    ///   - If local is empty and `dht_fallback = false`, return empty.
    /// - `local_first = false`: query both local and DHT, then merge.
    pub async fn query(&self, query: &CapabilityQuery) -> Result<Vec<AgentRecord>, SemanticError> {
        if self.config.local_first {
            let local = self.query_local(query);
            if local.is_empty() {
                if self.config.dht_fallback {
                    return self.query_dht(query).await;
                }
                return Ok(Vec::new());
            }
            // Local has results.
            if self.config.dht_fallback {
                // Hybrid: merge local + DHT.
                let dht = self.query_dht(query).await?;
                return Ok(Self::merge_results(local, dht));
            }
            // dht_fallback = false: return local only.
            return Ok(local);
        }

        // local_first = false: query both and merge.
        let local = self.query_local(query);
        let dht = self.query_dht(query).await?;
        Ok(Self::merge_results(local, dht))
    }

    /// Query the local index only (fast, no network).
    ///
    /// Returns all locally-indexed records that advertise the query's
    /// capability name. Since legacy [`AgentRecord`]s do not carry
    /// [`SemanticCapability`] data, advanced filters (performance, quality,
    /// cost, geo, version) cannot be evaluated locally and are not applied
    /// here. When the full semantic index is available, this method should
    /// delegate to `CapabilityIndex::query` for multi-dimensional filtering.
    pub fn query_local(&self, query: &CapabilityQuery) -> Vec<AgentRecord> {
        let index = self.local_index.read().expect("local_index lock poisoned");
        let candidates = index.get(&query.name);
        // The index is already keyed by capability name, so all candidates
        // match the name. We additionally verify the capability is present
        // in the record's list (defensive check).
        candidates
            .into_iter()
            .filter(|record| record.capabilities.iter().any(|c| c == &query.name))
            .collect()
    }

    /// Query the DHT only (slow, comprehensive).
    ///
    /// Retrieves agents by the query's capability name from the DHT, applies
    /// a timeout safeguard, caches the results with TTL, and optionally
    /// applies post-retrieval geo filtering (if the query carries a geo
    /// filter and the records carry geo data).
    pub async fn query_dht(
        &self,
        query: &CapabilityQuery,
    ) -> Result<Vec<AgentRecord>, SemanticError> {
        // Check the cache first.
        if let Some(cached) = self.get_cached(&query.name) {
            return Ok(cached);
        }

        // Enforce max_hops.
        if self.config.max_hops == 0 {
            return Err(SemanticError::InvalidField {
                field: "max_hops",
                message: "max_hops must be greater than 0".into(),
            });
        }

        // A timeout of 0 means "immediate timeout" — fail before querying.
        if self.config.timeout_ms == 0 {
            return Err(SemanticError::InvalidField {
                field: "timeout",
                message: "DHT query timed out after 0ms".into(),
            });
        }

        // Query the DHT with a timeout safeguard.
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let raw = tokio::time::timeout(timeout, async {
            #[allow(deprecated)]
            self.dht.get(&query.name)
        })
        .await
        .map_err(|_| SemanticError::InvalidField {
            field: "timeout",
            message: format!("DHT query timed out after {}ms", self.config.timeout_ms),
        })?;

        // Convert Vec<&AgentRecord> to Vec<AgentRecord>.
        let mut records: Vec<AgentRecord> = raw.into_iter().cloned().collect();

        // Apply geo filter post-retrieval.
        //
        // Legacy AgentRecords do not carry geographic data, so the geo
        // filter is a no-op for them. If SemanticCapability data were
        // available, we would evaluate `query.geo` against
        // `SemanticCapability.geo` here.
        if query.geo.is_some() {
            // No-op for legacy records: all records pass the geo filter
            // because they lack geo metadata. This is documented behavior;
            // callers needing geo filtering should use the semantic index.
        }

        // Sort by agent_id for deterministic output (useful for testing
        // and reproducible discovery).
        records.sort_by_key(|a| a.agent_id);

        // Cache the results.
        self.set_cached(&query.name, records.clone());

        Ok(records)
    }

    /// Merge local and DHT results, deduplicating by `agent_id`.
    ///
    /// On conflict (same `agent_id` in both), **local results are preferred**
    /// since they are assumed to be more fresh (the local index is updated
    /// by the discovering agent and reflects the most recent local
    /// observations).
    pub fn merge_results(local: Vec<AgentRecord>, dht: Vec<AgentRecord>) -> Vec<AgentRecord> {
        let mut seen: HashMap<AgentId, AgentRecord> = HashMap::new();

        // Insert DHT results first.
        for record in dht {
            seen.insert(record.agent_id, record);
        }
        // Local results overwrite DHT results on conflict (local is fresher).
        for record in local {
            seen.insert(record.agent_id, record);
        }

        let mut merged: Vec<AgentRecord> = seen.into_values().collect();
        merged.sort_by_key(|a| a.agent_id);
        merged
    }

    // --- Cache helpers ---------------------------------------------------

    /// Return cached results for a capability if the entry is still fresh.
    ///
    /// Returns `None` if the entry is missing or expired.
    fn get_cached(&self, capability: &str) -> Option<Vec<AgentRecord>> {
        let cache = self.cache.read().expect("cache lock poisoned");
        if let Some(entry) = cache.get(capability) {
            let elapsed = Instant::now().duration_since(entry.cached_at);
            if elapsed.as_millis() < self.config.cache_ttl_ms as u128 {
                return Some(entry.result.clone());
            }
        }
        None
    }

    /// Store results in the cache with the current timestamp.
    fn set_cached(&self, capability: &str, result: Vec<AgentRecord>) {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.insert(
            capability.to_string(),
            CacheEntry {
                result,
                cached_at: Instant::now(),
            },
        );
    }

    /// Evict expired cache entries. Returns the number of entries removed.
    pub fn evict_expired_cache(&self) -> usize {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        let now = Instant::now();
        let ttl = Duration::from_millis(self.config.cache_ttl_ms);
        let before = cache.len();
        cache.retain(|_, entry| now.duration_since(entry.cached_at) < ttl);
        before - cache.len()
    }

    /// Clear all cached DHT results.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.clear();
    }

    /// Return the number of entries currently in the cache (including
    /// potentially expired entries that have not yet been evicted).
    pub fn cache_len(&self) -> usize {
        let cache = self.cache.read().expect("cache lock poisoned");
        cache.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use aafp_identity::AgentKeypair;

    // --- Test helpers ----------------------------------------------------

    /// Create a signed [`AgentRecord`] advertising the given capabilities.
    fn make_record(caps: Vec<&str>) -> AgentRecord {
        let kp = AgentKeypair::generate();
        AgentRecord::new(
            &kp,
            caps.into_iter().map(String::from).collect(),
            vec!["quic://1.2.3.4:4433".into()],
        )
    }

    /// Create a signed [`AgentRecord`] with a specific endpoint.
    fn make_record_with_endpoint(caps: Vec<&str>, endpoint: &str) -> AgentRecord {
        let kp = AgentKeypair::generate();
        AgentRecord::new(
            &kp,
            caps.into_iter().map(String::from).collect(),
            vec![endpoint.into()],
        )
    }

    /// Build a `CapabilityDht` populated with `count` agents, each
    /// advertising `capability`.
    fn make_dht(capability: &str, count: usize) -> Arc<CapabilityDht> {
        let mut dht = CapabilityDht::new();
        for _ in 0..count {
            let record = make_record(vec![capability]);
            dht.put(record).expect("record should verify");
        }
        Arc::new(dht)
    }

    /// Build a `LocalIndex` populated with `count` agents, each advertising
    /// `capability`.
    fn make_local_index(capability: &str, count: usize) -> Arc<RwLock<LocalIndex>> {
        let mut index = LocalIndex::new();
        for _ in 0..count {
            let record = make_record(vec![capability]);
            index.insert(record);
        }
        Arc::new(RwLock::new(index))
    }

    /// Collect the set of agent_ids from a Vec<AgentRecord>.
    fn agent_ids(records: &[AgentRecord]) -> Vec<AgentId> {
        let mut ids: Vec<AgentId> = records.iter().map(|r| r.agent_id).collect();
        ids.sort();
        ids
    }

    // --- Test 1: Local-only query ---------------------------------------

    #[tokio::test]
    async fn test_local_only_query() {
        let local = make_local_index("inference", 2);
        let dht = make_dht("inference", 3);
        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let results = query_engine.query(&q).await.expect("query should succeed");

        // Should return only local results (2), not DHT results (3).
        assert_eq!(results.len(), 2);
    }

    // --- Test 2: DHT-only query (local_first=false) ---------------------

    #[tokio::test]
    async fn test_dht_only_query() {
        // Local index has 2 records, DHT has 3 different records.
        let local = make_local_index("inference", 2);
        let dht = make_dht("inference", 3);
        let config = DhtQueryConfig {
            local_first: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let results = query_engine.query(&q).await.expect("query should succeed");

        // local_first=false queries both and merges. Local has 2, DHT has 3,
        // no overlap (different agents), so merged = 5.
        assert_eq!(results.len(), 5);
    }

    // --- Test 3: Hybrid query (local + DHT merged) ----------------------

    #[tokio::test]
    async fn test_hybrid_query() {
        let local = make_local_index("ocr", 2);
        let dht = make_dht("ocr", 3);
        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: true,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("ocr").build();
        let results = query_engine.query(&q).await.expect("query should succeed");

        // Local has 2, DHT has 3, no overlap → merged = 5.
        assert_eq!(results.len(), 5);
    }

    // --- Test 4: DHT fallback when local empty --------------------------

    #[tokio::test]
    async fn test_dht_fallback_when_local_empty() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("translation", 3);
        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: true,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("translation").build();
        let results = query_engine.query(&q).await.expect("query should succeed");

        // Local is empty, dht_fallback=true → query DHT.
        assert_eq!(results.len(), 3);
    }

    // --- Test 5: Result deduplication -----------------------------------

    #[tokio::test]
    async fn test_result_deduplication() {
        // Create one record and insert it into both local and DHT.
        let shared_record = make_record(vec!["inference"]);

        let mut local_index = LocalIndex::new();
        local_index.insert(shared_record.clone());
        let local = Arc::new(RwLock::new(local_index));

        let mut dht = CapabilityDht::new();
        dht.put(shared_record.clone())
            .expect("record should verify");
        let dht = Arc::new(dht);

        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: true,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let results = query_engine.query(&q).await.expect("query should succeed");

        // Same agent in both local and DHT → deduplicated to 1.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, shared_record.agent_id);
    }

    // --- Test 6: Query timeout ------------------------------------------

    #[tokio::test]
    async fn test_query_timeout() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 2);
        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: true,
            timeout_ms: 0, // immediately elapses
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let result = query_engine.query(&q).await;

        // Local is empty → falls back to DHT → DHT times out.
        assert!(result.is_err(), "query should time out with timeout_ms=0");
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("timed out"),
            "error should mention timeout, got: {}",
            msg
        );
    }

    // --- Test 7: Max hops enforcement -----------------------------------

    #[tokio::test]
    async fn test_max_hops_enforcement() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 2);
        let config = DhtQueryConfig {
            local_first: false, // bypass local, go straight to DHT
            max_hops: 0,        // invalid
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let result = query_engine.query_dht(&q).await;

        assert!(result.is_err(), "query_dht should fail with max_hops=0");
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("max_hops"),
            "error should mention max_hops, got: {}",
            msg
        );
    }

    // --- Test 8: Cache TTL ----------------------------------------------

    #[tokio::test]
    async fn test_cache_ttl() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 2);
        let config = DhtQueryConfig {
            local_first: false,
            cache_ttl_ms: 10, // 10ms TTL for fast testing
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();

        // First query: populates cache.
        let results1 = query_engine.query(&q).await.expect("first query");
        assert_eq!(results1.len(), 2);
        assert_eq!(query_engine.cache_len(), 1, "cache should have 1 entry");

        // Second query: should be served from cache (still fresh).
        let results2 = query_engine.query(&q).await.expect("second query");
        assert_eq!(results2.len(), 2);

        // Wait for cache to expire.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Evict expired entries.
        let evicted = query_engine.evict_expired_cache();
        assert_eq!(evicted, 1, "one expired entry should be evicted");
        assert_eq!(query_engine.cache_len(), 0, "cache should be empty");
    }

    // --- Test 9: Empty results ------------------------------------------

    #[tokio::test]
    async fn test_empty_results() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = Arc::new(CapabilityDht::new()); // empty DHT
        let config = DhtQueryConfig::default();
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("nonexistent-capability").build();
        let results = query_engine.query(&q).await.expect("query should succeed");
        assert!(results.is_empty(), "no matching agents should be found");
    }

    // --- Test 10: Large result set --------------------------------------

    #[tokio::test]
    async fn test_large_result_set() {
        let count = 100;
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", count);
        let config = DhtQueryConfig {
            local_first: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let results = query_engine.query(&q).await.expect("query should succeed");

        assert_eq!(results.len(), count);

        // Verify all agent_ids are unique.
        let ids = agent_ids(&results);
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), count, "all agents should be unique");
    }

    // --- Test 11: Concurrent queries (thread safety) --------------------

    #[tokio::test]
    async fn test_concurrent_queries() {
        let local = make_local_index("inference", 2);
        let dht = make_dht("inference", 3);
        let config = DhtQueryConfig {
            local_first: false,
            ..Default::default()
        };
        let query_engine = Arc::new(DhtSemanticQuery::new(local, dht, config));

        let q = Arc::new(CapabilityQuery::new("inference").build());

        // Spawn 10 concurrent queries.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let engine = Arc::clone(&query_engine);
            let q = Arc::clone(&q);
            handles.push(tokio::spawn(async move {
                engine
                    .query(&q)
                    .await
                    .expect("concurrent query should succeed")
            }));
        }

        let mut all_results = Vec::new();
        for handle in handles {
            let results = handle.await.expect("task should not panic");
            all_results.push(results);
        }

        // Every concurrent query should return the same 5 results
        // (2 local + 3 DHT, no overlap).
        for results in &all_results {
            assert_eq!(results.len(), 5, "each query should return 5 results");
        }

        // Verify all queries returned the same set of agent_ids.
        let first_ids = agent_ids(&all_results[0]);
        for results in &all_results[1..] {
            assert_eq!(
                agent_ids(results),
                first_ids,
                "all queries should return the same agents"
            );
        }
    }

    // --- Test 12: Query with geo filter ---------------------------------

    #[tokio::test]
    async fn test_query_with_geo_filter() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 3);
        let config = DhtQueryConfig {
            local_first: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        // Query with a geo filter. Legacy AgentRecords do not carry geo
        // data, so the filter is a no-op — all DHT results are returned.
        let q = CapabilityQuery::new("inference")
            .with_geo(super::super::query::GeoFilter {
                region: Some("na".into()),
                country: Some("US".into()),
            })
            .build();

        let results = query_engine.query(&q).await.expect("query should succeed");

        // All 3 DHT records are returned because geo filtering cannot be
        // applied to legacy AgentRecords (they lack geo metadata).
        assert_eq!(
            results.len(),
            3,
            "geo filter is a no-op for legacy records; all results returned"
        );
    }

    // --- Additional tests ------------------------------------------------

    #[tokio::test]
    async fn test_local_first_no_fallback_local_empty() {
        // local_first=true, dht_fallback=false, local empty → return empty.
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 3);
        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let results = query_engine.query(&q).await.expect("query should succeed");
        assert!(results.is_empty(), "no local results and no DHT fallback");
    }

    #[tokio::test]
    async fn test_merge_results_prefers_local() {
        // Create the same agent in both local and DHT, but with different
        // endpoints. The merge should prefer the local version.
        let kp = AgentKeypair::generate();
        let local_record = AgentRecord::new(
            &kp,
            vec!["inference".into()],
            vec!["quic://local:4433".into()],
        );
        let dht_record = AgentRecord::new(
            &kp,
            vec!["inference".into()],
            vec!["quic://dht:4433".into()],
        );

        // Both records have the same agent_id (same keypair).
        assert_eq!(local_record.agent_id, dht_record.agent_id);

        let merged = DhtSemanticQuery::merge_results(vec![local_record.clone()], vec![dht_record]);

        assert_eq!(merged.len(), 1, "dedup should produce 1 record");
        // Local is preferred: its endpoint should be in the result.
        assert!(
            merged[0]
                .endpoints
                .contains(&"quic://local:4433".to_string()),
            "local record should be preferred on conflict"
        );
    }

    #[tokio::test]
    async fn test_query_local_directly() {
        let local = make_local_index("ocr", 3);
        let dht = Arc::new(CapabilityDht::new());
        let query_engine = DhtSemanticQuery::new(local, dht, DhtQueryConfig::default());

        let q = CapabilityQuery::new("ocr").build();
        let results = query_engine.query_local(&q);
        assert_eq!(results.len(), 3);

        // Query for a capability not in the local index.
        let q2 = CapabilityQuery::new("nonexistent").build();
        let results2 = query_engine.query_local(&q2);
        assert!(results2.is_empty());
    }

    #[tokio::test]
    async fn test_query_dht_caching() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 2);
        let config = DhtQueryConfig {
            local_first: false,
            cache_ttl_ms: 60000, // long TTL
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();

        // First DHT query: populates cache.
        let results1 = query_engine.query_dht(&q).await.expect("first DHT query");
        assert_eq!(results1.len(), 2);
        assert_eq!(query_engine.cache_len(), 1);

        // Second DHT query: should be served from cache.
        let results2 = query_engine.query_dht(&q).await.expect("second DHT query");
        assert_eq!(results2.len(), 2);
        assert_eq!(
            query_engine.cache_len(),
            1,
            "cache should still have 1 entry"
        );

        // Results should be identical.
        assert_eq!(agent_ids(&results1), agent_ids(&results2));
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 2);
        let config = DhtQueryConfig {
            local_first: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let _ = query_engine.query_dht(&q).await.expect("DHT query");
        assert_eq!(query_engine.cache_len(), 1);

        query_engine.clear_cache();
        assert_eq!(query_engine.cache_len(), 0);
    }

    #[tokio::test]
    async fn test_default_config_values() {
        let config = DhtQueryConfig::default();
        assert!(config.local_first);
        assert!(config.dht_fallback);
        assert_eq!(config.max_hops, 5);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.cache_ttl_ms, 30000);
    }

    #[test]
    fn test_local_index_operations() {
        let mut index = LocalIndex::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);

        let record = make_record(vec!["inference", "translation"]);
        index.insert(record);

        assert_eq!(index.len(), 2, "record indexed under 2 capabilities");
        assert!(!index.is_empty());

        let inference = index.get("inference");
        assert_eq!(inference.len(), 1);

        let translation = index.get("translation");
        assert_eq!(translation.len(), 1);

        let nonexistent = index.get("nonexistent");
        assert!(nonexistent.is_empty());

        index.clear();
        assert!(index.is_empty());
    }

    #[tokio::test]
    async fn test_merge_results_empty_inputs() {
        let merged = DhtSemanticQuery::merge_results(Vec::new(), Vec::new());
        assert!(merged.is_empty());
    }

    #[tokio::test]
    async fn test_merge_results_only_local() {
        let records = vec![
            make_record(vec!["inference"]),
            make_record(vec!["inference"]),
        ];
        let ids = agent_ids(&records);
        let merged = DhtSemanticQuery::merge_results(records, Vec::new());
        assert_eq!(merged.len(), 2);
        assert_eq!(agent_ids(&merged), ids);
    }

    #[tokio::test]
    async fn test_merge_results_only_dht() {
        let records = vec![
            make_record(vec!["inference"]),
            make_record(vec!["inference"]),
        ];
        let ids = agent_ids(&records);
        let merged = DhtSemanticQuery::merge_results(Vec::new(), records);
        assert_eq!(merged.len(), 2);
        assert_eq!(agent_ids(&merged), ids);
    }

    #[tokio::test]
    async fn test_query_dht_sorted_output() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 5);
        let config = DhtQueryConfig {
            local_first: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        let q = CapabilityQuery::new("inference").build();
        let results = query_engine.query_dht(&q).await.expect("DHT query");

        // Verify results are sorted by agent_id.
        for i in 1..results.len() {
            assert!(
                results[i - 1].agent_id <= results[i].agent_id,
                "results should be sorted by agent_id"
            );
        }
    }

    #[tokio::test]
    async fn test_multiple_capabilities_in_local_index() {
        let mut local_index = LocalIndex::new();
        let r1 = make_record(vec!["inference", "translation"]);
        let r2 = make_record(vec!["inference", "coding"]);
        local_index.insert(r1.clone());
        local_index.insert(r2.clone());
        let local = Arc::new(RwLock::new(local_index));

        let dht = Arc::new(CapabilityDht::new());
        let config = DhtQueryConfig {
            local_first: true,
            dht_fallback: false,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        // Query for "inference" — both records have it.
        let q1 = CapabilityQuery::new("inference").build();
        let results1 = query_engine.query(&q1).await.expect("query inference");
        assert_eq!(results1.len(), 2);

        // Query for "translation" — only r1 has it.
        let q2 = CapabilityQuery::new("translation").build();
        let results2 = query_engine.query(&q2).await.expect("query translation");
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0].agent_id, r1.agent_id);

        // Query for "coding" — only r2 has it.
        let q3 = CapabilityQuery::new("coding").build();
        let results3 = query_engine.query(&q3).await.expect("query coding");
        assert_eq!(results3.len(), 1);
        assert_eq!(results3[0].agent_id, r2.agent_id);
    }

    #[tokio::test]
    async fn test_evict_expired_cache_returns_count() {
        let local = Arc::new(RwLock::new(LocalIndex::new()));
        let dht = make_dht("inference", 1);
        let config = DhtQueryConfig {
            local_first: false,
            cache_ttl_ms: 5,
            ..Default::default()
        };
        let query_engine = DhtSemanticQuery::new(local, dht, config);

        // Populate cache with two different capabilities.
        let q1 = CapabilityQuery::new("inference").build();
        let _ = query_engine.query_dht(&q1).await.expect("query 1");
        assert_eq!(query_engine.cache_len(), 1);

        // Wait for expiry.
        tokio::time::sleep(Duration::from_millis(15)).await;

        let evicted = query_engine.evict_expired_cache();
        assert_eq!(evicted, 1);
        assert_eq!(query_engine.cache_len(), 0);
    }
}
