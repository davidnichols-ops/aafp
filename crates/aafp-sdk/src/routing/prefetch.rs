//! Track T9 — Predictive Prefetcher.
//!
//! Predicts and pre-fetches likely-needed data/capabilities before an agent
//! actually requests them, reducing observed latency.
//!
//! The [`PredictivePrefetcher`] maintains:
//! - An LRU-bounded in-memory cache of pre-fetched resources ([`CacheEntry`]).
//! - Per-resource access histories ([`AccessPattern`]) used to predict which
//!   resources are likely to be accessed next.
//! - A simple frequency + recency scoring model that ranks candidate
//!   resources by predicted access probability.
//!
//! The prefetcher is *simulated* — there is no real network fetch. A fetch
//! is represented by storing placeholder bytes in the cache and recording
//! the simulated fetch time. This keeps the module fully deterministic and
//! testable without external dependencies.
//!
//! # CBOR Encoding
//!
//! [`PrefetchRequest`] and [`PrefetchResult`] support RFC 8949 deterministic
//! CBOR encoding via integer-keyed maps, consistent with the rest of the
//! execution fabric.

use crate::SdkError;
use aafp_cbor::{decode, encode, int_map, int_map_get, Value};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Simulated fetch latency (ms) applied to every pre-fetch operation.
const SIMULATED_FETCH_LATENCY_MS: u64 = 5;

// ──────────────────────────────────────────────────────────────────────
// PrefetchStatus
// ──────────────────────────────────────────────────────────────────────

/// Outcome of a prefetch attempt for a single resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefetchStatus {
    /// The resource was already present in the cache (fresh).
    Hit,
    /// The resource was not in the cache.
    Miss,
    /// The resource was successfully pre-fetched into the cache.
    Fetched,
    /// The fetch attempt failed.
    Failed,
    /// The resource was cached but its TTL had expired.
    Expired,
}

impl PrefetchStatus {
    /// Encode the status as a CBOR unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode a status from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let n = match val {
            Value::Unsigned(n) => *n,
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchStatus: expected unsigned integer".into(),
                ))
            }
        };
        match n {
            0 => Ok(Self::Hit),
            1 => Ok(Self::Miss),
            2 => Ok(Self::Fetched),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Expired),
            _ => Err(SdkError::Messaging(format!(
                "PrefetchStatus: unknown variant {n}"
            ))),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// PrefetchRequest
// ──────────────────────────────────────────────────────────────────────

/// A request to prefetch a single resource.
#[derive(Clone, Debug)]
pub struct PrefetchRequest {
    /// Opaque resource identifier (e.g. a capability URI or content hash).
    pub resource_id: String,
    /// Resource type tag (e.g. `"capability"`, `"blob"`).
    pub resource_type: String,
    /// Predicted time (ms since some epoch) at which the resource will be
    /// accessed. Used for scheduling and TTL decisions.
    pub predicted_access_time: u64,
    /// Priority of this prefetch (higher = more important).
    pub priority: u8,
}

impl PrefetchRequest {
    /// Encode the request as a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.resource_id.clone())),
            (2, Value::TextString(self.resource_type.clone())),
            (3, Value::Unsigned(self.predicted_access_time)),
            (4, Value::Unsigned(self.priority as u64)),
        ])
    }

    /// Decode a request from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let resource_id = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchRequest: missing resource_id".into(),
                ))
            }
        };
        let resource_type = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => s.clone(),
            None => String::new(),
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchRequest: resource_type not text".into(),
                ))
            }
        };
        let predicted_access_time = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n,
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchRequest: predicted_access_time not uint".into(),
                ))
            }
        };
        let priority = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => {
                if *n > u8::MAX as u64 {
                    return Err(SdkError::Messaging(
                        "PrefetchRequest: priority overflow".into(),
                    ));
                }
                *n as u8
            }
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchRequest: priority not uint".into(),
                ))
            }
        };
        Ok(Self {
            resource_id,
            resource_type,
            predicted_access_time,
            priority,
        })
    }

    /// Serialize the request to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError> {
        encode(&self.to_cbor()).map_err(|e| SdkError::Messaging(format!("cbor encode: {e}")))
    }

    /// Deserialize a request from CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError> {
        let (val, consumed) =
            decode(data).map_err(|e| SdkError::Messaging(format!("cbor decode: {e}")))?;
        if consumed != data.len() {
            return Err(SdkError::Messaging(format!(
                "PrefetchRequest: {} trailing bytes after decode",
                data.len() - consumed
            )));
        }
        Self::from_cbor(&val)
    }
}

// ──────────────────────────────────────────────────────────────────────
// PrefetchResult
// ──────────────────────────────────────────────────────────────────────

/// The result of a prefetch attempt.
#[derive(Clone, Debug)]
pub struct PrefetchResult {
    /// The original request.
    pub request: PrefetchRequest,
    /// Outcome status.
    pub status: PrefetchStatus,
    /// Cached data (present on `Hit`/`Fetched`; empty otherwise).
    pub data: Vec<u8>,
    /// Simulated fetch time in milliseconds (0 for `Hit`).
    pub fetch_time_ms: u64,
}

impl PrefetchResult {
    /// Encode the result as a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, self.request.to_cbor()),
            (2, self.status.to_cbor()),
            (3, Value::ByteString(self.data.clone())),
            (4, Value::Unsigned(self.fetch_time_ms)),
        ])
    }

    /// Decode a result from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let request = match int_map_get(val, 1) {
            Some(v) => PrefetchRequest::from_cbor(v)?,
            None => {
                return Err(SdkError::Messaging(
                    "PrefetchResult: missing request".into(),
                ))
            }
        };
        let status = match int_map_get(val, 2) {
            Some(v) => PrefetchStatus::from_cbor(v)?,
            None => PrefetchStatus::Miss,
        };
        let data = match int_map_get(val, 3) {
            Some(Value::ByteString(b)) => b.clone(),
            None => Vec::new(),
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchResult: data not byte string".into(),
                ))
            }
        };
        let fetch_time_ms = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => *n,
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "PrefetchResult: fetch_time_ms not uint".into(),
                ))
            }
        };
        Ok(Self {
            request,
            status,
            data,
            fetch_time_ms,
        })
    }

    /// Serialize the result to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError> {
        encode(&self.to_cbor()).map_err(|e| SdkError::Messaging(format!("cbor encode: {e}")))
    }

    /// Deserialize a result from CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError> {
        let (val, consumed) =
            decode(data).map_err(|e| SdkError::Messaging(format!("cbor decode: {e}")))?;
        if consumed != data.len() {
            return Err(SdkError::Messaging(format!(
                "PrefetchResult: {} trailing bytes after decode",
                data.len() - consumed
            )));
        }
        Self::from_cbor(&val)
    }
}

// ──────────────────────────────────────────────────────────────────────
// CacheEntry
// ──────────────────────────────────────────────────────────────────────

/// A single entry in the prefetch cache.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// The cached resource bytes.
    pub data: Vec<u8>,
    /// Monotonic timestamp (ms) when the entry was fetched.
    pub fetched_at: u64,
    /// Time-to-live (ms) after which the entry is considered expired.
    pub ttl: u64,
    /// Number of times the entry has been retrieved via `get_cached`.
    pub access_count: u64,
    /// Monotonic timestamp (ms) of the most recent `get_cached` access.
    pub last_accessed: u64,
}

impl CacheEntry {
    /// Create a new cache entry.
    pub fn new(data: Vec<u8>, fetched_at: u64, ttl: u64) -> Self {
        Self {
            data,
            fetched_at,
            ttl,
            access_count: 0,
            last_accessed: fetched_at,
        }
    }

    /// Returns `true` if the entry has expired relative to `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.ttl > 0 && now_ms.saturating_sub(self.fetched_at) >= self.ttl
    }

    /// Record an access at `now_ms`, bumping the access count and updating
    /// `last_accessed`.
    pub fn touch(&mut self, now_ms: u64) {
        self.access_count = self.access_count.saturating_add(1);
        self.last_accessed = now_ms;
    }
}

// ──────────────────────────────────────────────────────────────────────
// AccessPattern
// ──────────────────────────────────────────────────────────────────────

/// Historical access pattern for a single resource, used to predict future
/// accesses.
#[derive(Clone, Debug)]
pub struct AccessPattern {
    /// The resource this pattern describes.
    pub resource_id: String,
    /// Timestamps (ms) of recorded accesses, oldest first.
    pub access_times: Vec<u64>,
    /// Number of accesses recorded (== `access_times.len()`).
    pub frequency: usize,
    /// Trend slope: positive = increasing access rate, negative = decreasing.
    pub trend: f64,
}

impl AccessPattern {
    /// Create a fresh, empty pattern for `resource_id`.
    pub fn new(resource_id: impl Into<String>) -> Self {
        Self {
            resource_id: resource_id.into(),
            access_times: Vec::new(),
            frequency: 0,
            trend: 0.0,
        }
    }

    /// Record an access at `timestamp_ms` and recompute `frequency`/`trend`.
    pub fn record(&mut self, timestamp_ms: u64) {
        self.access_times.push(timestamp_ms);
        self.frequency = self.access_times.len();
        self.trend = compute_trend(&self.access_times);
    }

    /// Recency score in `[0, 1]`: 1.0 if the most recent access was at
    /// `now_ms`, decaying linearly to 0 over `window_ms`.
    pub fn recency_score(&self, now_ms: u64, window_ms: u64) -> f64 {
        match self.access_times.last() {
            None => 0.0,
            Some(&last) => {
                if window_ms == 0 {
                    return 1.0;
                }
                let elapsed = now_ms.saturating_sub(last);
                if elapsed >= window_ms {
                    0.0
                } else {
                    1.0 - (elapsed as f64 / window_ms as f64)
                }
            }
        }
    }

    /// Frequency score in `[0, 1]` relative to `max_frequency`.
    pub fn frequency_score(&self, max_frequency: usize) -> f64 {
        if max_frequency == 0 {
            return 0.0;
        }
        (self.frequency as f64 / max_frequency as f64).clamp(0.0, 1.0)
    }
}

// ──────────────────────────────────────────────────────────────────────
// PrefetcherConfig
// ──────────────────────────────────────────────────────────────────────

/// Configuration for the [`PredictivePrefetcher`].
#[derive(Clone, Debug)]
pub struct PrefetcherConfig {
    /// Maximum number of entries the cache will hold before LRU eviction.
    pub max_cache_size: usize,
    /// Confidence threshold (0.0-1.0); only predictions at or above this
    /// score trigger a prefetch.
    pub prefetch_threshold: f64,
    /// Maximum number of concurrent prefetches per `predict_and_prefetch`
    /// call.
    pub max_concurrent_prefetches: usize,
    /// Default TTL (ms) for cache entries.
    pub ttl_ms: u64,
    /// Prediction window (ms) — how far ahead to look when scoring
    /// recency.
    pub prediction_window_ms: u64,
}

impl Default for PrefetcherConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 128,
            prefetch_threshold: 0.3,
            max_concurrent_prefetches: 8,
            ttl_ms: 30_000,
            prediction_window_ms: 10_000,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// PrefetchStats
// ──────────────────────────────────────────────────────────────────────

/// Aggregate statistics about prefetcher activity.
#[derive(Clone, Debug, Default)]
pub struct PrefetchStats {
    /// Total number of prefetch attempts (including hits/misses).
    pub total_prefetches: u64,
    /// Number of prefetches that found the resource already cached.
    pub hits: u64,
    /// Number of prefetches that found the resource absent.
    pub misses: u64,
    /// Number of prefetches that failed.
    pub failures: u64,
    /// Current number of entries in the cache.
    pub cache_size: usize,
    /// Hit rate: `hits / total_prefetches` (0.0 if no prefetches yet).
    pub hit_rate: f64,
}

// ──────────────────────────────────────────────────────────────────────
// PredictivePrefetcher
// ──────────────────────────────────────────────────────────────────────

/// Predicts and pre-fetches likely-needed data/capabilities.
///
/// The prefetcher combines a frequency + recency scoring model with an
/// LRU-bounded cache. Callers record actual accesses via
/// [`record_access`](Self::record_access); the prefetcher then predicts
/// which resources are likely to be accessed next and pre-populates the
/// cache via [`predict_and_prefetch`](Self::predict_and_prefetch).
///
/// All operations are thread-safe via an internal [`RwLock`].
pub struct PredictivePrefetcher {
    config: PrefetcherConfig,
    inner: RwLock<PrefetcherInner>,
}

/// Internal mutable state, guarded by the prefetcher's `RwLock`.
#[derive(Debug, Default)]
struct PrefetcherInner {
    /// `resource_id -> CacheEntry`.
    cache: HashMap<String, CacheEntry>,
    /// `resource_id -> AccessPattern`.
    patterns: HashMap<String, AccessPattern>,
    /// Monotonic logical clock (ms) advanced by the caller or by operations.
    clock_ms: u64,
    /// Aggregate counters.
    total_prefetches: u64,
    hits: u64,
    misses: u64,
    failures: u64,
}

impl PredictivePrefetcher {
    /// Create a new prefetcher with the given configuration.
    pub fn new(config: PrefetcherConfig) -> Self {
        Self {
            config,
            inner: RwLock::new(PrefetcherInner::default()),
        }
    }

    /// Create a new prefetcher with the default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PrefetcherConfig::default())
    }

    /// Borrow the prefetcher's configuration.
    pub fn config(&self) -> &PrefetcherConfig {
        &self.config
    }

    /// Advance the internal logical clock to `now_ms`.
    ///
    /// The clock is monotonic: calls with a value smaller than the current
    /// clock are ignored.
    pub fn advance_clock(&self, now_ms: u64) {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        if now_ms > inner.clock_ms {
            inner.clock_ms = now_ms;
        }
    }

    /// Current internal clock value (ms).
    pub fn now(&self) -> u64 {
        self.inner
            .read()
            .expect("prefetcher lock poisoned")
            .clock_ms
    }

    // ── prediction ────────────────────────────────────────────────────

    /// Compute a prediction score in `[0, 1]` for `resource_id` based on
    /// its access pattern.
    ///
    /// The score is a weighted blend of frequency and recency:
    /// `score = 0.5 * frequency_score + 0.5 * recency_score`, adjusted by
    /// the trend (a positive trend boosts the score, a negative one
    /// reduces it). Returns `0.0` for unknown resources.
    pub fn prediction_score(&self, resource_id: &str) -> f64 {
        let inner = self.inner.read().expect("prefetcher lock poisoned");
        let pattern = match inner.patterns.get(resource_id) {
            Some(p) => p,
            None => return 0.0,
        };
        let max_freq = inner
            .patterns
            .values()
            .map(|p| p.frequency)
            .max()
            .unwrap_or(0);
        let freq_score = pattern.frequency_score(max_freq);
        let recency_score = pattern.recency_score(inner.clock_ms, self.config.prediction_window_ms);
        let base = 0.5 * freq_score + 0.5 * recency_score;
        // Trend adjustment: clamp trend to [-1, 1] and apply ±20%.
        let trend_adj = pattern.trend.clamp(-1.0, 1.0) * 0.2;
        let score = base + trend_adj;
        if score.is_finite() {
            score.clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    /// Return the set of resource IDs whose prediction score meets or
    /// exceeds the configured `prefetch_threshold`, sorted by descending
    /// score (ties broken by resource_id for determinism).
    pub fn predicted_resources(&self) -> Vec<String> {
        let inner = self.inner.read().expect("prefetcher lock poisoned");
        let known: Vec<String> = inner.patterns.keys().cloned().collect();
        drop(inner);

        let mut scored: Vec<(String, f64)> = known
            .into_iter()
            .map(|id| {
                let score = self.prediction_score(&id);
                (id, score)
            })
            .filter(|(_, s)| *s >= self.config.prefetch_threshold)
            .collect();
        // Sort by descending score, then by resource_id for determinism.
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        scored.into_iter().map(|(id, _)| id).collect()
    }

    // ── prefetch operations ───────────────────────────────────────────

    /// Predict likely-needed resources and pre-fetch them.
    ///
    /// Returns the results for each resource that was considered. Only
    /// resources whose prediction score meets `prefetch_threshold` are
    /// fetched, up to `max_concurrent_prefetches` at a time. Resources
    /// already cached (and fresh) are reported as [`PrefetchStatus::Hit`].
    pub fn predict_and_prefetch(&self) -> Vec<PrefetchResult> {
        let candidates = self.predicted_resources();
        let limit = self.config.max_concurrent_prefetches.min(candidates.len());
        let mut results = Vec::with_capacity(limit);
        for resource_id in candidates.into_iter().take(limit) {
            let score = self.prediction_score(&resource_id);
            // Use the score as a pseudo-priority (0-255).
            let priority = (score * 255.0).clamp(0.0, 255.0) as u8;
            let request = PrefetchRequest {
                resource_id,
                resource_type: "predicted".to_string(),
                predicted_access_time: self.now().saturating_add(self.config.prediction_window_ms),
                priority,
            };
            results.push(self.prefetch(&request));
        }
        results
    }

    /// Explicitly prefetch a single resource.
    ///
    /// If the resource is already cached and fresh, returns
    /// [`PrefetchStatus::Hit`] with no fetch. If cached but expired, the
    /// entry is evicted and re-fetched. Otherwise the resource is
    /// "fetched" (simulated) and stored.
    pub fn prefetch(&self, request: &PrefetchRequest) -> PrefetchResult {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        let now = inner.clock_ms;

        // Check for an existing fresh entry.
        if let Some(entry) = inner.cache.get(&request.resource_id) {
            if !entry.is_expired(now) {
                let data = entry.data.clone();
                inner.total_prefetches = inner.total_prefetches.saturating_add(1);
                inner.hits = inner.hits.saturating_add(1);
                return PrefetchResult {
                    request: request.clone(),
                    status: PrefetchStatus::Hit,
                    data,
                    fetch_time_ms: 0,
                };
            } else {
                // Expired — evict and fall through to re-fetch.
                inner.cache.remove(&request.resource_id);
            }
        }

        // Simulate a fetch. In this implementation the fetch always
        // succeeds; the `Failed` path is exercised via `prefetch_failing`.
        let start = Instant::now();
        let data = simulate_fetch(&request.resource_id);
        let fetch_time_ms = start.elapsed().as_millis() as u64 + SIMULATED_FETCH_LATENCY_MS;

        // Evict if we are about to exceed the cache size.
        evict_if_needed(&mut inner.cache, self.config.max_cache_size);

        let entry = CacheEntry::new(data.clone(), now, self.config.ttl_ms);
        inner.cache.insert(request.resource_id.clone(), entry);
        inner.total_prefetches = inner.total_prefetches.saturating_add(1);
        inner.misses = inner.misses.saturating_add(1);

        PrefetchResult {
            request: request.clone(),
            status: PrefetchStatus::Fetched,
            data,
            fetch_time_ms,
        }
    }

    /// Like [`prefetch`](Self::prefetch) but always reports
    /// [`PrefetchStatus::Failed`] without modifying the cache. Useful for
    /// simulating a fetch error.
    pub fn prefetch_failing(&self, request: &PrefetchRequest) -> PrefetchResult {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        inner.total_prefetches = inner.total_prefetches.saturating_add(1);
        inner.failures = inner.failures.saturating_add(1);
        PrefetchResult {
            request: request.clone(),
            status: PrefetchStatus::Failed,
            data: Vec::new(),
            fetch_time_ms: SIMULATED_FETCH_LATENCY_MS,
        }
    }

    // ── cache access ──────────────────────────────────────────────────

    /// Retrieve a cached resource by ID.
    ///
    /// Returns `Some(data)` if the entry exists and is fresh, touching its
    /// access counters. Returns `None` if absent or expired (expired
    /// entries are evicted).
    pub fn get_cached(&self, resource_id: &str) -> Option<Vec<u8>> {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        let now = inner.clock_ms;
        let entry = inner.cache.get_mut(resource_id)?;
        if entry.is_expired(now) {
            inner.cache.remove(resource_id);
            return None;
        }
        entry.touch(now);
        Some(entry.data.clone())
    }

    /// Check whether a resource is cached and fresh without touching it.
    pub fn is_cached(&self, resource_id: &str) -> bool {
        let inner = self.inner.read().expect("prefetcher lock poisoned");
        match inner.cache.get(resource_id) {
            Some(e) => !e.is_expired(inner.clock_ms),
            None => false,
        }
    }

    /// Remove a cached resource. Returns `true` if an entry was removed.
    pub fn invalidate(&self, resource_id: &str) -> bool {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        inner.cache.remove(resource_id).is_some()
    }

    /// Remove all cached resources.
    pub fn invalidate_all(&self) {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        inner.cache.clear();
    }

    /// Remove all expired entries, returning the number evicted.
    pub fn evict_expired(&self) -> usize {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        let now = inner.clock_ms;
        let before = inner.cache.len();
        inner.cache.retain(|_, e| !e.is_expired(now));
        before - inner.cache.len()
    }

    /// Current number of entries in the cache.
    pub fn cache_size(&self) -> usize {
        self.inner
            .read()
            .expect("prefetcher lock poisoned")
            .cache
            .len()
    }

    /// Snapshot a clone of a cache entry (for inspection/testing).
    pub fn cache_entry(&self, resource_id: &str) -> Option<CacheEntry> {
        let inner = self.inner.read().expect("prefetcher lock poisoned");
        inner.cache.get(resource_id).cloned()
    }

    // ── access recording / patterns ───────────────────────────────────

    /// Record an actual access to `resource_id` at the current logical
    /// clock time. This trains the prediction model.
    pub fn record_access(&self, resource_id: &str) {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        let now = inner.clock_ms;
        let pattern = inner
            .patterns
            .entry(resource_id.to_string())
            .or_insert_with(|| AccessPattern::new(resource_id));
        pattern.record(now);
    }

    /// Record an access to `resource_id` at an explicit `timestamp_ms`,
    /// also advancing the clock if needed.
    pub fn record_access_at(&self, resource_id: &str, timestamp_ms: u64) {
        let mut inner = self.inner.write().expect("prefetcher lock poisoned");
        if timestamp_ms > inner.clock_ms {
            inner.clock_ms = timestamp_ms;
        }
        let pattern = inner
            .patterns
            .entry(resource_id.to_string())
            .or_insert_with(|| AccessPattern::new(resource_id));
        pattern.record(timestamp_ms);
    }

    /// Snapshot a clone of the access pattern for a resource.
    pub fn access_pattern(&self, resource_id: &str) -> Option<AccessPattern> {
        let inner = self.inner.read().expect("prefetcher lock poisoned");
        inner.patterns.get(resource_id).cloned()
    }

    /// Number of distinct resources with recorded access patterns.
    pub fn pattern_count(&self) -> usize {
        self.inner
            .read()
            .expect("prefetcher lock poisoned")
            .patterns
            .len()
    }

    // ── stats ─────────────────────────────────────────────────────────

    /// Snapshot the current aggregate statistics.
    pub fn stats(&self) -> PrefetchStats {
        let inner = self.inner.read().expect("prefetcher lock poisoned");
        let total = inner.total_prefetches;
        let hit_rate = if total == 0 {
            0.0
        } else {
            inner.hits as f64 / total as f64
        };
        PrefetchStats {
            total_prefetches: total,
            hits: inner.hits,
            misses: inner.misses,
            failures: inner.failures,
            cache_size: inner.cache.len(),
            hit_rate,
        }
    }
}

impl Default for PredictivePrefetcher {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ──────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────

/// Produce deterministic placeholder bytes for a "fetched" resource.
fn simulate_fetch(resource_id: &str) -> Vec<u8> {
    resource_id.as_bytes().to_vec()
}

/// Evict the least-recently-used entry if the cache is at capacity.
///
/// "Least recently used" is determined by `last_accessed` (falling back to
/// `fetched_at`). Ties are broken by resource_id for determinism.
fn evict_if_needed(cache: &mut HashMap<String, CacheEntry>, max_size: usize) {
    if cache.len() < max_size || max_size == 0 {
        return;
    }
    // Find the LRU key.
    let lru_key = cache
        .iter()
        .map(|(k, e)| (k.clone(), e.last_accessed, e.fetched_at))
        .min_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| a.0.cmp(&b.0))
        })
        .map(|(k, _, _)| k);
    if let Some(key) = lru_key {
        cache.remove(&key);
    }
}

/// Compute a simple trend slope over access timestamps.
///
/// Returns the slope of a least-squares linear fit of access index vs.
/// inter-arrival time. A positive slope means inter-arrival times are
/// growing (accesses slowing down); we invert so that *positive trend*
/// means *increasing access rate*.
fn compute_trend(access_times: &[u64]) -> f64 {
    let n = access_times.len();
    if n < 2 {
        return 0.0;
    }
    // Inter-arrival deltas.
    let deltas: Vec<f64> = access_times
        .windows(2)
        .map(|w| {
            let d = w[1].saturating_sub(w[0]);
            d as f64
        })
        .collect();
    if deltas.is_empty() {
        return 0.0;
    }
    // Mean delta.
    let mean: f64 = deltas.iter().sum::<f64>() / deltas.len() as f64;
    if !mean.is_finite() || mean <= 0.0 {
        return 0.0;
    }
    // Linear regression of delta vs index: slope tells us if gaps are
    // growing (positive) or shrinking (negative).
    let mut sum_x: f64 = 0.0;
    let mut sum_y: f64 = 0.0;
    let mut sum_xy: f64 = 0.0;
    let mut sum_x2: f64 = 0.0;
    let count = deltas.len() as f64;
    for (i, d) in deltas.iter().enumerate() {
        let x = i as f64;
        let y = *d;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
    }
    let denominator = count * sum_x2 - sum_x * sum_x;
    if denominator.abs() < f64::EPSILON || !denominator.is_finite() {
        return 0.0;
    }
    let slope = (count * sum_xy - sum_x * sum_y) / denominator;
    if !slope.is_finite() {
        return 0.0;
    }
    // Normalize: slope relative to mean delta. Invert sign so that
    // shrinking gaps => positive trend (increasing access rate).
    let normalized = -slope / mean;
    if normalized.is_finite() {
        normalized.clamp(-1.0, 1.0)
    } else {
        0.0
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str) -> PrefetchRequest {
        PrefetchRequest {
            resource_id: id.to_string(),
            resource_type: "test".to_string(),
            predicted_access_time: 0,
            priority: 1,
        }
    }

    // 1. Default config values --------------------------------------------------
    #[test]
    fn test_default_config() {
        let cfg = PrefetcherConfig::default();
        assert_eq!(cfg.max_cache_size, 128);
        assert!((cfg.prefetch_threshold - 0.3).abs() < f64::EPSILON);
        assert_eq!(cfg.max_concurrent_prefetches, 8);
        assert_eq!(cfg.ttl_ms, 30_000);
        assert_eq!(cfg.prediction_window_ms, 10_000);
    }

    // 2. Prefetch a fresh resource reports Fetched ------------------------------
    #[test]
    fn test_prefetch_fresh_resource() {
        let pf = PredictivePrefetcher::with_defaults();
        let result = pf.prefetch(&req("res-1"));
        assert_eq!(result.status, PrefetchStatus::Fetched);
        assert!(!result.data.is_empty());
        assert!(result.fetch_time_ms >= SIMULATED_FETCH_LATENCY_MS);
        assert!(pf.is_cached("res-1"));
    }

    // 3. Prefetch an already-cached resource reports Hit ------------------------
    #[test]
    fn test_prefetch_cached_resource_is_hit() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.prefetch(&req("res-1"));
        let result = pf.prefetch(&req("res-1"));
        assert_eq!(result.status, PrefetchStatus::Hit);
        assert_eq!(result.fetch_time_ms, 0);
    }

    // 4. get_cached returns data and touches access count -----------------------
    #[test]
    fn test_get_cached_touches_access_count() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.prefetch(&req("res-1"));
        let entry = pf.cache_entry("res-1").expect("entry");
        assert_eq!(entry.access_count, 0);

        let data = pf.get_cached("res-1").expect("should get data");
        assert!(!data.is_empty());
        let entry = pf.cache_entry("res-1").expect("entry");
        assert_eq!(entry.access_count, 1);
    }

    // 5. get_cached returns None for unknown resource ---------------------------
    #[test]
    fn test_get_cached_unknown_returns_none() {
        let pf = PredictivePrefetcher::with_defaults();
        assert!(pf.get_cached("nope").is_none());
    }

    // 6. invalidate removes a cached resource -----------------------------------
    #[test]
    fn test_invalidate_removes_entry() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.prefetch(&req("res-1"));
        assert!(pf.invalidate("res-1"));
        assert!(!pf.is_cached("res-1"));
        assert!(!pf.invalidate("res-1"));
    }

    // 7. invalidate_all clears the cache ----------------------------------------
    #[test]
    fn test_invalidate_all() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.prefetch(&req("a"));
        pf.prefetch(&req("b"));
        assert_eq!(pf.cache_size(), 2);
        pf.invalidate_all();
        assert_eq!(pf.cache_size(), 0);
    }

    // 8. TTL expiry causes Expired path on next prefetch ------------------------
    #[test]
    fn test_ttl_expiry_refetches() {
        let cfg = PrefetcherConfig {
            ttl_ms: 100,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        pf.advance_clock(0);
        pf.prefetch(&req("res-1"));
        assert!(pf.is_cached("res-1"));

        // Advance past TTL.
        pf.advance_clock(200);
        assert!(!pf.is_cached("res-1"));

        // get_cached on expired returns None and evicts.
        pf.advance_clock(200); // clock stays at 200 (already there)
        pf.prefetch(&req("res-1")); // re-fetch at 200, expires at 300
        pf.advance_clock(400); // advance to 400, past TTL
        assert!(pf.get_cached("res-1").is_none());
    }

    // 9. evict_expired removes only expired entries -----------------------------
    #[test]
    fn test_evict_expired() {
        let cfg = PrefetcherConfig {
            ttl_ms: 100,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        pf.advance_clock(0);
        pf.prefetch(&req("a"));
        pf.advance_clock(50);
        pf.prefetch(&req("b"));
        // Advance past TTL of "a" only.
        pf.advance_clock(120);
        let evicted = pf.evict_expired();
        assert_eq!(evicted, 1);
        assert!(!pf.is_cached("a"));
        assert!(pf.is_cached("b"));
    }

    // 10. LRU eviction when cache is full ---------------------------------------
    #[test]
    fn test_lru_eviction_when_full() {
        let cfg = PrefetcherConfig {
            max_cache_size: 2,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        pf.advance_clock(0);
        pf.prefetch(&req("a"));
        pf.advance_clock(10);
        pf.prefetch(&req("b"));
        // Access "a" so it becomes more-recently-used than "b".
        pf.advance_clock(20);
        pf.get_cached("a");
        // Now prefetch "c" — should evict "b" (LRU).
        pf.advance_clock(30);
        pf.prefetch(&req("c"));
        assert!(pf.is_cached("a"));
        assert!(!pf.is_cached("b"));
        assert!(pf.is_cached("c"));
    }

    // 11. record_access builds an access pattern --------------------------------
    #[test]
    fn test_record_access_builds_pattern() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.advance_clock(0);
        pf.record_access("res-1");
        pf.advance_clock(100);
        pf.record_access("res-1");
        let pattern = pf.access_pattern("res-1").expect("pattern");
        assert_eq!(pattern.frequency, 2);
        assert_eq!(pattern.access_times, vec![0, 100]);
    }

    // 12. prediction_score is 0 for unknown resources ---------------------------
    #[test]
    fn test_prediction_score_unknown_is_zero() {
        let pf = PredictivePrefetcher::with_defaults();
        assert!((pf.prediction_score("nope") - 0.0).abs() < f64::EPSILON);
    }

    // 13. prediction_score increases with frequency and recency -----------------
    #[test]
    fn test_prediction_score_increases_with_access() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.advance_clock(0);
        pf.record_access("res-1");
        let s1 = pf.prediction_score("res-1");
        assert!(s1 > 0.0, "s1={} should be positive", s1);

        pf.advance_clock(100);
        pf.record_access("res-1");
        pf.advance_clock(200);
        pf.record_access("res-1");
        let s3 = pf.prediction_score("res-1");
        assert!(s3 > 0.0, "s3={} should be positive", s3);
    }

    // 14. predict_and_prefetch fetches predicted resources ----------------------
    #[test]
    fn test_predict_and_prefetch_fetches_predicted() {
        let pf = PredictivePrefetcher::with_defaults();
        // Record accesses so "res-1" is predicted.
        for t in 0..5u64 {
            pf.advance_clock(t * 100);
            pf.record_access("res-1");
        }
        let results = pf.predict_and_prefetch();
        assert!(!results.is_empty(), "should predict at least one resource");
        let ids: Vec<&str> = results
            .iter()
            .map(|r| r.request.resource_id.as_str())
            .collect();
        assert!(ids.contains(&"res-1"));
        // Should have been fetched (not previously cached).
        assert!(results.iter().any(|r| r.status == PrefetchStatus::Fetched));
    }

    // 15. predict_and_prefetch respects max_concurrent_prefetches ---------------
    #[test]
    fn test_predict_and_prefetch_respects_concurrency_limit() {
        let cfg = PrefetcherConfig {
            max_concurrent_prefetches: 2,
            prefetch_threshold: 0.0,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        for i in 0..5u64 {
            pf.advance_clock(i * 100);
            pf.record_access(&format!("res-{i}"));
        }
        let results = pf.predict_and_prefetch();
        assert_eq!(results.len(), 2);
    }

    // 16. predict_and_prefetch reports Hit for already-cached -------------------
    #[test]
    fn test_predict_and_prefetch_hit_for_cached() {
        let pf = PredictivePrefetcher::with_defaults();
        for t in 0..5u64 {
            pf.advance_clock(t * 100);
            pf.record_access("res-1");
        }
        // Pre-populate the cache.
        pf.prefetch(&req("res-1"));
        // Now predict_and_prefetch should report a Hit.
        let results = pf.predict_and_prefetch();
        let hit = results
            .iter()
            .find(|r| r.request.resource_id == "res-1")
            .expect("should have result for res-1");
        assert_eq!(hit.status, PrefetchStatus::Hit);
    }

    // 17. prefetch_failing records a failure ------------------------------------
    #[test]
    fn test_prefetch_failing() {
        let pf = PredictivePrefetcher::with_defaults();
        let result = pf.prefetch_failing(&req("res-1"));
        assert_eq!(result.status, PrefetchStatus::Failed);
        assert!(result.data.is_empty());
        let stats = pf.stats();
        assert_eq!(stats.failures, 1);
    }

    // 18. stats track hits, misses, failures ------------------------------------
    #[test]
    fn test_stats_tracking() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.prefetch(&req("a")); // miss -> fetched
        pf.prefetch(&req("a")); // hit
        pf.prefetch_failing(&req("b")); // failure

        let stats = pf.stats();
        assert_eq!(stats.total_prefetches, 3);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.failures, 1);
        assert!((stats.hit_rate - (1.0 / 3.0)).abs() < 0.001);
        assert_eq!(stats.cache_size, 1);
    }

    // 19. CacheEntry expiry logic -----------------------------------------------
    #[test]
    fn test_cache_entry_expiry() {
        let entry = CacheEntry::new(vec![1, 2, 3], 0, 100);
        assert!(!entry.is_expired(50));
        assert!(entry.is_expired(100));
        assert!(entry.is_expired(200));
    }

    // 20. CacheEntry with ttl=0 never expires -----------------------------------
    #[test]
    fn test_cache_entry_zero_ttl_never_expires() {
        let entry = CacheEntry::new(vec![1], 0, 0);
        assert!(!entry.is_expired(1_000_000));
    }

    // 21. AccessPattern recency_score decays ------------------------------------
    #[test]
    fn test_access_pattern_recency_score() {
        let mut pattern = AccessPattern::new("res-1");
        pattern.record(0);
        assert!((pattern.recency_score(0, 1000) - 1.0).abs() < f64::EPSILON);
        assert!((pattern.recency_score(500, 1000) - 0.5).abs() < 0.001);
        assert!((pattern.recency_score(1000, 1000) - 0.0).abs() < f64::EPSILON);
        assert!((pattern.recency_score(2000, 1000) - 0.0).abs() < f64::EPSILON);
    }

    // 22. AccessPattern frequency_score -----------------------------------------
    #[test]
    fn test_access_pattern_frequency_score() {
        let mut pattern = AccessPattern::new("res-1");
        for _ in 0..5 {
            pattern.record(0);
        }
        assert!((pattern.frequency_score(10) - 0.5).abs() < 0.001);
        assert!((pattern.frequency_score(5) - 1.0).abs() < 0.001);
        assert!((pattern.frequency_score(0) - 0.0).abs() < f64::EPSILON);
    }

    // 23. AccessPattern trend is positive for accelerating accesses -------------
    #[test]
    fn test_access_pattern_trend_accelerating() {
        let mut pattern = AccessPattern::new("res-1");
        // Gaps shrink: 1000, 500, 250 => increasing access rate.
        pattern.record(0);
        pattern.record(1000);
        pattern.record(1500);
        pattern.record(1750);
        assert!(
            pattern.trend > 0.0,
            "accelerating accesses should have positive trend: {}",
            pattern.trend
        );
    }

    // 24. AccessPattern trend is negative for decelerating accesses -------------
    #[test]
    fn test_access_pattern_trend_decelerating() {
        let mut pattern = AccessPattern::new("res-1");
        // Gaps grow: 250, 500, 1000 => decreasing access rate.
        pattern.record(0);
        pattern.record(250);
        pattern.record(750);
        pattern.record(1750);
        assert!(
            pattern.trend < 0.0,
            "decelerating accesses should have negative trend: {}",
            pattern.trend
        );
    }

    // 25. PrefetchStatus CBOR round-trip ----------------------------------------
    #[test]
    fn test_prefetch_status_cbor_round_trip() {
        for status in [
            PrefetchStatus::Hit,
            PrefetchStatus::Miss,
            PrefetchStatus::Fetched,
            PrefetchStatus::Failed,
            PrefetchStatus::Expired,
        ] {
            let val = status.to_cbor();
            let decoded = PrefetchStatus::from_cbor(&val).expect("decode");
            assert_eq!(decoded, status);
        }
    }

    // 26. PrefetchRequest CBOR round-trip ---------------------------------------
    #[test]
    fn test_prefetch_request_cbor_round_trip() {
        let request = PrefetchRequest {
            resource_id: "cap:compute".to_string(),
            resource_type: "capability".to_string(),
            predicted_access_time: 12_345,
            priority: 200,
        };
        let bytes = request.to_bytes().expect("encode");
        let decoded = PrefetchRequest::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.resource_id, request.resource_id);
        assert_eq!(decoded.resource_type, request.resource_type);
        assert_eq!(decoded.predicted_access_time, request.predicted_access_time);
        assert_eq!(decoded.priority, request.priority);
    }

    // 27. PrefetchResult CBOR round-trip ----------------------------------------
    #[test]
    fn test_prefetch_result_cbor_round_trip() {
        let request = req("res-1");
        let result = PrefetchResult {
            request: request.clone(),
            status: PrefetchStatus::Fetched,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            fetch_time_ms: 42,
        };
        let bytes = result.to_bytes().expect("encode");
        let decoded = PrefetchResult::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.request.resource_id, result.request.resource_id);
        assert_eq!(decoded.status, result.status);
        assert_eq!(decoded.data, result.data);
        assert_eq!(decoded.fetch_time_ms, result.fetch_time_ms);
    }

    // 28. PrefetchStatus from_cbor rejects unknown variant ----------------------
    #[test]
    fn test_prefetch_status_cbor_unknown_variant() {
        let val = Value::Unsigned(99);
        assert!(PrefetchStatus::from_cbor(&val).is_err());
    }

    // 29. record_access_at advances the clock -----------------------------------
    #[test]
    fn test_record_access_at_advances_clock() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.record_access_at("res-1", 500);
        assert_eq!(pf.now(), 500);
        let pattern = pf.access_pattern("res-1").expect("pattern");
        assert_eq!(pattern.access_times, vec![500]);
    }

    // 30. predicted_resources returns sorted by descending score ----------------
    #[test]
    fn test_predicted_resources_sorted_by_score() {
        let pf = PredictivePrefetcher::with_defaults();
        // "a" accessed more frequently than "b".
        for t in 0..10u64 {
            pf.advance_clock(t * 100);
            pf.record_access("a");
        }
        for t in 0..3u64 {
            pf.advance_clock(1000 + t * 100);
            pf.record_access("b");
        }
        let predicted = pf.predicted_resources();
        assert!(!predicted.is_empty());
        // "a" should come before "b" (higher score).
        let pos_a = predicted.iter().position(|r| r == "a");
        let pos_b = predicted.iter().position(|r| r == "b");
        if let (Some(pa), Some(pb)) = (pos_a, pos_b) {
            assert!(pa < pb, "a should rank higher than b");
        }
    }

    // 31. predict_and_prefetch with no patterns returns empty -------------------
    #[test]
    fn test_predict_and_prefetch_no_patterns() {
        let pf = PredictivePrefetcher::with_defaults();
        let results = pf.predict_and_prefetch();
        assert!(results.is_empty());
    }

    // 32. pattern_count reflects recorded resources -----------------------------
    #[test]
    fn test_pattern_count() {
        let pf = PredictivePrefetcher::with_defaults();
        pf.record_access("a");
        pf.record_access("b");
        pf.record_access("a");
        assert_eq!(pf.pattern_count(), 2);
    }

    // 33. prefetch_threshold filters predictions --------------------------------
    #[test]
    fn test_prefetch_threshold_filters() {
        // With a threshold > 1.0, no resource can ever be predicted
        // (scores are clamped to [0, 1]).
        let cfg = PrefetcherConfig {
            prefetch_threshold: 1.01,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        pf.advance_clock(0);
        pf.record_access("res-1");
        let predicted = pf.predicted_resources();
        assert!(
            predicted.is_empty(),
            "no resource should exceed threshold 1.01"
        );
    }

    // 34. get_cached on expired entry evicts it ---------------------------------
    #[test]
    fn test_get_cached_expired_evicts() {
        let cfg = PrefetcherConfig {
            ttl_ms: 100,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        pf.advance_clock(0);
        pf.prefetch(&req("res-1"));
        pf.advance_clock(200);
        assert!(pf.get_cached("res-1").is_none());
        assert_eq!(pf.cache_size(), 0);
    }

    // 35. CacheEntry touch updates last_accessed --------------------------------
    #[test]
    fn test_cache_entry_touch() {
        let mut entry = CacheEntry::new(vec![1], 0, 1000);
        entry.touch(500);
        assert_eq!(entry.access_count, 1);
        assert_eq!(entry.last_accessed, 500);
        entry.touch(800);
        assert_eq!(entry.access_count, 2);
        assert_eq!(entry.last_accessed, 800);
    }

    // 36. Multiple resources LRU ordering ---------------------------------------
    #[test]
    fn test_lru_eviction_ordering_with_many_entries() {
        let cfg = PrefetcherConfig {
            max_cache_size: 3,
            ..PrefetcherConfig::default()
        };
        let pf = PredictivePrefetcher::new(cfg);
        pf.advance_clock(0);
        pf.prefetch(&req("a"));
        pf.advance_clock(10);
        pf.prefetch(&req("b"));
        pf.advance_clock(20);
        pf.prefetch(&req("c"));
        // Touch "a" and "c" so "b" is LRU.
        pf.advance_clock(30);
        pf.get_cached("a");
        pf.advance_clock(40);
        pf.get_cached("c");
        // Insert "d" -> evict "b".
        pf.advance_clock(50);
        pf.prefetch(&req("d"));
        assert!(pf.is_cached("a"));
        assert!(!pf.is_cached("b"));
        assert!(pf.is_cached("c"));
        assert!(pf.is_cached("d"));
        assert_eq!(pf.cache_size(), 3);
    }
}
