//! Normative nonce replay detection (RFC-0002 §6.7, Rev 6 A-9).
//!
//! The `ReplayCache` is a time-bounded set of observed handshake nonces,
//! keyed by `(agent_id, nonce)`. It is the single authority for
//! cross-connection nonce uniqueness. The handshake state machine consults
//! it upon receipt of a ClientHello (server side) or ServerHello (client
//! side) to reject replayed handshakes **before** signature verification.
//!
//! ## Design
//!
//! The `ReplayCache` is **transport-agnostic** and **synchronous**. It
//! does not own timers or background tasks. The caller is responsible for:
//!
//! 1. Calling `evict_expired()` periodically (or relying on lazy eviction
//!    on `check`/`insert`).
//! 2. Configuring `retention` and `max_entries` appropriately for the
//!    deployment.
//!
//! Thread safety: `ReplayCache` uses internal synchronization (a
//! `Mutex<HashMap>`) and is safe to share across threads via `Arc`.
//! The `check_and_insert` operation is atomic under the lock, satisfying
//! §6.7.4 Invariant 4.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default retention window (RFC-0002 §6.7.3).
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(300);

/// Minimum retention window (RFC-0002 §6.7.3).
pub const MIN_RETENTION: Duration = Duration::from_secs(60);

/// Maximum retention window (RFC-0002 §6.7.3).
pub const MAX_RETENTION: Duration = Duration::from_secs(3600);

/// Default maximum number of entries (RFC-0002 §6.7.3).
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Minimum maximum entries (RFC-0002 §6.7.3).
pub const MIN_MAX_ENTRIES: usize = 1_000;

/// Maximum maximum entries (RFC-0002 §6.7.3).
pub const MAX_MAX_ENTRIES: usize = 10_000_000;

/// Nonce size (RFC-0002 §5.3-5.4).
pub const NONCE_SIZE: usize = 32;

/// AgentId size (RFC-0002 §5.3).
pub const AGENT_ID_SIZE: usize = 32;

/// Error returned by `check_and_insert` when a replay is detected.
#[derive(Debug, thiserror::Error)]
#[error("nonce reuse detected: replay attack")]
pub struct NonceReuseError;

/// Error returned by `ReplayCache::new` for invalid parameters.
#[derive(Debug, thiserror::Error)]
pub enum ReplayCacheError {
    #[error("retention must be between {min:?} and {max:?}, got {got:?}")]
    RetentionOutOfRange {
        got: Duration,
        min: Duration,
        max: Duration,
    },
    #[error("max_entries must be between {min} and {max}, got {got}")]
    MaxEntriesOutOfRange { got: usize, min: usize, max: usize },
}

/// A single replay cache entry (RFC-0002 §6.7.2).
#[derive(Clone, Debug)]
struct Entry {
    /// When the entry expires (`inserted_at + retention`).
    expires_at: Instant,
    /// Last access time (for LRU eviction).
    last_accessed: Instant,
}

impl Entry {
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Cache key: `(agent_id, nonce)` as a 64-byte array.
///
/// We use a fixed-size array to avoid heap allocation per lookup.
/// Both `agent_id` and `nonce` are 32 bytes per RFC-0002.
type CacheKey = [u8; AGENT_ID_SIZE + NONCE_SIZE];

fn make_key(agent_id: &[u8], nonce: &[u8; NONCE_SIZE]) -> CacheKey {
    let mut key = [0u8; AGENT_ID_SIZE + NONCE_SIZE];
    // Copy up to AGENT_ID_SIZE bytes (pad with zeros if shorter).
    let id_len = agent_id.len().min(AGENT_ID_SIZE);
    key[..id_len].copy_from_slice(&agent_id[..id_len]);
    key[AGENT_ID_SIZE..].copy_from_slice(nonce);
    key
}

/// Normative nonce replay cache (RFC-0002 §6.7).
///
/// A time-bounded set of observed `(agent_id, nonce)` pairs. The cache
/// rejects replays before signature verification, conserving CPU and
/// preventing session-ID collisions.
///
/// Thread-safe via internal `Mutex`. The `check_and_insert` operation is
/// atomic under the lock.
pub struct ReplayCache {
    inner: Mutex<Inner>,
    retention: Duration,
    max_entries: usize,
}

struct Inner {
    entries: HashMap<CacheKey, Entry>,
    /// Lazy eviction batch size: how many entries to scan per access.
    lazy_evict_batch: usize,
}

impl ReplayCache {
    /// Create a new `ReplayCache` with default parameters.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                lazy_evict_batch: 64,
            }),
            retention: DEFAULT_RETENTION,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// Create a `ReplayCache` with custom retention and max_entries.
    ///
    /// Returns an error if parameters are out of range (§6.7.3).
    pub fn with_params(retention: Duration, max_entries: usize) -> Result<Self, ReplayCacheError> {
        if !(MIN_RETENTION..=MAX_RETENTION).contains(&retention) {
            return Err(ReplayCacheError::RetentionOutOfRange {
                got: retention,
                min: MIN_RETENTION,
                max: MAX_RETENTION,
            });
        }
        if !(MIN_MAX_ENTRIES..=MAX_MAX_ENTRIES).contains(&max_entries) {
            return Err(ReplayCacheError::MaxEntriesOutOfRange {
                got: max_entries,
                min: MIN_MAX_ENTRIES,
                max: MAX_MAX_ENTRIES,
            });
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                lazy_evict_batch: 64,
            }),
            retention,
            max_entries,
        })
    }

    /// Create a `ReplayCache` with custom parameters and pre-allocated capacity.
    pub fn with_capacity(
        retention: Duration,
        max_entries: usize,
        capacity: usize,
    ) -> Result<Self, ReplayCacheError> {
        let cache = Self::with_params(retention, max_entries)?;
        let cap = capacity.min(max_entries);
        {
            let mut inner = cache.inner.lock().unwrap();
            inner.entries.reserve(cap);
        }
        Ok(cache)
    }

    /// Create a `ReplayCache` with custom parameters, bypassing validation.
    ///
    /// **For testing only.** This constructor does not enforce the RFC
    /// minimum/maximum parameter ranges, allowing tests to use short
    /// retention durations and small max_entries for fast eviction tests.
    #[doc(hidden)]
    pub fn with_params_unchecked(retention: Duration, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                lazy_evict_batch: 64,
            }),
            retention,
            max_entries,
        }
    }

    // ── Queries ───────────────────────────────────────────────────────

    /// Configured retention duration.
    pub fn retention(&self) -> Duration {
        self.retention
    }

    /// Configured max entries.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Current number of entries (including expired, not yet swept).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().entries.is_empty()
    }

    // ── Core operations ───────────────────────────────────────────────

    /// Check if `(agent_id, nonce)` is a replay. Does NOT insert.
    ///
    /// Returns `true` if a non-expired entry exists (replay detected).
    /// Returns `false` if no entry exists or the entry has expired.
    ///
    /// This is a read-only query. Use `check_and_insert` for the atomic
    /// check-and-insert operation used in handshake integration.
    pub fn check(&self, agent_id: &[u8], nonce: &[u8; NONCE_SIZE]) -> bool {
        let now = Instant::now();
        let key = make_key(agent_id, nonce);
        let mut inner = self.inner.lock().unwrap();
        self.lazy_evict(&mut inner, now);
        if let Some(entry) = inner.entries.get_mut(&key) {
            if entry.is_expired(now) {
                // Expired entry: not a replay, but clean it up.
                inner.entries.remove(&key);
                false
            } else {
                entry.last_accessed = now;
                true
            }
        } else {
            false
        }
    }

    /// Atomically check-and-insert (RFC-0002 §6.7.4 Invariant 4).
    ///
    /// Returns `Ok(())` if the nonce is fresh (inserted into cache).
    /// Returns `Err(())` if the nonce is a replay (already present and
    /// non-expired).
    ///
    /// This is the primary entry point for handshake integration
    /// (§6.7.5 step 3-5, §6.7.6 step 3-5). It combines the replay check
    /// and cache insertion into a single atomic operation.
    pub fn check_and_insert(
        &self,
        agent_id: &[u8],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<(), NonceReuseError> {
        let now = Instant::now();
        let key = make_key(agent_id, nonce);
        let mut inner = self.inner.lock().unwrap();
        self.lazy_evict(&mut inner, now);

        // Check for existing non-expired entry.
        if let Some(entry) = inner.entries.get(&key) {
            if !entry.is_expired(now) {
                // Replay detected.
                return Err(NonceReuseError);
            }
            // Expired: remove and re-insert below.
            inner.entries.remove(&key);
        }

        // Enforce max_entries with LRU eviction if needed.
        if inner.entries.len() >= self.max_entries {
            self.evict_lru(&mut inner, now);
        }

        // Insert new entry.
        inner.entries.insert(
            key,
            Entry {
                expires_at: now + self.retention,
                last_accessed: now,
            },
        );

        Ok(())
    }

    /// Insert a nonce without checking. Used when the caller has already
    /// verified uniqueness via `check()`.
    ///
    /// If the entry already exists (non-expired), this is a no-op.
    /// If the entry exists but is expired, it is refreshed.
    pub fn insert(&self, agent_id: &[u8], nonce: &[u8; NONCE_SIZE]) {
        let now = Instant::now();
        let key = make_key(agent_id, nonce);
        let mut inner = self.inner.lock().unwrap();
        self.lazy_evict(&mut inner, now);

        // Enforce max_entries with LRU eviction if needed.
        if !inner.entries.contains_key(&key) && inner.entries.len() >= self.max_entries {
            self.evict_lru(&mut inner, now);
        }

        inner.entries.insert(
            key,
            Entry {
                expires_at: now + self.retention,
                last_accessed: now,
            },
        );
    }

    /// Evict all expired entries. Returns the number evicted.
    ///
    /// This is a full sweep. For lazy eviction (small batch), the
    /// `check`/`insert`/`check_and_insert` methods already perform
    /// partial sweeps on each access.
    pub fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let before = inner.entries.len();
        inner.entries.retain(|_, entry| !entry.is_expired(now));
        before - inner.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.inner.lock().unwrap().entries.clear();
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Lazy eviction: scan a small batch of entries and remove expired ones.
    /// This bounds the per-call work to O(batch_size) (§6.7.4 Invariant 6).
    fn lazy_evict(&self, inner: &mut Inner, now: Instant) {
        if inner.entries.len() <= self.max_entries / 2 {
            // Cache is small; skip lazy eviction for efficiency.
            return;
        }
        let batch = inner.lazy_evict_batch;
        let mut to_remove = Vec::new();
        for (checked, (key, entry)) in inner.entries.iter().enumerate() {
            if checked >= batch {
                break;
            }
            if entry.is_expired(now) {
                to_remove.push(*key);
            }
        }
        for key in to_remove {
            inner.entries.remove(&key);
        }
    }

    /// Evict the least-recently-used non-expired entry (§6.7.7).
    fn evict_lru(&self, inner: &mut Inner, _now: Instant) {
        // First try to evict expired entries.
        let mut expired_key: Option<CacheKey> = None;
        for (key, entry) in &inner.entries {
            if entry.is_expired(_now) {
                expired_key = Some(*key);
                break;
            }
        }
        if let Some(key) = expired_key {
            inner.entries.remove(&key);
            return;
        }

        // No expired entries: evict LRU.
        let mut lru_key: Option<CacheKey> = None;
        let mut lru_time = Instant::now();
        for (key, entry) in &inner.entries {
            if entry.last_accessed < lru_time {
                lru_time = entry.last_accessed;
                lru_key = Some(*key);
            }
        }
        if let Some(key) = lru_key {
            inner.entries.remove(&key);
        }
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayCache")
            .field("retention", &self.retention)
            .field("max_entries", &self.max_entries)
            .field("len", &self.len())
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn agent_id(seed: u8) -> Vec<u8> {
        vec![seed; AGENT_ID_SIZE]
    }

    fn nonce(seed: u8) -> [u8; NONCE_SIZE] {
        [seed; NONCE_SIZE]
    }

    // ── Basic functionality ───────────────────────────────────────────

    #[test]
    fn test_new_cache_is_empty() {
        let cache = ReplayCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.retention(), DEFAULT_RETENTION);
        assert_eq!(cache.max_entries(), DEFAULT_MAX_ENTRIES);
    }

    #[test]
    fn test_check_and_insert_fresh_nonce() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = nonce(0x42);
        assert!(!cache.check(&aid, &n), "fresh nonce should not be replay");
        let result = cache.check_and_insert(&aid, &n);
        assert!(result.is_ok(), "first insert should succeed");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_check_and_insert_replay_detected() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.check_and_insert(&aid, &n).unwrap();
        let result = cache.check_and_insert(&aid, &n);
        assert!(result.is_err(), "second insert should be replay");
        assert_eq!(cache.len(), 1, "replay should not add new entry");
    }

    #[test]
    fn test_check_detects_existing() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.check_and_insert(&aid, &n).unwrap();
        assert!(cache.check(&aid, &n), "check should detect existing nonce");
    }

    #[test]
    fn test_check_does_not_detect_missing() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = nonce(0x42);
        assert!(
            !cache.check(&aid, &n),
            "check should not detect missing nonce"
        );
    }

    #[test]
    fn test_different_agent_same_nonce_not_replay() {
        let cache = ReplayCache::new();
        let aid1 = agent_id(1);
        let aid2 = agent_id(2);
        let n = nonce(0x42);
        cache.check_and_insert(&aid1, &n).unwrap();
        let result = cache.check_and_insert(&aid2, &n);
        assert!(
            result.is_ok(),
            "same nonce, different agent should not be replay"
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_different_nonce_same_agent_not_replay() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n1 = nonce(0x01);
        let n2 = nonce(0x02);
        cache.check_and_insert(&aid, &n1).unwrap();
        let result = cache.check_and_insert(&aid, &n2);
        assert!(
            result.is_ok(),
            "same agent, different nonce should not be replay"
        );
        assert_eq!(cache.len(), 2);
    }

    // ── Insert without check ──────────────────────────────────────────

    #[test]
    fn test_insert_without_check() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.insert(&aid, &n);
        assert_eq!(cache.len(), 1);
        assert!(
            cache.check(&aid, &n),
            "inserted nonce should be detected by check"
        );
    }

    #[test]
    fn test_insert_idempotent() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.insert(&aid, &n);
        cache.insert(&aid, &n);
        assert_eq!(cache.len(), 1, "double insert should not duplicate");
    }

    // ── Eviction ──────────────────────────────────────────────────────

    #[test]
    fn test_evict_expired_removes_expired_entries() {
        let cache = ReplayCache::with_params_unchecked(Duration::from_millis(50), 10_000);
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.check_and_insert(&aid, &n).unwrap();
        assert_eq!(cache.len(), 1);
        // Wait for expiry.
        std::thread::sleep(Duration::from_millis(60));
        let evicted = cache.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_expired_nonce_not_detected_as_replay() {
        let cache = ReplayCache::with_params_unchecked(Duration::from_millis(50), 10_000);
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.check_and_insert(&aid, &n).unwrap();
        // Wait for expiry.
        std::thread::sleep(Duration::from_millis(60));
        let result = cache.check_and_insert(&aid, &n);
        assert!(result.is_ok(), "expired nonce should not be replay");
    }

    #[test]
    fn test_expired_nonce_check_returns_false() {
        let cache = ReplayCache::with_params_unchecked(Duration::from_millis(50), 10_000);
        let aid = agent_id(1);
        let n = nonce(0x42);
        cache.check_and_insert(&aid, &n).unwrap();
        // Wait for expiry.
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            !cache.check(&aid, &n),
            "expired nonce should not be detected"
        );
    }

    #[test]
    fn test_max_entries_enforced() {
        let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 5);
        for i in 0..10u8 {
            let aid = agent_id(i);
            let n = nonce(i);
            cache.check_and_insert(&aid, &n).unwrap();
        }
        assert_eq!(cache.len(), 5, "cache should be capped at max_entries");
    }

    #[test]
    fn test_lru_eviction_allows_replay_of_evicted() {
        let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 3);
        // Insert 3 entries.
        for i in 0..3u8 {
            let aid = agent_id(i);
            let n = nonce(i);
            cache.check_and_insert(&aid, &n).unwrap();
        }
        assert_eq!(cache.len(), 3);
        // Insert 4th: should evict LRU (agent 0).
        let aid3 = agent_id(3);
        let n3 = nonce(3);
        cache.check_and_insert(&aid3, &n3).unwrap();
        assert_eq!(cache.len(), 3);
        // Agent 0's nonce was evicted, so it should be insertable again.
        let aid0 = agent_id(0);
        let n0 = nonce(0);
        let result = cache.check_and_insert(&aid0, &n0);
        assert!(result.is_ok(), "evicted nonce should be insertable again");
    }

    // ── Parameter validation ──────────────────────────────────────────

    #[test]
    fn test_retention_too_short() {
        let result = ReplayCache::with_params(Duration::from_secs(30), 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_retention_too_long() {
        let result = ReplayCache::with_params(Duration::from_secs(7200), 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_entries_too_small() {
        let result = ReplayCache::with_params(Duration::from_secs(300), 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_entries_too_large() {
        let result = ReplayCache::with_params(Duration::from_secs(300), 20_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_params() {
        let result = ReplayCache::with_params(Duration::from_secs(120), 5000);
        assert!(result.is_ok());
        let cache = result.unwrap();
        assert_eq!(cache.retention(), Duration::from_secs(120));
        assert_eq!(cache.max_entries(), 5000);
    }

    // ── Clear ─────────────────────────────────────────────────────────

    #[test]
    fn test_clear() {
        let cache = ReplayCache::new();
        for i in 0..10u8 {
            let aid = agent_id(i);
            let n = nonce(i);
            cache.check_and_insert(&aid, &n).unwrap();
        }
        assert_eq!(cache.len(), 10);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    // ── Concurrency ───────────────────────────────────────────────────

    #[test]
    fn test_concurrent_check_and_insert() {
        let cache = Arc::new(ReplayCache::new());
        let aid = agent_id(1);
        let n = nonce(0x42);
        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let aid = aid.clone();
            handles.push(thread::spawn(move || cache.check_and_insert(&aid, &n)));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let err_count = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(ok_count, 1, "exactly one concurrent insert should succeed");
        assert_eq!(err_count, 9, "all others should be replay");
    }

    #[test]
    fn test_concurrent_different_nonces() {
        let cache = Arc::new(ReplayCache::new());
        let mut handles = Vec::new();
        for i in 0..20u8 {
            let cache = Arc::clone(&cache);
            let aid = agent_id(i);
            let n = nonce(i);
            handles.push(thread::spawn(move || cache.check_and_insert(&aid, &n)));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(ok_count, 20, "all unique nonces should succeed");
        assert_eq!(cache.len(), 20);
    }

    // ── Debug ─────────────────────────────────────────────────────────

    #[test]
    fn test_debug_format() {
        let cache = ReplayCache::new();
        let debug_str = format!("{:?}", cache);
        assert!(debug_str.contains("ReplayCache"));
        assert!(debug_str.contains("retention"));
        assert!(debug_str.contains("max_entries"));
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn test_short_agent_id_padded() {
        let cache = ReplayCache::new();
        let aid = vec![0xAA; 16]; // Short agent ID (16 bytes)
        let n = nonce(0x42);
        cache.check_and_insert(&aid, &n).unwrap();
        assert!(cache.check(&aid, &n), "short agent ID should work");
    }

    #[test]
    fn test_all_zero_nonce() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = [0u8; NONCE_SIZE];
        cache.check_and_insert(&aid, &n).unwrap();
        let result = cache.check_and_insert(&aid, &n);
        assert!(result.is_err(), "all-zero nonce replay should be detected");
    }

    #[test]
    fn test_all_ff_nonce() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        let n = [0xFFu8; NONCE_SIZE];
        cache.check_and_insert(&aid, &n).unwrap();
        let result = cache.check_and_insert(&aid, &n);
        assert!(result.is_err(), "all-FF nonce replay should be detected");
    }

    #[test]
    fn test_many_nonces_same_agent() {
        let cache = ReplayCache::new();
        let aid = agent_id(1);
        for i in 0..100u8 {
            let n = nonce(i);
            let result = cache.check_and_insert(&aid, &n);
            assert!(result.is_ok(), "nonce {} should be fresh", i);
        }
        assert_eq!(cache.len(), 100);
        // All should be detected as replays.
        for i in 0..100u8 {
            let n = nonce(i);
            assert!(cache.check(&aid, &n), "nonce {} should be replay", i);
        }
    }

    #[test]
    fn test_many_agents_same_nonce() {
        let cache = ReplayCache::new();
        let n = nonce(0x42);
        for i in 0..100u8 {
            let aid = agent_id(i);
            let result = cache.check_and_insert(&aid, &n);
            assert!(result.is_ok(), "agent {} should be fresh", i);
        }
        assert_eq!(cache.len(), 100);
    }

    #[test]
    fn test_with_capacity() {
        let cache = ReplayCache::with_capacity(Duration::from_secs(300), 10_000, 500).unwrap();
        assert_eq!(cache.max_entries(), 10_000);
    }
}
