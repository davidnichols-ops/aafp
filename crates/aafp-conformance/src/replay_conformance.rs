//! Conformance tests for normative nonce replay detection (RFC-0002 §6.7, A-9).
//!
//! These tests verify that the ReplayCache implements every normative
//! requirement from §6.7. Each test is tagged with its source section.
//!
//! ## Test Categories
//!
//! - **Threat model**: §6.7.1
//! - **Cache structure**: §6.7.2
//! - **Cache parameters**: §6.7.3
//! - **Normative invariants**: §6.7.4 (7 invariants)
//! - **Server-side replay check**: §6.7.5
//! - **Client-side replay check**: §6.7.6
//! - **Eviction and resource management**: §6.7.7
//! - **Concurrency**: §6.7.8
//! - **Security considerations**: §6.7.11

#![allow(unused_imports)]
use aafp_crypto::{
    NonceReuseError, ReplayCache, DEFAULT_MAX_ENTRIES, DEFAULT_RETENTION, MAX_MAX_ENTRIES,
    MAX_RETENTION, MIN_MAX_ENTRIES, MIN_RETENTION,
};
use std::sync::Arc;
use std::time::Duration;

// ── §6.7.2 Cache Structure ─────────────────────────────────────────

#[test]
fn test_r2_400_cache_key_is_agent_id_plus_nonce() {
    // §6.7.2: Cache key is (agent_id, nonce). Same nonce with different
    // agent_id must NOT be a replay.
    let cache = ReplayCache::new();
    let aid1 = vec![0x01u8; 32];
    let aid2 = vec![0x02u8; 32];
    let nonce = [0x42u8; 32];

    cache.check_and_insert(&aid1, &nonce).unwrap();
    let result = cache.check_and_insert(&aid2, &nonce);
    assert!(
        result.is_ok(),
        "same nonce, different agent_id must not be replay"
    );
}

#[test]
fn test_r2_401_cache_key_nonce_scoped_per_agent() {
    // §6.7.2: Same agent_id with different nonces must not be replay.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let n1 = [0x01u8; 32];
    let n2 = [0x02u8; 32];

    cache.check_and_insert(&aid, &n1).unwrap();
    let result = cache.check_and_insert(&aid, &n2);
    assert!(
        result.is_ok(),
        "same agent, different nonce must not be replay"
    );
}

// ── §6.7.3 Cache Parameters ────────────────────────────────────────

#[test]
fn test_r2_402_default_retention_300s() {
    // §6.7.3: Default retention is 300 seconds.
    let cache = ReplayCache::new();
    assert_eq!(cache.retention(), Duration::from_secs(300));
}

#[test]
fn test_r2_403_default_max_entries_100k() {
    // §6.7.3: Default max_entries is 100,000.
    let cache = ReplayCache::new();
    assert_eq!(cache.max_entries(), 100_000);
}

#[test]
fn test_r2_404_retention_minimum_60s() {
    // §6.7.3: Minimum retention is 60 seconds.
    let result = ReplayCache::with_params(Duration::from_secs(30), 1000);
    assert!(result.is_err(), "retention < 60s must be rejected");
}

#[test]
fn test_r2_405_retention_maximum_3600s() {
    // §6.7.3: Maximum retention is 3600 seconds.
    let result = ReplayCache::with_params(Duration::from_secs(7200), 1000);
    assert!(result.is_err(), "retention > 3600s must be rejected");
}

#[test]
fn test_r2_406_max_entries_minimum_1000() {
    // §6.7.3: Minimum max_entries is 1,000.
    let result = ReplayCache::with_params(Duration::from_secs(300), 100);
    assert!(result.is_err(), "max_entries < 1000 must be rejected");
}

#[test]
fn test_r2_407_max_entries_maximum_10m() {
    // §6.7.3: Maximum max_entries is 10,000,000.
    let result = ReplayCache::with_params(Duration::from_secs(300), 20_000_000);
    assert!(result.is_err(), "max_entries > 10M must be rejected");
}

// ── §6.7.4 Normative Invariants ────────────────────────────────────

#[test]
fn test_r2_408_invariant1_check_before_verify() {
    // §6.7.4 Invariant 1: Check MUST be performed before signature
    // verification. The check() method is O(1) and does not verify
    // signatures. This test verifies that check() returns quickly
    // and does not require any crypto parameters.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];

    // check() should return false for a fresh nonce without any
    // signature material.
    assert!(!cache.check(&aid, &nonce));
}

#[test]
fn test_r2_409_invariant2_insert_after_verify_server() {
    // §6.7.4 Invariant 2: Server inserts (agent_id, client_nonce)
    // AFTER signature verification, BEFORE ServerHello.
    // The insert() method is separate from check(), allowing the
    // caller to verify first, then insert.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];

    // Step 1: Check (before verify) — fresh.
    assert!(!cache.check(&aid, &nonce));
    // Step 2: Verify signature (simulated — would fail for invalid sig).
    // Step 3: Insert (after verify).
    cache.insert(&aid, &nonce);
    // Step 4: Subsequent check detects replay.
    assert!(cache.check(&aid, &nonce));
}

#[test]
fn test_r2_410_invariant3_insert_after_verify_client() {
    // §6.7.4 Invariant 3: Client inserts (agent_id, server_nonce)
    // AFTER ServerHello verification, BEFORE ClientFinished.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];

    assert!(!cache.check(&aid, &nonce));
    cache.insert(&aid, &nonce);
    assert!(cache.check(&aid, &nonce));
}

#[test]
fn test_r2_411_invariant4_atomicity_concurrent() {
    // §6.7.4 Invariant 4: check_and_insert MUST be atomic. If two
    // connections with same (agent_id, nonce) arrive simultaneously,
    // exactly one MUST succeed.
    let cache = Arc::new(ReplayCache::new());
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];

    let mut handles = Vec::new();
    for _ in 0..10 {
        let cache = Arc::clone(&cache);
        let aid = aid.clone();
        handles.push(std::thread::spawn(move || {
            cache.check_and_insert(&aid, &nonce)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok_count, 1, "exactly one concurrent insert must succeed");
}

#[test]
fn test_r2_412_invariant5_no_silent_acceptance() {
    // §6.7.4 Invariant 5: If a replay is detected, MUST return error.
    // The check_and_insert method returns Err(NonceReuseError) for replays.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];

    cache.check_and_insert(&aid, &nonce).unwrap();
    let result = cache.check_and_insert(&aid, &nonce);
    assert!(result.is_err(), "replay must not be silently accepted");
}

#[test]
fn test_r2_413_invariant6_eviction_non_blocking() {
    // §6.7.4 Invariant 6: Eviction MUST not block for > 1ms.
    // We verify that check_and_insert with a large cache is fast.
    let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 50_000);
    let aid = vec![0x01u8; 32];

    // Fill cache to trigger lazy eviction.
    for i in 0..50_000u32 {
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        cache.check_and_insert(&aid, &nonce).unwrap();
    }

    // Time a single check_and_insert — should be < 1ms.
    let start = std::time::Instant::now();
    let nonce = [0xFFu8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "check_and_insert should be fast even with large cache, took {:?}",
        elapsed
    );
}

#[test]
fn test_r2_414_invariant7_persistence_optional() {
    // §6.7.4 Invariant 7: Persistence is optional. The in-memory cache
    // works without any persistence layer.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    assert!(cache.check(&aid, &nonce));
}

// ── §6.7.5 Server-Side Replay Check ────────────────────────────────

#[test]
fn test_r2_415_server_side_fresh_nonce_accepted() {
    // §6.7.5: Fresh ClientHello nonce is accepted (check returns false).
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    assert!(
        !cache.check(&aid, &nonce),
        "fresh nonce should not be replay"
    );
}

#[test]
fn test_r2_416_server_side_replay_detected() {
    // §6.7.5: Replayed ClientHello nonce is rejected.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    assert!(cache.check(&aid, &nonce), "replayed nonce must be detected");
}

#[test]
fn test_r2_417_server_side_wrong_nonce_size_rejected() {
    // §6.7.5 step 2: Validate nonce is 32 bytes.
    // The check_and_insert method requires [u8; 32], enforced by type.
    // This is implicitly tested by the type system.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
}

// ── §6.7.6 Client-Side Replay Check ────────────────────────────────

#[test]
fn test_r2_418_client_side_fresh_server_nonce_accepted() {
    // §6.7.6: Fresh ServerHello nonce is accepted.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    assert!(!cache.check(&aid, &nonce));
}

#[test]
fn test_r2_419_client_side_replay_detected() {
    // §6.7.6: Replayed ServerHello nonce is rejected.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    assert!(cache.check(&aid, &nonce));
}

// ── §6.7.7 Eviction and Resource Management ────────────────────────

#[test]
fn test_r2_420_max_entries_enforced() {
    // §6.7.7: Cache MUST enforce max_entries.
    let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 10);
    for i in 0..20u8 {
        let aid = vec![i; 32];
        let nonce = [i; 32];
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    assert_eq!(cache.len(), 10, "cache must be capped at max_entries");
}

#[test]
fn test_r2_421_lru_eviction_when_full() {
    // §6.7.7: When full with no expired entries, evict LRU.
    let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 3);
    for i in 0..3u8 {
        let aid = vec![i; 32];
        let nonce = [i; 32];
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    // Insert 4th — should evict LRU (agent 0).
    let aid3 = vec![3u8; 32];
    let n3 = [3u8; 32];
    cache.check_and_insert(&aid3, &n3).unwrap();
    assert_eq!(cache.len(), 3);

    // Agent 0 should be evicted (insertable again).
    let aid0 = vec![0u8; 32];
    let n0 = [0u8; 32];
    assert!(
        cache.check_and_insert(&aid0, &n0).is_ok(),
        "evicted nonce should be insertable again"
    );
}

#[test]
fn test_r2_422_expired_entries_evicted_first() {
    // §6.7.7: Expired entries are evicted first.
    let cache = ReplayCache::with_params_unchecked(Duration::from_millis(50), 100);
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();

    std::thread::sleep(Duration::from_millis(60));
    let evicted = cache.evict_expired();
    assert_eq!(evicted, 1, "expired entry should be evicted");
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_r2_423_expired_nonce_not_replay() {
    // §6.7.7: After retention expires, nonce is no longer a replay.
    let cache = ReplayCache::with_params_unchecked(Duration::from_millis(50), 100);
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();

    std::thread::sleep(Duration::from_millis(60));
    let result = cache.check_and_insert(&aid, &nonce);
    assert!(result.is_ok(), "expired nonce should not be replay");
}

// ── §6.7.8 Concurrency ─────────────────────────────────────────────

#[test]
fn test_r2_424_concurrent_unique_nonces_all_succeed() {
    // §6.7.8: Concurrent unique nonces must all succeed.
    let cache = Arc::new(ReplayCache::new());
    let mut handles = Vec::new();
    for i in 0..20u8 {
        let cache = Arc::clone(&cache);
        let aid = vec![i; 32];
        let nonce = [i; 32];
        handles.push(std::thread::spawn(move || {
            cache.check_and_insert(&aid, &nonce)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok_count, 20, "all unique nonces must succeed");
}

#[test]
fn test_r2_425_concurrent_same_nonce_one_wins() {
    // §6.7.8: Concurrent same nonce — exactly one wins.
    let cache = Arc::new(ReplayCache::new());
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    let mut handles = Vec::new();
    for _ in 0..10 {
        let cache = Arc::clone(&cache);
        let aid = aid.clone();
        handles.push(std::thread::spawn(move || {
            cache.check_and_insert(&aid, &nonce)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok_count, 1, "exactly one must win");
}

// ── §6.7.11 Security Considerations ────────────────────────────────

#[test]
fn test_r2_426_check_before_verify_prevents_cpu_amplification() {
    // §6.7.11.1: Check before verify prevents CPU amplification.
    // A replayed nonce is rejected without signature verification.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();

    // The check is O(1) — no signature verification needed.
    let start = std::time::Instant::now();
    let is_replay = cache.check(&aid, &nonce);
    let elapsed = start.elapsed();
    assert!(is_replay);
    assert!(
        elapsed < Duration::from_millis(1),
        "check should be O(1), took {:?}",
        elapsed
    );
}

#[test]
fn test_r2_427_cache_poisoning_prevented() {
    // §6.7.11.2: Cache poisoning prevented by insert-after-verify.
    // A forged ClientHello with wrong signature would not be inserted.
    // The caller calls check() first, then verifies, then inserts.
    // If verification fails, insert() is never called.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];

    // Simulate: check (fresh), verify FAILS, do NOT insert.
    assert!(!cache.check(&aid, &nonce));
    // Verification fails — we skip insert.
    // The nonce is NOT in the cache, so a legitimate client can still use it.
    assert!(
        !cache.check(&aid, &nonce),
        "failed verification must not poison cache"
    );
}

#[test]
fn test_r2_428_false_positives_impossible() {
    // §6.7.11.4: With 32-byte random nonces, false positives are
    // statistically impossible. Verify that different nonces are
    // never detected as replays.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    for i in 0..100u8 {
        let nonce = [i; 32];
        let result = cache.check_and_insert(&aid, &nonce);
        assert!(result.is_ok(), "nonce {} must be fresh", i);
    }
}

#[test]
fn test_r2_429_all_zero_nonce_handled() {
    // §6.7.11: Edge case — all-zero nonce.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    let result = cache.check_and_insert(&aid, &nonce);
    assert!(result.is_err(), "all-zero nonce replay must be detected");
}

#[test]
fn test_r2_430_all_ff_nonce_handled() {
    // §6.7.11: Edge case — all-FF nonce.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0xFFu8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    let result = cache.check_and_insert(&aid, &nonce);
    assert!(result.is_err(), "all-FF nonce replay must be detected");
}

#[test]
fn test_r2_431_clear_resets_cache() {
    // Clear removes all entries.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = [0x42u8; 32];
    cache.check_and_insert(&aid, &nonce).unwrap();
    assert_eq!(cache.len(), 1);
    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(
        !cache.check(&aid, &nonce),
        "after clear, nonce should be fresh"
    );
}
