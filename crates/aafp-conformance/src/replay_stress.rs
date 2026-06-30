//! Stress tests for nonce replay detection (RFC-0002 §6.7, A-9).
//!
//! These tests verify the ReplayCache under heavy load:
//! - 100K nonces insertion and detection
//! - Concurrent access from many threads
//! - Eviction under pressure
//! - Memory bounds

#![allow(unused_imports)]
use aafp_crypto::{NonceReuseError, ReplayCache};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn make_nonce(seed: u32) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    nonce[..4].copy_from_slice(&seed.to_be_bytes());
    nonce
}

fn make_agent_id(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

// ── 100K nonces ────────────────────────────────────────────────────

#[test]
fn test_stress_100k_nonces_single_agent() {
    let cache = ReplayCache::new();
    let aid = make_agent_id(1);
    let count = 100_000u32;

    let start = Instant::now();
    for i in 0..count {
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    let insert_elapsed = start.elapsed();
    assert_eq!(cache.len(), count as usize);

    // All nonces should be detected as replays.
    let start = Instant::now();
    for i in 0..count {
        let nonce = make_nonce(i);
        assert!(cache.check(&aid, &nonce), "nonce {} should be replay", i);
    }
    let check_elapsed = start.elapsed();

    // Performance assertions (generous to avoid CI flakiness).
    assert!(
        insert_elapsed < Duration::from_secs(5),
        "100K inserts took {:?}",
        insert_elapsed
    );
    assert!(
        check_elapsed < Duration::from_secs(5),
        "100K checks took {:?}",
        check_elapsed
    );
}

#[test]
fn test_stress_100k_nonces_different_agents() {
    let cache = ReplayCache::new();
    let count = 100_000u32;

    let start = Instant::now();
    for i in 0..count {
        let aid = make_agent_id((i % 256) as u8);
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    let elapsed = start.elapsed();
    assert_eq!(cache.len(), count as usize);

    assert!(
        elapsed < Duration::from_secs(5),
        "100K inserts (different agents) took {:?}",
        elapsed
    );
}

// ── Concurrency stress ─────────────────────────────────────────────

#[test]
fn test_stress_concurrent_10k_nonces_10_threads() {
    let cache = Arc::new(ReplayCache::new());
    let threads = 10;
    let per_thread = 10_000u32;
    let mut handles = Vec::new();

    let start = Instant::now();
    for t in 0..threads {
        let cache = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            let aid = make_agent_id(t as u8);
            for i in 0..per_thread {
                let nonce = make_nonce(t as u32 * per_thread + i);
                cache.check_and_insert(&aid, &nonce).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed();

    assert_eq!(cache.len(), (threads * per_thread) as usize);
    assert!(
        elapsed < Duration::from_secs(10),
        "concurrent 100K inserts took {:?}",
        elapsed
    );
}

#[test]
fn test_stress_concurrent_same_nonce_100_threads() {
    // 100 threads all trying to insert the same nonce.
    // Exactly one should succeed.
    let cache = Arc::new(ReplayCache::new());
    let aid = make_agent_id(1);
    let nonce = make_nonce(0x42);
    let threads = 100;
    let mut handles = Vec::new();

    for _ in 0..threads {
        let cache = Arc::clone(&cache);
        let aid = aid.clone();
        handles.push(std::thread::spawn(move || {
            cache.check_and_insert(&aid, &nonce)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one must win out of {} threads",
        threads
    );
    assert_eq!(cache.len(), 1);
}

// ── Eviction stress ────────────────────────────────────────────────

#[test]
fn test_stress_eviction_with_small_max_entries() {
    // Insert 100K nonces with max_entries=1000.
    // Cache should stay at 1000 entries.
    let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 1000);
    let aid = make_agent_id(1);

    for i in 0..100_000u32 {
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    assert_eq!(cache.len(), 1000, "cache must stay at max_entries");
}

#[test]
fn test_stress_eviction_allows_replay_of_evicted() {
    // With small cache, early nonces are evicted and become insertable again.
    let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), 100);
    let aid = make_agent_id(1);

    // Fill cache.
    for i in 0..200u32 {
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    assert_eq!(cache.len(), 100);

    // Nonce 0 should have been evicted (LRU).
    let n0 = make_nonce(0);
    let result = cache.check_and_insert(&aid, &n0);
    assert!(result.is_ok(), "evicted nonce should be insertable again");
}

// ── Memory bounds ──────────────────────────────────────────────────

#[test]
fn test_stress_memory_bounded_at_max_entries() {
    let max = 10_000;
    let cache = ReplayCache::with_params_unchecked(Duration::from_secs(60), max);
    let aid = make_agent_id(1);

    // Insert far more than max_entries.
    for i in 0..(max * 5) as u32 {
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    assert_eq!(cache.len(), max, "cache must not exceed max_entries");
}

// ── Expiry stress ──────────────────────────────────────────────────

#[test]
fn test_stress_expired_entries_cleaned_up() {
    let cache = ReplayCache::with_params_unchecked(Duration::from_millis(50), 10_000);
    let aid = make_agent_id(1);

    // Insert 1000 entries.
    for i in 0..1000u32 {
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    assert_eq!(cache.len(), 1000);

    // Wait for expiry.
    std::thread::sleep(Duration::from_millis(60));

    // Evict expired.
    let evicted = cache.evict_expired();
    assert_eq!(evicted, 1000);
    assert_eq!(cache.len(), 0);

    // All nonces should be fresh again.
    for i in 0..1000u32 {
        let nonce = make_nonce(i);
        let result = cache.check_and_insert(&aid, &nonce);
        assert!(result.is_ok(), "expired nonce {} should be fresh", i);
    }
}

// ── Mixed workload ─────────────────────────────────────────────────

#[test]
fn test_stress_mixed_insert_and_check() {
    let cache = Arc::new(ReplayCache::new());
    let aid = make_agent_id(1);
    let mut handles = Vec::new();

    // Thread 1: insert nonces 0-4999
    {
        let cache = Arc::clone(&cache);
        let aid = aid.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..5000u32 {
                let nonce = make_nonce(i);
                cache.check_and_insert(&aid, &nonce).unwrap();
            }
        }));
    }

    // Thread 2: insert nonces 5000-9999
    {
        let cache = Arc::clone(&cache);
        let aid = aid.clone();
        handles.push(std::thread::spawn(move || {
            for i in 5000..10_000u32 {
                let nonce = make_nonce(i);
                cache.check_and_insert(&aid, &nonce).unwrap();
            }
        }));
    }

    // Thread 3: check nonces 0-9999 (some will be replays, some fresh)
    {
        let cache = Arc::clone(&cache);
        let aid = aid.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..10_000u32 {
                let nonce = make_nonce(i);
                let _ = cache.check(&aid, &nonce);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(cache.len(), 10_000);
}
