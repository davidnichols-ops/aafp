//! Benchmarks for nonce replay detection (RFC-0002 §6.7, A-9).

use aafp_crypto::ReplayCache;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn make_nonce(seed: u32) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    nonce[..4].copy_from_slice(&seed.to_be_bytes());
    nonce
}

fn bench_check_and_insert_fresh(c: &mut Criterion) {
    let mut group = c.benchmark_group("replay_cache");
    group.bench_function("check_and_insert_fresh", |b| {
        let mut i = 0u32;
        b.iter(|| {
            let cache = ReplayCache::new();
            let aid = vec![0x01u8; 32];
            let nonce = make_nonce(i);
            i += 1;
            black_box(cache.check_and_insert(&aid, &nonce))
        });
    });
    group.finish();
}

fn bench_check_and_insert_replay(c: &mut Criterion) {
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = make_nonce(0x42);
    cache.check_and_insert(&aid, &nonce).unwrap();

    c.bench_function("check_and_insert_replay", |b| {
        b.iter(|| black_box(cache.check_and_insert(&aid, &nonce)));
    });
}

fn bench_check_fresh(c: &mut Criterion) {
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = make_nonce(0x42);

    c.bench_function("check_fresh", |b| {
        b.iter(|| black_box(cache.check(&aid, &nonce)));
    });
}

fn bench_check_existing(c: &mut Criterion) {
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    let nonce = make_nonce(0x42);
    cache.check_and_insert(&aid, &nonce).unwrap();

    c.bench_function("check_existing", |b| {
        b.iter(|| black_box(cache.check(&aid, &nonce)));
    });
}

fn bench_check_and_insert_100k_cache(c: &mut Criterion) {
    // Pre-fill cache with 100K entries, then benchmark insert of new nonce.
    let cache = ReplayCache::new();
    let aid = vec![0x01u8; 32];
    for i in 0..100_000u32 {
        let nonce = make_nonce(i);
        cache.check_and_insert(&aid, &nonce).unwrap();
    }
    let mut i = 100_000u32;

    c.bench_function("check_and_insert_100k_cache", |b| {
        b.iter(|| {
            let nonce = make_nonce(i);
            i += 1;
            black_box(cache.check_and_insert(&aid, &nonce))
        });
    });
}

fn bench_evict_expired(c: &mut Criterion) {
    c.bench_function("evict_expired_10k", |b| {
        b.iter(|| {
            let cache = ReplayCache::with_params_unchecked(Duration::from_millis(1), 100_000);
            let aid = vec![0x01u8; 32];
            for i in 0..10_000u32 {
                let nonce = make_nonce(i);
                cache.check_and_insert(&aid, &nonce).unwrap();
            }
            std::thread::sleep(Duration::from_millis(2));
            black_box(cache.evict_expired())
        });
    });
}

criterion_group!(
    replay_bench,
    bench_check_and_insert_fresh,
    bench_check_and_insert_replay,
    bench_check_fresh,
    bench_check_existing,
    bench_check_and_insert_100k_cache,
    bench_evict_expired,
);
criterion_main!(replay_bench);
