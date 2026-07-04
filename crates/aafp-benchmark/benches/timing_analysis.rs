//! Timing side-channel analysis (Track Q5).
//!
//! These benchmarks measure timing differences in security-critical paths:
//! 1. Signature verification: valid vs invalid signature
//! 2. AgentId comparison: matching vs non-matching
//! 3. ReplayCache lookup: hit vs miss
//! 4. CBOR decode: valid vs invalid
//!
//! If timing differences are significant, an attacker can use them to
//! distinguish valid from invalid inputs without full verification.
//!
//! Run with: cargo bench --bench timing_analysis

use aafp_cbor::{decode, encode, int_map, Value};
use aafp_crypto::{
    generate_nonce, verify_client_hello, ClientHelloV1, MlDsa65, MlDsa65SecretKey, ReplayCache,
    SignatureScheme, TranscriptHash, KEY_ALG_ML_DSA_65, PROTOCOL_VERSION,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::Digest;
use std::time::Instant;

// ── Helper: build a valid ClientHello ──────────────────────────────

fn build_valid_client_hello(
    expires_at: u64,
) -> (
    ClientHelloV1,
    MlDsa65SecretKey,
    [u8; 32], // transcript hash
) {
    let (pk, sk) = MlDsa65::keypair();
    let agent_id = sha2::Sha256::digest(&pk.0).to_vec();

    let tls_binding = [0u8; 32];
    let mut th = TranscriptHash::from_tls_binding(&tls_binding);

    let mut ch = ClientHelloV1 {
        protocol_version: PROTOCOL_VERSION,
        agent_id,
        public_key: pk.0.clone(),
        nonce: generate_nonce(),
        capabilities: vec![],
        extensions: vec![],
        signature: vec![],
        expires_at,
        receiver_mac: None,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    let ch_cbor = ch.to_cbor_without_sig_and_mac();
    let ch_cbor_bytes = encode(&ch_cbor).unwrap();
    let h_after_ch = th.fold(&ch_cbor_bytes);

    let sig_input = {
        let mut input = Vec::new();
        input.extend_from_slice(aafp_crypto::handshake_v1::DOMAIN_SEPARATOR);
        input.extend_from_slice(&h_after_ch);
        input
    };
    let sig = MlDsa65::sign(&sk, &sig_input);
    ch.signature = sig.0;

    (ch, sk, h_after_ch)
}

// ── 1. Signature verification timing ───────────────────────────────

fn bench_sig_verify_timing(c: &mut Criterion) {
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3600)
        .unwrap_or(3600);
    let (ch, _sk, h_after_ch) = build_valid_client_hello(future);

    // Create an invalid signature (tampered)
    let mut ch_invalid = ch.clone();
    ch_invalid.signature[0] ^= 0xff;

    let mut group = c.benchmark_group("sig_verify_timing");

    group.bench_function("valid_signature", |b| {
        b.iter(|| {
            let result = verify_client_hello(black_box(&ch), black_box(&h_after_ch), 0);
            black_box(result);
        });
    });

    group.bench_function("invalid_signature", |b| {
        b.iter(|| {
            let result = verify_client_hello(black_box(&ch_invalid), black_box(&h_after_ch), 0);
            black_box(result);
        });
    });

    group.finish();
}

// ── 2. AgentId comparison timing ───────────────────────────────────

fn bench_agent_id_comparison_timing(c: &mut Criterion) {
    // AgentId is [u8; 32] with derived PartialEq (short-circuit comparison).
    // This is a potential timing side-channel.
    let id_a = [0u8; 32];
    let id_b = [0u8; 32]; // identical to id_a
    let mut id_c = [0u8; 32];
    id_c[0] = 1; // differs in first byte
    let mut id_d = [0u8; 32];
    id_d[31] = 1; // differs in last byte

    let mut group = c.benchmark_group("agent_id_comparison_timing");

    group.bench_function("matching", |b| {
        b.iter(|| {
            let result = black_box(id_a) == black_box(id_b);
            black_box(result);
        });
    });

    group.bench_function("non_matching_first_byte", |b| {
        b.iter(|| {
            let result = black_box(id_a) == black_box(id_c);
            black_box(result);
        });
    });

    group.bench_function("non_matching_last_byte", |b| {
        b.iter(|| {
            let result = black_box(id_a) == black_box(id_d);
            black_box(result);
        });
    });

    group.finish();
}

// ── 3. ReplayCache lookup timing ───────────────────────────────────

fn bench_replay_cache_timing(c: &mut Criterion) {
    let cache = ReplayCache::with_params_unchecked(std::time::Duration::from_secs(300), 10_000);

    // Insert a nonce
    let agent_id = vec![0u8; 32];
    let nonce_hit = generate_nonce();
    cache.check_and_insert(&agent_id, &nonce_hit).unwrap();

    // A nonce that's not in the cache
    let nonce_miss = generate_nonce();

    let mut group = c.benchmark_group("replay_cache_timing");

    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            let result = cache.check(black_box(&agent_id), black_box(&nonce_hit));
            black_box(result);
        });
    });

    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            let result = cache.check(black_box(&agent_id), black_box(&nonce_miss));
            black_box(result);
        });
    });

    group.finish();
}

// ── 4. CBOR decode timing ──────────────────────────────────────────

fn bench_cbor_decode_timing(c: &mut Criterion) {
    // Valid CBOR: a simple map {1: "hello"}
    let valid_cbor = encode(&int_map(vec![(1, Value::TextString("hello".to_string()))])).unwrap();

    // Invalid CBOR: truncated valid CBOR
    let invalid_cbor = &valid_cbor[..valid_cbor.len() / 2];

    // Invalid CBOR: random bytes
    let random_bytes = vec![0xffu8; 32];

    let mut group = c.benchmark_group("cbor_decode_timing");

    group.bench_function("valid_cbor", |b| {
        b.iter(|| {
            let result = decode(black_box(&valid_cbor));
            black_box(result);
        });
    });

    group.bench_function("truncated_cbor", |b| {
        b.iter(|| {
            let result = decode(black_box(invalid_cbor));
            black_box(result);
        });
    });

    group.bench_function("random_bytes", |b| {
        b.iter(|| {
            let result = decode(black_box(&random_bytes));
            black_box(result);
        });
    });

    group.finish();
}

// ── 5. Manual timing measurement (for JSON output) ─────────────────

fn bench_manual_timing(c: &mut Criterion) {
    c.bench_function("manual_timing_overhead", |b| {
        b.iter(|| {
            let start = Instant::now();
            let _ = black_box(1 + 1);
            let elapsed = start.elapsed();
            black_box(elapsed);
        });
    });
}

criterion_group!(
    timing_analysis,
    bench_sig_verify_timing,
    bench_agent_id_comparison_timing,
    bench_replay_cache_timing,
    bench_cbor_decode_timing,
    bench_manual_timing,
);
criterion_main!(timing_analysis);
