//! ML-DSA-65 performance benchmarks (A-10 Phase 7).
//!
//! Measures keygen, sign, verify, and deterministic sign performance
//! for both Rust and Go (via shared vectors).

use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_keypair(c: &mut Criterion) {
    c.bench_function("mldsa65_keypair", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair();
            black_box(&pk);
            black_box(&sk);
        });
    });
}

fn bench_keypair_from_seed(c: &mut Criterion) {
    c.bench_function("mldsa65_keypair_from_seed", |b| {
        let seed = [0x42u8; 32];
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair_from_seed(black_box(&seed));
            black_box(&pk);
            black_box(&sk);
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    let (_, sk) = MlDsa65::keypair();
    let msg = b"benchmark message for ML-DSA-65 signing";
    c.bench_function("mldsa65_sign", |b| {
        b.iter(|| {
            let sig = MlDsa65::sign(black_box(&sk), black_box(msg));
            black_box(&sig);
        });
    });
}

fn bench_sign_deterministic(c: &mut Criterion) {
    let (_, sk) = MlDsa65::keypair();
    let msg = b"benchmark message for ML-DSA-65 deterministic signing";
    let seed = [0u8; 32];
    c.bench_function("mldsa65_sign_deterministic", |b| {
        b.iter(|| {
            let sig = MlDsa65::sign_deterministic(black_box(&sk), black_box(msg), black_box(&seed));
            black_box(&sig);
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"benchmark message for ML-DSA-65 verification";
    let sig = MlDsa65::sign(&sk, msg);
    c.bench_function("mldsa65_verify", |b| {
        b.iter(|| {
            let result = MlDsa65::verify(black_box(&pk), black_box(msg), black_box(&sig));
            let _ = black_box(result);
        });
    });
}

fn bench_verify_invalid(c: &mut Criterion) {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"benchmark message for ML-DSA-65 verification";
    let sig = MlDsa65::sign(&sk, msg);
    let wrong_msg = b"wrong message";
    c.bench_function("mldsa65_verify_invalid", |b| {
        b.iter(|| {
            let result = MlDsa65::verify(black_box(&pk), black_box(wrong_msg), black_box(&sig));
            let _ = black_box(result);
        });
    });
}

fn bench_decode_public_key(c: &mut Criterion) {
    let (pk, _) = MlDsa65::keypair();
    c.bench_function("mldsa65_decode_public_key", |b| {
        b.iter(|| {
            let result = MlDsa65PublicKey::from_bytes(black_box(&pk.0));
            let _ = black_box(result);
        });
    });
}

fn bench_decode_secret_key(c: &mut Criterion) {
    let (_, sk) = MlDsa65::keypair();
    c.bench_function("mldsa65_decode_secret_key", |b| {
        b.iter(|| {
            let result = MlDsa65SecretKey::from_bytes(black_box(&sk.0));
            let _ = black_box(result);
        });
    });
}

fn bench_decode_signature(c: &mut Criterion) {
    let (_, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"msg");
    c.bench_function("mldsa65_decode_signature", |b| {
        b.iter(|| {
            let result = MlDsa65Signature::from_bytes(black_box(&sig.0));
            let _ = black_box(result);
        });
    });
}

criterion_group!(
    mldsa65_benches,
    bench_keypair,
    bench_keypair_from_seed,
    bench_sign,
    bench_sign_deterministic,
    bench_verify,
    bench_verify_invalid,
    bench_decode_public_key,
    bench_decode_secret_key,
    bench_decode_signature,
);
criterion_main!(mldsa65_benches);
