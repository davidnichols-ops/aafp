#![allow(deprecated)]

use aafp_crypto::handshake::PqHandshake;
use aafp_crypto::{MlDsa65, SignatureScheme};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_mldsa65_keypair(c: &mut Criterion) {
    c.bench_function("mldsa65_keypair", |b| {
        b.iter(|| MlDsa65::keypair());
    });
}

fn bench_mldsa65_sign(c: &mut Criterion) {
    let (_pk, sk) = MlDsa65::keypair();
    let msg = b"benchmark message";
    c.bench_function("mldsa65_sign", |b| {
        b.iter(|| MlDsa65::sign(&sk, msg));
    });
}

fn bench_mldsa65_verify(c: &mut Criterion) {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"benchmark message";
    let sig = MlDsa65::sign(&sk, msg);
    c.bench_function("mldsa65_verify", |b| {
        b.iter(|| MlDsa65::verify(&pk, msg, &sig));
    });
}

fn bench_pq_handshake(c: &mut Criterion) {
    c.bench_function("pq_handshake_full", |b| {
        b.iter(|| {
            let server_kp = MlDsa65::keypair();
            let (hello, mut state) = PqHandshake::client_init();
            let (server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
            PqHandshake::client_finish(&server_hello, &mut state).unwrap();
        });
    });
}

fn bench_aead_encrypt(c: &mut Criterion) {
    use aafp_crypto::{Aead, AeadAlgorithm};
    let aead = Aead::new([0x42u8; 32], AeadAlgorithm::ChaCha20Poly1305);
    let nonce = [0u8; 12];
    let aad = b"aad";
    let pt = vec![0u8; 1024];
    c.bench_function("aead_encrypt_1kb", |b| {
        b.iter(|| aead.encrypt(&nonce, aad, &pt));
    });
}

fn bench_aead_decrypt(c: &mut Criterion) {
    use aafp_crypto::{Aead, AeadAlgorithm};
    let aead = Aead::new([0x42u8; 32], AeadAlgorithm::ChaCha20Poly1305);
    let nonce = [0u8; 12];
    let aad = b"aad";
    let pt = vec![0u8; 1024];
    let ct = aead.encrypt(&nonce, aad, &pt);
    c.bench_function("aead_decrypt_1kb", |b| {
        b.iter(|| aead.decrypt(&nonce, aad, &ct));
    });
}

criterion_group!(
    benches,
    bench_mldsa65_keypair,
    bench_mldsa65_sign,
    bench_mldsa65_verify,
    bench_pq_handshake,
    bench_aead_encrypt,
    bench_aead_decrypt,
);
criterion_main!(benches);
