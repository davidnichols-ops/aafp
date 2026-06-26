use criterion::{criterion_group, criterion_main, Criterion};
use aafp_crypto::{MlDsa65, PqHandshake, SignatureScheme};

fn bench_mldsa65_sign(c: &mut Criterion) {
    let (_pk, sk) = MlDsa65::keypair();
    let msg = b"benchmark message for ml-dsa-65 signing";
    c.bench_function("mldsa65_sign", |b| {
        b.iter(|| MlDsa65::sign(&sk, msg));
    });
}

fn bench_mldsa65_verify(c: &mut Criterion) {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"benchmark message for ml-dsa-65 verify";
    let sig = MlDsa65::sign(&sk, msg);
    c.bench_function("mldsa65_verify", |b| {
        b.iter(|| MlDsa65::verify(&pk, msg, &sig));
    });
}

fn bench_mldsa65_keypair(c: &mut Criterion) {
    c.bench_function("mldsa65_keypair", |b| {
        b.iter(|| MlDsa65::keypair());
    });
}

fn bench_handshake(c: &mut Criterion) {
    c.bench_function("pq_handshake_full", |b| {
        b.iter(|| {
            let server_kp = MlDsa65::keypair();
            let (hello, mut state) = PqHandshake::client_init();
            let (server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
            PqHandshake::client_finish(&server_hello, &mut state).unwrap();
        });
    });
}

criterion_group!(benches, bench_mldsa65_sign, bench_mldsa65_verify, bench_mldsa65_keypair, bench_handshake);
criterion_main!(benches);
