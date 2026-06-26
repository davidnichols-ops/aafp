use criterion::{criterion_group, criterion_main, Criterion};
use aafp_messaging::{serialize_frame, deserialize_frame};
use aafp_messaging::rpc::{serialize_request, RpcRequest};

fn bench_frame_serialize(c: &mut Criterion) {
    let payload = vec![0u8; 1024];
    c.bench_function("frame_serialize_1kb", |b| {
        b.iter(|| serialize_frame(&payload));
    });
}

fn bench_frame_deserialize(c: &mut Criterion) {
    let payload = vec![0u8; 1024];
    let frame = serialize_frame(&payload);
    c.bench_function("frame_deserialize_1kb", |b| {
        b.iter(|| deserialize_frame(&frame));
    });
}

fn bench_rpc_serialize(c: &mut Criterion) {
    let req = RpcRequest {
        id: 1,
        method: "echo".into(),
        params: vec![0u8; 256],
    };
    c.bench_function("rpc_serialize", |b| {
        b.iter(|| serialize_request(&req).unwrap());
    });
}

criterion_group!(
    benches,
    bench_frame_serialize,
    bench_frame_deserialize,
    bench_rpc_serialize,
);
criterion_main!(benches);
