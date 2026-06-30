use aafp_messaging::{decode_frame, encode_frame, Frame};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_frame_serialize(c: &mut Criterion) {
    let payload = vec![0u8; 1024];
    c.bench_function("frame_serialize_1kb", |b| {
        b.iter(|| {
            let frame = Frame::data(0, payload.clone());
            encode_frame(&frame)
        });
    });
}

fn bench_frame_deserialize(c: &mut Criterion) {
    let payload = vec![0u8; 1024];
    let frame = Frame::data(0, payload);
    let encoded = encode_frame(&frame).unwrap();
    c.bench_function("frame_deserialize_1kb", |b| {
        b.iter(|| decode_frame(&encoded));
    });
}

criterion_group!(benches, bench_frame_serialize, bench_frame_deserialize,);
criterion_main!(benches);
