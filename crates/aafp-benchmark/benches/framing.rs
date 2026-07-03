use aafp_messaging::{decode_frame, encode_frame, Frame};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encode");
    for size in [64, 256, 1024, 4096, 16384, 65536] {
        let payload = vec![0u8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                let frame = Frame::data(0, payload.clone());
                encode_frame(&frame)
            });
        });
    }
    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decode");
    for size in [64, 256, 1024, 4096, 16384, 65536] {
        let payload = vec![0u8; size];
        let frame = Frame::data(0, payload);
        let encoded = encode_frame(&frame).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &encoded, |b, encoded| {
            b.iter(|| decode_frame(encoded));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_frame_encode, bench_frame_decode);
criterion_main!(benches);
