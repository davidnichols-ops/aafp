use aafp_messaging::CloseManager;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_initiate_close(c: &mut Criterion) {
    c.bench_function("close_initiate", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.initiate_close(0, "goodbye")
        });
    });
}

fn bench_graceful_close_full(c: &mut Criterion) {
    c.bench_function("close_graceful_full", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.initiate_close(0, "goodbye");
            cm.on_close_received(0, "ack");
        });
    });
}

fn bench_forced_close_abort(c: &mut Criterion) {
    c.bench_function("close_forced_abort", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.abort()
        });
    });
}

fn bench_close_under_flood(c: &mut Criterion) {
    // Simulate receiving 1000 frames during close.
    c.bench_function("close_under_flood_1000", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.initiate_close(0, "bye");
            for i in 0..1000u32 {
                cm.on_close_received(i, "flood");
            }
        });
    });
}

fn bench_frame_disposition_during_close(c: &mut Criterion) {
    c.bench_function("close_frame_disposition", |b| {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        b.iter(|| {
            for ft in 0u8..=255 {
                cm.frame_disposition(ft);
            }
        });
    });
}

fn bench_can_send_during_close(c: &mut Criterion) {
    c.bench_function("close_can_send", |b| {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        b.iter(|| {
            for ft in 0u8..=255 {
                cm.can_send(ft);
            }
        });
    });
}

fn bench_respond_close(c: &mut Criterion) {
    c.bench_function("close_respond", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.on_close_received(0, "peer");
            cm.respond_close(0, "ack");
        });
    });
}

fn bench_crossed_close(c: &mut Criterion) {
    c.bench_function("close_crossed", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.initiate_close(0, "local");
            cm.on_close_received(0, "peer");
        });
    });
}

fn bench_timeout_close(c: &mut Criterion) {
    c.bench_function("close_timeout", |b| {
        b.iter(|| {
            let mut cm = CloseManager::new();
            cm.initiate_close(0, "bye");
            cm.on_timeout();
        });
    });
}

criterion_group!(
    benches,
    bench_initiate_close,
    bench_graceful_close_full,
    bench_forced_close_abort,
    bench_close_under_flood,
    bench_frame_disposition_during_close,
    bench_can_send_during_close,
    bench_respond_close,
    bench_crossed_close,
    bench_timeout_close,
);
criterion_main!(benches);
