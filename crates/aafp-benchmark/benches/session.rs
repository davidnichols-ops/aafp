use aafp_core::{Session, SessionState};
use criterion::{criterion_group, criterion_main, Criterion};

/// Measure memory per session by creating many sessions and checking
/// the approximate size via std::mem::size_of.
fn bench_memory_per_session(c: &mut Criterion) {
    c.bench_function("memory_per_session", |b| {
        b.iter(|| {
            let session = Session::new();
            // Session is very lightweight — just state + metadata
            let _ = criterion::black_box(&session);
            session
        });
    });

    // Also measure size_of for a Session
    let size = std::mem::size_of::<Session>();
    println!("sizeof(Session) = {} bytes", size);
}

/// Measure how many sessions can be created quickly.
fn bench_concurrent_sessions(c: &mut Criterion) {
    c.bench_function("create_1000_sessions", |b| {
        b.iter(|| {
            let mut sessions = Vec::with_capacity(1000);
            for _ in 0..1000 {
                sessions.push(Session::new());
            }
            sessions
        });
    });
}

criterion_group!(benches, bench_memory_per_session, bench_concurrent_sessions);
criterion_main!(benches);
