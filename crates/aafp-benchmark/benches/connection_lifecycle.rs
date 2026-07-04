//! Benchmark: Connection lifecycle — cold vs warm (resumption) connect times.
//!
//! Track I1: Measures the time to establish a QUIC connection:
//! 1. Cold connect: First connection to a server (full TLS handshake)
//! 2. Warm connect: Second connection to same server (TLS session resumption)
//! 3. Pooled connect: Open a new stream on an existing connection
//!
//! The warm connect should be faster than cold because the client reuses the
//! cached TLS 1.3 session ticket, skipping the full key exchange.
//!
//! Run with:
//! ```bash
//! cargo bench --bench connection_lifecycle -- --warm-up-time 2 --measurement-time 3 --sample-size 10
//! ```

use aafp_transport_quic::{QuicConfig, QuicTransport};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Set up a server transport with resumption enabled.
fn setup_server() -> Arc<QuicTransport> {
    let config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    Arc::new(QuicTransport::new_with_resumption(config).unwrap())
}

/// Benchmark: Cold connect (no session cache, full TLS handshake).
///
/// Each iteration creates a fresh client (no session cache) and connects
/// to a server. The full TLS handshake including PQ KEX is performed.
fn bench_cold_connect(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("connection_lifecycle");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_function("cold_connect", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server();
                    let server_addr = server.local_multiaddr().unwrap();

                    let server_clone = server.clone();
                    let handle = tokio::spawn(async move {
                        let _ = server_clone.accept().await;
                    });

                    // Client with NO resumption (cold)
                    let client_config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new(client_config).unwrap();

                    let start = Instant::now();
                    let conn = client.dial(&server_addr).await.unwrap();
                    let elapsed = start.elapsed();

                    handle.await.unwrap();
                    conn.close(0u32, b"done");
                    client.close();
                    drop(server);
                    elapsed
                });
            }
            total
        });
    });

    group.finish();
}

/// Benchmark: Warm connect (with session cache, TLS resumption).
///
/// A shared client with session resumption is created once. Each iteration
/// connects to a fresh server, then immediately connects again. The second
/// connection should reuse the cached session ticket.
///
/// Note: Each iteration needs a fresh server because the previous server's
/// endpoint is closed. The session ticket is keyed by SNI ("localhost"), so
/// it should be reused across different server addresses.
fn bench_warm_connect(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("connection_lifecycle");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_function("warm_connect", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server();
                    let server_addr = server.local_multiaddr().unwrap();

                    // Client WITH resumption
                    let client_config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new_with_resumption(client_config).unwrap();

                    // First connection: populates session cache (full handshake)
                    let server_clone = server.clone();
                    let handle1 = tokio::spawn(async move {
                        let conn = server_clone.accept().await.unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        conn.close(0u32, b"done");
                    });
                    let conn1 = client.dial(&server_addr).await.unwrap();
                    handle1.await.unwrap();
                    drop(conn1);

                    // Wait for first connection to fully close
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    // Second connection: should reuse session ticket (warm)
                    let server_clone2 = server.clone();
                    let handle2 = tokio::spawn(async move {
                        let conn = server_clone2.accept().await.unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        conn.close(0u32, b"done");
                    });

                    let start = Instant::now();
                    let conn2 = client.dial(&server_addr).await.unwrap();
                    let elapsed = start.elapsed();

                    handle2.await.unwrap();
                    drop(conn2);
                    client.close();
                    drop(server);
                    elapsed
                });
            }
            total
        });
    });

    group.finish();
}

/// Benchmark: Pooled connect (reuse existing connection — open new stream).
///
/// This measures the time to open a new bidirectional stream on an existing
/// QUIC connection. This is the baseline for Track I5 (connection pool) —
/// a pooled connection skips the TLS handshake entirely.
fn bench_pooled_connect(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("connection_lifecycle");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_function("pooled_connect", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server();
                    let server_addr = server.local_multiaddr().unwrap();

                    let server_clone = server.clone();
                    let handle = tokio::spawn(async move {
                        let conn = server_clone.accept().await.unwrap();
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        conn.close(0u32, b"done");
                    });

                    let client_config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new_with_resumption(client_config).unwrap();

                    // Establish connection once
                    let conn = client.dial(&server_addr).await.unwrap();

                    // Measure: open a new bidirectional stream (pooled connection)
                    let start = Instant::now();
                    let _ = conn.open_bi().await.unwrap();
                    let elapsed = start.elapsed();

                    handle.await.unwrap();
                    conn.close(0u32, b"done");
                    client.close();
                    drop(server);
                    elapsed
                });
            }
            total
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cold_connect,
    bench_warm_connect,
    bench_pooled_connect
);
criterion_main!(benches);
