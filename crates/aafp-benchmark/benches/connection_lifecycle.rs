//! Benchmark: Connection lifecycle — cold vs warm vs pooled vs pool vs rebind.
//!
//! Track I1 + I8: Measures connection lifecycle scenarios:
//! 1. Cold connect: First connection to a server (full TLS handshake)
//! 2. Warm connect: Second connection to same server (TLS session resumption)
//! 3. Pooled connect: Open a new stream on an existing connection
//! 4. Pool vs no-pool: 100 sequential RPCs with pool vs without (Track I8)
//! 5. Rebind: Time to rebind endpoint (Track I8/I6)
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

/// Benchmark: 100 sequential RPCs with connection pool vs without (Track I8).
///
/// This measures the total time for 100 sequential "connect + open stream"
/// operations:
/// - Without pool: 100 full TLS handshakes (240µs each = ~24ms total)
/// - With pool: 1 handshake + 99 stream opens (14µs each = ~1.4ms total)
///
/// The improvement demonstrates the value of connection pooling (Track I5).
fn bench_pool_vs_no_pool(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("connection_lifecycle_pool");
    group.sample_size(10);
    group.throughput(Throughput::Elements(100));

    // Without pool: 100 separate connections
    group.bench_function("100_rpcs_no_pool", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server();
                    let server_addr = server.local_multiaddr().unwrap();

                    // Server accepts 100 connections and their streams
                    let server_clone = server.clone();
                    let handle = tokio::spawn(async move {
                        for _ in 0..100 {
                            if let Ok(conn) = server_clone.accept().await {
                                // Accept the one stream the client opens
                                let _ = conn.accept_bi().await;
                                conn.close(0u32, b"done");
                            }
                        }
                    });

                    let client_config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new_with_resumption(client_config).unwrap();

                    let start = Instant::now();
                    for _ in 0..100 {
                        let conn = client.dial(&server_addr).await.unwrap();
                        let _ = conn.open_bi().await;
                        conn.close(0u32, b"done");
                    }
                    let elapsed = start.elapsed();

                    let _ = handle.await;
                    client.close();
                    drop(server);
                    elapsed
                });
            }
            total
        });
    });

    // With pool: 1 connection, 100 stream opens (raw QUIC, no AAFP handshake)
    group.bench_function("100_rpcs_with_pool", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server();
                    let server_addr = server.local_multiaddr().unwrap();

                    // Server accepts 1 connection, then accepts streams in a loop
                    let server_clone = server.clone();
                    let handle = tokio::spawn(async move {
                        if let Ok(conn) = server_clone.accept().await {
                            while let Ok((_s, _r)) = conn.accept_bi().await {
                                // Drop the stream
                            }
                        }
                    });

                    let client_config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new_with_resumption(client_config).unwrap();

                    // First call: establish connection (full handshake)
                    let conn = client.dial(&server_addr).await.unwrap();

                    let start = Instant::now();
                    // Subsequent 100 calls: just open streams (pooled connection)
                    for _ in 0..100 {
                        let _ = conn.open_bi().await.unwrap();
                    }
                    let elapsed = start.elapsed();

                    conn.close(0u32, b"done");
                    let _ = handle.await;
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

/// Benchmark: Rebind time (Track I8/I6 — connection migration).
///
/// Measures the time to rebind the endpoint to a new UDP socket.
/// This is the local address change that triggers QUIC connection migration.
fn bench_rebind(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("connection_lifecycle_migration");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_function("rebind_endpoint", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let transport = QuicTransport::new(config).unwrap();

                    // Create a new socket to rebind to
                    let new_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

                    let start = Instant::now();
                    transport.rebind(new_socket).unwrap();
                    let elapsed = start.elapsed();

                    transport.close();
                    tokio::time::sleep(Duration::from_millis(10)).await;
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
    bench_pooled_connect,
    bench_pool_vs_no_pool,
    bench_rebind
);
criterion_main!(benches);
