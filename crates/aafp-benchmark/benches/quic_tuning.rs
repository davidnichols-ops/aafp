//! Benchmark: QUIC transport tuning (Track J7).
//!
//! Measures the impact of QUIC transport tuning (J1-J5) on round-trip
//! latency and throughput:
//! 1. Default config (Cubic, 333ms RTT, 25ms ACK) vs Low-latency (BBR, 10ms RTT, 5ms ACK)
//! 2. Small message round-trip (100 bytes)
//! 3. Medium message round-trip (1KB)
//! 4. Large message throughput (100KB)
//!
//! Run with:
//! ```bash
//! cargo bench --bench quic_tuning -- --warm-up-time 2 --measurement-time 3 --sample-size 10
//! ```

use aafp_transport_quic::{CongestionController, QuicConfig, QuicTransport};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Set up a server with the given config.
fn setup_server(config: QuicConfig) -> Arc<QuicTransport> {
    Arc::new(QuicTransport::new_with_resumption(config).unwrap())
}

/// Benchmark: Small message round-trip (100 bytes) with different configs.
///
/// Measures the time to send 100 bytes and receive 100 bytes back.
/// This is the critical RPC latency metric.
fn bench_small_message_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quic_tuning_small_message");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    let payload = vec![0u8; 100];

    // Default config (Cubic, 10ms RTT, 5ms ACK — already tuned in default)
    group.bench_function("default_config", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server(QuicConfig::default());
                    let server_addr = server.local_multiaddr().unwrap();

                    let server_clone = server.clone();
                    let payload_clone = payload.clone();
                    let handle = tokio::spawn(async move {
                        let conn = server_clone.accept().await.unwrap();
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let mut buf = vec![0u8; 100];
                        recv.read_exact(&mut buf).await.unwrap();
                        send.write_all(&payload_clone).await.unwrap();
                        send.finish();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    });

                    let client_config = QuicConfig {
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new_with_resumption(client_config).unwrap();

                    let conn = client.dial(&server_addr).await.unwrap();
                    let (mut send, mut recv) = conn.open_bi().await.unwrap();

                    let start = Instant::now();
                    send.write_all(&payload).await.unwrap();
                    send.finish();
                    let mut buf = vec![0u8; 100];
                    recv.read_exact(&mut buf).await.unwrap();
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

    // Low-latency config (BBR, 10ms RTT, 5ms ACK, 1MB window)
    group.bench_function("low_latency_bbr", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server(QuicConfig::low_latency());
                    let server_addr = server.local_multiaddr().unwrap();

                    let server_clone = server.clone();
                    let payload_clone = payload.clone();
                    let handle = tokio::spawn(async move {
                        let conn = server_clone.accept().await.unwrap();
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let mut buf = vec![0u8; 100];
                        recv.read_exact(&mut buf).await.unwrap();
                        send.write_all(&payload_clone).await.unwrap();
                        send.finish();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    });

                    let client =
                        QuicTransport::new_with_resumption(QuicConfig::low_latency()).unwrap();

                    let conn = client.dial(&server_addr).await.unwrap();
                    let (mut send, mut recv) = conn.open_bi().await.unwrap();

                    let start = Instant::now();
                    send.write_all(&payload).await.unwrap();
                    send.finish();
                    let mut buf = vec![0u8; 100];
                    recv.read_exact(&mut buf).await.unwrap();
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

    // NewReno config (for comparison)
    group.bench_function("newreno_config", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let config = QuicConfig {
                        congestion: CongestionController::NewReno,
                        ..Default::default()
                    };
                    let server = setup_server(config.clone());
                    let server_addr = server.local_multiaddr().unwrap();

                    let server_clone = server.clone();
                    let payload_clone = payload.clone();
                    let handle = tokio::spawn(async move {
                        let conn = server_clone.accept().await.unwrap();
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let mut buf = vec![0u8; 100];
                        recv.read_exact(&mut buf).await.unwrap();
                        send.write_all(&payload_clone).await.unwrap();
                        send.finish();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    });

                    let client_config = QuicConfig {
                        congestion: CongestionController::NewReno,
                        bind_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    };
                    let client = QuicTransport::new_with_resumption(client_config).unwrap();

                    let conn = client.dial(&server_addr).await.unwrap();
                    let (mut send, mut recv) = conn.open_bi().await.unwrap();

                    let start = Instant::now();
                    send.write_all(&payload).await.unwrap();
                    send.finish();
                    let mut buf = vec![0u8; 100];
                    recv.read_exact(&mut buf).await.unwrap();
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

/// Benchmark: Stream open latency (measures tuning impact on connection).
///
/// Measures the time to open a bidirectional stream on an existing
/// connection. This isolates the transport tuning from the TLS handshake.
fn bench_stream_open(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quic_tuning_stream_open");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_function("low_latency_bbr", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += rt.block_on(async {
                    let server = setup_server(QuicConfig::low_latency());
                    let server_addr = server.local_multiaddr().unwrap();

                    let server_clone = server.clone();
                    let handle = tokio::spawn(async move {
                        if let Ok(conn) = server_clone.accept().await {
                            while let Ok((_s, _r)) = conn.accept_bi().await {}
                        }
                    });

                    let client =
                        QuicTransport::new_with_resumption(QuicConfig::low_latency()).unwrap();
                    let conn = client.dial(&server_addr).await.unwrap();

                    let start = Instant::now();
                    let _ = conn.open_bi().await.unwrap();
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

criterion_group!(benches, bench_small_message_roundtrip, bench_stream_open);
criterion_main!(benches);
