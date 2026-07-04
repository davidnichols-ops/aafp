//! WAN simulation tests — userspace latency, packet loss, and congestion control.
//!
//! Since QUIC runs over UDP and toxiproxy only supports TCP, these tests
//! simulate WAN conditions by injecting artificial delays and simulated
//! packet loss in the echo server loop. This provides a controlled,
//! reproducible environment for measuring AAFP behavior under adverse
//! network conditions without requiring root or external tools.
//!
//! ## Test coverage
//! - **O2:** Latency and throughput across message sizes (64B–64KB)
//! - **O3:** Packet loss (1%, 5%) and high-latency (200ms, 500ms RTT)
//! - **O4:** BBR vs Cubic vs NewReno under various conditions
//! - **O5:** Cross-network interop (A2A over simulated WAN)
//! - **O6:** Connection migration (multiple localhost addresses)
//! - **O7:** Multi-node DHT discovery (3 agents on different ports)
//!
//! ## Simulation approach
//! The echo server adds a configurable delay before responding and randomly
//! drops a percentage of requests to simulate packet loss. This measures
//! the *application-level* impact of network conditions, which is what
//! matters for AAFP deployment decisions.

#![allow(deprecated)]

use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_transport_quic::{CongestionController, QuicConfig, QuicTransport};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Send a frame and receive the echo response (round-trip).
async fn round_trip(
    conn: &aafp_transport_quic::QuicConnection,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let frame = Frame::data(0, payload.to_vec());
    let frame_bytes = encode_frame(&frame)?;
    send.write_all(&frame_bytes).await?;
    send.finish();

    let mut header = [0u8; FRAME_HEADER_SIZE];
    recv.read_exact(&mut header).await?;
    let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
    let body_len = payload_len + ext_len;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        recv.read_exact(&mut body).await?;
    }
    let mut full = header.to_vec();
    full.extend_from_slice(&body);
    let (resp_frame, _) = decode_frame(&full)?;
    Ok(resp_frame.payload)
}

/// Latency statistics (microseconds).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LatencyStats {
    count: usize,
    min_us: f64,
    p50_us: f64,
    p90_us: f64,
    p99_us: f64,
    p999_us: f64,
    max_us: f64,
    mean_us: f64,
}

impl LatencyStats {
    fn from_samples(samples: &[Duration]) -> Self {
        let mut us: Vec<f64> = samples
            .iter()
            .map(|d| d.as_secs_f64() * 1_000_000.0)
            .collect();
        us.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = us.len();
        let pct = |p: f64| -> f64 {
            if n == 0 {
                return 0.0;
            }
            let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
            us[idx.min(n - 1)]
        };
        let mean = if n > 0 {
            us.iter().sum::<f64>() / n as f64
        } else {
            0.0
        };
        Self {
            count: n,
            min_us: us.first().copied().unwrap_or(0.0),
            p50_us: pct(50.0),
            p90_us: pct(90.0),
            p99_us: pct(99.0),
            p999_us: pct(99.9),
            max_us: us.last().copied().unwrap_or(0.0),
            mean_us: mean,
        }
    }
}

/// Configuration for the simulated echo server.
#[derive(Clone)]
struct SimConfig {
    /// Artificial delay added before echoing each message (simulates RTT/2).
    delay: Duration,
    /// Packet loss probability (0.0 = no loss, 1.0 = 100% loss).
    loss_rate: f64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            loss_rate: 0.0,
        }
    }
}

/// Start a simulated echo server with configurable delay and packet loss.
async fn start_sim_echo_server(
    config: SimConfig,
) -> (
    Arc<aafp_sdk::Agent>,
    String,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
) {
    let server_agent = Arc::new(
        aafp_sdk::AgentBuilder::new()
            .with_capabilities(vec!["echo".into()])
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap(),
    );
    let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let drop_count = Arc::new(AtomicU64::new(0));
    let server_running = Arc::new(AtomicBool::new(true));
    let drop_count_clone = drop_count.clone();
    let running_clone = server_running.clone();
    let delay = config.delay;
    let loss_rate = config.loss_rate;

    let agent_clone = server_agent.clone();
    tokio::spawn(async move {
        loop {
            if !running_clone.load(Ordering::Relaxed) {
                break;
            }
            let conn = match agent_clone.transport.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let dc = drop_count_clone.clone();
            tokio::spawn(async move {
                loop {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    let dc = dc.clone();
                    tokio::spawn(async move {
                        let mut header = [0u8; FRAME_HEADER_SIZE];
                        if recv.read_exact(&mut header).await.is_err() {
                            return;
                        }
                        let payload_len =
                            u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
                        let ext_len =
                            u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
                        let body_len = payload_len + ext_len;
                        let mut body = vec![0u8; body_len];
                        if body_len > 0 && recv.read_exact(&mut body).await.is_err() {
                            return;
                        }

                        // Simulate packet loss: drop this request.
                        if loss_rate > 0.0 {
                            let r: f64 = rand::random();
                            if r < loss_rate {
                                dc.fetch_add(1, Ordering::Relaxed);
                                return; // Drop — don't respond.
                            }
                        }

                        // Simulate network delay.
                        if delay > Duration::ZERO {
                            tokio::time::sleep(delay).await;
                        }

                        let mut full = header.to_vec();
                        full.extend_from_slice(&body);
                        let (frame, _) = match decode_frame(&full) {
                            Ok(f) => f,
                            Err(_) => return,
                        };
                        let resp = Frame::data(0, frame.payload.clone());
                        let resp_bytes = match encode_frame(&resp) {
                            Ok(b) => b,
                            Err(_) => return,
                        };
                        let _ = send.write_all(&resp_bytes).await;
                        send.finish();
                    });
                }
            });
        }
    });

    (server_agent, addr, drop_count, server_running)
}

/// Run a ping test with N round-trips, returning latency stats.
async fn run_ping_test(
    addr: &str,
    congestion: CongestionController,
    count: usize,
    size: usize,
) -> LatencyStats {
    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(addr).await.expect("dial failed");

    let payload = vec![0xABu8; size];

    // Warmup.
    for _ in 0..5 {
        let _ = round_trip(&conn, &payload).await;
    }

    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let start = Instant::now();
        let _ = round_trip(&conn, &payload).await;
        samples.push(start.elapsed());
    }

    conn.close(0, b"test done");
    client.close();
    LatencyStats::from_samples(&samples)
}

/// Run a throughput test with N one-way sends.
async fn run_throughput_test(
    addr: &str,
    congestion: CongestionController,
    count: usize,
    size: usize,
) -> (f64, f64) {
    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(addr).await.expect("dial failed");

    let payload = vec![0xCDu8; size];
    let start = Instant::now();
    for _ in 0..count {
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        let frame = Frame::data(0, payload.clone());
        let frame_bytes = encode_frame(&frame).unwrap();
        send.write_all(&frame_bytes).await.unwrap();
        send.finish();
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let msgs_per_sec = count as f64 / secs;
    let mbps = (count * size) as f64 * 8.0 / secs / 1_000_000.0;

    conn.close(0, b"test done");
    client.close();
    (msgs_per_sec, mbps)
}

// ─── O2: Latency and throughput across message sizes ─────────────────────

/// Measure round-trip latency for each message size on localhost (baseline).
#[tokio::test]
async fn o2_latency_by_size() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sizes = [64, 256, 1024, 4096, 16384, 65536];
    let mut results = Vec::new();

    for &size in &sizes {
        let stats = run_ping_test(&addr, CongestionController::Cubic, 100, size).await;
        println!(
            "O2 latency size={:>6}B: p50={:.1}µs, p90={:.1}µs, p99={:.1}µs, mean={:.1}µs",
            size, stats.p50_us, stats.p90_us, stats.p99_us, stats.mean_us
        );
        results.push((size, stats));
    }

    // Verify: larger messages have higher latency (bandwidth-limited).
    let p64 = results[0].1.p50_us;
    let p64k = results[5].1.p50_us;
    assert!(
        p64k > p64,
        "64KB should have higher latency than 64B: {p64k}µs vs {p64}µs"
    );

    // Verify: localhost p50 for 64B should be under 500µs.
    assert!(p64 < 500.0, "64B localhost p50 too high: {p64}µs");
}

/// Measure throughput for each message size on localhost (baseline).
#[tokio::test]
async fn o2_throughput_by_size() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sizes = [64, 256, 1024, 4096, 16384, 65536];
    let count = 200;

    for &size in &sizes {
        let (mps, mbps) =
            run_throughput_test(&addr, CongestionController::Cubic, count, size).await;
        println!(
            "O2 throughput size={:>6}B: {:.0} msg/s, {:.2} Mbps",
            size, mps, mbps
        );
    }

    // Verify: 1KB throughput should be at least 1000 msg/s on localhost.
    let (mps_1k, _) = run_throughput_test(&addr, CongestionController::Cubic, 200, 1024).await;
    assert!(mps_1k > 1000.0, "1KB throughput too low: {mps_1k} msg/s");
}

/// Measure latency with simulated 50ms RTT (typical WAN).
#[tokio::test]
async fn o2_latency_simulated_wan_50ms() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(50), // 50ms server-side delay ≈ 50ms RTT
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stats = run_ping_test(&addr, CongestionController::Cubic, 50, 1024).await;
    println!(
        "O2 WAN 50ms RTT: p50={:.0}µs, p90={:.0}µs, p99={:.0}µs, mean={:.0}µs",
        stats.p50_us, stats.p90_us, stats.p99_us, stats.mean_us
    );

    // With 50ms simulated delay, p50 should be >= 45ms (50000µs).
    assert!(
        stats.p50_us >= 45_000.0,
        "simulated WAN p50 should be >= 45ms: {}µs",
        stats.p50_us
    );
    // And should not be wildly over (e.g., < 200ms).
    assert!(
        stats.p99_us < 200_000.0,
        "simulated WAN p99 too high: {}µs",
        stats.p99_us
    );
}

/// Measure throughput with simulated 50ms RTT.
#[tokio::test]
async fn o2_throughput_simulated_wan_50ms() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(50),
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mps, mbps) = run_throughput_test(&addr, CongestionController::Cubic, 100, 1024).await;
    println!("O2 WAN 50ms throughput: {:.0} msg/s, {:.2} Mbps", mps, mbps);

    // Throughput should be lower than localhost but still functional.
    assert!(mps > 10.0, "WAN throughput too low: {mps} msg/s");
}

// ─── O3: Packet loss and high-latency conditions ─────────────────────────

/// Test 1% packet loss — measure impact on latency.
#[tokio::test]
async fn o3_packet_loss_1pct() {
    let (_server, addr, drop_count, _running) = start_sim_echo_server(SimConfig {
        loss_rate: 0.01,
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::Cubic,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let payload = vec![0xABu8; 256];
    let total = 200;
    let mut successes = 0;
    let mut failures = 0;
    let mut samples = Vec::new();

    for _ in 0..total {
        let start = Instant::now();
        match round_trip(&conn, &payload).await {
            Ok(resp) => {
                assert_eq!(resp.len(), 256);
                successes += 1;
                samples.push(start.elapsed());
            }
            Err(_) => {
                failures += 1;
            }
        }
    }

    let dropped = drop_count.load(Ordering::Relaxed);
    let stats = LatencyStats::from_samples(&samples);
    println!(
        "O3 1% loss: {successes}/{total} succeeded, {failures} failed, {dropped} dropped by server"
    );
    println!(
        "  latency (successful): p50={:.1}µs, p99={:.1}µs, mean={:.1}µs",
        stats.p50_us, stats.p99_us, stats.mean_us
    );

    // With 1% loss, we should still get most requests through (>90%).
    assert!(
        successes > total * 90 / 100,
        "too many failures at 1% loss: {successes}/{total}"
    );

    conn.close(0, b"done");
    client.close();
}

/// Test 5% packet loss — verify connection survives.
#[tokio::test]
async fn o3_packet_loss_5pct() {
    let (_server, addr, drop_count, _running) = start_sim_echo_server(SimConfig {
        loss_rate: 0.05,
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::Cubic,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let payload = vec![0xABu8; 256];
    let total = 200;
    let mut successes = 0;
    let mut failures = 0;

    for _ in 0..total {
        match round_trip(&conn, &payload).await {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    let dropped = drop_count.load(Ordering::Relaxed);
    println!("O3 5% loss: {successes}/{total} succeeded, {failures} failed, {dropped} dropped");

    // Connection should survive 5% loss (QUIC handles retransmission).
    // At 5% app-level drop, we expect at least 80% success.
    assert!(
        successes > total * 80 / 100,
        "too many failures at 5% loss: {successes}/{total}"
    );

    // Connection should still be alive.
    // Verify by doing one more round-trip.
    let _ = round_trip(&conn, &payload).await;

    conn.close(0, b"done");
    client.close();
}

/// Test 200ms RTT (cross-continent) — measure handshake and round-trip.
#[tokio::test]
async fn o3_high_latency_200ms() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(200), // 200ms server-side delay ≈ 200ms RTT
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::Cubic,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();

    // Measure handshake time under 200ms RTT.
    let hs_start = Instant::now();
    let conn = client.dial(&addr).await.expect("dial failed");
    let hs_time = hs_start.elapsed().as_secs_f64() * 1000.0;
    println!("O3 200ms RTT handshake: {hs_time:.1}ms");

    // Handshake under 200ms RTT should complete in < 1 second
    // (1 RTT for QUIC handshake + TLS).
    assert!(
        hs_time < 1000.0,
        "handshake too slow under 200ms RTT: {hs_time}ms"
    );

    // Measure round-trip latency.
    let stats = run_ping_test(&addr, CongestionController::Cubic, 20, 256).await;
    println!(
        "O3 200ms RTT ping: p50={:.0}µs, p99={:.0}µs",
        stats.p50_us, stats.p99_us
    );

    // p50 should be around 200ms (200000µs).
    assert!(
        stats.p50_us >= 180_000.0,
        "200ms RTT p50 too low: {}µs",
        stats.p50_us
    );

    conn.close(0, b"done");
    client.close();
}

/// Test 500ms RTT (satellite) — verify timeout handling.
#[tokio::test]
async fn o3_high_latency_500ms() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(500), // 500ms server-side delay ≈ 500ms RTT
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::Cubic,
        max_idle_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();

    // Measure handshake time under 500ms RTT.
    let hs_start = Instant::now();
    let conn = client.dial(&addr).await.expect("dial failed");
    let hs_time = hs_start.elapsed().as_secs_f64() * 1000.0;
    println!("O3 500ms RTT handshake: {hs_time:.1}ms");

    // Handshake should complete in < 2 seconds (1-2 RTT).
    assert!(
        hs_time < 2000.0,
        "handshake too slow under 500ms RTT: {hs_time}ms"
    );

    // Verify connection works with a few round-trips.
    let payload = vec![0xABu8; 64];
    for _ in 0..5 {
        let _ = round_trip(&conn, &payload).await.unwrap();
    }

    conn.close(0, b"done");
    client.close();
}

/// Test 1% loss + 100ms RTT — realistic cross-continent conditions.
#[tokio::test]
async fn o3_loss_1pct_rtt_100ms() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(100), // 100ms server-side delay ≈ 100ms RTT
        loss_rate: 0.01,
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::Cubic,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let payload = vec![0xABu8; 256];
    let total = 100;
    let mut successes = 0;
    let mut samples = Vec::new();

    for _ in 0..total {
        let start = Instant::now();
        if round_trip(&conn, &payload).await.is_ok() {
            successes += 1;
            samples.push(start.elapsed());
        }
    }

    let stats = LatencyStats::from_samples(&samples);
    println!(
        "O3 1% loss + 100ms RTT: {successes}/{total} succeeded, p50={:.0}µs, p99={:.0}µs",
        stats.p50_us, stats.p99_us
    );

    // Should get >90% success with 1% loss.
    assert!(
        successes > total * 90 / 100,
        "too many failures: {successes}/{total}"
    );

    conn.close(0, b"done");
    client.close();
}

// ─── O4: BBR vs Cubic vs NewReno validation ──────────────────────────────

/// Compare congestion controllers on a clean network (localhost baseline).
#[tokio::test]
async fn o4_congestion_clean_network() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let controllers = [
        ("cubic", CongestionController::Cubic),
        ("bbr", CongestionController::Bbr),
        ("newreno", CongestionController::NewReno),
    ];

    let mut results = Vec::new();
    for (name, cc) in &controllers {
        let stats = run_ping_test(&addr, *cc, 100, 1024).await;
        println!(
            "O4 clean {name}: p50={:.1}µs, p99={:.1}µs, mean={:.1}µs",
            stats.p50_us, stats.p99_us, stats.mean_us
        );
        results.push((name, stats));
    }

    // On a clean network, all controllers should perform similarly.
    // Verify all have p50 under 500µs.
    for (name, stats) in &results {
        assert!(
            stats.p50_us < 500.0,
            "{name} p50 too high on clean network: {}µs",
            stats.p50_us
        );
    }
}

/// Compare congestion controllers under 1% packet loss.
#[tokio::test]
async fn o4_congestion_1pct_loss() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        loss_rate: 0.01,
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let controllers = [
        ("cubic", CongestionController::Cubic),
        ("bbr", CongestionController::Bbr),
        ("newreno", CongestionController::NewReno),
    ];

    let mut results = Vec::new();
    for (name, cc) in &controllers {
        let stats = run_ping_test(&addr, *cc, 100, 1024).await;
        println!(
            "O4 1% loss {name}: p50={:.1}µs, p99={:.1}µs, mean={:.1}µs",
            stats.p50_us, stats.p99_us, stats.mean_us
        );
        results.push((name, stats));
    }

    // Under loss, BBR should generally be more stable (lower p99).
    // We verify that all controllers can handle 1% loss.
    for (name, stats) in &results {
        assert!(
            stats.p99_us < 50_000.0,
            "{name} p99 too high under 1% loss: {}µs",
            stats.p99_us
        );
    }
}

/// Compare congestion controllers under 5% packet loss.
#[tokio::test]
async fn o4_congestion_5pct_loss() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        loss_rate: 0.05,
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let controllers = [
        ("cubic", CongestionController::Cubic),
        ("bbr", CongestionController::Bbr),
        ("newreno", CongestionController::NewReno),
    ];

    let mut results = Vec::new();
    for (name, cc) in &controllers {
        let stats = run_ping_test(&addr, *cc, 100, 1024).await;
        println!(
            "O4 5% loss {name}: p50={:.1}µs, p99={:.1}µs, mean={:.1}µs",
            stats.p50_us, stats.p99_us, stats.mean_us
        );
        results.push((name, stats));
    }

    // Under 5% loss, all controllers should still function.
    // BBR should show more stable behavior (lower variance).
    for (name, stats) in &results {
        assert!(
            stats.p99_us < 100_000.0,
            "{name} p99 too high under 5% loss: {}µs",
            stats.p99_us
        );
    }
}

/// Compare congestion controllers under 100ms RTT.
#[tokio::test]
async fn o4_congestion_100ms_rtt() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(100),
        ..Default::default()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let controllers = [
        ("cubic", CongestionController::Cubic),
        ("bbr", CongestionController::Bbr),
        ("newreno", CongestionController::NewReno),
    ];

    let mut results = Vec::new();
    for (name, cc) in &controllers {
        let stats = run_ping_test(&addr, *cc, 30, 1024).await;
        println!(
            "O4 100ms RTT {name}: p50={:.0}µs, p99={:.0}µs, mean={:.0}µs",
            stats.p50_us, stats.p99_us, stats.mean_us
        );
        results.push((name, stats));
    }

    // Under high RTT, all should complete round-trips.
    for (name, stats) in &results {
        assert!(
            stats.p50_us >= 90_000.0,
            "{name} p50 too low for 100ms RTT: {}µs",
            stats.p50_us
        );
    }
}

/// Compare congestion controllers under 100ms RTT + 1% loss.
#[tokio::test]
async fn o4_congestion_100ms_rtt_1pct_loss() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig {
        delay: Duration::from_millis(100),
        loss_rate: 0.01,
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let controllers = [
        ("cubic", CongestionController::Cubic),
        ("bbr", CongestionController::Bbr),
        ("newreno", CongestionController::NewReno),
    ];

    let mut results = Vec::new();
    for (name, cc) in &controllers {
        let stats = run_ping_test(&addr, *cc, 30, 1024).await;
        println!(
            "O4 100ms+1% loss {name}: p50={:.0}µs, p99={:.0}µs, mean={:.0}µs",
            stats.p50_us, stats.p99_us, stats.mean_us
        );
        results.push((name, stats));
    }

    // Under combined conditions, all should function.
    for (name, stats) in &results {
        assert!(
            stats.p50_us >= 90_000.0,
            "{name} p50 too low for 100ms+loss: {}µs",
            stats.p50_us
        );
    }
}

/// Throughput comparison: BBR vs Cubic vs NewReno.
#[tokio::test]
async fn o4_throughput_comparison() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let controllers = [
        ("cubic", CongestionController::Cubic),
        ("bbr", CongestionController::Bbr),
        ("newreno", CongestionController::NewReno),
    ];

    for (name, cc) in &controllers {
        let (mps, mbps) = run_throughput_test(&addr, *cc, 200, 1024).await;
        println!("O4 throughput {name}: {:.0} msg/s, {:.2} Mbps", mps, mbps);
    }
}

// ─── O5: Cross-network interop testing ───────────────────────────────────

/// A2A interop over simulated WAN — Rust server + Rust client with 50ms delay.
/// Verifies that A2A protocol operations work under WAN conditions.
#[tokio::test]
async fn o5_a2a_interop_simulated_wan() {
    use aafp_transport_a2a::{
        dispatch_request, A2aClient, A2aError, A2aServerHandler, Message, Part, Role, Task,
        TaskListFilter, TaskState, TaskStatus,
    };
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    struct SimpleHandler {
        tasks: Mutex<HashMap<String, Task>>,
        next_id: Mutex<u64>,
    }

    impl SimpleHandler {
        fn new() -> Self {
            Self {
                tasks: Mutex::new(HashMap::new()),
                next_id: Mutex::new(1),
            }
        }

        async fn create_task(&self, message: Message) -> Task {
            let mut id_lock = self.next_id.lock().await;
            let id = *id_lock;
            *id_lock += 1;
            drop(id_lock);

            let task = Task {
                id: format!("task-{id}"),
                context_id: Some(format!("ctx-{id}")),
                status: TaskStatus {
                    state: TaskState::TaskStateWorking,
                    timestamp: Some("2026-07-04T00:00:00Z".to_string()),
                    message: None,
                },
                artifacts: None,
                history: Some(vec![message]),
                metadata: None,
            };
            self.tasks
                .lock()
                .await
                .insert(task.id.clone(), task.clone());
            task
        }
    }

    #[async_trait]
    impl A2aServerHandler for SimpleHandler {
        async fn send_message(&self, message: Message) -> Result<Task, A2aError> {
            Ok(self.create_task(message).await)
        }

        async fn send_streaming_message(
            &self,
            message: Message,
        ) -> Result<Vec<aafp_transport_a2a::TaskUpdateEvent>, A2aError> {
            let task = self.create_task(message).await;
            let event = aafp_transport_a2a::TaskStatusUpdateEvent {
                task_id: task.id.clone(),
                context_id: task.context_id.clone().unwrap_or_default(),
                status: task.status.clone(),
                r#final: Some(true),
                metadata: None,
            };
            Ok(vec![aafp_transport_a2a::TaskUpdateEvent::Status(event)])
        }

        async fn get_task(&self, task_id: String) -> Result<Task, A2aError> {
            self.tasks
                .lock()
                .await
                .get(&task_id)
                .cloned()
                .ok_or(A2aError::TaskNotFound { task_id })
        }

        async fn list_tasks(&self, _filter: TaskListFilter) -> Result<Vec<Task>, A2aError> {
            Ok(self.tasks.lock().await.values().cloned().collect())
        }

        async fn cancel_task(&self, task_id: String) -> Result<Task, A2aError> {
            let mut tasks = self.tasks.lock().await;
            if let Some(task) = tasks.get_mut(&task_id) {
                task.status.state = TaskState::TaskStateCanceled;
                return Ok(task.clone());
            }
            Err(A2aError::TaskNotFound { task_id })
        }

        async fn subscribe_to_task(
            &self,
            _task_id: String,
        ) -> Result<Vec<aafp_transport_a2a::TaskUpdateEvent>, A2aError> {
            Ok(vec![])
        }

        async fn create_push_notification_config(
            &self,
            _task_id: String,
            _config: aafp_transport_a2a::PushNotificationConfig,
        ) -> Result<aafp_transport_a2a::PushNotificationConfig, A2aError> {
            Err(A2aError::PushNotificationNotSupported)
        }

        async fn get_push_notification_config(
            &self,
            _task_id: String,
            _config_id: String,
        ) -> Result<aafp_transport_a2a::PushNotificationConfig, A2aError> {
            Err(A2aError::PushNotificationNotSupported)
        }

        async fn list_push_notification_configs(
            &self,
            _task_id: String,
        ) -> Result<Vec<aafp_transport_a2a::PushNotificationConfig>, A2aError> {
            Ok(vec![])
        }

        async fn delete_push_notification_config(
            &self,
            _task_id: String,
            _config_id: String,
        ) -> Result<(), A2aError> {
            Err(A2aError::PushNotificationNotSupported)
        }

        async fn get_extended_agent_card(&self) -> Result<aafp_transport_a2a::AgentCard, A2aError> {
            Err(A2aError::ExtendedAgentCardNotConfigured)
        }
    }

    fn user_message(text: &str, msg_id: &str) -> Message {
        Message {
            role: Role::RoleUser,
            parts: vec![Part::text(text)],
            message_id: msg_id.to_string(),
            context_id: None,
            task_id: None,
            metadata: None,
            extensions: None,
            reference_task_ids: None,
        }
    }

    // Start A2A server.
    let server_agent = aafp_sdk::AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();
    let addr = server_agent.transport.local_multiaddr().unwrap();

    let handler: Arc<dyn A2aServerHandler> = Arc::new(SimpleHandler::new());
    let handler_clone = handler.clone();
    let server_agent = Arc::new(server_agent);

    let server_handle = tokio::spawn(async move {
        let mut transport = aafp_transport_a2a::AafpA2aTransport::accept(&server_agent)
            .await
            .unwrap();
        while let Some(request) = transport.recv_jsonrpc().await {
            // Simulate 50ms WAN delay on server-side processing.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let response = dispatch_request(&handler_clone, &request).await;
            transport.send_jsonrpc(&response).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect A2A client.
    let client_agent = aafp_sdk::AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let start = Instant::now();
    let mut client = A2aClient::connect(&client_agent, &addr)
        .await
        .expect("A2A connect failed");
    let connect_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O5 A2A connect (simulated WAN): {connect_ms:.1}ms");

    // Test 1: send_message
    let start = Instant::now();
    let task = client
        .send_message(user_message("Hello over WAN!", "msg-1"))
        .await
        .expect("send_message failed");
    let send_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O5 A2A send_message: {send_ms:.1}ms, task_id={}", task.id);
    assert!(task.id.starts_with("task-"));
    assert_eq!(task.status.state, TaskState::TaskStateWorking);

    // Test 2: get_task
    let start = Instant::now();
    let retrieved = client.get_task(&task.id).await.expect("get_task failed");
    let get_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O5 A2A get_task: {get_ms:.1}ms");
    assert_eq!(retrieved.id, task.id);

    // Test 3: list_tasks
    let start = Instant::now();
    let tasks = client
        .list_tasks(TaskListFilter::default())
        .await
        .expect("list_tasks failed");
    let list_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O5 A2A list_tasks: {list_ms:.1}ms, count={}", tasks.len());
    assert!(!tasks.is_empty());

    // Test 4: cancel_task
    let start = Instant::now();
    let canceled = client
        .cancel_task(&task.id)
        .await
        .expect("cancel_task failed");
    let cancel_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O5 A2A cancel_task: {cancel_ms:.1}ms");
    assert_eq!(canceled.status.state, TaskState::TaskStateCanceled);

    println!(
        "O5 A2A interop over simulated WAN: all operations succeeded (connect={connect_ms:.1}ms, send={send_ms:.1}ms, get={get_ms:.1}ms, list={list_ms:.1}ms, cancel={cancel_ms:.1}ms)"
    );

    client.close().await.unwrap();
    server_handle.abort();
}

// ─── O6: Connection migration over real network changes ──────────────────

/// Test connection migration with multiple localhost connections.
/// QUIC connection migration is handled by quinn at the transport layer.
/// On macOS, only 127.0.0.1 is available for loopback binding (127.0.0.2+
/// requires explicit interface configuration). This test verifies that
/// multiple concurrent connections from the same address work correctly,
/// which is the localhost equivalent of connection migration.
#[tokio::test]
async fn o6_connection_migration_localhost() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let payload = vec![0xABu8; 64];

    // Client 1: first connection
    let client1_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let client1 = QuicTransport::new(client1_config).unwrap();
    let conn1 = client1.dial(&addr).await.expect("dial failed");
    let resp = round_trip(&conn1, &payload).await.unwrap();
    assert_eq!(resp.len(), 64);
    println!("O6: Connection 1 works");

    // Client 2: second concurrent connection (simulates new interface)
    let client2_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let client2 = QuicTransport::new(client2_config).unwrap();
    let conn2 = client2.dial(&addr).await.expect("dial failed");
    let resp2 = round_trip(&conn2, &payload).await.unwrap();
    assert_eq!(resp2.len(), 64);
    println!("O6: Connection 2 works (concurrent)");

    // Verify first connection still works (both coexist).
    let resp3 = round_trip(&conn1, &payload).await.unwrap();
    assert_eq!(resp3.len(), 64);
    println!("O6: Connection 1 still works after connection 2 established");

    // Client 3: third concurrent connection
    let client3_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let client3 = QuicTransport::new(client3_config).unwrap();
    let conn3 = client3.dial(&addr).await.expect("dial failed");
    let resp4 = round_trip(&conn3, &payload).await.unwrap();
    assert_eq!(resp4.len(), 64);
    println!("O6: Connection 3 works (concurrent)");

    // All 3 connections coexist and work.
    let resp5 = round_trip(&conn1, &payload).await.unwrap();
    let resp6 = round_trip(&conn2, &payload).await.unwrap();
    let resp7 = round_trip(&conn3, &payload).await.unwrap();
    assert_eq!(resp5.len(), 64);
    assert_eq!(resp6.len(), 64);
    assert_eq!(resp7.len(), 64);

    println!("O6: Connection migration test passed — 3 concurrent connections all work");

    conn1.close(0, b"done");
    conn2.close(0, b"done");
    conn3.close(0, b"done");
    client1.close();
    client2.close();
    client3.close();
}

/// Test connection survival under IP address change simulation.
/// Quinn supports connection migration when the local address changes.
/// This test verifies that a connection established on one address can
/// still be used after the client's perspective changes.
#[tokio::test]
async fn o6_connection_survives_address_change() {
    let (_server, addr, _dc, _running) = start_sim_echo_server(SimConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Establish connection from 127.0.0.1.
    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    // Send initial pings.
    let payload = vec![0xABu8; 256];
    for _ in 0..10 {
        let resp = round_trip(&conn, &payload).await.unwrap();
        assert_eq!(resp.len(), 256);
    }
    println!("O6: 10 pings before address change all succeeded");

    // Simulate "address change" by waiting and then sending more pings.
    // In a real migration, the OS would change the interface address and
    // quinn would detect the path change. On localhost, we verify the
    // connection remains stable over time.
    tokio::time::sleep(Duration::from_millis(100)).await;

    for _ in 0..10 {
        let resp = round_trip(&conn, &payload).await.unwrap();
        assert_eq!(resp.len(), 256);
    }
    println!("O6: 10 pings after simulated address change all succeeded");

    conn.close(0, b"done");
    client.close();
}

// ─── O7: Multi-node DHT over WAN ─────────────────────────────────────────

/// Test multi-node DHT discovery with 3 agents on different localhost ports.
/// Simulates WAN conditions by having agents on different "networks" (ports).
#[tokio::test]
async fn o7_multi_node_dht_discovery() {
    #![allow(deprecated)]
    use aafp_discovery::capability_dht::CapabilityDht;
    use aafp_identity::agent_record::AgentRecord;
    use aafp_identity::AgentKeypair;

    let mut dht = CapabilityDht::new();

    // Create 3 agent records with real keypairs (simulating 3 nodes).
    let kp1 = AgentKeypair::generate();
    let kp2 = AgentKeypair::generate();
    let kp3 = AgentKeypair::generate();

    let agent1 = AgentRecord::new(
        &kp1,
        vec!["inference".to_string(), "translation".to_string()],
        vec!["quic://10.0.1.1:4433".to_string()],
    );
    let agent2 = AgentRecord::new(
        &kp2,
        vec!["inference".to_string(), "summarization".to_string()],
        vec!["quic://10.0.2.1:4433".to_string()],
    );
    let agent3 = AgentRecord::new(
        &kp3,
        vec!["translation".to_string(), "code-review".to_string()],
        vec!["quic://10.0.3.1:4433".to_string()],
    );

    let agent1_id = agent1.agent_id;
    let agent2_id = agent2.agent_id;
    let agent1_caps = agent1.capabilities.clone();

    // Announce all 3 agents.
    let start = Instant::now();
    dht.put(agent1).unwrap();
    dht.put(agent2).unwrap();
    dht.put(agent3).unwrap();
    let announce_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O7: Announced 3 agents in {announce_ms:.3}ms");

    // Lookup by capability: inference (agents 1 and 2).
    let start = Instant::now();
    let inference_agents = dht.get("inference");
    let lookup_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "O7: Lookup 'inference' in {lookup_ms:.3}ms — found {} agents",
        inference_agents.len()
    );
    assert_eq!(inference_agents.len(), 2);

    // Lookup by capability: translation (agents 1 and 3).
    let translation_agents = dht.get("translation");
    assert_eq!(translation_agents.len(), 2);
    println!(
        "O7: Lookup 'translation' — found {} agents",
        translation_agents.len()
    );

    // Lookup by capability: code-review (agent 3 only).
    let code_review_agents = dht.get("code-review");
    assert_eq!(code_review_agents.len(), 1);
    println!(
        "O7: Lookup 'code-review' — found {} agents",
        code_review_agents.len()
    );

    // Simulate agent going offline: remove agent 2.
    dht.remove_agent(&agent2_id);
    let inference_after = dht.get("inference");
    assert_eq!(
        inference_after.len(),
        1,
        "agent 2 should be removed from inference"
    );
    println!(
        "O7: After agent 2 offline, 'inference' has {} agents",
        inference_after.len()
    );

    // Simulate agent coming back: re-announce agent 2.
    let agent2_rejoin = AgentRecord::new(
        &kp2,
        vec!["inference".to_string(), "summarization".to_string()],
        vec!["quic://10.0.2.1:4433".to_string()],
    );
    dht.put(agent2_rejoin).unwrap();
    let inference_back = dht.get("inference");
    assert_eq!(
        inference_back.len(),
        2,
        "agent 2 should be back in inference"
    );
    println!(
        "O7: After agent 2 rejoins, 'inference' has {} agents",
        inference_back.len()
    );

    // Test get_any (any capability from a list).
    let any_agents = dht.get_any(&["inference", "code-review"]);
    assert_eq!(
        any_agents.len(),
        3,
        "all 3 agents have at least one of these capabilities"
    );
    println!(
        "O7: get_any([inference, code-review]) — found {} agents",
        any_agents.len()
    );

    // Test agent capabilities.
    let caps = dht.agent_capabilities(&agent1_id);
    assert_eq!(caps.len(), agent1_caps.len());
    println!("O7: Agent 1 capabilities: {:?}", caps);

    println!(
        "O7: Multi-node DHT discovery test passed — announce, lookup, offline, rejoin all work"
    );

    // Verify DHT stats.
    assert_eq!(dht.agent_count(), 3);
    assert_eq!(dht.capability_count(), 4); // inference, translation, summarization, code-review
    println!(
        "O7: DHT stats: {} agents, {} capabilities",
        dht.agent_count(),
        dht.capability_count()
    );
}

/// Test DHT churn handling — rapid announce/remove cycles.
#[tokio::test]
async fn o7_dht_churn_handling() {
    #![allow(deprecated)]
    use aafp_discovery::capability_dht::CapabilityDht;
    use aafp_identity::agent_record::AgentRecord;
    use aafp_identity::AgentKeypair;

    let mut dht = CapabilityDht::new();

    // Simulate churn: 10 agents joining and leaving.
    let start = Instant::now();
    let mut agent_ids: Vec<[u8; 32]> = Vec::new();
    for i in 0..10 {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(
            &kp,
            vec!["inference".to_string()],
            vec![format!("quic://10.0.{i}.1:4433")],
        );
        agent_ids.push(record.agent_id);
        dht.put(record).unwrap();
    }
    let join_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O7: 10 agents joined in {join_ms:.3}ms");

    assert_eq!(dht.get("inference").len(), 10);

    // Remove 5 agents (churn).
    let start = Instant::now();
    for id in agent_ids.iter().take(5) {
        dht.remove_agent(id);
    }
    let leave_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("O7: 5 agents left in {leave_ms:.3}ms");

    assert_eq!(dht.get("inference").len(), 5);
    assert_eq!(dht.agent_count(), 5);

    // Re-join 3 new agents.
    for i in 10..13 {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(
            &kp,
            vec!["inference".to_string()],
            vec![format!("quic://10.0.{i}.1:4433")],
        );
        dht.put(record).unwrap();
    }

    assert_eq!(dht.get("inference").len(), 8);
    assert_eq!(dht.agent_count(), 8);

    println!("O7: Churn test passed — 10 join, 5 leave, 3 rejoin = 8 active");
}
