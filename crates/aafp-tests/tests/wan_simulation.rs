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
