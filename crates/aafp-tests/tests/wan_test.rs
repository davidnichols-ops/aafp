//! WAN integration test — configurable via environment variables.
//!
//! This test can be run against a remote AAFP server to validate WAN
//! behavior. It is configured via environment variables:
//!
//! - `AAFP_REMOTE_ADDR` — remote server address (e.g. `quic://host:4433`)
//! - `AAFP_TEST_MODE` — test mode: `ping`, `echo`, `stream`, `handshake`,
//!   `discovery`, `migration` (default: `ping`)
//! - `AAFP_MSG_COUNT` — number of messages (default: 100)
//! - `AAFP_MSG_SIZE` — message size in bytes (default: 1024)
//! - `AAFP_CONGESTION` — congestion controller: `cubic`, `bbr`, `newreno`
//!
//! If `AAFP_REMOTE_ADDR` is not set, the test is skipped (not failed).
//!
//! Run with:
//! ```bash
//! AAFP_REMOTE_ADDR=quic://remote:4433 cargo test --test wan_test -- --nocapture --ignored
//! ```
//!
//! For local testing (no remote server), a localhost test is always run
//! to verify the test harness works:
//! ```bash
//! cargo test --test wan_test -- --nocapture
//! ```

#![allow(deprecated)]

use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_sdk::AgentBuilder;
use aafp_transport_quic::{CongestionController, QuicConfig, QuicTransport};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Parse a congestion controller from a string.
fn parse_congestion(s: &str) -> CongestionController {
    match s.to_lowercase().as_str() {
        "bbr" => CongestionController::Bbr,
        "newreno" | "new_reno" => CongestionController::NewReno,
        _ => CongestionController::Cubic,
    }
}

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

/// Compute latency percentiles from Duration samples (in microseconds).
struct LatencyStats {
    count: usize,
    p50_us: f64,
    p90_us: f64,
    p99_us: f64,
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
            p50_us: pct(50.0),
            p90_us: pct(90.0),
            p99_us: pct(99.0),
            mean_us: mean,
        }
    }
}

/// Start a local echo server for testing.
async fn start_local_echo_server() -> (Arc<aafp_sdk::Agent>, String) {
    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec!["echo".into()])
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap(),
    );
    let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    // Spawn echo server loop.
    let agent_clone = server_agent.clone();
    tokio::spawn(async move {
        loop {
            let conn = match agent_clone.transport.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                loop {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
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

    (server_agent, addr)
}

/// Localhost test: verifies the WAN test harness works on localhost.
/// This test always runs (no remote server needed).
#[tokio::test]
async fn wan_test_localhost_ping() {
    let (_server, addr) = start_local_echo_server().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let payload = vec![0xABu8; 64];
    let mut samples = Vec::new();

    // Warmup.
    for _ in 0..5 {
        let _ = round_trip(&conn, &payload).await.unwrap();
    }

    for _ in 0..100 {
        let start = Instant::now();
        let resp = round_trip(&conn, &payload).await.unwrap();
        samples.push(start.elapsed());
        assert_eq!(resp.len(), 64);
    }

    let stats = LatencyStats::from_samples(&samples);
    println!(
        "localhost ping: count={}, p50={:.1}µs, p90={:.1}µs, p99={:.1}µs, mean={:.1}µs",
        stats.count, stats.p50_us, stats.p90_us, stats.p99_us, stats.mean_us
    );

    // Localhost round-trip should be under 10ms.
    assert!(
        stats.p99_us < 10_000.0,
        "p99 latency too high: {}µs",
        stats.p99_us
    );

    conn.close(0, b"test done");
    client.close();
}

/// Localhost throughput test.
#[tokio::test]
async fn wan_test_localhost_throughput() {
    let (_server, addr) = start_local_echo_server().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let count = 100;
    let size = 1024;
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

    println!(
        "localhost throughput: {} msgs in {:.3}s = {:.0} msg/s ({:.2} Mbps)",
        count, secs, msgs_per_sec, mbps
    );

    // Should achieve at least 1000 msg/s on localhost.
    assert!(
        msgs_per_sec > 1000.0,
        "throughput too low: {msgs_per_sec} msg/s"
    );

    conn.close(0, b"test done");
    client.close();
}

/// Localhost handshake time test.
#[tokio::test]
async fn wan_test_localhost_handshake() {
    let (_server, addr) = start_local_echo_server().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };

    // Measure handshake time (dial = QUIC connection + TLS handshake).
    let mut times = Vec::new();
    for _ in 0..5 {
        let client = QuicTransport::new(client_config.clone()).unwrap();
        let start = Instant::now();
        let conn = client.dial(&addr).await.expect("dial failed");
        let hs_time = start.elapsed();
        times.push(hs_time);
        conn.close(0, b"done");
        client.close();
    }

    let avg_ms = times.iter().map(|t| t.as_secs_f64() * 1000.0).sum::<f64>() / times.len() as f64;
    println!(
        "localhost handshake: {} trials, avg = {:.2}ms",
        times.len(),
        avg_ms
    );

    // Localhost handshake should be under 100ms.
    assert!(avg_ms < 100.0, "handshake too slow: {avg_ms}ms");
}

/// Remote WAN test — only runs if AAFP_REMOTE_ADDR is set.
/// Use `--ignored` to run this test explicitly.
#[tokio::test]
#[ignore = "requires AAFP_REMOTE_ADDR environment variable"]
async fn wan_test_remote() {
    let remote_addr = match std::env::var("AAFP_REMOTE_ADDR") {
        Ok(addr) => addr,
        Err(_) => {
            println!("AAFP_REMOTE_ADDR not set — skipping remote WAN test");
            return;
        }
    };

    let mode = std::env::var("AAFP_TEST_MODE").unwrap_or_else(|_| "ping".to_string());
    let msg_count: usize = std::env::var("AAFP_MSG_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let msg_size: usize = std::env::var("AAFP_MSG_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let congestion = parse_congestion(&std::env::var("AAFP_CONGESTION").unwrap_or_default());

    println!("WAN test: addr={remote_addr}, mode={mode}, count={msg_count}, size={msg_size}");

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).expect("client transport failed");

    let start = Instant::now();
    let conn = client.dial(&remote_addr).await.expect("dial failed");
    let hs_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("Handshake time: {hs_ms:.2}ms");

    match mode.as_str() {
        "ping" | "echo" => {
            let payload = vec![0xABu8; msg_size];
            let mut samples = Vec::new();
            for _ in 0..msg_count {
                let s = Instant::now();
                let resp = round_trip(&conn, &payload)
                    .await
                    .expect("round-trip failed");
                samples.push(s.elapsed());
                assert_eq!(resp.len(), msg_size);
            }
            let stats = LatencyStats::from_samples(&samples);
            println!(
                "WAN ping: count={}, p50={:.1}µs, p90={:.1}µs, p99={:.1}µs, mean={:.1}µs",
                stats.count, stats.p50_us, stats.p90_us, stats.p99_us, stats.mean_us
            );
        }
        "stream" => {
            let payload = vec![0xCDu8; msg_size];
            let start = Instant::now();
            for _ in 0..msg_count {
                let (mut send, _recv) = conn.open_bi().await.unwrap();
                let frame = Frame::data(0, payload.clone());
                send.write_all(&encode_frame(&frame).unwrap())
                    .await
                    .unwrap();
                send.finish();
            }
            let secs = start.elapsed().as_secs_f64();
            let mps = msg_count as f64 / secs;
            println!("WAN throughput: {mps:.0} msg/s ({secs:.3}s for {msg_count} msgs)");
        }
        "handshake" => {
            println!("WAN handshake completed in {hs_ms:.2}ms");
        }
        _ => {
            println!("WAN test mode '{mode}' — basic connectivity verified");
        }
    }

    conn.close(0, b"test done");
    client.close();
}

/// Test with BBR congestion controller on localhost.
#[tokio::test]
async fn wan_test_bbr_localhost() {
    let (_server, addr) = start_local_echo_server().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::Bbr,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let payload = vec![0xABu8; 256];
    let mut samples = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = round_trip(&conn, &payload).await.unwrap();
        samples.push(start.elapsed());
    }
    let stats = LatencyStats::from_samples(&samples);
    println!(
        "BBR localhost ping: p50={:.1}µs, p99={:.1}µs",
        stats.p50_us, stats.p99_us
    );

    conn.close(0, b"test done");
    client.close();
}

/// Test with NewReno congestion controller on localhost.
#[tokio::test]
async fn wan_test_newreno_localhost() {
    let (_server, addr) = start_local_echo_server().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        congestion: CongestionController::NewReno,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config).unwrap();
    let conn = client.dial(&addr).await.expect("dial failed");

    let payload = vec![0xABu8; 256];
    let mut samples = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = round_trip(&conn, &payload).await.unwrap();
        samples.push(start.elapsed());
    }
    let stats = LatencyStats::from_samples(&samples);
    println!(
        "NewReno localhost ping: p50={:.1}µs, p99={:.1}µs",
        stats.p50_us, stats.p99_us
    );

    conn.close(0, b"test done");
    client.close();
}
