//! WAN test client — connects to a remote AAFP server and runs a test suite.
//!
//! Supports multiple test modes: ping, echo, stream, handshake, discovery,
//! migration. Outputs JSON results to a file and stdout.
//!
//! Run with:
//! ```bash
//! cargo run --example wan_test_client -p aafp-tests -- quic://127.0.0.1:4433 ping results.json
//! ```
//!
//! Environment variables:
//! - `AAFP_MSG_COUNT` — number of messages (default: 1000)
//! - `AAFP_MSG_SIZE` — message size in bytes (default: 1024)
//! - `AAFP_CONGESTION` — congestion controller: cubic|bbr|newreno (default: cubic)

use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_transport_quic::{CongestionController, QuicConfig, QuicTransport};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Test modes supported by the WAN test client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TestMode {
    Ping,
    Echo,
    Stream,
    Handshake,
    Discovery,
    Migration,
}

impl std::str::FromStr for TestMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ping" => Ok(Self::Ping),
            "echo" => Ok(Self::Echo),
            "stream" => Ok(Self::Stream),
            "handshake" => Ok(Self::Handshake),
            "discovery" => Ok(Self::Discovery),
            "migration" => Ok(Self::Migration),
            other => Err(format!("unknown test mode: {other}")),
        }
    }
}

/// Latency statistics for a set of round-trip measurements (in microseconds).
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

/// Complete WAN test result record.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WanTestResult {
    test_mode: String,
    remote_addr: String,
    timestamp: String,
    congestion: String,
    msg_count: usize,
    msg_size: usize,
    success: bool,
    error: Option<String>,
    latency: Option<LatencyStats>,
    throughput_msgs_per_sec: Option<f64>,
    throughput_mbps: Option<f64>,
    handshake_time_ms: Option<f64>,
    duration_secs: f64,
}

impl WanTestResult {
    fn new(mode: &str, addr: &str, congestion: &str, count: usize, size: usize) -> Self {
        Self {
            test_mode: mode.to_string(),
            remote_addr: addr.to_string(),
            timestamp: chrono_now(),
            congestion: congestion.to_string(),
            msg_count: count,
            msg_size: size,
            success: false,
            error: None,
            latency: None,
            throughput_msgs_per_sec: None,
            throughput_mbps: None,
            handshake_time_ms: None,
            duration_secs: 0.0,
        }
    }
}

fn chrono_now() -> String {
    // Use a simple timestamp without chrono dependency.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn parse_congestion(s: &str) -> CongestionController {
    match s.to_lowercase().as_str() {
        "bbr" => CongestionController::Bbr,
        "newreno" | "new_reno" => CongestionController::NewReno,
        _ => CongestionController::Cubic,
    }
}

/// Send a frame and receive the echo response (round-trip).
async fn round_trip(conn: &aafp_transport_quic::QuicConnection, payload: &[u8]) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let frame = Frame::data(0, payload.to_vec());
    let frame_bytes = encode_frame(&frame)?;
    send.write_all(&frame_bytes).await?;
    send.finish();

    // Read response frame.
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

/// Run a ping test: N round-trips, measure latency percentiles.
async fn run_ping(
    conn: &aafp_transport_quic::QuicConnection,
    count: usize,
    size: usize,
) -> Result<LatencyStats> {
    let payload = vec![0xABu8; size];
    let mut samples = Vec::with_capacity(count);

    // Warmup: 10 round-trips.
    for _ in 0..10.min(count) {
        let _ = round_trip(conn, &payload).await?;
    }

    for _ in 0..count {
        let start = Instant::now();
        let resp = round_trip(conn, &payload).await?;
        samples.push(start.elapsed());
        if resp.len() != size {
            return Err(anyhow!(
                "response size mismatch: {} != {}",
                resp.len(),
                size
            ));
        }
    }

    Ok(LatencyStats::from_samples(&samples))
}

/// Run a throughput test: N one-way sends, measure messages per second.
async fn run_throughput(
    conn: &aafp_transport_quic::QuicConnection,
    count: usize,
    size: usize,
) -> Result<(f64, f64)> {
    let payload = vec![0xCDu8; size];

    let start = Instant::now();
    for _ in 0..count {
        let (mut send, _recv) = conn.open_bi().await?;
        let frame = Frame::data(0, payload.clone());
        let frame_bytes = encode_frame(&frame)?;
        send.write_all(&frame_bytes).await?;
        send.finish();
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let msgs_per_sec = count as f64 / secs;
    let bytes_per_sec = (count * size) as f64 / secs;
    let mbps = bytes_per_sec * 8.0 / 1_000_000.0;
    Ok((msgs_per_sec, mbps))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let remote_addr = std::env::args().nth(1).ok_or_else(|| {
        anyhow!("usage: wan_test_client <REMOTE_ADDR> [TEST_MODE] [RESULTS_FILE]")
    })?;
    let mode: TestMode = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "ping".to_string())
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let results_file = std::env::args().nth(3);

    let msg_count: usize = std::env::var("AAFP_MSG_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let msg_size: usize = std::env::var("AAFP_MSG_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let congestion_str = std::env::var("AAFP_CONGESTION").unwrap_or_else(|_| "cubic".to_string());
    let congestion = parse_congestion(&congestion_str);

    let mode_str = format!("{mode:?}").to_lowercase();

    eprintln!("[wan-client] Connecting to {remote_addr} (mode={mode_str}, count={msg_count}, size={msg_size}, congestion={congestion_str})");

    let mut result = WanTestResult::new(
        &mode_str,
        &remote_addr,
        &congestion_str,
        msg_count,
        msg_size,
    );

    let client_config = QuicConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        congestion,
        ..Default::default()
    };
    let client = QuicTransport::new(client_config)?;

    let test_start = Instant::now();

    let outcome = match mode {
        TestMode::Ping | TestMode::Echo => {
            let conn = client.dial(&remote_addr).await?;
            let stats = run_ping(&conn, msg_count, msg_size).await;
            conn.close(0, b"test complete");
            client.close();
            stats.map(|s| {
                result.latency = Some(s);
            })
        }
        TestMode::Stream => {
            let conn = client.dial(&remote_addr).await?;
            let tp = run_throughput(&conn, msg_count, msg_size).await;
            conn.close(0, b"test complete");
            client.close();
            tp.map(|(mps, mbps)| {
                result.throughput_msgs_per_sec = Some(mps);
                result.throughput_mbps = Some(mbps);
            })
        }
        TestMode::Handshake => {
            let hs_start = Instant::now();
            let conn = client.dial(&remote_addr).await;
            let hs_time = hs_start.elapsed().as_secs_f64() * 1000.0;
            match conn {
                Ok(c) => {
                    c.close(0, b"handshake done");
                    client.close();
                    result.handshake_time_ms = Some(hs_time);
                    Ok(())
                }
                Err(e) => Err(anyhow!("handshake failed: {e}")),
            }
        }
        TestMode::Discovery => {
            // Discovery mode: connect and do a single round-trip to verify
            // the connection works. Full DHT discovery is tested in O7.
            let conn = client.dial(&remote_addr).await?;
            let stats = run_ping(&conn, 10, 64).await;
            conn.close(0, b"discovery done");
            client.close();
            stats.map(|s| {
                result.latency = Some(s);
            })
        }
        TestMode::Migration => {
            // Migration mode: connect, send a few pings, then close.
            // Full migration testing is in O6.
            let conn = client.dial(&remote_addr).await?;
            let stats = run_ping(&conn, 10, 64).await;
            conn.close(0, b"migration done");
            client.close();
            stats.map(|s| {
                result.latency = Some(s);
            })
        }
    };

    result.duration_secs = test_start.elapsed().as_secs_f64();

    match outcome {
        Ok(()) => {
            result.success = true;
            eprintln!("[wan-client] Test completed successfully");
        }
        Err(e) => {
            result.success = false;
            result.error = Some(e.to_string());
            eprintln!("[wan-client] Test FAILED: {e}");
        }
    }

    let json = serde_json::to_string_pretty(&result)?;

    // Write to file if specified.
    if let Some(path) = &results_file {
        std::fs::write(path, &json)?;
        eprintln!("[wan-client] Results written to {path}");
    }

    // Print JSON to stdout.
    println!("{json}");

    if result.success {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

// (Arc import removed — not needed in this binary)
