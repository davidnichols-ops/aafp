//! Stability test binary (Track S3).
//!
//! Runs a single agent that accepts connections from N clients. Each client
//! sends 1 message/second continuously. Monitors memory, CPU, file descriptors,
//! and connection count, logging metrics every 5 minutes.
//!
//! Usage:
//! ```bash
//! cargo run --features cli --bin stability -- --duration 14400 --clients 10
//! ```
//!
//! For a 4-hour run: `--duration 14400` (14400 seconds = 4 hours)
//! For a 24-hour run: `--duration 86400`

use aafp_core::AuthorizationProvider;
use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_sdk::{establish_session, AgentBuilder};
use clap::Parser;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Stability test metrics (collected periodically).
#[derive(Clone, Debug, serde::Serialize)]
struct StabilityMetrics {
    elapsed_secs: f64,
    messages_sent: u64,
    messages_received: u64,
    messages_failed: u64,
    connections_active: u64,
    memory_bytes: u64,
    file_descriptors: u64,
}

#[derive(Parser, Debug)]
#[command(
    name = "stability",
    about = "AAFP stability test (Track S3) — long-running leak detection"
)]
struct Args {
    /// Test duration in seconds.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Number of client agents.
    #[arg(long, default_value_t = 10)]
    clients: usize,

    /// Messages per client per second.
    #[arg(long, default_value_t = 1)]
    rate: u64,

    /// Message size in bytes.
    #[arg(long, default_value_t = 1024)]
    size: usize,

    /// Metrics logging interval in seconds.
    #[arg(long, default_value_t = 300)]
    interval: u64,

    /// Output JSON file path.
    #[arg(long)]
    output: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();
    let duration = Duration::from_secs(args.duration);
    let interval = Duration::from_secs(args.interval);

    println!(
        "Stability test: {} clients, {} msg/s each, {} bytes, {}s duration, {}s interval",
        args.clients, args.rate, args.size, args.duration, args.interval
    );

    // Create the server agent.
    let server_agent = Arc::new(
        AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .expect("failed to build server agent"),
    );
    let server_addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());
    info!("Server agent listening on {}", server_addr);

    // Shared counters.
    let messages_sent = Arc::new(AtomicU64::new(0));
    let messages_received = Arc::new(AtomicU64::new(0));
    let messages_failed = Arc::new(AtomicU64::new(0));
    let connections_active = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Start server echo task.
    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);
    let server_keypair = server_agent.keypair.clone();
    let server_stop = stop.clone();
    let server_conn_active = connections_active.clone();

    let server_handle = tokio::spawn(async move {
        loop {
            if server_stop.load(Ordering::Relaxed) {
                break;
            }
            let conn = match server_agent.transport.accept().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Server accept failed: {}", e);
                    continue;
                }
            };

            let auth = auth.clone();
            let keypair = server_keypair.clone();
            let conn_active = server_conn_active.clone();
            let stop = server_stop.clone();

            tokio::spawn(async move {
                let (session, conn, _peer_info) =
                    match establish_session(conn, &keypair, auth, false, None).await {
                        Ok(result) => result,
                        Err(e) => {
                            warn!("Server handshake failed: {}", e);
                            return;
                        }
                    };
                let _session = tokio::sync::Mutex::new(session);
                conn_active.fetch_add(1, Ordering::Relaxed);

                // Echo loop until stopped.
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };

                    let mut header = [0u8; FRAME_HEADER_SIZE];
                    if recv.read_exact(&mut header).await.is_err() {
                        continue;
                    }
                    let payload_len =
                        u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
                    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
                    let body_len = payload_len + ext_len;
                    let mut body = vec![0u8; body_len];
                    if body_len > 0 && recv.read_exact(&mut body).await.is_err() {
                        continue;
                    }
                    let mut full = header.to_vec();
                    full.extend_from_slice(&body);
                    let (frame, _) = match decode_frame(&full) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let resp = Frame::data(frame.stream_id, frame.payload.clone());
                    let resp_bytes = match encode_frame(&resp) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    if send.write_all(&resp_bytes).await.is_err() {
                        continue;
                    }
                    send.finish();
                }

                conn_active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });

    // Start client tasks.
    let mut client_handles = Vec::new();
    for i in 0..args.clients {
        let addr = server_addr.clone();
        let sent = messages_sent.clone();
        let recv = messages_received.clone();
        let fail = messages_failed.clone();
        let stop = stop.clone();
        let msg_size = args.size;
        let rate = args.rate;

        let handle = tokio::spawn(async move {
            // Create client agent.
            let client = match AgentBuilder::new().build().await {
                Ok(a) => Arc::new(a),
                Err(e) => {
                    warn!("Client {} failed to build: {}", i, e);
                    return;
                }
            };

            let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);

            // Connect and handshake.
            let conn = match client.transport.dial(&addr).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Client {} dial failed: {}", i, e);
                    return;
                }
            };

            let (session, conn, _peer_info) =
                match establish_session(conn, &client.keypair, auth, true, None).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Client {} handshake failed: {}", i, e);
                        return;
                    }
                };
            let _session = tokio::sync::Mutex::new(session);

            let payload = vec![0xABu8; msg_size];
            let period = Duration::from_secs_f64(1.0 / rate as f64);

            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                sent.fetch_add(1, Ordering::Relaxed);
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    send_and_receive(&conn, &payload),
                )
                .await;

                match result {
                    Ok(Ok(())) => {
                        recv.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(e)) => {
                        warn!("Client {} send failed: {}", i, e);
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        warn!("Client {} send timed out", i);
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }

                tokio::time::sleep(period).await;
            }

            conn.close(0, b"stability test done");
        });
        client_handles.push(handle);
    }

    // Metrics collection loop.
    let start = Instant::now();
    let metrics_stop = stop.clone();
    // Clone Arcs for final metrics collection (the originals are moved into spawn).
    let final_sent = messages_sent.clone();
    let final_recv = messages_received.clone();
    let final_fail = messages_failed.clone();
    let final_conn = connections_active.clone();

    let metrics_handle: tokio::task::JoinHandle<Vec<StabilityMetrics>> = tokio::spawn(async move {
        let mut metrics_log: Vec<StabilityMetrics> = Vec::new();
        loop {
            if metrics_stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = start.elapsed();
            if elapsed >= duration {
                break;
            }

            let m = collect_metrics(
                elapsed,
                &messages_sent,
                &messages_received,
                &messages_failed,
                &connections_active,
            );
            metrics_log.push(m.clone());

            info!(
                "Metrics: elapsed={:.0}s sent={} recv={} fail={} conn={} mem={:.1}MB fd={}",
                m.elapsed_secs,
                m.messages_sent,
                m.messages_received,
                m.messages_failed,
                m.connections_active,
                m.memory_bytes as f64 / 1_000_000.0,
                m.file_descriptors,
            );

            tokio::time::sleep(interval).await;
        }
        metrics_log
    });

    // Wait for duration.
    tokio::time::sleep(duration).await;

    // Signal stop.
    stop.store(true, Ordering::Relaxed);

    // Wait for tasks to finish.
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    for handle in client_handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
    let metrics_log = metrics_handle.await.unwrap_or_default();

    // Final metrics.
    let final_metrics = collect_metrics(
        start.elapsed(),
        &final_sent,
        &final_recv,
        &final_fail,
        &final_conn,
    );

    // Analyze memory growth.
    // Skip the first measurement (warmup — before all clients connect).
    // Use the second measurement as the baseline for steady-state analysis.
    let baseline_mem = if metrics_log.len() > 1 {
        metrics_log[1].memory_bytes
    } else {
        metrics_log.first().map(|m| m.memory_bytes).unwrap_or(0)
    };
    let last_mem = metrics_log.last().map(|m| m.memory_bytes).unwrap_or(0);
    let first_mem = metrics_log.first().map(|m| m.memory_bytes).unwrap_or(0);
    let mem_growth_pct = if baseline_mem > 0 {
        ((last_mem as f64 - baseline_mem as f64) / baseline_mem as f64) * 100.0
    } else {
        0.0
    };

    let result = serde_json::json!({
        "test_name": "AAFP Stability Test (Track S3)",
        "config": {
            "duration_secs": args.duration,
            "num_clients": args.clients,
            "rate_per_client": args.rate,
            "message_size_bytes": args.size,
            "metrics_interval_secs": args.interval,
        },
        "final_metrics": final_metrics,
        "metrics_log": metrics_log,
        "analysis": {
            "memory_growth_pct": mem_growth_pct,
            "memory_first_bytes": first_mem,
            "memory_baseline_bytes": baseline_mem,
            "memory_last_bytes": last_mem,
            "leak_detected": mem_growth_pct > 10.0,
            "verdict": if mem_growth_pct < 10.0 { "PASS" } else { "FAIL" },
            "verdict_details": format!(
                "Steady-state memory growth {:.1}% (baseline after warmup: {:.1}MB, final: {:.1}MB, threshold: <10%)",
                mem_growth_pct,
                baseline_mem as f64 / 1_000_000.0,
                last_mem as f64 / 1_000_000.0,
            ),
        }
    });

    let json = serde_json::to_string_pretty(&result).unwrap();

    if let Some(path) = args.output {
        std::fs::write(&path, &json).expect("failed to write output file");
        println!("Results written to {}", path);
    } else {
        println!("{}", json);
    }

    println!(
        "\nStability test complete: {} sent, {} received, {} failed, memory growth {:.1}%",
        final_metrics.messages_sent,
        final_metrics.messages_received,
        final_metrics.messages_failed,
        mem_growth_pct
    );
}

fn collect_metrics(
    elapsed: Duration,
    sent: &AtomicU64,
    recv: &AtomicU64,
    fail: &AtomicU64,
    conn: &AtomicU64,
) -> StabilityMetrics {
    let (memory_bytes, file_descriptors) = collect_resource_usage();
    StabilityMetrics {
        elapsed_secs: elapsed.as_secs_f64(),
        messages_sent: sent.load(Ordering::Relaxed),
        messages_received: recv.load(Ordering::Relaxed),
        messages_failed: fail.load(Ordering::Relaxed),
        connections_active: conn.load(Ordering::Relaxed),
        memory_bytes,
        file_descriptors,
    }
}

fn collect_resource_usage() -> (u64, u64) {
    let mut memory = 0u64;
    #[allow(unused_mut)]
    let mut fds = 0u64;

    // Use `ps` command for portable memory measurement (RSS in KB).
    if let Ok(output) = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
    {
        if let Ok(s) = std::str::from_utf8(&output.stdout) {
            if let Ok(kb) = s.trim().parse::<u64>() {
                memory = kb * 1024;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // File descriptors (Linux only — macOS doesn't expose /proc).
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            fds = entries.count() as u64;
        }
    }

    (memory, fds)
}

async fn send_and_receive(
    conn: &aafp_transport_quic::QuicConnection,
    payload: &[u8],
) -> Result<(), String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let frame = Frame::data(0, payload.to_vec());
    let frame_bytes = encode_frame(&frame).map_err(|e| e.to_string())?;
    send.write_all(&frame_bytes)
        .await
        .map_err(|e| e.to_string())?;
    send.finish();

    let mut header = [0u8; FRAME_HEADER_SIZE];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
    let body_len = payload_len + ext_len;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        recv.read_exact(&mut body)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
