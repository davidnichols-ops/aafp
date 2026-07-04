//! Load test runner (Track S1).
//!
//! The runner creates N agents, starts a server task on each, connects them
//! according to the configured topology, sends messages, and collects metrics.
//!
//! ## Architecture
//!
//! ```text
//! For each agent i:
//!   ┌─ Server task: accept connections, handshake, echo DATA frames
//!   └─ Client tasks (per edge): connect to peer, handshake, send M messages
//!
//! Metrics collected via ResultsAccumulator (lock-free atomics + Mutex<Vec>)
//! ```

use crate::config::LoadTestConfig;
use crate::metrics::{ConfigSummary, LoadTestMetrics, ResultsAccumulator};
use crate::topology::{generate_edges, Edge};
use aafp_core::AuthorizationProvider;
use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_sdk::{establish_session, AgentBuilder};
use aafp_transport_quic::QuicConnection;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Run a load test with the given configuration.
///
/// This creates `num_agents` agents, starts a server echo loop on each,
/// connects them per the topology, sends `messages_per_agent` messages per
/// edge, and returns the collected metrics.
///
/// # Arguments
/// - `config`: Load test configuration
///
/// # Returns
/// - `LoadTestMetrics` with throughput, latency, error rate, etc.
pub async fn run_load_test(config: &LoadTestConfig) -> LoadTestMetrics {
    let n = config.num_agents;
    info!(
        "Starting load test: {} agents, {:?} topology",
        n, config.topology
    );

    // 1. Create all agents and get their addresses.
    let mut addresses: Vec<String> = Vec::new();
    let mut built_agents: Vec<Arc<aafp_sdk::Agent>> = Vec::new();

    for i in 0..n {
        let agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .expect("failed to build agent"),
        );
        let addr = format!("quic://{}", agent.transport.local_addr().unwrap());
        debug!("Agent {} listening on {}", i, addr);
        addresses.push(addr);
        built_agents.push(agent);
    }

    // 2. Generate topology edges.
    let edges = generate_edges(config);
    info!("Topology: {} edges", edges.len());

    // 3. Start server echo tasks on all agents.
    let accumulator = Arc::new(ResultsAccumulator::new());
    let auth_provider: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);

    let mut server_handles = Vec::new();
    // Each server needs to accept enough connections for all incoming edges.
    let incoming_count = count_incoming_edges(&edges, n);

    for (i, agent) in built_agents.iter().enumerate() {
        let agent = agent.clone();
        let auth = auth_provider.clone();
        let num_accepts = incoming_count[i];
        // Each accepted connection may receive multiple messages.
        let msgs_per_conn = config.messages_per_agent;

        let handle = tokio::spawn(async move {
            server_echo_loop(agent, auth, num_accepts, msgs_per_conn).await;
        });
        server_handles.push(handle);
    }

    // Give servers time to start listening.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Start client tasks for each edge.
    let start = Instant::now();
    let mut client_handles = Vec::new();

    for edge in &edges {
        let from_agent = built_agents[edge.from].clone();
        let to_addr = addresses[edge.to].to_string();
        let auth = auth_provider.clone();
        let acc = accumulator.clone();
        let msg_size = config.message_size;
        let num_msgs = config.messages_per_agent;
        let concurrency = config.concurrency;
        let timeout = config.duration;

        let handle = tokio::spawn(async move {
            client_send_loop(
                from_agent,
                &to_addr,
                auth,
                num_msgs,
                msg_size,
                concurrency,
                timeout,
                acc,
            )
            .await;
        });
        client_handles.push(handle);
    }

    // 5. Wait for all client tasks to complete (or timeout).
    let deadline = Instant::now() + config.duration;
    for handle in client_handles {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining, handle).await;
    }

    let elapsed = start.elapsed();

    // 6. Abort server tasks (they loop forever accepting connections).
    for handle in server_handles {
        handle.abort();
    }

    // 7. Close all agent transports.
    for agent in &built_agents {
        agent.transport.close();
    }

    // 8. Build final metrics.
    let config_summary = ConfigSummary {
        num_agents: config.num_agents,
        messages_per_agent: config.messages_per_agent,
        message_size: config.message_size,
        topology: config.topology.to_string(),
        num_edges: edges.len(),
    };

    // Extract accumulator from Arc (there should be exactly one strong ref left
    // after all tasks complete, but tasks may still be winding down).
    // We clone the data out instead of trying to unwrap the Arc.
    let metrics = {
        let acc = accumulator.clone();
        let sent = acc.sent.load(std::sync::atomic::Ordering::Relaxed);
        let received = acc.received.load(std::sync::atomic::Ordering::Relaxed);
        let failed = acc.failed.load(std::sync::atomic::Ordering::Relaxed);
        let conn_est = acc
            .connections_established
            .load(std::sync::atomic::Ordering::Relaxed);
        let conn_fail = acc
            .connections_failed
            .load(std::sync::atomic::Ordering::Relaxed);
        let latencies = acc.latencies.lock().unwrap().clone();

        let latency = crate::metrics::LatencyStats::from_sorted(latencies);

        let mut m = LoadTestMetrics {
            config_summary,
            messages_sent: sent,
            messages_received: received,
            messages_failed: failed,
            latency,
            connections_established: conn_est,
            connections_failed: conn_fail,
            duration_secs: elapsed.as_secs_f64(),
            resources: crate::metrics::ResourceUsage::default(),
            ..Default::default()
        };
        m.finalize();
        m
    };

    info!(
        "Load test complete: {} sent, {} received, {} failed, {:.0} msg/s, error rate {:.4}%",
        metrics.messages_sent,
        metrics.messages_received,
        metrics.messages_failed,
        metrics.throughput_msgps,
        metrics.error_rate * 100.0
    );

    metrics
}

/// Count how many incoming edges each agent has (how many connections it
/// needs to accept).
fn count_incoming_edges(edges: &[Edge], n: usize) -> Vec<usize> {
    let mut counts = vec![0usize; n];
    for e in edges {
        counts[e.to] += 1;
    }
    counts
}

/// Server-side echo loop: accept connections, handshake, echo DATA frames.
///
/// Accepts up to `num_accepts` connections. For each connection, reads DATA
/// frames and echoes them back. The server keeps accepting streams until the
/// client closes the connection (the client is the one that decides when to
/// stop). This avoids premature connection closure that causes message loss.
async fn server_echo_loop(
    agent: Arc<aafp_sdk::Agent>,
    auth: Arc<dyn AuthorizationProvider>,
    num_accepts: usize,
    _msgs_per_conn: usize,
) {
    for _ in 0..num_accepts {
        // Accept a QUIC connection.
        let conn = match agent.transport.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Server accept failed: {}", e);
                continue;
            }
        };

        let auth = auth.clone();
        let keypair = agent.keypair.clone();

        tokio::spawn(async move {
            // Drive server-side AAFP handshake.
            let (session, conn, _peer_info) =
                match establish_session(conn, &keypair, auth, false, None).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Server handshake failed: {}", e);
                        return;
                    }
                };

            // We need to keep the session alive — store it in a Mutex so it
            // isn't dropped (dropping Session doesn't close the connection,
            // but we want to keep it for correctness).
            let _session = Mutex::new(session);

            // Echo loop: accept bidirectional streams and echo DATA frames.
            // Loop until the client closes the connection (accept_bi returns
            // an error when the connection is closed).
            loop {
                let (mut send, mut recv) = match conn.accept_bi().await {
                    Ok(pair) => pair,
                    Err(_) => break, // connection closed by client
                };

                // Read frame header.
                let mut header = [0u8; FRAME_HEADER_SIZE];
                if recv.read_exact(&mut header).await.is_err() {
                    continue;
                }

                // Parse payload + extension lengths.
                let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
                let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
                let body_len = payload_len + ext_len;

                let mut body = vec![0u8; body_len];
                if body_len > 0 && recv.read_exact(&mut body).await.is_err() {
                    continue;
                }

                // Reconstruct and decode frame.
                let mut full = header.to_vec();
                full.extend_from_slice(&body);
                let (frame, _) = match decode_frame(&full) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                // Echo back the same payload.
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

            // Don't close the connection — the client already closed it.
            // Just let the connection handle drop naturally.
        });
    }
}

/// Client-side send loop: connect to a peer, handshake, send N messages.
///
/// Sends `num_msgs` messages of `msg_size` bytes each, measuring round-trip
/// latency for each. Uses `concurrency` concurrent in-flight requests.
#[allow(clippy::too_many_arguments)]
async fn client_send_loop(
    agent: Arc<aafp_sdk::Agent>,
    addr: &str,
    auth: Arc<dyn AuthorizationProvider>,
    num_msgs: usize,
    msg_size: usize,
    concurrency: usize,
    timeout: Duration,
    acc: Arc<ResultsAccumulator>,
) {
    // Establish a single connection and reuse it for all messages.
    let conn = match agent.transport.dial(addr).await {
        Ok(c) => c,
        Err(e) => {
            warn!("Client dial failed to {}: {}", addr, e);
            acc.record_connection_failure();
            return;
        }
    };

    // Drive client-side AAFP handshake.
    let (session, conn, _peer_info) =
        match establish_session(conn, &agent.keypair, auth, true, None).await {
            Ok(result) => result,
            Err(e) => {
                warn!("Client handshake failed to {}: {}", addr, e);
                acc.record_connection_failure();
                return;
            }
        };

    // Keep session alive.
    let _session = Mutex::new(session);
    acc.record_connection();

    // Create the payload once and reuse.
    let payload = vec![0xABu8; msg_size];

    // Send messages with bounded concurrency.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    for _ in 0..num_msgs {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let conn = conn.clone();
        let payload = payload.clone();
        let acc = acc.clone();

        tasks.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = tokio::time::timeout(timeout, send_and_receive(&conn, &payload)).await;

            drop(permit);

            match result {
                Ok(Ok(())) => {
                    let latency_us = start.elapsed().as_secs_f64() * 1_000_000.0;
                    acc.record_success(latency_us);
                }
                Ok(Err(e)) => {
                    debug!("Send failed: {}", e);
                    acc.record_failure();
                }
                Err(_) => {
                    debug!("Send timed out");
                    acc.record_failure();
                }
            }
        }));
    }

    // Wait for all sends to complete.
    for task in tasks {
        let _ = task.await;
    }

    conn.close(0, b"load test done");
}

/// Send a DATA frame and receive the echo response.
async fn send_and_receive(conn: &QuicConnection, payload: &[u8]) -> Result<(), String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let frame = Frame::data(0, payload.to_vec());
    let frame_bytes = encode_frame(&frame).map_err(|e| e.to_string())?;
    send.write_all(&frame_bytes)
        .await
        .map_err(|e| e.to_string())?;
    send.finish();

    // Read response frame header.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_test_2_agents_ring() {
        let config = LoadTestConfig {
            num_agents: 2,
            messages_per_agent: 5,
            message_size: 64,
            duration: Duration::from_secs(10),
            topology: crate::config::Topology::Ring,
            concurrency: 2,
            ..Default::default()
        };

        let metrics = run_load_test(&config).await;

        // Ring with 2 agents = 2 edges, 5 messages each = 10 total
        assert!(metrics.messages_sent > 0, "should have sent messages");
        assert_eq!(
            metrics.messages_received,
            metrics.messages_sent - metrics.messages_failed,
            "received + failed should equal sent"
        );
        assert!(metrics.error_rate < 0.5, "error rate should be low");
    }

    #[tokio::test]
    async fn load_test_3_agents_star() {
        let config = LoadTestConfig {
            num_agents: 3,
            messages_per_agent: 3,
            message_size: 128,
            duration: Duration::from_secs(10),
            topology: crate::config::Topology::Star,
            concurrency: 2,
            ..Default::default()
        };

        let metrics = run_load_test(&config).await;

        // Star with 3 agents = 2 edges, 3 messages each = 6 total
        assert!(metrics.messages_sent > 0);
        assert!(metrics.error_rate < 0.5, "error rate should be low");
    }
}
