//! Stress tests for AAFP edge cases (Track S7).
//!
//! Tests:
//! 1. Burst traffic: many agents send messages simultaneously
//! 2. Large messages: 1MB messages with frame encoding
//! 3. Many streams: 100+ concurrent QUIC streams on one connection
//! 4. Connection churn: rapid connect/disconnect cycles
//! 5. DHT under load: many simultaneous announce/lookup operations

#![allow(deprecated)]

use aafp_core::AuthorizationProvider;
use aafp_discovery::capability_dht::CapabilityDht;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::{derive_agent_id, AgentKeypair};
use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_sdk::{establish_session, AgentBuilder};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

/// Helper: create a server agent and return its address.
async fn create_server_agent() -> (Arc<aafp_sdk::Agent>, String) {
    let agent = Arc::new(
        AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap(),
    );
    let addr = format!("quic://{}", agent.transport.local_addr().unwrap());
    (agent, addr)
}

/// Helper: create a client agent.
async fn create_client_agent() -> Arc<aafp_sdk::Agent> {
    Arc::new(AgentBuilder::new().build().await.unwrap())
}

/// Helper: start a server echo loop that accepts connections and echoes DATA frames.
fn start_echo_server(
    agent: Arc<aafp_sdk::Agent>,
    num_accepts: usize,
) -> tokio::task::JoinHandle<()> {
    let keypair = agent.keypair.clone();
    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);

    tokio::spawn(async move {
        for _ in 0..num_accepts {
            let conn = match agent.transport.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let auth = auth.clone();
            let kp = keypair.clone();

            tokio::spawn(async move {
                let (session, conn, _) = match establish_session(conn, &kp, auth, false, None).await
                {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let _session = Mutex::new(session);

                loop {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(p) => p,
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
            });
        }
    })
}

/// Helper: send a message and receive the echo response.
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

// ═══════════════════════════════════════════════════════════════════════════════
// Test 1: Burst Traffic — 10 agents send 100 messages simultaneously (1K burst)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn stress_burst_traffic_10_agents() {
    let num_agents = 10;
    let messages_per_agent = 100;
    let msg_size = 1024;

    // Create server agents.
    let mut servers = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..num_agents {
        let (agent, addr) = create_server_agent().await;
        servers.push(agent);
        addresses.push(addr);
    }

    // Start echo servers (each accepts up to num_agents connections).
    let mut server_handles = Vec::new();
    for agent in &servers {
        server_handles.push(start_echo_server(agent.clone(), num_agents));
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // All agents send simultaneously to all other agents.
    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);
    let mut client_handles = Vec::new();
    let success_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fail_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    for i in 0..num_agents {
        let client = create_client_agent().await;
        let auth = auth.clone();
        let success = success_count.clone();
        let fail = fail_count.clone();

        // Connect to all other agents.
        for j in 0..num_agents {
            if i == j {
                continue;
            }
            let client = client.clone();
            let addr = addresses[j].clone();
            let auth = auth.clone();
            let success = success.clone();
            let fail = fail.clone();

            client_handles.push(tokio::spawn(async move {
                let conn = match client.transport.dial(&addr).await {
                    Ok(c) => c,
                    Err(_) => {
                        fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                };
                let (session, conn, _) =
                    match establish_session(conn, &client.keypair, auth, true, None).await {
                        Ok(r) => r,
                        Err(_) => {
                            fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    };
                let _session = Mutex::new(session);

                let payload = vec![0xABu8; msg_size];
                for _ in 0..messages_per_agent {
                    let result = tokio::time::timeout(
                        Duration::from_secs(10),
                        send_and_receive(&conn, &payload),
                    )
                    .await;
                    match result {
                        Ok(Ok(())) => {
                            success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        _ => {
                            fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
    }

    // Wait for all clients.
    for handle in client_handles {
        let _ = handle.await;
    }

    // Abort servers.
    for handle in server_handles {
        handle.abort();
    }
    for agent in &servers {
        agent.transport.close();
    }

    let success = success_count.load(std::sync::atomic::Ordering::Relaxed);
    let fail = fail_count.load(std::sync::atomic::Ordering::Relaxed);
    let total = success + fail;

    println!(
        "Burst test: {} total, {} success, {} fail, {:.2}% success rate",
        total,
        success,
        fail,
        success as f64 / total as f64 * 100.0
    );

    // VERIFY: at least 80% success rate (some may fail due to timing).
    assert!(total > 0, "should have sent some messages");
    assert!(
        success as f64 / total as f64 > 0.8,
        "burst success rate should be >80%, got {:.2}%",
        success as f64 / total as f64 * 100.0
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 2: Large Messages — 1MB messages
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn stress_large_message_1mb() {
    let (server, addr) = create_server_agent().await;
    let server_handle = start_echo_server(server.clone(), 1);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = create_client_agent().await;
    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);
    let conn = client.transport.dial(&addr).await.unwrap();
    let (session, conn, _) = establish_session(conn, &client.keypair, auth, true, None)
        .await
        .unwrap();
    let _session = Mutex::new(session);

    // Send 1MB message.
    let payload_1mb = vec![0xCDu8; 1024 * 1024]; // 1MB
    let start = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        send_and_receive(&conn, &payload_1mb),
    )
    .await;
    let elapsed = start.elapsed();

    conn.close(0, b"done");
    server.transport.close();
    server_handle.abort();

    assert!(result.is_ok(), "1MB message should not time out");
    assert!(result.unwrap().is_ok(), "1MB message should succeed");

    println!(
        "1MB message: {:.1}ms ({:.1} MB/s)",
        elapsed.as_secs_f64() * 1000.0,
        1.0 / elapsed.as_secs_f64()
    );
}

#[tokio::test]
async fn stress_large_message_100kb() {
    let (server, addr) = create_server_agent().await;
    let server_handle = start_echo_server(server.clone(), 1);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = create_client_agent().await;
    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);
    let conn = client.transport.dial(&addr).await.unwrap();
    let (session, conn, _) = establish_session(conn, &client.keypair, auth, true, None)
        .await
        .unwrap();
    let _session = Mutex::new(session);

    // Send 100KB message.
    let payload = vec![0xEFu8; 100 * 1024];
    let result =
        tokio::time::timeout(Duration::from_secs(10), send_and_receive(&conn, &payload)).await;

    conn.close(0, b"done");
    server.transport.close();
    server_handle.abort();

    assert!(result.is_ok(), "100KB message should not time out");
    assert!(result.unwrap().is_ok(), "100KB message should succeed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 3: Many Streams — 100 concurrent streams on one connection
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn stress_100_concurrent_streams() {
    let (server, addr) = create_server_agent().await;
    let server_handle = start_echo_server(server.clone(), 1);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = create_client_agent().await;
    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);
    let conn = client.transport.dial(&addr).await.unwrap();
    let (session, conn, _) = establish_session(conn, &client.keypair, auth, true, None)
        .await
        .unwrap();
    let _session = Mutex::new(session);

    let num_streams = 100;
    let payload = vec![0xABu8; 256];

    // Open 100 concurrent streams.
    let mut tasks = Vec::new();
    for _ in 0..num_streams {
        let conn = conn.clone();
        let payload = payload.clone();
        tasks.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), send_and_receive(&conn, &payload)).await
        }));
    }

    let mut success = 0;
    let mut fail = 0;
    for task in tasks {
        match task.await {
            Ok(Ok(Ok(()))) => success += 1,
            _ => fail += 1,
        }
    }

    conn.close(0, b"done");
    server.transport.close();
    server_handle.abort();

    println!("100 concurrent streams: {} success, {} fail", success, fail);

    // VERIFY: at least 90% success
    assert!(
        success >= 90,
        "at least 90/100 streams should succeed, got {}",
        success
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 4: Connection Churn — rapid connect/disconnect cycles
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn stress_connection_churn_20_cycles() {
    let (server, addr) = create_server_agent().await;
    // Server needs to accept many connections (20 cycles * 1 connection each).
    let server_handle = start_echo_server(server.clone(), 20);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let auth: Arc<dyn AuthorizationProvider> = Arc::new(aafp_core::TestingAuthProvider);
    let success_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fail_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 20 cycles of connect, send 1 message, disconnect.
    for _cycle in 0..20 {
        let client = create_client_agent().await;
        let auth = auth.clone();
        let _success = success_count.clone();
        let _fail = fail_count.clone();
        let addr = addr.clone();

        let conn = match client.transport.dial(&addr).await {
            Ok(c) => c,
            Err(_) => {
                fail_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
        };
        let (session, conn, _) =
            match establish_session(conn, &client.keypair, auth, true, None).await {
                Ok(r) => r,
                Err(_) => {
                    fail_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
            };
        let _session = Mutex::new(session);

        let payload = vec![0xABu8; 64];
        let result =
            tokio::time::timeout(Duration::from_secs(5), send_and_receive(&conn, &payload)).await;

        match result {
            Ok(Ok(())) => {
                success_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {
                fail_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        conn.close(0, b"churn done");
        // Small delay between cycles.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server.transport.close();
    server_handle.abort();

    let success = success_count.load(std::sync::atomic::Ordering::Relaxed);
    let fail = fail_count.load(std::sync::atomic::Ordering::Relaxed);

    println!(
        "Connection churn (20 cycles): {} success, {} fail",
        success, fail
    );

    // VERIFY: at least 90% success rate.
    assert!(
        success >= 18,
        "at least 18/20 churn cycles should succeed, got {}",
        success
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 5: DHT Under Load — 100 simultaneous announce + 100 lookup
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn stress_dht_100_announce_and_lookup() {
    let dht = Arc::new(std::sync::Mutex::new(CapabilityDht::new()));

    // Create 100 agent records and announce them.
    let mut records = Vec::new();
    for i in 0..100 {
        let kp = AgentKeypair::generate();
        let _id = derive_agent_id(&kp.public_key);
        let record = AgentRecord::new(
            &kp,
            vec![format!("capability_{}", i % 5)], // 5 different capabilities
            vec![format!("quic://127.0.0.1:{}", 40000 + i)],
        );
        records.push(record);
    }

    // Announce all 100 records.
    let start = Instant::now();
    {
        let mut dht = dht.lock().unwrap();
        for record in &records {
            dht.put(record.clone()).unwrap();
        }
    }
    let announce_time = start.elapsed();

    // Lookup all 5 capabilities.
    let start = Instant::now();
    let mut total_found = 0;
    {
        let dht = dht.lock().unwrap();
        for cap_idx in 0..5 {
            let cap = format!("capability_{}", cap_idx);
            let results = dht.get(&cap);
            total_found += results.len();
        }
    }
    let lookup_time = start.elapsed();

    println!(
        "DHT stress: 100 announce in {:.1}ms, 5 lookups in {:.1}ms, {} total records found",
        announce_time.as_secs_f64() * 1000.0,
        lookup_time.as_secs_f64() * 1000.0,
        total_found
    );

    // VERIFY: all 100 records should be found across 5 capabilities (20 each).
    assert_eq!(total_found, 100, "all 100 records should be found");
}

#[tokio::test]
async fn stress_dht_concurrent_access() {
    let dht = Arc::new(std::sync::Mutex::new(CapabilityDht::new()));

    // Pre-populate with 50 records.
    for i in 0..50 {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(
            &kp,
            vec!["inference".to_string()],
            vec![format!("quic://127.0.0.1:{}", 40000 + i)],
        );
        dht.lock().unwrap().put(record).unwrap();
    }

    // Concurrent lookups from multiple threads.
    let mut handles = Vec::new();
    for _ in 0..10 {
        let dht = dht.clone();
        handles.push(tokio::spawn(async move {
            let dht = dht.lock().unwrap();
            dht.get("inference").len()
        }));
    }

    let mut all_ok = true;
    for handle in handles {
        let count = handle.await.unwrap();
        if count != 50 {
            all_ok = false;
            warn!("Expected 50 records, got {}", count);
        }
    }

    assert!(all_ok, "all concurrent lookups should return 50 records");
}
