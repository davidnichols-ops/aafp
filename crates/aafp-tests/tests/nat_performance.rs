//! Relay performance and capacity tests (Track N8).
//!
//! Tests relay throughput, latency, and capacity limits.

use aafp_identity::AgentId;
use aafp_nat::relay_forwarding::{RelayV1CallerHelper, RelayV1Server, RelayV1TargetHandler};
use aafp_transport_quic::{QuicConfig, QuicTransport};
use std::time::{Duration, Instant};

fn make_agent_id(byte: u8) -> AgentId {
    [byte; 32]
}

/// Test relay throughput: measure bytes/sec through the relay.
#[tokio::test]
async fn perf_relay_throughput() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B — behind NAT
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_id = make_agent_id(2);
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    // B echoes back all data
    let b_handle = tokio::spawn(async move {
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Echo: read all data, send it back
        let mut all_data = Vec::new();
        let mut buf = vec![0u8; 16384];
        loop {
            match b_recv.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => all_data.extend_from_slice(&buf[..n]),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        // Send all data back
        b_send.write_all(&all_data).await.unwrap();
        b_send.finish();
    });

    // Agent A — connects to B through relay
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let (_conn_id, mut a_send, mut a_recv) =
        RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
            .await
            .expect("A connect to B");

    // Send 1MB of data
    let data_size = 1_000_000;
    let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

    let start = Instant::now();
    a_send.write_all(&data).await.unwrap();
    a_send.finish();

    // Read echo back
    let mut received = Vec::new();
    let mut buf = vec![0u8; 16384];
    loop {
        match a_recv.read(&mut buf).await {
            Ok(Some(0)) => break,
            Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let elapsed = start.elapsed();

    assert_eq!(received.len(), data_size);
    assert_eq!(received, data);

    let throughput_mbps = (data_size as f64 * 2.0) / elapsed.as_secs_f64() / 1_000_000.0;
    println!(
        "Relay throughput: {:.2} MB/s ({:.2} Mbps) for {} bytes in {:?}",
        throughput_mbps / 8.0,
        throughput_mbps,
        data_size,
        elapsed
    );

    // Throughput should be at least 1 MB/s on localhost
    assert!(
        throughput_mbps / 8.0 > 1.0,
        "throughput too low: {:.2} MB/s",
        throughput_mbps / 8.0
    );

    b_handle.await.unwrap();
    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}

/// Test relay latency: measure round-trip time for small messages.
#[tokio::test]
async fn perf_relay_latency() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B — behind NAT
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_id = make_agent_id(2);
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    // B echoes back each message
    let b_handle = tokio::spawn(async move {
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Echo 10 messages
        for _ in 0..10 {
            let mut buf = vec![0u8; 1024];
            match b_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    b_send.write_all(&buf[..n]).await.unwrap();
                }
                _ => break,
            }
        }
        b_send.finish();
    });

    // Agent A — connects to B through relay
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let (_conn_id, mut a_send, mut a_recv) =
        RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
            .await
            .expect("A connect to B");

    // Measure round-trip latency for 10 small messages
    let mut latencies = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        a_send.write_all(b"ping").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let _ = a_recv.read(&mut buf).await;
        latencies.push(start.elapsed());
    }

    let avg_latency_us =
        latencies.iter().map(|d| d.as_micros()).sum::<u128>() / latencies.len() as u128;
    let min_latency_us = latencies.iter().map(|d| d.as_micros()).min().unwrap();
    let max_latency_us = latencies.iter().map(|d| d.as_micros()).max().unwrap();

    println!(
        "Relay latency (10 pings): avg={}μs, min={}μs, max={}μs",
        avg_latency_us, min_latency_us, max_latency_us
    );

    // Average latency should be under 10ms on localhost
    assert!(
        avg_latency_us < 10_000,
        "latency too high: {}μs",
        avg_latency_us
    );

    b_handle.await.unwrap();
    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}

/// Test relay capacity: multiple concurrent relayed connections.
#[tokio::test]
async fn perf_relay_capacity_concurrent_connections() {
    // Create relay with higher capacity
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());

    let relay_service = std::sync::Arc::new(std::sync::Mutex::new(
        aafp_nat::RelayV1Service::with_defaults(),
    ));
    let relay_server = RelayV1Server::new(relay_transport, relay_service);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create 5 targets behind NAT
    let mut target_handles = vec![];
    let mut target_ids = vec![];
    let mut target_conns = vec![];

    for i in 2..7 {
        let transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create target transport");
        let id = make_agent_id(i);
        target_ids.push(id);
        let relay_conn = transport
            .dial(&relay_addr)
            .await
            .expect("target dial relay");
        target_conns.push(relay_conn.clone());

        let mut target = RelayV1TargetHandler::new(relay_conn, id);
        target
            .reserve(&relay_addr, 3600)
            .await
            .expect("target reserve");

        let handle = tokio::spawn(async move {
            let (_conn_id, mut send, mut recv) =
                target.accept_incoming().await.expect("target accept");

            // Echo
            let mut buf = vec![0u8; 4096];
            if let Ok(Some(n)) = recv.read(&mut buf).await {
                send.write_all(&buf[..n]).await.unwrap();
            }
            send.finish();
        });
        target_handles.push(handle);
    }

    // Caller A connects to all 5 targets concurrently
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let mut caller_handles = vec![];
    for target_id in target_ids {
        let relay_conn = a_relay_conn.clone();
        let handle = tokio::spawn(async move {
            let (_conn_id, mut send, mut recv) =
                RelayV1CallerHelper::connect(&relay_conn, target_id, a_id)
                    .await
                    .expect("connect to target");

            send.write_all(b"hello").await.unwrap();

            let mut buf = vec![0u8; 4096];
            let _ = recv.read(&mut buf).await;
        });
        caller_handles.push(handle);
    }

    // Wait for all callers
    for handle in caller_handles {
        handle.await.unwrap();
    }

    // Wait for all targets
    for handle in target_handles {
        handle.await.unwrap();
    }

    a_relay_conn.close(0, b"done");
    for conn in target_conns {
        conn.close(0, b"done");
    }
}

/// Test relay connection setup time.
#[tokio::test]
async fn perf_relay_connection_setup_time() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B — behind NAT
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_id = make_agent_id(2);
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    let b_handle = tokio::spawn(async move {
        let (_conn_id, mut send, mut recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        let mut buf = vec![0u8; 1024];
        if let Ok(Some(n)) = recv.read(&mut buf).await {
            send.write_all(&buf[..n]).await.unwrap();
        }
        send.finish();
    });

    // Agent A — measure connection setup time
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let start = Instant::now();
    let (_conn_id, mut a_send, mut a_recv) =
        RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
            .await
            .expect("A connect to B");

    // Send first byte and read echo
    a_send.write_all(b"x").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let _ = a_recv.read(&mut buf).await;
    let setup_time = start.elapsed();

    println!("Relay connection setup time: {:?}", setup_time);

    // Setup time should be under 100ms on localhost
    assert!(
        setup_time.as_millis() < 100,
        "setup time too high: {:?}",
        setup_time
    );

    b_handle.await.unwrap();
    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}

/// Test relay with many small messages (message rate).
#[tokio::test]
async fn perf_relay_message_rate() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B — behind NAT
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_id = make_agent_id(2);
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    // B echoes back each message
    let b_handle = tokio::spawn(async move {
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Echo 100 messages
        for _ in 0..100 {
            let mut buf = vec![0u8; 64];
            match b_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    b_send.write_all(&buf[..n]).await.unwrap();
                }
                _ => break,
            }
        }
        b_send.finish();
    });

    // Agent A — sends 100 small messages
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let (_conn_id, mut a_send, mut a_recv) =
        RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
            .await
            .expect("A connect to B");

    let num_messages = 100;
    let start = Instant::now();

    for _ in 0..num_messages {
        a_send.write_all(b"msg").await.unwrap();

        let mut buf = vec![0u8; 64];
        let _ = a_recv.read(&mut buf).await;
    }

    let elapsed = start.elapsed();
    let msg_rate = num_messages as f64 / elapsed.as_secs_f64();

    println!(
        "Relay message rate: {} messages in {:?} ({:.0} msg/s)",
        num_messages, elapsed, msg_rate
    );

    // Message rate should be at least 100 msg/s on localhost
    assert!(
        msg_rate > 100.0,
        "message rate too low: {:.0} msg/s",
        msg_rate
    );

    b_handle.await.unwrap();
    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}
