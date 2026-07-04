//! NAT traversal test harness: 4 NAT scenarios (Track N6).
//!
//! Tests the full NAT traversal stack across different scenarios:
//! 1. No NAT — both agents publicly reachable
//! 2. One agent behind NAT — relayed connection
//! 3. Both agents behind NAT — relayed connection through relay
//! 4. DCuTR upgrade — relayed connection upgraded to direct

use aafp_identity::AgentId;
use aafp_nat::{
    auto_nat_v1::{DialBackResult, NatStatus},
    relay_forwarding::{RelayV1CallerHelper, RelayV1Server, RelayV1TargetHandler},
    AutoNatV1DialBack,
};
use aafp_transport_quic::{QuicConfig, QuicTransport};
use std::time::Duration;

fn make_agent_id(byte: u8) -> AgentId {
    [byte; 32]
}

/// Scenario 1: No NAT — both agents publicly reachable.
///
/// Both agents can dial each other directly. No relay needed.
#[tokio::test]
async fn scenario1_no_nat_direct_connection() {
    // Create two agents
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");

    let addr_a = format!("quic://{}", agent_a.local_addr().unwrap());
    let addr_b = format!("quic://{}", agent_b.local_addr().unwrap());

    // B accepts
    let b_handle = tokio::spawn(async move {
        let conn = agent_b.accept().await.expect("B accept");
        let (mut send, mut recv) = conn.accept_bi().await.expect("B accept_bi");

        // Read message from A
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"Direct connection!");

        // Send reply (don't finish yet — wait for A to read)
        send.write_all(b"Direct reply!").await.unwrap();
        // Give A time to read before closing
        tokio::time::sleep(Duration::from_millis(100)).await;
        send.finish();
    });

    // A dials B directly
    let conn = agent_a.dial(&addr_b).await.expect("A dial B");
    let (mut send, mut recv) = conn.open_bi().await.expect("A open_bi");

    // A sends message (don't finish yet — B needs to reply on same bi-stream)
    send.write_all(b"Direct connection!").await.unwrap();

    // A reads reply
    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"Direct reply!");

    b_handle.await.unwrap();

    // Verify AutoNAT would detect both as public
    let mut autonat_a = AutoNatV1DialBack::new();
    autonat_a.record_dialback(&DialBackResult {
        success: true,
        error: None,
        observed_addr: Some(addr_a.clone()),
    });
    autonat_a.record_dialback(&DialBackResult {
        success: true,
        error: None,
        observed_addr: Some(addr_a),
    });
    assert_eq!(autonat_a.status(), &NatStatus::Public);
}

/// Scenario 2: One agent behind NAT — relayed connection.
///
/// Agent B is behind NAT (cannot accept incoming connections).
/// Agent A connects to B through a relay.
#[tokio::test]
async fn scenario2_one_behind_nat_relayed_connection() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    // Start relay
    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B (behind NAT) — connects to relay and reserves
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_id = make_agent_id(2);
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    // B accepts incoming relayed connection
    let b_handle = tokio::spawn(async move {
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Read message from A
        let mut buf = vec![0u8; 1024];
        let n = b_recv.read(&mut buf).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"Hello through relay!");

        // Send reply
        b_send.write_all(b"Relayed reply!").await.unwrap();
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

    // A sends message
    a_send.write_all(b"Hello through relay!").await.unwrap();

    // A reads reply
    let mut reply_buf = vec![0u8; 1024];
    let n = a_recv.read(&mut reply_buf).await.unwrap().unwrap();
    assert_eq!(&reply_buf[..n], b"Relayed reply!");

    b_handle.await.unwrap();

    // Verify AutoNAT would detect B as behind NAT
    let mut autonat_b = AutoNatV1DialBack::new();
    autonat_b.record_dialback(&DialBackResult {
        success: false,
        error: Some("connection refused".into()),
        observed_addr: None,
    });
    autonat_b.record_dialback(&DialBackResult {
        success: false,
        error: Some("connection refused".into()),
        observed_addr: None,
    });
    assert_eq!(autonat_b.status(), &NatStatus::Private);

    // Clean up
    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}

/// Scenario 3: Both agents behind NAT — relayed connection through relay.
///
/// Both A and B are behind NAT. They communicate through a relay.
#[tokio::test]
async fn scenario3_both_behind_nat_relayed_connection() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B (behind NAT) — reserves on relay
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_id = make_agent_id(2);
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    // B accepts incoming relayed connection and echoes
    let b_handle = tokio::spawn(async move {
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Echo: read message, send echo back
        let mut buf = vec![0u8; 1024];
        let n = b_recv.read(&mut buf).await.unwrap().unwrap();
        let msg = format!("Echo: {}", String::from_utf8_lossy(&buf[..n]));
        b_send.write_all(msg.as_bytes()).await.unwrap();
        b_send.finish();
    });

    // Agent A (also behind NAT) — connects to B through relay
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let (_conn_id, mut a_send, mut a_recv) =
        RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
            .await
            .expect("A connect to B");

    // A sends message
    let test_msg = b"Both behind NAT!";
    a_send.write_all(test_msg).await.unwrap();

    // A reads echo reply
    let mut reply_buf = vec![0u8; 1024];
    let n = a_recv.read(&mut reply_buf).await.unwrap().unwrap();
    let expected = format!("Echo: {}", String::from_utf8_lossy(test_msg));
    assert_eq!(&reply_buf[..n], expected.as_bytes());

    b_handle.await.unwrap();

    // Verify both agents would be detected as behind NAT
    let mut autonat = AutoNatV1DialBack::new();
    for _ in 0..2 {
        autonat.record_dialback(&DialBackResult {
            success: false,
            error: Some("connection refused".into()),
            observed_addr: None,
        });
    }
    assert_eq!(autonat.status(), &NatStatus::Private);

    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}

/// Scenario 4: DCuTR upgrade — relayed connection upgraded to direct.
///
/// After a relayed connection is established, peers attempt a direct
/// connection via hole punching. In this test (localhost), the direct
/// connection succeeds and replaces the relayed connection.
#[tokio::test]
async fn scenario4_dcutr_upgrade() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent B — has a direct address that A can dial
    let agent_b =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent B transport");
    let b_direct_addr = format!("quic://{}", agent_b.local_addr().unwrap());
    let b_id = make_agent_id(2);

    // B also reserves on relay
    let b_relay_conn = agent_b.dial(&relay_addr).await.expect("B dial relay");
    let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
    b_target
        .reserve(&relay_addr, 3600)
        .await
        .expect("B reserve");

    // B accepts the relayed connection first, then the direct connection
    let b_handle = tokio::spawn(async move {
        // Accept relayed connection
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Read coordinate message from A (via relay)
        let mut buf = vec![0u8; 1024];
        let _ = b_recv.read(&mut buf).await;

        // Signal back that we received the coordinate
        b_send.write_all(b"coordinate received").await.unwrap();
        // Don't finish yet — keep the relayed connection open

        // Now accept the direct connection (hole punch)
        let direct_conn = agent_b.accept().await.expect("B accept direct");
        let (mut direct_send, mut direct_recv) =
            direct_conn.accept_bi().await.expect("B accept_bi direct");

        // Read message from A via direct connection
        let mut direct_buf = vec![0u8; 1024];
        let n = direct_recv.read(&mut direct_buf).await.unwrap().unwrap();
        assert_eq!(&direct_buf[..n], b"Direct after upgrade!");

        // Send reply via direct connection
        direct_send
            .write_all(b"Direct upgrade reply!")
            .await
            .unwrap();
        // Keep stream open briefly for A to read
        tokio::time::sleep(Duration::from_millis(100)).await;
        direct_send.finish();
    });

    // Agent A — connects to B through relay first
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    let (_conn_id, mut a_send, mut a_recv) =
        RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
            .await
            .expect("A connect to B via relay");

    // A sends coordinate message to B via relay
    let coord_msg = aafp_nat::CoordinateMessage::new(b_direct_addr.clone(), b_direct_addr.clone());
    a_send
        .write_all(&coord_msg.encode().unwrap())
        .await
        .unwrap();

    // Wait for B to acknowledge coordinate
    let mut ack_buf = vec![0u8; 1024];
    let _ = a_recv.read(&mut ack_buf).await;

    // A attempts direct hole punch to B
    let direct_conn = agent_a.dial(&b_direct_addr).await.expect("A dial B direct");
    let (mut direct_send, mut direct_recv) = direct_conn.open_bi().await.expect("A open_bi direct");

    // A sends message via direct connection
    direct_send
        .write_all(b"Direct after upgrade!")
        .await
        .unwrap();
    direct_send.finish();

    // A reads reply via direct connection
    let mut direct_buf = vec![0u8; 1024];
    let n = direct_recv.read(&mut direct_buf).await.unwrap().unwrap();
    assert_eq!(&direct_buf[..n], b"Direct upgrade reply!");

    b_handle.await.unwrap();

    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}

/// Scenario 5: Multiple relayed connections through one relay.
///
/// Tests that a single relay can handle multiple concurrent relayed connections.
#[tokio::test]
async fn scenario5_multiple_relayed_connections() {
    // Create relay
    let relay_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
    let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
    let relay_server = RelayV1Server::with_defaults(relay_transport);

    tokio::spawn(async move {
        relay_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create 3 targets (B, C, D) behind NAT
    let mut target_handles = vec![];
    let mut target_ids = vec![];
    let mut target_conns = vec![];

    for i in 2..5 {
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

            let mut buf = vec![0u8; 1024];
            let n = recv.read(&mut buf).await.unwrap().unwrap();
            let reply = format!("Reply from target {}", String::from_utf8_lossy(&buf[..n]));
            send.write_all(reply.as_bytes()).await.unwrap();
            send.finish();
        });
        target_handles.push(handle);
    }

    // Caller A connects to each target through relay
    let agent_a =
        QuicTransport::new(QuicConfig::default()).expect("failed to create agent A transport");
    let a_id = make_agent_id(1);
    let a_relay_conn = agent_a.dial(&relay_addr).await.expect("A dial relay");

    for (i, target_id) in target_ids.iter().enumerate() {
        let (_conn_id, mut a_send, mut a_recv) =
            RelayV1CallerHelper::connect(&a_relay_conn, *target_id, a_id)
                .await
                .expect("A connect to target");

        let msg = format!("Message {}", i);
        a_send.write_all(msg.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = a_recv.read(&mut buf).await.unwrap().unwrap();
        let expected = format!("Reply from target {}", msg);
        assert_eq!(&buf[..n], expected.as_bytes());
    }

    // Wait for all targets to complete
    for handle in target_handles {
        handle.await.unwrap();
    }

    a_relay_conn.close(0, b"done");
    for conn in target_conns {
        conn.close(0, b"done");
    }
}

/// Scenario 6: Relay discovery and health checking.
///
/// Tests that the relay discovery service can discover relays,
/// health-check them, and select the best one.
#[tokio::test]
async fn scenario6_relay_discovery_and_health_check() {
    use aafp_nat::{RelayDiscoveryService, RelayNodeInfo};

    // Create two relay servers
    let relay1_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay1 transport");
    let relay1_addr = format!("quic://{}", relay1_transport.local_addr().unwrap());
    let relay1_server = RelayV1Server::with_defaults(relay1_transport);

    let relay2_transport =
        QuicTransport::new(QuicConfig::default()).expect("failed to create relay2 transport");
    let relay2_addr = format!("quic://{}", relay2_transport.local_addr().unwrap());
    let relay2_server = RelayV1Server::with_defaults(relay2_transport);

    tokio::spawn(async move {
        relay1_server.run().await;
    });
    tokio::spawn(async move {
        relay2_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create discovery service
    let service = RelayDiscoveryService::new();

    // Add and health-check both relays
    service.add_and_check(make_agent_id(10), relay1_addr).await;
    service.add_and_check(make_agent_id(20), relay2_addr).await;

    // Both should be healthy
    let healthy = service.healthy_relays();
    assert_eq!(healthy.len(), 2);

    // Select best relay — should return one of them
    let best = service.select_best_relay();
    assert!(best.is_some());
    assert!(best.unwrap().is_healthy());
}

/// Scenario 7: AutoNAT dial-back full flow.
///
/// Tests the complete AutoNAT dial-back flow: agent advertises its
/// address, peers dial back, agent processes results and determines
/// its NAT status.
#[tokio::test]
async fn scenario7_autonat_dialback_full_flow() {
    use aafp_nat::AutoNatClient;

    // Start a server (the agent that wants to know its NAT status)
    let server =
        QuicTransport::new(QuicConfig::default()).expect("failed to create server transport");
    let server_addr = format!("quic://{}", server.local_addr().unwrap());

    let server_handle = tokio::spawn(async move {
        // Accept connections for dial-back checks
        for _ in 0..3 {
            let _ = server.accept().await;
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent creates AutoNAT client with its advertised address
    let client = AutoNatClient::new().with_advertised_addr(server_addr.clone());

    // Simulate 3 peers performing dial-back (threshold = 2)
    for _ in 0..3 {
        let request = client.encode_request().unwrap();
        let response = aafp_nat::auto_nat_v1::handle_dialback_request(&request, 5)
            .await
            .unwrap();
        client.process_response(&response).unwrap();
    }

    // After 3 successful dial-backs, status should be Public
    assert_eq!(client.status(), NatStatus::Public);

    server_handle.abort();
}

/// Scenario 8: Large data transfer through relay.
///
/// Tests that the relay can handle larger data transfers (not just small messages).
#[tokio::test]
async fn scenario8_large_data_transfer_through_relay() {
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
        let (_conn_id, mut b_send, mut b_recv) =
            b_target.accept_incoming().await.expect("B accept incoming");

        // Read large message from A
        let mut all_data = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            match b_recv.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => all_data.extend_from_slice(&buf[..n]),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        // Echo it back
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

    // Send 100KB of data
    let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    a_send.write_all(&large_data).await.unwrap();
    a_send.finish();

    // Read echo back
    let mut received = Vec::new();
    let mut buf = vec![0u8; 8192];
    loop {
        match a_recv.read(&mut buf).await {
            Ok(Some(0)) => break,
            Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    assert_eq!(received.len(), large_data.len());
    assert_eq!(received, large_data);

    b_handle.await.unwrap();

    a_relay_conn.close(0, b"done");
    b_relay_conn.close(0, b"done");
}
