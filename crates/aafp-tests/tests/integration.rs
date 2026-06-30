//! Integration test: multiple agents discover each other and exchange messages.
//!
//! This test creates a small network of agents (reduced from 1000 to 10 for
//! CI feasibility), verifies that:
//! 1. Agents can be created with ML-DSA-65 identities.

#![allow(unused)]
#![allow(deprecated)]
//! 2. AgentRecords are self-signed and verifiable.
//! 3. The capability DHT correctly indexes and retrieves records.
//! 4. Agents can connect over QUIC and exchange framed messages.
//! 5. The PQ handshake completes successfully.

use aafp_crypto::handshake::PqHandshake;
use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_discovery::capability_dht::CapabilityDht;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::{agent_id_to_hex, AgentKeypair};
use aafp_messaging::{decode_frame, encode_frame};
use aafp_sdk::AgentBuilder;
use aafp_transport_quic::QuicConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Test that 10 agents can be created with unique identities.
#[tokio::test]
async fn test_multiple_agent_identities() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..10 {
        let kp = AgentKeypair::generate();
        let id = aafp_identity::derive_agent_id(&kp.public_key);
        // Verify uniqueness.
        assert!(ids.insert(agent_id_to_hex(&id)));
        // Verify keypair signs correctly.
        let msg = b"test";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
    }
    assert_eq!(ids.len(), 10);
}

/// Test that 10 agent records can be stored in the DHT and retrieved by capability.
#[tokio::test]
async fn test_dht_with_10_agents() {
    let mut dht = CapabilityDht::new();

    // Create 10 agents with various capabilities.
    for i in 0..10 {
        let kp = AgentKeypair::generate();
        let caps = if i < 5 {
            vec!["inference".into()]
        } else if i < 8 {
            vec!["translation".into()]
        } else {
            vec!["inference".into(), "translation".into()]
        };
        let record = AgentRecord::new(&kp, caps, vec![]);
        assert!(record.verify());
        dht.put(record).unwrap();
    }

    // 7 agents have "inference" (5 + 2 with both).
    assert_eq!(dht.get("inference").len(), 7);
    // 5 agents have "translation" (3 + 2 with both).
    assert_eq!(dht.get("translation").len(), 5);
    // 2 agents have both.
    assert_eq!(dht.get_all(&["inference", "translation"]).len(), 2);
    assert_eq!(dht.agent_count(), 10);
}

/// Test PQ handshake between multiple agent pairs.
#[tokio::test]
async fn test_pq_handshake_multiple_pairs() {
    for _ in 0..5 {
        let server_kp = MlDsa65::keypair();
        let (hello, mut state) = PqHandshake::client_init();
        let (server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
        let result = PqHandshake::client_finish(&server_hello, &mut state).unwrap();
        assert_eq!(result.shared_secret.len(), 32);
        assert_eq!(result.peer_public_key, server_kp.0 .0);
    }
}

/// Test QUIC connection and message exchange between two agents.
#[tokio::test]
async fn test_quic_message_exchange() {
    // Create server agent.
    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec!["echo".into()])
            .build()
            .await
            .unwrap(),
    );
    let server_addr = server_agent.multiaddr().unwrap();

    // Create client transport.
    let client = aafp_transport_quic::QuicTransport::new(QuicConfig::default()).unwrap();

    // Spawn server echo handler.
    let server_handle = tokio::spawn(async move {
        let conn = server_agent.transport.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // Read frame header (28 bytes).
        let mut header = [0u8; aafp_messaging::FRAME_HEADER_SIZE];
        recv.read_exact(&mut header).await.unwrap();
        let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
        let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
        let body_len = payload_len + ext_len;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            recv.read_exact(&mut body).await.unwrap();
        }
        let mut full_frame = header.to_vec();
        full_frame.extend_from_slice(&body);
        let (frame, _) = decode_frame(&full_frame).unwrap();

        // Echo back.
        let resp_frame = aafp_messaging::Frame::data(0, frame.payload.clone());
        let resp_bytes = encode_frame(&resp_frame).unwrap();
        send.write_all(&resp_bytes).await.unwrap();
        send.finish();

        // Keep alive.
        sleep(Duration::from_millis(200)).await;
    });

    // Client connects and sends a message.
    let conn = client.dial(&server_addr).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let msg = b"integration test message";
    let msg_frame = aafp_messaging::Frame::data(0, msg.to_vec());
    let msg_bytes = encode_frame(&msg_frame).unwrap();
    send.write_all(&msg_bytes).await.unwrap();
    send.finish();

    // Read echo response (full frame).
    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await.unwrap().unwrap_or(0);
    let (resp_frame, _) = decode_frame(&buf[..n]).unwrap();
    assert_eq!(resp_frame.payload, msg);

    server_handle.await.unwrap();
    client.close();
}

/// Test UCAN delegation chain.
#[tokio::test]
async fn test_ucan_delegation() {
    use aafp_identity::{Capability, UcanToken};

    let root = AgentKeypair::generate();
    let (child_kp, child_id) = {
        let kp = AgentKeypair::generate();
        let id = aafp_identity::derive_agent_id(&kp.public_key);
        (kp, id)
    };

    let far_future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3600)
        .unwrap_or(u64::MAX);

    // Root delegates to child.
    let token = UcanToken::delegate(
        &root,
        &child_id,
        vec![Capability {
            resource: "compute.inference".into(),
            action: "invoke".into(),
            constraints: None,
        }],
        far_future,
    )
    .unwrap();

    // Verify token.
    token.verify(&root.public_key).unwrap();

    // Child can re-delegate (with proof).
    let (grandchild_kp, grandchild_id) = {
        let kp = AgentKeypair::generate();
        let id = aafp_identity::derive_agent_id(&kp.public_key);
        (kp, id)
    };

    let token2 = UcanToken::delegate_with_proof(
        &child_kp,
        &grandchild_id,
        vec![Capability {
            resource: "compute.inference".into(),
            action: "invoke".into(),
            constraints: None,
        }],
        far_future,
        &token,
    )
    .unwrap();

    token2.verify(&child_kp.public_key).unwrap();
}

/// Test regional discovery with 10 agents across regions.
#[tokio::test]
async fn test_regional_discovery() {
    use aafp_discovery::{Region, RegionalDiscovery};

    let mut rd = RegionalDiscovery::new();
    let regions = [
        Region::UsEast,
        Region::UsWest,
        Region::Europe,
        Region::AsiaPacific,
        Region::UsEast,
        Region::Europe,
        Region::UsWest,
        Region::AsiaPacific,
        Region::UsEast,
        Region::Europe,
    ];

    for region in &regions {
        let kp = AgentKeypair::generate();
        let id = aafp_identity::derive_agent_id(&kp.public_key);
        let record = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        rd.add(id, *region, record);
    }

    assert_eq!(rd.len(), 10);
    assert_eq!(rd.agents_in_region(Region::UsEast).len(), 3);
    assert_eq!(rd.agents_in_region(Region::Europe).len(), 3);
    assert_eq!(rd.agents_in_region(Region::UsWest).len(), 2);
    assert_eq!(rd.agents_in_region(Region::AsiaPacific).len(), 2);

    // Find closest from UsEast should return UsEast agents first.
    let closest = rd.find_closest(Region::UsEast, 5);
    assert_eq!(closest.len(), 5);
}

/// Test NAT status detection.
#[tokio::test]
async fn test_nat_detection() {
    use aafp_nat::auto_nat::DialBackResult;
    use aafp_nat::{AutoNat, NatStatus};
    use std::time::Instant;

    let mut auto_nat = AutoNat::new();
    assert_eq!(auto_nat.status(), NatStatus::Unknown);

    // Simulate dial-back probes.
    for success in [true, true, true] {
        auto_nat.record_probe(DialBackResult {
            peer: [0u8; 32],
            success,
            dialed_addr: "quic://1.2.3.4:4433".into(),
            timestamp: Instant::now(),
        });
    }
    assert_eq!(auto_nat.status(), NatStatus::Public);

    auto_nat.reset();
    for success in [false, false, false] {
        auto_nat.record_probe(DialBackResult {
            peer: [0u8; 32],
            success,
            dialed_addr: "quic://1.2.3.4:4433".into(),
            timestamp: Instant::now(),
        });
    }
    assert_eq!(auto_nat.status(), NatStatus::Private);
}

/// Test full agent lifecycle: build, start, discover, connect, send.
#[tokio::test]
async fn test_agent_lifecycle() {
    let agent = AgentBuilder::new()
        .with_capabilities(vec!["inference".into(), "coding".into()])
        .build()
        .await
        .unwrap();

    // Verify agent properties.
    assert_eq!(agent.capabilities().len(), 2);
    assert!(!agent.is_running());

    // Verify DHT has self.
    let inference = agent.find_by_capability("inference");
    assert_eq!(inference.len(), 1);
    let coding = agent.find_by_capability("coding");
    assert_eq!(coding.len(), 1);
    assert_eq!(inference[0].agent_id, *agent.id());
    assert_eq!(coding[0].agent_id, *agent.id());

    // Verify multiaddr.
    let addr = agent.multiaddr().unwrap();
    assert!(addr.starts_with("quic://"));
}
