//! Multi-node DHT integration tests (Track R7).
//!
//! End-to-end tests that exercise the full DHT stack:
//! - Bootstrap from seed nodes
//! - Announce and lookup across multiple nodes
//! - Churn (node going offline and coming back)
//! - Network partition and reconciliation
//!
//! Uses InMemoryDhtNetwork to simulate multiple nodes in a single process.

use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_discovery::dht_router::{
    Bootstrap, BootstrapConfig, DhtRouter, DhtRouterConfig, InMemoryDhtNetwork,
};
use aafp_identity::identity_v1::{AgentRecord, CapabilityDescriptor};
use std::sync::Arc;
use tokio::time::{timeout, Duration};

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

const TEST_NOW: u64 = 1700000000;

fn make_record(seed: u8, capabilities: Vec<&str>) -> AgentRecord {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    let (pk, sk) = MlDsa65::keypair_from_seed(&seed_bytes);
    let mut record = AgentRecord::new(
        &pk.0,
        capabilities
            .iter()
            .map(|c| CapabilityDescriptor::new(*c))
            .collect(),
        vec![format!("/ip4/127.0.0.1/tcp/{}", 4000 + seed as u16)],
        TEST_NOW,
        TEST_NOW + 86400,
        1,
    );
    record.sign(&sk);
    record
}

fn make_router(
    self_id: aafp_identity::identity_v1::AgentId,
    transport: Arc<InMemoryDhtNetwork>,
) -> DhtRouter {
    DhtRouter::with_config(self_id, transport, DhtRouterConfig::default())
        .with_time_provider(|| TEST_NOW)
}

/// Create a network of N nodes, each with its own record and capabilities.
fn create_network(
    n: usize,
    network: &Arc<InMemoryDhtNetwork>,
) -> (Vec<Arc<DhtRouter>>, Vec<AgentRecord>) {
    let records: Vec<AgentRecord> = (0..n)
        .map(|i| make_record((i + 1) as u8, vec![&format!("cap{}", i)]))
        .collect();

    let routers: Vec<Arc<DhtRouter>> = records
        .iter()
        .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
        .collect();

    (routers, records)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test 1: 10-node DHT — bootstrap, announce, lookup.
#[tokio::test]
async fn test_10_node_dht_bootstrap_announce_lookup() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(10, &network);

    // Register all nodes
    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }

    // Build mesh
    for i in 0..10 {
        for j in 0..10 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Each node announces its capability
    for (i, router) in routers.iter().enumerate() {
        router.announce(records[i].clone()).await;
    }

    // Each node looks up all other capabilities
    for i in 0..10 {
        for j in 0..10 {
            if i == j {
                continue;
            }
            let cap = format!("cap{}", j);
            let results = routers[i].lookup(&cap, 10).await;
            assert!(
                results.iter().any(|r| r.agent_id == records[j].agent_id),
                "node {} should find node {}'s record for capability '{}'",
                i,
                j,
                cap
            );
        }
    }
}

/// Test 2: Bootstrap from seed node.
#[tokio::test]
async fn test_bootstrap_from_seed() {
    let network = Arc::new(InMemoryDhtNetwork::new());

    // Create seed node (node 0)
    let seed_record = make_record(1, vec!["seed"]);
    let seed_router = Arc::new(make_router(seed_record.agent_id.clone(), network.clone()));
    seed_router.set_own_record(seed_record.clone()).await;
    network.register(seed_router.clone()).await;

    // Create 5 more nodes that the seed knows about
    let peer_records: Vec<AgentRecord> = (0..5)
        .map(|i| make_record((i + 2) as u8, vec![&format!("peer{}", i)]))
        .collect();

    for record in &peer_records {
        let router = Arc::new(make_router(record.agent_id.clone(), network.clone()));
        router.set_own_record(record.clone()).await;
        network.register(router.clone()).await;
        seed_router.add_peer(record.clone()).await;
    }

    // New node bootstraps from the seed
    let own_record = make_record(10, vec!["newcomer"]);
    let own_id = own_record.agent_id.clone();
    let own_router = make_router(own_id, network.clone());
    own_router.set_own_record(own_record.clone()).await;
    let own_router_arc = Arc::new(make_router(own_record.agent_id.clone(), network.clone()));
    own_router_arc.set_own_record(own_record.clone()).await;
    network.register(own_router_arc).await;

    let config = BootstrapConfig {
        seed_nodes: vec!["quic://seed:4433".into()],
        min_peers: 1,
        ..Default::default()
    };
    let bootstrap = Bootstrap::new(config);

    let result = timeout(
        Duration::from_secs(5),
        bootstrap.run(&own_router, vec![seed_record]),
    )
    .await;
    assert!(result.is_ok(), "bootstrap should complete within timeout");
    let peer_count = result.unwrap().unwrap();
    assert!(
        peer_count >= 1,
        "should have discovered at least 1 peer, got {}",
        peer_count
    );
}

/// Test 3: Node goes offline, records expire.
#[tokio::test]
async fn test_node_goes_offline_records_expire() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(5, &network);

    // Register and build mesh
    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }
    for i in 0..5 {
        for j in 0..5 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Each node announces
    for (i, router) in routers.iter().enumerate() {
        router.announce(records[i].clone()).await;
    }

    // Verify node 0's record is on other nodes
    let local = routers[1].lookup_local("cap0").await;
    assert!(!local.is_empty(), "node 1 should have node 0's record");

    // Node 0 departs gracefully
    let notified = routers[0].depart().await;
    assert!(notified >= 1, "node 0 should notify peers on departure");

    // Node 1 should no longer have node 0's record
    let local = routers[1].lookup_local("cap0").await;
    assert!(
        local.is_empty(),
        "node 1 should not have node 0's record after departure"
    );
}

/// Test 4: Node restarts and re-announces.
#[tokio::test]
async fn test_node_restarts_and_reannounces() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(3, &network);

    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Node 0 announces
    routers[0].announce(records[0].clone()).await;

    // Node 0 departs
    routers[0].depart().await;

    // Node 1 no longer has node 0's record
    let local = routers[1].lookup_local("cap0").await;
    assert!(local.is_empty(), "record should be gone after departure");

    // Node 0 re-announces (simulating restart)
    routers[0].announce(records[0].clone()).await;

    // Node 0's record should be back in its local DHT
    let local = routers[0].lookup_local("cap0").await;
    assert!(
        !local.is_empty(),
        "record should reappear after re-announce"
    );
}

/// Test 5: Network partition — two groups, then heal.
#[tokio::test]
async fn test_network_partition_and_heal() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(10, &network);

    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }
    for i in 0..10 {
        for j in 0..10 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Each node stores its record
    for (i, router) in routers.iter().enumerate() {
        router.store_local(records[i].clone()).await;
    }

    // Partition: remove nodes 5-9
    for i in 5..10 {
        network.remove_node(&records[i].agent_id).await;
    }

    // Nodes 0-4 should still work
    let results = routers[0].lookup("cap1", 10).await;
    assert!(
        results.iter().any(|r| r.agent_id == records[1].agent_id),
        "nodes 0-4 should still be able to look up each other"
    );

    // Heal: re-register nodes 5-9
    for i in 5..10 {
        network.register(routers[i].clone()).await;
    }

    // Reconcile
    for router in &routers {
        router.reconcile_after_partition().await;
    }

    // Node 0 should now be able to find node 5's record
    let results = routers[0].lookup("cap5", 10).await;
    assert!(
        results.iter().any(|r| r.agent_id == records[5].agent_id),
        "node 0 should find node 5's record after reconciliation"
    );
}

/// Test 6: Churn — multiple nodes go offline, liveness check removes them.
#[tokio::test]
async fn test_churn_liveness_check() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(5, &network);

    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }

    // Node 0 knows all other nodes
    for j in 1..5 {
        routers[0].add_peer(records[j].clone()).await;
    }

    // Kill nodes 3 and 4
    network.remove_node(&records[3].agent_id).await;
    network.remove_node(&records[4].agent_id).await;

    // Liveness check should remove dead peers
    let (alive, removed) = routers[0].check_peer_liveness(0).await;
    assert_eq!(alive, 2, "nodes 1 and 2 should be alive");
    assert_eq!(removed, 2, "nodes 3 and 4 should be removed");

    // Verify routing table
    assert_eq!(routers[0].peer_count().await, 2);
}

/// Test 7: Record replication — record on multiple nodes.
#[tokio::test]
async fn test_record_replication_across_nodes() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(6, &network);

    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }
    for i in 0..6 {
        for j in 0..6 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Node 0 announces
    routers[0].announce(records[0].clone()).await;

    // Record should be on multiple nodes
    let mut nodes_with_record = 0;
    for router in &routers {
        let local = router.lookup_local("cap0").await;
        if local.iter().any(|r| r.agent_id == records[0].agent_id) {
            nodes_with_record += 1;
        }
    }
    assert!(
        nodes_with_record >= 2,
        "record should be replicated to at least 2 nodes, got {}",
        nodes_with_record
    );
}

/// Test 8: Recursive lookup across multiple nodes.
#[tokio::test]
async fn test_recursive_lookup_multi_node() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(5, &network);

    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }
    for i in 0..5 {
        for j in 0..5 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Each node stores its record
    for (i, router) in routers.iter().enumerate() {
        router.store_local(records[i].clone()).await;
    }

    // Node 0 does recursive lookup for cap3
    routers[0].invalidate_all_cache().await;
    let results = routers[0].lookup_recursive("cap3", 10).await;

    assert!(
        results.iter().any(|r| r.agent_id == records[3].agent_id),
        "recursive lookup should find node 3's record"
    );
}

/// Test 9: Bootstrap with PEX discovers peers transitively.
#[tokio::test]
async fn test_bootstrap_pex_transitive_discovery() {
    let network = Arc::new(InMemoryDhtNetwork::new());

    // Create a chain: seed → node1 → node2 → node3
    let seed_record = make_record(1, vec!["seed"]);
    let seed_router = Arc::new(make_router(seed_record.agent_id.clone(), network.clone()));
    seed_router.set_own_record(seed_record.clone()).await;
    network.register(seed_router.clone()).await;

    let node1_record = make_record(2, vec!["node1"]);
    let node1_router = Arc::new(make_router(node1_record.agent_id.clone(), network.clone()));
    node1_router.set_own_record(node1_record.clone()).await;
    network.register(node1_router.clone()).await;
    seed_router.add_peer(node1_record.clone()).await;

    let node2_record = make_record(3, vec!["node2"]);
    let node2_router = Arc::new(make_router(node2_record.agent_id.clone(), network.clone()));
    node2_router.set_own_record(node2_record.clone()).await;
    network.register(node2_router.clone()).await;
    node1_router.add_peer(node2_record.clone()).await;

    // New node bootstraps from seed
    let own_record = make_record(10, vec!["newcomer"]);
    let own_id = own_record.agent_id.clone();
    let own_router = make_router(own_id, network.clone());
    own_router.set_own_record(own_record).await;

    let config = BootstrapConfig {
        min_peers: 1,
        ..Default::default()
    };
    let bootstrap = Bootstrap::new(config);

    bootstrap.run(&own_router, vec![seed_record]).await.unwrap();

    // Should have discovered at least the seed
    let peer_count = own_router.peer_count().await;
    assert!(
        peer_count >= 1,
        "should have discovered at least 1 peer via PEX"
    );
}

/// Test 10: Full lifecycle — bootstrap, announce, lookup, churn, partition, heal.
#[tokio::test]
async fn test_full_dht_lifecycle() {
    let network = Arc::new(InMemoryDhtNetwork::new());
    let (routers, records) = create_network(8, &network);

    // Setup
    for (i, router) in routers.iter().enumerate() {
        router.set_own_record(records[i].clone()).await;
        network.register(router.clone()).await;
    }
    for i in 0..8 {
        for j in 0..8 {
            if i != j {
                routers[i].add_peer(records[j].clone()).await;
            }
        }
    }

    // Announce
    for (i, router) in routers.iter().enumerate() {
        router.announce(records[i].clone()).await;
    }

    // Verify all lookups work
    for i in 0..8 {
        let cap = format!("cap{}", (i + 1) % 8);
        let results = routers[i].lookup(&cap, 10).await;
        assert!(
            !results.is_empty(),
            "node {} should find records for {}",
            i,
            cap
        );
    }

    // Churn: kill node 3
    network.remove_node(&records[3].agent_id).await;
    let (alive, removed) = routers[0].check_peer_liveness(0).await;
    assert!(removed >= 1, "should remove dead node 3");

    // Partition: kill nodes 5-7
    for i in 5..8 {
        network.remove_node(&records[i].agent_id).await;
    }

    // Nodes 0-3 (minus 3) still work
    let results = routers[0].lookup("cap1", 10).await;
    assert!(
        !results.is_empty(),
        "nodes 0-4 should still work during partition"
    );

    // Heal: re-register all nodes
    for i in 3..8 {
        network.register(routers[i].clone()).await;
    }

    // Reconcile
    for router in &routers {
        router.reconcile_after_partition().await;
    }

    // All lookups should work again
    for i in 0..8 {
        routers[i].invalidate_all_cache().await;
        let cap = format!("cap{}", (i + 1) % 8);
        let results = routers[i].lookup(&cap, 10).await;
        assert!(
            !results.is_empty(),
            "node {} should find records for {} after heal",
            i,
            cap
        );
    }
}
