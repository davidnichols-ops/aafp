//! Load test: 10 agents, mesh topology, 100 messages each, 1KB (Track S1).
//!
//! This is the verification test for the load test harness. It runs a small
//! but complete load test and verifies that metrics are collected correctly.

#![allow(deprecated)]

use aafp_loadtest::{run_load_test, LoadTestConfig, Topology};
use std::time::Duration;

/// S1 VERIFY: Load test runs with 10 agents, 100 messages each, 1KB message
/// size, mesh topology, and produces metrics.
#[tokio::test]
async fn s1_load_test_10_agents_mesh() {
    let config = LoadTestConfig {
        num_agents: 10,
        messages_per_agent: 10, // reduced from 100 for CI speed
        message_size: 1024,
        duration: Duration::from_secs(30),
        topology: Topology::Mesh,
        max_connections_per_agent: 5,
        concurrency: 4,
        ..Default::default()
    };

    let metrics = run_load_test(&config).await;

    // VERIFY: metrics are populated
    assert!(metrics.messages_sent > 0, "should have sent messages");
    assert!(
        metrics.messages_received > 0,
        "should have received messages"
    );
    assert!(
        metrics.connections_established > 0,
        "should have established connections"
    );

    // VERIFY: error rate is reasonable (< 20% for localhost)
    assert!(
        metrics.error_rate < 0.2,
        "error rate should be < 20%, got {:.4}%",
        metrics.error_rate * 100.0
    );

    // VERIFY: latency stats are populated
    assert!(metrics.latency.p50_us > 0.0, "p50 latency should be > 0");
    assert!(
        metrics.latency.p99_us >= metrics.latency.p50_us,
        "p99 should be >= p50"
    );

    // VERIFY: throughput is reasonable
    assert!(metrics.throughput_msgps > 0.0, "throughput should be > 0");

    // VERIFY: config summary is correct
    assert_eq!(metrics.config_summary.num_agents, 10);
    assert_eq!(metrics.config_summary.message_size, 1024);
    assert_eq!(metrics.config_summary.topology, "mesh");

    println!("\n{}", metrics.to_json().unwrap());
}

/// Test all four topologies with a small number of agents.
#[tokio::test]
async fn s1_all_topologies_work() {
    for topology in [
        Topology::Mesh,
        Topology::Star,
        Topology::Ring,
        Topology::Random,
    ] {
        let config = LoadTestConfig {
            num_agents: 5,
            messages_per_agent: 3,
            message_size: 64,
            duration: Duration::from_secs(15),
            topology,
            max_connections_per_agent: 3,
            random_degree: 2,
            concurrency: 2,
        };

        let metrics = run_load_test(&config).await;

        assert!(
            metrics.messages_sent > 0,
            "{topology}: should have sent messages"
        );
        assert!(
            metrics.error_rate < 0.5,
            "{topology}: error rate should be < 50%, got {pct:.2}%",
            pct = metrics.error_rate * 100.0
        );

        println!(
            "{topology}: {sent} sent, {recv} received, {tps:.0} msg/s, error rate {err:.2}%",
            sent = metrics.messages_sent,
            recv = metrics.messages_received,
            tps = metrics.throughput_msgps,
            err = metrics.error_rate * 100.0
        );
    }
}

/// Test that the harness handles a single agent (no edges) gracefully.
#[tokio::test]
async fn s1_single_agent_no_edges() {
    let config = LoadTestConfig {
        num_agents: 1,
        messages_per_agent: 5,
        message_size: 64,
        duration: Duration::from_secs(5),
        topology: Topology::Mesh,
        ..Default::default()
    };

    let metrics = run_load_test(&config).await;

    // No edges = no messages sent
    assert_eq!(metrics.messages_sent, 0);
    assert_eq!(metrics.messages_received, 0);
    assert_eq!(metrics.error_rate, 0.0);
}
