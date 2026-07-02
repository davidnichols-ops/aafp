//! Benchmark: MCP transport throughput over AAFP.
//!
//! Measures the round-trip latency and throughput of JSON-RPC messages
//! exchanged over the AAFP MCP transport. These benchmarks establish a
//! baseline before any optimization work.
//!
//! ## Environment Reporting
//!
//! This benchmark prints a structured environment summary at startup
//! including CPU model, OS, Rust version, build profile, and transport
//! configuration. This ensures results are reproducible by another
//! developer.
//!
//! Run with:
//! ```bash
//! cargo bench --bench mcp_transport -- --warm-up-time 3 --measurement-time 5
//! ```

use aafp_benchmark::env_report::{print_env_summary, BenchmarkConfig};
use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::AafpMcpTransport;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rmcp::model::{ClientRequest, JsonRpcMessage, PingRequest, RequestId};
use rmcp::service::TxJsonRpcMessage;
use rmcp::transport::Transport;
use rmcp::{RoleClient, RoleServer};
use std::sync::Arc;

fn client_ping(id: i64) -> TxJsonRpcMessage<RoleClient> {
    JsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(id),
    )
}

/// Set up a connected client-server pair for benchmarking.
///
/// Note: Quinn's `open_bi()` doesn't send anything to the peer until data
/// is written. So the client must send a message after connecting to make
/// the stream visible to the server's `accept_bi()`.
async fn setup_transport_async() -> (AafpMcpTransport, AafpMcpTransport) {
    let server_agent = Arc::new(
        AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap(),
    );
    let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    // Spawn server acceptor
    let server_agent_clone = server_agent.clone();
    let server_handle = tokio::spawn(async move {
        let mut t = AafpMcpTransport::accept(&server_agent_clone).await.unwrap();
        // Receive the initial ping that makes the stream visible
        let _ = Transport::<RoleServer>::receive(&mut t).await;
        t
    });

    // Give server time to start listening
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect client
    let mut client = AafpMcpTransport::connect(&client_agent, &addr)
        .await
        .unwrap();

    // Send a ping to make the stream visible to the server's accept_bi()
    Transport::<RoleClient>::send(&mut client, client_ping(0))
        .await
        .unwrap();

    // Wait for server to complete
    let server = server_handle.await.unwrap();

    (client, server)
}

/// Benchmark: round-trip ping latency.
fn bench_ping_round_trip(c: &mut Criterion) {
    print_env_summary(&BenchmarkConfig::mcp_transport_default());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut client, mut server) = rt.block_on(setup_transport_async());

    let mut group = c.benchmark_group("mcp_transport_ping");
    group.throughput(Throughput::Elements(1));

    group.bench_function("round_trip", |b| {
        b.iter(|| {
            rt.block_on(async {
                Transport::<RoleClient>::send(&mut client, client_ping(1))
                    .await
                    .unwrap();

                let _ = Transport::<RoleServer>::receive(&mut server).await;

                let pong = JsonRpcMessage::response(
                    rmcp::model::ServerResult::EmptyResult(rmcp::model::EmptyResult {}),
                    RequestId::Number(1),
                );
                Transport::<RoleServer>::send(&mut server, pong)
                    .await
                    .unwrap();

                let _ = Transport::<RoleClient>::receive(&mut client).await;
            });
        });
    });

    group.finish();

    rt.block_on(async {
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<RoleServer>::close(&mut server).await.ok();
    });
}

/// Benchmark: one-way message throughput (client → server only).
fn bench_one_way_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut client, mut server) = rt.block_on(setup_transport_async());

    let mut group = c.benchmark_group("mcp_transport_one_way");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(format!("send_{}", count).as_str(), |b| {
            b.iter(|| {
                rt.block_on(async {
                    for i in 0..count {
                        Transport::<RoleClient>::send(&mut client, client_ping(i as i64))
                            .await
                            .unwrap();
                    }
                    for _ in 0..count {
                        let _ = Transport::<RoleServer>::receive(&mut server).await;
                    }
                });
            });
        });
    }

    group.finish();

    rt.block_on(async {
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<RoleServer>::close(&mut server).await.ok();
    });
}

criterion_group!(benches, bench_ping_round_trip, bench_one_way_throughput);
criterion_main!(benches);
