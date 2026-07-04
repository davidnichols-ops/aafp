//! Benchmark: Tokio runtime tuning (Track L5).
//!
//! Compares `current_thread` vs `multi_thread` runtime for localhost RPC.
//! L1 profiling showed 84% of time was spent in condvar wait (cross-thread
//! scheduling) with the multi_thread runtime. The `current_thread` runtime
//! should eliminate this overhead.
//!
//! Run with:
//! ```bash
//! cargo bench --bench runtime_tuning -- --warm-up-time 2 --measurement-time 3 --sample-size 10
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

    let server_agent_clone = server_agent.clone();
    let server_handle = tokio::spawn(async move {
        let mut t = AafpMcpTransport::accept(&server_agent_clone).await.unwrap();
        let _ = Transport::<RoleServer>::receive(&mut t).await;
        t
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut client = AafpMcpTransport::connect(&client_agent, &addr)
        .await
        .unwrap();

    Transport::<RoleClient>::send(&mut client, client_ping(0))
        .await
        .unwrap();

    let server = server_handle.await.unwrap();
    (client, server)
}

fn do_round_trip(
    client: &mut AafpMcpTransport,
    server: &mut AafpMcpTransport,
    rt: &tokio::runtime::Runtime,
) {
    rt.block_on(async {
        Transport::<RoleClient>::send(client, client_ping(1))
            .await
            .unwrap();
        let _ = Transport::<RoleServer>::receive(server).await;
        let pong = JsonRpcMessage::response(
            rmcp::model::ServerResult::EmptyResult(rmcp::model::EmptyResult {}),
            RequestId::Number(1),
        );
        Transport::<RoleServer>::send(server, pong).await.unwrap();
        let _ = Transport::<RoleClient>::receive(client).await;
    });
}

/// Benchmark with multi_thread runtime (current default).
fn bench_multi_thread(c: &mut Criterion) {
    print_env_summary(&BenchmarkConfig::mcp_transport_default());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(2 * 1024 * 1024)
        .build()
        .unwrap();
    let (mut client, mut server) = rt.block_on(setup_transport_async());

    let mut group = c.benchmark_group("runtime_tuning_multi_thread");
    group.throughput(Throughput::Elements(1));
    group.bench_function("round_trip", |b| {
        b.iter(|| do_round_trip(&mut client, &mut server, &rt));
    });
    group.finish();

    rt.block_on(async {
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<RoleServer>::close(&mut server).await.ok();
    });
}

/// Benchmark with current_thread runtime (L5 low-latency preset).
fn bench_current_thread(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_stack_size(2 * 1024 * 1024)
        .build()
        .unwrap();
    let (mut client, mut server) = rt.block_on(setup_transport_async());

    let mut group = c.benchmark_group("runtime_tuning_current_thread");
    group.throughput(Throughput::Elements(1));
    group.bench_function("round_trip", |b| {
        b.iter(|| do_round_trip(&mut client, &mut server, &rt));
    });
    group.finish();

    rt.block_on(async {
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<RoleServer>::close(&mut server).await.ok();
    });
}

/// Benchmark: task scheduling latency (notify + wake).
/// Measures the overhead of tokio task wake/notify without any I/O.
fn bench_task_scheduling(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_tuning_scheduling");

    // Multi-thread scheduling
    {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(2 * 1024 * 1024)
            .build()
            .unwrap();

        group.bench_function("yield_multi_thread", |b| {
            b.iter(|| {
                rt.block_on(async {
                    tokio::task::yield_now().await;
                });
            });
        });
    }

    // Current-thread scheduling
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .thread_stack_size(2 * 1024 * 1024)
            .build()
            .unwrap();

        group.bench_function("yield_current_thread", |b| {
            b.iter(|| {
                rt.block_on(async {
                    tokio::task::yield_now().await;
                });
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_multi_thread,
    bench_current_thread,
    bench_task_scheduling,
);
criterion_main!(benches);
