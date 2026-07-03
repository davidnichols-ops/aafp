//! Benchmark: Lock contention profile for concurrent senders (Track H1).
//!
//! Measures throughput vs concurrency level. The current send path uses
//! `Arc<Mutex<Option<QuicSendStream>>>` — every send acquires a tokio mutex.
//! Under concurrent load (multiple tasks sending on the same connection),
//! this serializes all sends and creates contention.
//!
//! This benchmark establishes the baseline before Track H2 replaces the
//! mutex with an mpsc channel.
//!
//! ## Methodology
//!
//! 1. Set up a connected client-server pair (one QUIC connection, one bidi stream).
//! 2. Extract the client's send handle (`Arc<Mutex<Option<QuicSendStream>>>`).
//! 3. Spawn N concurrent sender tasks, each sending M messages via
//!    `send_raw_json_on_handle_zero_copy` (the zero-copy path that still
//!    acquires the mutex).
//! 4. Server receives all N*M messages.
//! 5. Measure total wall-clock time and compute throughput (msg/s).
//!
//! Run with:
//! ```bash
//! cargo bench -p aafp-benchmark --bench lock_contention -- --warm-up-time 3 --measurement-time 5
//! ```

use aafp_benchmark::env_report::{print_env_summary, BenchmarkConfig};
use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::{send_raw_json_on_handle_zero_copy, AafpMcpTransport};
use rmcp::model::{ClientRequest, JsonRpcMessage, PingRequest, RequestId};
use rmcp::service::TxJsonRpcMessage;
use rmcp::transport::Transport;
use rmcp::{RoleClient, RoleServer};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Number of messages each sender task sends per iteration.
const MSGS_PER_SENDER: usize = 1000;

/// Build a simple JSON-RPC ping message as a `serde_json::Value`.
///
/// We use raw JSON (not the rmcp Transport trait) so that multiple tasks
/// can share the send handle concurrently — the `Transport::send` method
/// requires `&mut self` and cannot be called from multiple tasks.
fn ping_value(id: i64) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "ping"
    })
}

/// Set up a connected client-server pair for benchmarking.
///
/// Returns `(client_send_handle, server_transport)`. The client transport
/// is consumed — only its send handle is kept so multiple tasks can share it.
async fn setup_concurrent_async() -> (
    Arc<tokio::sync::Mutex<Option<aafp_transport_quic::QuicSendStream>>>,
    AafpMcpTransport,
) {
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
    tokio::time::sleep(Duration::from_millis(100)).await;

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

    // Extract the send handle so multiple tasks can share it.
    // The client transport itself is dropped; only the send handle remains.
    let send_handle = client.send_handle();

    (send_handle, server)
}

fn client_ping(id: i64) -> TxJsonRpcMessage<RoleClient> {
    JsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(id),
    )
}

/// Run a concurrent-sender throughput measurement.
///
/// Spawns `num_senders` tasks, each sending `MSGS_PER_SENDER` messages
/// through the shared send handle. The server receives all messages.
/// Returns throughput in messages/second.
async fn run_concurrent_throughput(
    send_handle: &Arc<tokio::sync::Mutex<Option<aafp_transport_quic::QuicSendStream>>>,
    server: &mut AafpMcpTransport,
    num_senders: usize,
) -> f64 {
    let total_msgs = num_senders * MSGS_PER_SENDER;

    // Spawn sender tasks
    let mut sender_handles = Vec::new();
    for task_id in 0..num_senders {
        let handle = send_handle.clone();
        let h = tokio::spawn(async move {
            for i in 0..MSGS_PER_SENDER {
                let id = (task_id * MSGS_PER_SENDER + i) as i64;
                let msg = ping_value(id);
                // This acquires the mutex — contention point under study.
                send_raw_json_on_handle_zero_copy(&handle, &msg)
                    .await
                    .unwrap();
            }
        });
        sender_handles.push(h);
    }

    // Start timer
    let start = Instant::now();

    // Receive all messages on the server side
    for _ in 0..total_msgs {
        let _ = server.recv_raw_json_zero_copy().await;
    }

    // Wait for all senders to finish
    for h in sender_handles {
        h.await.unwrap();
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-9);
    total_msgs as f64 / secs
}

/// Benchmark: concurrent sender throughput at 1, 2, 4, 8 senders.
///
/// This is the H1 baseline. It should show a throughput plateau because
/// all senders contend on the same `Arc<Mutex<Option<QuicSendStream>>>`.
fn bench_concurrent_senders(c: &mut Criterion) {
    print_env_summary(&BenchmarkConfig::mcp_transport_default());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("lock_contention_concurrent_senders");
    group.sample_size(10);

    for num_senders in [1, 2, 4, 8] {
        let label = format!("senders_{}", num_senders);
        group.throughput(Throughput::Elements((num_senders * MSGS_PER_SENDER) as u64));
        group.bench_function(label.as_str(), |b| {
            b.iter_with_setup(
                || {
                    rt.block_on(async {
                        let (send_handle, server) = setup_concurrent_async().await;
                        (send_handle, server)
                    })
                },
                |(send_handle, mut server)| {
                    let tps = rt.block_on(run_concurrent_throughput(
                        &send_handle,
                        &mut server,
                        num_senders,
                    ));
                    // Close the server to clean up
                    rt.block_on(async {
                        Transport::<RoleServer>::close(&mut server).await.ok();
                    });
                    tps
                },
            );
        });
    }

    group.finish();
}

/// Benchmark: raw concurrent throughput measurement (no criterion wrapper).
///
/// This produces a clean JSON-serializable result for the baseline file.
/// It runs each concurrency level once and records the throughput.
fn bench_concurrent_raw(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("lock_contention_raw");
    group.sample_size(10);

    for num_senders in [1, 2, 4, 8] {
        let label = format!("raw_senders_{}", num_senders);
        group.bench_function(label.as_str(), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (send_handle, mut server) = setup_concurrent_async().await;
                    let tps =
                        run_concurrent_throughput(&send_handle, &mut server, num_senders).await;
                    Transport::<RoleServer>::close(&mut server).await.ok();
                    tps
                });
            });
        });
    }

    group.finish();
}

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

criterion_group!(benches, bench_concurrent_senders, bench_concurrent_raw);
criterion_main!(benches);
