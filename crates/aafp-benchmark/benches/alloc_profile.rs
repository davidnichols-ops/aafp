//! Benchmark: Allocation profile of the MCP transport hot path.
//!
//! Measures allocations per message on the send path:
//! 1. serde_json::to_vec() — JSON serialization
//! 2. Frame::data() — frame construction
//! 3. encode_frame() — frame encoding
//!
//! This establishes the baseline for Track G (Zero-Copy Data Path).

use aafp_benchmark::alloc_tracker::CountingAllocator;
use aafp_benchmark::alloc_tracker::{track_allocs, track_allocs_with_result, AllocReport};
use aafp_messaging::{encode_frame, Frame};
use criterion::{criterion_group, criterion_main, Criterion};
use rmcp::model::{ClientRequest, JsonRpcMessage, PingRequest, RequestId};
use rmcp::service::TxJsonRpcMessage;
use rmcp::RoleClient;
use serde_json::json;
use std::io::Write;

// Set the counting allocator as the global allocator for this benchmark.
#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

/// MCP stream ID used for data frames.
const MCP_STREAM_ID: u64 = 4;

/// Create a typical MCP ping request message.
fn make_ping(id: i64) -> TxJsonRpcMessage<RoleClient> {
    JsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(id),
    )
}

/// Create a larger MCP tools/list request message (as raw JSON).
fn make_tools_list_json(id: i64) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": {
            "cursor": "some-long-cursor-string-for-pagination-aaaaaaaaaaaa"
        }
    })
}

/// Print an allocation report.
fn print_report(label: &str, report: &AllocReport) {
    println!(
        "  {:<30} allocs={:<4} bytes={:<8} deallocs={:<4} freed={}",
        label,
        report.alloc_count,
        report.bytes_allocated,
        report.dealloc_count,
        report.bytes_deallocated,
    );
}

/// Measure allocations for each step of the send path.
fn bench_send_path_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_send_path", |b| {
        b.iter(|| {
            let ping = make_ping(1);

            // Step 1: JSON serialization
            let (json_bytes, json_report) =
                track_allocs_with_result(|| serde_json::to_vec(&ping).unwrap());
            print_report("1. serde_json::to_vec", &json_report);

            // Step 2: Frame construction
            let (frame, frame_report) =
                track_allocs_with_result(|| Frame::data(MCP_STREAM_ID, json_bytes));
            print_report("2. Frame::data()", &frame_report);

            // Step 3: Frame encoding
            let (_encoded, encode_report) =
                track_allocs_with_result(|| encode_frame(&frame).unwrap());
            print_report("3. encode_frame()", &encode_report);

            // Total
            let total = track_allocs(|| {
                let ping = make_ping(1);
                let json_bytes = serde_json::to_vec(&ping).unwrap();
                let frame = Frame::data(MCP_STREAM_ID, json_bytes);
                let _encoded = encode_frame(&frame).unwrap();
            });
            print_report("TOTAL (send path)", &total);
        });
    });
}

/// Measure allocations for the receive path (decode + deserialize).
fn bench_recv_path_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_recv_path", |b| {
        // Pre-encode a message to decode.
        let ping = make_ping(1);
        let json_bytes = serde_json::to_vec(&ping).unwrap();
        let frame = Frame::data(MCP_STREAM_ID, json_bytes);
        let encoded = encode_frame(&frame).unwrap();

        b.iter(|| {
            // Step 1: Frame decoding
            let (_frame, decode_report) =
                track_allocs_with_result(|| aafp_messaging::decode_frame(&encoded).unwrap());
            print_report("1. decode_frame()", &decode_report);

            // Step 2: JSON deserialization (from payload)
            let (decoded_frame, _) = aafp_messaging::decode_frame(&encoded).unwrap();
            let (_msg, deser_report) = track_allocs_with_result(|| {
                serde_json::from_slice::<serde_json::Value>(&decoded_frame.payload)
            });
            print_report("2. serde_json::from_slice", &deser_report);

            // Total
            let total = track_allocs(|| {
                let (frame, _) = aafp_messaging::decode_frame(&encoded).unwrap();
                let _: serde_json::Value = serde_json::from_slice(&frame.payload).unwrap();
            });
            print_report("TOTAL (recv path)", &total);
        });
    });
}

/// Measure allocations for a simulated round-trip (send + recv).
fn bench_round_trip_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_round_trip", |b| {
        b.iter(|| {
            let report = track_allocs(|| {
                // Send side
                let ping = make_ping(1);
                let json_bytes = serde_json::to_vec(&ping).unwrap();
                let frame = Frame::data(MCP_STREAM_ID, json_bytes);
                let encoded = encode_frame(&frame).unwrap();

                // Receive side
                let (decoded, _) = aafp_messaging::decode_frame(&encoded).unwrap();
                let _: serde_json::Value = serde_json::from_slice(&decoded.payload).unwrap();
            });
            print_report("ROUND TRIP (send+recv)", &report);
        });
    });
}

/// Measure allocations for a larger message (tools/list).
fn bench_large_msg_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_large_msg", |b| {
        b.iter(|| {
            let report = track_allocs(|| {
                let msg = make_tools_list_json(1);
                let json_bytes = serde_json::to_vec(&msg).unwrap();
                let frame = Frame::data(MCP_STREAM_ID, json_bytes);
                let _encoded = encode_frame(&frame).unwrap();
            });
            print_report("LARGE MSG (tools/list)", &report);
        });
    });
}

/// Measure allocations for writing into a pre-allocated buffer.
fn bench_preallocated_write_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_preallocated", |b| {
        b.iter(|| {
            let report = track_allocs(|| {
                let ping = make_ping(1);
                // Simulate writing into a pre-allocated buffer
                let mut buf: Vec<u8> = Vec::with_capacity(2048);
                write!(&mut buf, "{}", serde_json::to_string(&ping).unwrap()).unwrap();
            });
            print_report("PREALLOC (with_capacity)", &report);
        });
    });
}

/// Measure allocations for the zero-copy send path (buffer pool + to_writer).
fn bench_zerocopy_send_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_zerocopy_send", |b| {
        // Warmup the buffer pool
        let warmup_bufs: Vec<bytes::BytesMut> = (0..4)
            .map(|_| aafp_transport_quic::buffer_pool::acquire())
            .collect();
        for buf in warmup_bufs {
            aafp_transport_quic::buffer_pool::release(buf);
        }

        b.iter(|| {
            let report = track_allocs(|| {
                use aafp_messaging::{backpatch_payload_len, encode_header_into, FrameType};
                use aafp_transport_quic::buffer_pool::{acquire, release, BytesMutWriter};

                let ping = make_ping(1);
                let mut buf = acquire();

                // Write frame header
                encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[]).unwrap();

                // Serialize JSON directly into buffer
                let payload_start = buf.len();
                {
                    let mut writer = BytesMutWriter::new(&mut buf);
                    serde_json::to_writer(&mut writer, &ping).unwrap();
                }
                let payload_len = buf.len() - payload_start;

                // Backpatch payload length
                backpatch_payload_len(&mut buf, payload_len).unwrap();

                // Simulate write (just blackbox the buffer)
                std::hint::black_box(&buf);

                release(buf);
            });
            print_report("ZEROCOPY SEND (pool)", &report);
        });
    });
}

/// Measure allocations for the zero-copy receive path (buffer pool + freeze).
fn bench_zerocopy_recv_allocs(c: &mut Criterion) {
    c.bench_function("alloc_profile_zerocopy_recv", |b| {
        // Pre-encode a message to decode
        let ping = make_ping(1);
        let json_bytes = serde_json::to_vec(&ping).unwrap();
        let frame = Frame::data(MCP_STREAM_ID, json_bytes);
        let encoded = encode_frame(&frame).unwrap();

        // Warmup the buffer pool
        let warmup_bufs: Vec<bytes::BytesMut> = (0..4)
            .map(|_| aafp_transport_quic::buffer_pool::acquire())
            .collect();
        for buf in warmup_bufs {
            aafp_transport_quic::buffer_pool::release(buf);
        }

        b.iter(|| {
            let report = track_allocs(|| {
                use aafp_transport_quic::buffer_pool::{acquire, release};
                use bytes::BufMut;

                // Simulate reading into a pooled buffer
                let mut buf = acquire();
                buf.resize(encoded.len(), 0);
                buf.as_mut().copy_from_slice(&encoded);

                // Decode using zero-copy decode_frame_from
                use aafp_messaging::decode_frame_from;
                let decoded = decode_frame_from(&mut buf).unwrap().unwrap();

                // Deserialize JSON from the zero-copy payload
                let _: serde_json::Value = serde_json::from_slice(&decoded.payload).unwrap();

                release(buf);
            });
            print_report("ZEROCOPY RECV (pool)", &report);
        });
    });
}

criterion_group!(
    benches,
    bench_send_path_allocs,
    bench_recv_path_allocs,
    bench_round_trip_allocs,
    bench_large_msg_allocs,
    bench_preallocated_write_allocs,
    bench_zerocopy_send_allocs,
    bench_zerocopy_recv_allocs,
);
criterion_main!(benches);
