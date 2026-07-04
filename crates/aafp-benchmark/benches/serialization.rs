//! Benchmark: Serialization baseline and optimization (Track K1/K7).
//!
//! Measures serialization performance for:
//! 1. JSON: serde_json vs simd-json (MCP transport messages)
//! 2. CBOR: aafp_cbor canonical encoding (AAFP protocol messages)
//!
//! Run with:
//! ```bash
//! cargo bench --bench serialization -- --warm-up-time 2 --measurement-time 3 --sample-size 10
//! ```

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use serde::{Deserialize, Serialize};

/// Typical MCP initialize request (JSON-RPC 2.0).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpInitializeRequest {
    jsonrpc: String,
    id: i64,
    method: String,
    params: McpInitializeParams,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpInitializeParams {
    protocol_version: String,
    capabilities: McpCapabilities,
    client_info: McpClientInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpCapabilities {
    tools: Option<bool>,
    resources: Option<bool>,
    prompts: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpClientInfo {
    name: String,
    version: String,
}

/// Typical MCP tools/list response (JSON-RPC 2.0).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpToolsListResponse {
    jsonrpc: String,
    id: i64,
    result: McpToolsListResult,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpToolsListResult {
    tools: Vec<McpTool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct McpTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

/// Create a typical MCP initialize request.
fn make_initialize_request() -> McpInitializeRequest {
    McpInitializeRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "initialize".to_string(),
        params: McpInitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: McpCapabilities {
                tools: Some(true),
                resources: Some(true),
                prompts: Some(false),
            },
            client_info: McpClientInfo {
                name: "aafp-agent".to_string(),
                version: "0.1.0".to_string(),
            },
        },
    }
}

/// Create a typical MCP tools/list response with 5 tools.
fn make_tools_list_response() -> McpToolsListResponse {
    let tools: Vec<McpTool> = (0..5)
        .map(|i| McpTool {
            name: format!("tool_{i}"),
            description: format!("Tool number {i} for testing"),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "arg1": { "type": "string" },
                    "arg2": { "type": "number" }
                },
                "required": ["arg1"]
            }),
        })
        .collect();

    McpToolsListResponse {
        jsonrpc: "2.0".to_string(),
        id: 2,
        result: McpToolsListResult { tools },
    }
}

/// Benchmark: JSON serialization (serde_json vs simd-json).
fn bench_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization_json");
    group.sample_size(100);

    let init_req = make_initialize_request();
    let tools_resp = make_tools_list_response();

    // --- serde_json: encode ---
    group.throughput(Throughput::Bytes(
        serde_json::to_vec(&init_req).unwrap().len() as u64,
    ));
    group.bench_function("serde_json/encode_initialize", |b| {
        b.iter(|| {
            let buf = serde_json::to_vec(black_box(&init_req)).unwrap();
            black_box(buf);
        })
    });

    let tools_vec = serde_json::to_vec(&tools_resp).unwrap();
    group.throughput(Throughput::Bytes(tools_vec.len() as u64));
    group.bench_function("serde_json/encode_tools_list", |b| {
        b.iter(|| {
            let buf = serde_json::to_vec(black_box(&tools_resp)).unwrap();
            black_box(buf);
        })
    });

    // --- serde_json: decode ---
    group.throughput(Throughput::Bytes(tools_vec.len() as u64));
    group.bench_function("serde_json/decode_initialize", |b| {
        let encoded = serde_json::to_vec(&init_req).unwrap();
        b.iter(|| {
            let msg: McpInitializeRequest = serde_json::from_slice(black_box(&encoded)).unwrap();
            black_box(msg);
        })
    });

    group.bench_function("serde_json/decode_tools_list", |b| {
        b.iter(|| {
            let msg: McpToolsListResponse = serde_json::from_slice(black_box(&tools_vec)).unwrap();
            black_box(msg);
        })
    });

    // --- simd-json: encode ---
    group.throughput(Throughput::Bytes(
        simd_json::to_vec(&init_req).unwrap().len() as u64,
    ));
    group.bench_function("simd_json/encode_initialize", |b| {
        b.iter(|| {
            let buf = simd_json::to_vec(black_box(&init_req)).unwrap();
            black_box(buf);
        })
    });

    let tools_vec_simd = simd_json::to_vec(&tools_resp).unwrap();
    group.throughput(Throughput::Bytes(tools_vec_simd.len() as u64));
    group.bench_function("simd_json/encode_tools_list", |b| {
        b.iter(|| {
            let buf = simd_json::to_vec(black_box(&tools_resp)).unwrap();
            black_box(buf);
        })
    });

    // --- simd-json: decode (requires mutable input) ---
    group.bench_function("simd_json/decode_initialize", |b| {
        let encoded = simd_json::to_vec(&init_req).unwrap();
        b.iter(|| {
            let mut buf = encoded.clone();
            let msg: McpInitializeRequest = simd_json::from_slice(black_box(&mut buf)).unwrap();
            black_box(msg);
        })
    });

    group.bench_function("simd_json/decode_tools_list", |b| {
        let encoded = tools_vec_simd.clone();
        b.iter(|| {
            let mut buf = encoded.clone();
            let msg: McpToolsListResponse = simd_json::from_slice(black_box(&mut buf)).unwrap();
            black_box(msg);
        })
    });

    group.finish();
}

/// Benchmark: CBOR serialization (aafp_cbor canonical encoding).
fn bench_cbor_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization_cbor");
    group.sample_size(100);

    // Create a simple CBOR message (map with integer keys, like AAFP v1)
    use aafp_cbor::{decode, encode};

    // AAFP-style RPC request: {1: "method", 2: 1, 3: {params}}
    let rpc_request = aafp_cbor::Value::IntMap(vec![
        (1, aafp_cbor::Value::TextString("tools/list".to_string())),
        (2, aafp_cbor::Value::Unsigned(1)),
        (3, aafp_cbor::Value::IntMap(vec![])),
    ]);

    let encoded = encode(&rpc_request).unwrap();
    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("aafp_cbor/encode_rpc_request", |b| {
        b.iter(|| {
            let buf = encode(black_box(&rpc_request)).unwrap();
            black_box(buf);
        })
    });

    group.bench_function("aafp_cbor/decode_rpc_request", |b| {
        b.iter(|| {
            let (val, _) = decode(black_box(&encoded)).unwrap();
            black_box(val);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_json_serialization, bench_cbor_serialization);
criterion_main!(benches);
