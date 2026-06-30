//! Differential tests for nonce replay detection (RFC-0002 §6.7, A-9).
//!
//! These tests load replay trace vectors from `replay_vectors.json` and
//! execute them against the Rust ReplayCache. The same vectors are
//! executed against the Go ReplayCache, ensuring both implementations
//! produce identical results for the same sequence of operations.

#![allow(unused_imports)]
use aafp_crypto::{NonceReuseError, ReplayCache};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TraceStep {
    op: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    nonce: String,
    expect: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Trace {
    name: String,
    steps: Vec<TraceStep>,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_to_nonce(hex: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex);
    assert_eq!(
        bytes.len(),
        32,
        "nonce must be 32 bytes, got {}",
        bytes.len()
    );
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn run_trace(trace: &Trace) -> Result<(), String> {
    let cache = ReplayCache::new();
    for (i, step) in trace.steps.iter().enumerate() {
        let result = match step.op.as_str() {
            "check_and_insert" => {
                let aid = hex_to_bytes(&step.agent_id);
                let nonce = hex_to_nonce(&step.nonce);
                match cache.check_and_insert(&aid, &nonce) {
                    Ok(()) => "ok",
                    Err(_) => "replay",
                }
            }
            "check" => {
                let aid = hex_to_bytes(&step.agent_id);
                let nonce = hex_to_nonce(&step.nonce);
                if cache.check(&aid, &nonce) {
                    "true"
                } else {
                    "false"
                }
            }
            "insert" => {
                let aid = hex_to_bytes(&step.agent_id);
                let nonce = hex_to_nonce(&step.nonce);
                cache.insert(&aid, &nonce);
                "ok"
            }
            "clear" => {
                cache.clear();
                "ok"
            }
            _ => return Err(format!("unknown op: {}", step.op)),
        };
        if result != step.expect {
            return Err(format!(
                "step {} ({}): expected '{}', got '{}'",
                i, step.op, step.expect, result
            ));
        }
    }
    Ok(())
}

#[test]
fn test_differential_replay_vectors() {
    let json = include_str!("replay_vectors.json");
    let traces: Vec<Trace> = serde_json::from_str(json).expect("failed to parse vectors");
    assert!(!traces.is_empty(), "should have at least one trace");

    let mut passed = 0;
    for trace in &traces {
        match run_trace(trace) {
            Ok(()) => passed += 1,
            Err(e) => panic!("trace '{}' failed: {}", trace.name, e),
        }
    }
    assert_eq!(passed, traces.len(), "all traces should pass");
}

#[test]
fn test_differential_trace_count() {
    let json = include_str!("replay_vectors.json");
    let traces: Vec<Trace> = serde_json::from_str(json).expect("failed to parse vectors");
    assert!(
        traces.len() >= 15,
        "should have at least 15 differential traces, got {}",
        traces.len()
    );
}
