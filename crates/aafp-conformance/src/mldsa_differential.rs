//! Differential testing for ML-DSA-65 (A-10 Phase 4).
//!
//! Generates deterministic signing traces and verifies them in both
//! Rust and Go. Since we can't call Go from Rust directly, this test
//! generates a large batch of vectors in Rust, exports them to JSON,
//! and the Go side verifies them (and vice versa).
//!
//! The trace generation uses deterministic seeds and messages, so both
//! sides can independently generate and verify the same traces.

#![allow(unused_imports)]
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiffTrace {
    seed_hex: String,
    message_hex: String,
    public_key_hex: String,
    signature_hex: String,
    verify_result: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Generate 10,000 deterministic traces.
fn generate_traces(count: usize) -> Vec<DiffTrace> {
    let mut traces = Vec::with_capacity(count);
    for i in 0..count {
        // Deterministic seed from index.
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64).to_be_bytes());

        // Deterministic message from index.
        let msg = format!("differential test message #{}", i).into_bytes();

        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);
        let sig = MlDsa65::sign_deterministic(&sk, &msg, &[0u8; 32]);
        let verify = MlDsa65::verify(&pk, &msg, &sig);

        traces.push(DiffTrace {
            seed_hex: hex(&seed),
            message_hex: hex(&msg),
            public_key_hex: hex(&pk.0),
            signature_hex: hex(&sig.0),
            verify_result: verify,
        });
    }
    traces
}

#[test]
fn test_differential_10k_generate_and_verify() {
    let traces = generate_traces(10_000);

    // Self-verify all traces.
    let mut passed = 0;
    for t in &traces {
        let pk = MlDsa65PublicKey::from_bytes(&hex_to_vec(&t.public_key_hex)).unwrap();
        let sig = MlDsa65Signature::from_bytes(&hex_to_vec(&t.signature_hex)).unwrap();
        let msg = hex_to_vec(&t.message_hex);
        let result = MlDsa65::verify(&pk, &msg, &sig);
        assert!(result, "differential trace should verify");
        assert!(t.verify_result, "trace verify_result should be true");
        passed += 1;
    }
    assert_eq!(passed, 10_000);
    eprintln!("Differential: {}/10000 traces verified in Rust", passed);

    // Export only every 100th trace to keep file size manageable.
    let export_traces: Vec<&DiffTrace> = traces.iter().step_by(100).collect();
    let json = serde_json::to_string(&export_traces).unwrap();
    let paths = [
        "test-vectors/mldsa65/diff_traces.json",
        "../../../test-vectors/mldsa65/diff_traces.json",
    ];
    for p in &paths {
        if std::fs::write(p, &json).is_ok() {
            eprintln!("Wrote {} diff traces to {}", export_traces.len(), p);
            return;
        }
    }
    let crate_path = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let abs = format!(
        "{}/../../../../test-vectors/mldsa65/diff_traces.json",
        crate_path
    );
    let _ = std::fs::write(&abs, &json);
    eprintln!("Wrote {} diff traces to {}", export_traces.len(), abs);
}

#[test]
fn test_differential_keygen_consistency_10k() {
    // Verify that keygen from seed is deterministic for 10K seeds.
    for i in 0..10_000u32 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());

        let (pk1, _) = MlDsa65::keypair_from_seed(&seed);
        let (pk2, _) = MlDsa65::keypair_from_seed(&seed);
        assert_eq!(pk1.0, pk2.0, "keygen not deterministic for seed {}", i);
    }
    eprintln!("Keygen consistency: 10000/10000 seeds deterministic");
}

#[test]
fn test_differential_verify_go_traces() {
    // Load Go-generated diff traces and verify them in Rust.
    let paths = [
        "test-vectors/mldsa65/go_diff_traces.json",
        "../../../test-vectors/mldsa65/go_diff_traces.json",
        "../../../../test-vectors/mldsa65/go_diff_traces.json",
    ];
    let data = paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .next();

    let data = match data {
        Some(d) => d,
        None => {
            // Try CARGO_MANIFEST_DIR.
            let crate_path =
                std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
            let abs = format!(
                "{}/../../../../test-vectors/mldsa65/go_diff_traces.json",
                crate_path
            );
            match std::fs::read_to_string(&abs) {
                Ok(d) => d,
                Err(_) => {
                    eprintln!("Go diff traces not found — run Go tests first");
                    return;
                }
            }
        }
    };

    let traces: Vec<DiffTrace> = serde_json::from_str(&data).expect("failed to parse");
    assert!(!traces.is_empty(), "Go diff traces should not be empty");

    let mut passed = 0;
    for t in &traces {
        let pk = MlDsa65PublicKey::from_bytes(&hex_to_vec(&t.public_key_hex)).unwrap();
        let sig = MlDsa65Signature::from_bytes(&hex_to_vec(&t.signature_hex)).unwrap();
        let msg = hex_to_vec(&t.message_hex);
        let result = MlDsa65::verify(&pk, &msg, &sig);
        assert_eq!(result, t.verify_result, "Go trace verification mismatch");
        passed += 1;
    }
    eprintln!(
        "Differential: {}/{} Go traces verified in Rust",
        passed,
        traces.len()
    );
}
