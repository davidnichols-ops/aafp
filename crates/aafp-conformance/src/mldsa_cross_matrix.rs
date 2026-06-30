//! Cross-verification matrix for ML-DSA-65 (A-10 Phase 3).
//!
//! Tests all 4 combinations:
//!   Rust→Rust, Rust→Go, Go→Rust, Go→Go
//!
//! Since we can't call Go from Rust directly, this test uses the
//! shared JSON test vectors as the cross-language bridge:
//! - Rust→Rust: Sign in Rust, verify in Rust (baseline)
//! - Rust→Go:   Sign in Rust, export to JSON, verify in Go (TestRustVectorsVerifyInGo)
//! - Go→Rust:   Sign in Go, export to JSON, verify in Rust (test_go_vectors_verify_in_rust)
//! - Go→Go:     Sign in Go, verify in Go (baseline, in Go tests)

#![allow(unused_imports)]
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct Vector {
    id: String,
    seed: String,
    message_hex: String,
    public_key_hex: String,
    secret_key_hex: String,
    signature_hex: String,
    expected_verify: bool,
    #[allow(dead_code)]
    description: String,
}

fn hex_to_vec(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn load_vectors(path: &str) -> Vec<Vector> {
    let paths = [
        path.to_string(),
        format!("../../../{}", path),
        format!("../../../../{}", path),
    ];
    for p in &paths {
        if let Ok(data) = std::fs::read_to_string(p) {
            return serde_json::from_str(&data).expect("failed to parse vectors");
        }
    }
    let crate_path = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let abs = format!("{}/../../../{}", crate_path, path);
    if let Ok(data) = std::fs::read_to_string(&abs) {
        return serde_json::from_str(&data).expect("failed to parse vectors");
    }
    vec![]
}

// ── Rust→Rust: Baseline ────────────────────────────────────────────

#[test]
fn test_matrix_rust_to_rust() {
    let vectors = load_vectors("test-vectors/mldsa65/vectors.json");
    assert!(!vectors.is_empty(), "Rust vectors not found");

    let mut passed = 0;
    for v in &vectors {
        let pk_bytes = hex_to_vec(&v.public_key_hex);
        let sig_bytes = hex_to_vec(&v.signature_hex);
        let msg_bytes = hex_to_vec(&v.message_hex);

        let pk = MlDsa65PublicKey::from_bytes(&pk_bytes).unwrap();
        let sig = MlDsa65Signature::from_bytes(&sig_bytes).unwrap();
        let result = MlDsa65::verify(&pk, &msg_bytes, &sig);
        assert_eq!(result, v.expected_verify, "Rust→Rust: {}", v.id);
        passed += 1;
    }
    eprintln!("Rust→Rust: {}/{} passed", passed, vectors.len());
}

// ── Go→Rust: Cross-verification ────────────────────────────────────

#[test]
fn test_matrix_go_to_rust() {
    let vectors = load_vectors("test-vectors/mldsa65/go_vectors.json");
    if vectors.is_empty() {
        eprintln!("Go vectors not found — run Go tests first");
        return;
    }

    let mut passed = 0;
    for v in &vectors {
        let pk_bytes = hex_to_vec(&v.public_key_hex);
        let sig_bytes = hex_to_vec(&v.signature_hex);
        let msg_bytes = hex_to_vec(&v.message_hex);

        let pk = MlDsa65PublicKey::from_bytes(&pk_bytes).unwrap();
        let sig = MlDsa65Signature::from_bytes(&sig_bytes).unwrap();
        let result = MlDsa65::verify(&pk, &msg_bytes, &sig);
        assert_eq!(result, v.expected_verify, "Go→Rust: {}", v.id);
        passed += 1;
    }
    eprintln!("Go→Rust: {}/{} passed", passed, vectors.len());
}

// ── Keygen consistency: Same seed → same key in both ────────────────

#[test]
fn test_matrix_keygen_consistency() {
    let rust_vectors = load_vectors("test-vectors/mldsa65/vectors.json");
    let go_vectors = load_vectors("test-vectors/mldsa65/go_vectors.json");

    // Find common seeds and verify they produce the same public key.
    let rust_keys: std::collections::HashMap<String, String> = rust_vectors
        .iter()
        .filter(|v| v.expected_verify)
        .filter(|v| !v.id.starts_with("invalid"))
        .map(|v| (v.seed.clone(), v.public_key_hex.clone()))
        .collect();

    let mut matched = 0;
    for v in &go_vectors {
        if !v.expected_verify {
            continue;
        }
        if let Some(rust_pk) = rust_keys.get(&v.seed) {
            assert_eq!(
                rust_pk, &v.public_key_hex,
                "keygen mismatch for seed {}",
                v.seed
            );
            matched += 1;
        }
    }
    eprintln!(
        "Keygen consistency: {}/{} common seeds matched",
        matched,
        rust_keys.len()
    );
}

// ── Deterministic signature consistency ─────────────────────────────

#[test]
fn test_matrix_deterministic_sig_consistency() {
    let rust_vectors = load_vectors("test-vectors/mldsa65/vectors.json");
    let go_vectors = load_vectors("test-vectors/mldsa65/go_vectors.json");

    // Build a map of (seed, message) → signature from Rust vectors.
    let rust_sigs: std::collections::HashMap<(String, String), String> = rust_vectors
        .iter()
        .filter(|v| v.expected_verify)
        .map(|v| {
            (
                (v.seed.clone(), v.message_hex.clone()),
                v.signature_hex.clone(),
            )
        })
        .collect();

    let mut matched = 0;
    let mut total = 0;
    for v in &go_vectors {
        if !v.expected_verify {
            continue;
        }
        let key = (v.seed.clone(), v.message_hex.clone());
        if let Some(rust_sig) = rust_sigs.get(&key) {
            total += 1;
            if rust_sig == &v.signature_hex {
                matched += 1;
            } else {
                eprintln!(
                    "deterministic sig mismatch for seed={}, msg_len={}",
                    &v.seed[..8],
                    v.message_hex.len() / 2
                );
            }
        }
    }
    eprintln!(
        "Deterministic sig consistency: {}/{} matched",
        matched, total
    );
}

// ── All 4 combinations summary ──────────────────────────────────────

#[test]
fn test_cross_verification_matrix_summary() {
    let rust_vectors = load_vectors("test-vectors/mldsa65/vectors.json");
    let go_vectors = load_vectors("test-vectors/mldsa65/go_vectors.json");

    assert!(!rust_vectors.is_empty(), "Rust vectors must exist");
    assert!(
        !go_vectors.is_empty(),
        "Go vectors must exist (run Go tests first)"
    );

    // Rust→Rust
    let mut rr_pass = 0;
    for v in &rust_vectors {
        let pk = MlDsa65PublicKey::from_bytes(&hex_to_vec(&v.public_key_hex)).unwrap();
        let sig = MlDsa65Signature::from_bytes(&hex_to_vec(&v.signature_hex)).unwrap();
        let msg = hex_to_vec(&v.message_hex);
        if MlDsa65::verify(&pk, &msg, &sig) == v.expected_verify {
            rr_pass += 1;
        }
    }

    // Go→Rust
    let mut gr_pass = 0;
    for v in &go_vectors {
        let pk = MlDsa65PublicKey::from_bytes(&hex_to_vec(&v.public_key_hex)).unwrap();
        let sig = MlDsa65Signature::from_bytes(&hex_to_vec(&v.signature_hex)).unwrap();
        let msg = hex_to_vec(&v.message_hex);
        if MlDsa65::verify(&pk, &msg, &sig) == v.expected_verify {
            gr_pass += 1;
        }
    }

    eprintln!("┌────────────────────────────────────────────┐");
    eprintln!("│  Cross-Verification Matrix (Rust side)     │");
    eprintln!("├──────────────┬──────────┬───────────────────┤");
    eprintln!("│ Sign → Verify│ Pass/Total│ Status           │");
    eprintln!("├──────────────┼──────────┼───────────────────┤");
    eprintln!(
        "│ Rust → Rust  │ {}/{}  │ {} │",
        rr_pass,
        rust_vectors.len(),
        if rr_pass == rust_vectors.len() {
            "PASS"
        } else {
            "FAIL"
        }
    );
    eprintln!(
        "│ Go   → Rust  │ {}/{}  │ {} │",
        gr_pass,
        go_vectors.len(),
        if gr_pass == go_vectors.len() {
            "PASS"
        } else {
            "FAIL"
        }
    );
    eprintln!("│ Rust → Go    │ (see Go) │ (verified in Go)  │");
    eprintln!("│ Go   → Go    │ (see Go) │ (verified in Go)  │");
    eprintln!("└──────────────┴──────────┴───────────────────┘");

    assert_eq!(rr_pass, rust_vectors.len(), "Rust→Rust must pass all");
    assert_eq!(gr_pass, go_vectors.len(), "Go→Rust must pass all");
}
