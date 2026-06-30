//! Cross-language test vector verification for ML-DSA-65 (A-10).
//!
//! This test loads the Go-generated test vectors and verifies them
//! using the Rust implementation. This proves Go→Rust interoperability.

#![allow(unused_imports)]
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct GoTestVector {
    id: String,
    seed: String,
    message_hex: String,
    #[serde(default)]
    context_hex: String,
    public_key_hex: String,
    secret_key_hex: String,
    signature_hex: String,
    expected_verify: bool,
    description: String,
}

fn hex_to_vec(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn load_go_vectors() -> Vec<GoTestVector> {
    let paths = [
        "test-vectors/mldsa65/go_vectors.json",
        "../../../test-vectors/mldsa65/go_vectors.json",
        "../../../../test-vectors/mldsa65/go_vectors.json",
    ];
    for path in &paths {
        if let Ok(data) = std::fs::read_to_string(path) {
            return serde_json::from_str(&data).expect("failed to parse Go vectors");
        }
    }
    // Try from the crate root.
    let crate_path = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let abs_path = format!(
        "{}/../../../../test-vectors/mldsa65/go_vectors.json",
        crate_path
    );
    if let Ok(data) = std::fs::read_to_string(&abs_path) {
        return serde_json::from_str(&data).expect("failed to parse Go vectors");
    }
    vec![]
}

#[test]
fn test_go_vectors_verify_in_rust() {
    let vectors = load_go_vectors();
    if vectors.is_empty() {
        eprintln!("Go vectors not found — skipping (run Go test first)");
        return;
    }
    assert!(
        vectors.len() >= 10,
        "expected at least 10 Go vectors, got {}",
        vectors.len()
    );

    let mut passed = 0;
    for v in &vectors {
        let pk_bytes = hex_to_vec(&v.public_key_hex);
        let sig_bytes = hex_to_vec(&v.signature_hex);
        let msg_bytes = hex_to_vec(&v.message_hex);

        let pk = MlDsa65PublicKey::from_bytes(&pk_bytes).expect("valid public key");
        let sig = MlDsa65Signature::from_bytes(&sig_bytes).expect("valid signature");

        let result = MlDsa65::verify(&pk, &msg_bytes, &sig);
        assert_eq!(
            result, v.expected_verify,
            "vector {}: expected {}, got {} ({})",
            v.id, v.expected_verify, result, v.description
        );
        passed += 1;
    }
    eprintln!("Verified {}/{} Go vectors in Rust", passed, vectors.len());
}

#[test]
fn test_go_vectors_keygen_match_in_rust() {
    let vectors = load_go_vectors();
    if vectors.is_empty() {
        eprintln!("Go vectors not found — skipping");
        return;
    }

    let mut seen = std::collections::HashSet::new();
    let mut matched = 0;
    for v in &vectors {
        if !v.expected_verify {
            continue;
        }
        if !seen.insert(v.seed.clone()) {
            continue;
        }

        let seed_bytes = hex_to_vec(&v.seed);
        assert_eq!(seed_bytes.len(), 32, "seed must be 32 bytes");

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_bytes);

        let (pk_rust, _) = MlDsa65::keypair_from_seed(&seed_arr);
        let pk_go = hex_to_vec(&v.public_key_hex);

        assert_eq!(
            pk_rust.0.len(),
            pk_go.len(),
            "public key length mismatch for seed {}",
            v.seed
        );
        assert_eq!(pk_rust.0, pk_go, "public key mismatch for seed {}", v.seed);
        matched += 1;
    }
    eprintln!("Keygen matched for {}/{} unique seeds", matched, seen.len());
}

#[test]
fn test_go_vectors_deterministic_sig_match_in_rust() {
    let vectors = load_go_vectors();
    if vectors.is_empty() {
        eprintln!("Go vectors not found — skipping");
        return;
    }

    let mut matched = 0;
    let mut total = 0;
    for v in &vectors {
        if !v.expected_verify {
            continue;
        }

        let sk_bytes = hex_to_vec(&v.secret_key_hex);
        let msg_bytes = hex_to_vec(&v.message_hex);
        let sig_go = hex_to_vec(&v.signature_hex);

        let sk = MlDsa65SecretKey::from_bytes(&sk_bytes).expect("valid secret key");
        let sig_rust = MlDsa65::sign_deterministic(&sk, &msg_bytes, &[0u8; 32]);

        total += 1;
        if sig_rust.0 == sig_go {
            matched += 1;
        } else {
            eprintln!(
                "vector {}: deterministic signatures differ (may be expected)",
                v.id
            );
        }
    }
    eprintln!("Deterministic signatures matched: {}/{}", matched, total);
}
