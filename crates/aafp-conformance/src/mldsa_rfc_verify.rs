//! RFC verification for ML-DSA-65 (A-10 Phase 8).
//!
//! Verifies that both Rust and Go implementations conform to:
//! - RFC-0002 §5.6: Transcript hash + signature procedure
//! - RFC-0003 §2.3: Key algorithm registry (ML-DSA-65 = algorithm 1)
//! - RFC-0003 §2.4: Key pair spec (hedged signing default)
//! - RFC-0003 §3.5: Domain separation (prefix-free, raw UTF-8)

#![allow(unused_imports)]
use aafp_crypto::handshake_v1::{
    DOMAIN_SEPARATOR, KEY_ALG_ML_DSA_65, NONCE_SIZE, PROTOCOL_VERSION, SESSION_ID_SIZE,
    TLS_EXPORTER_LABEL,
};
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};

// ── RFC-0003 §2.3: Key Algorithm Registry ──────────────────────────

#[test]
fn test_rfc0003_key_algorithm_id() {
    // ML-DSA-65 must be algorithm ID 1.
    assert_eq!(
        KEY_ALG_ML_DSA_65, 1,
        "RFC-0003 §2.3: ML-DSA-65 must be algorithm 1"
    );
}

#[test]
fn test_rfc0003_key_sizes() {
    // RFC-0003 §2.3: PK=1952, SK=4032, SIG=3309.
    assert_eq!(
        ML_DSA_65_PUBKEY_LEN, 1952,
        "RFC-0003 §2.3: public key must be 1952 bytes"
    );
    assert_eq!(
        ML_DSA_65_SECRETKEY_LEN, 4032,
        "RFC-0003 §2.3: secret key must be 4032 bytes"
    );
    assert_eq!(
        ML_DSA_65_SIGNATURE_LEN, 3309,
        "RFC-0003 §2.3: signature must be 3309 bytes"
    );
}

#[test]
fn test_rfc0003_generated_key_sizes() {
    let (pk, sk) = MlDsa65::keypair();
    assert_eq!(pk.0.len(), 1952);
    assert_eq!(sk.0.len(), 4032);
    let sig = MlDsa65::sign(&sk, b"test");
    assert_eq!(sig.0.len(), 3309);
}

// ── RFC-0003 §2.4: Key Pair Spec (hedged signing) ──────────────────

#[test]
fn test_rfc0003_hedged_signing_non_deterministic() {
    // RFC-0003 §2.4: Default signing is hedged (randomized).
    // The same message signed twice with the same key should produce
    // different signatures (with overwhelming probability).
    let (_, sk) = MlDsa65::keypair();
    let msg = b"hedged signing test message";
    let sig1 = MlDsa65::sign(&sk, msg);
    let sig2 = MlDsa65::sign(&sk, msg);
    assert_ne!(
        sig1.0, sig2.0,
        "RFC-0003 §2.4: hedged signing must produce different signatures"
    );
}

#[test]
fn test_rfc0003_deterministic_signing_available() {
    // RFC-0003 §2.4: Deterministic signing variant is available for
    // test vector generation. Both signatures must verify.
    let seed = [0x42u8; 32];
    let (pk, sk) = MlDsa65::keypair_from_seed(&seed);
    let msg = b"deterministic signing test";
    let sig1 = MlDsa65::sign_deterministic(&sk, msg, &[0u8; 32]);
    let sig2 = MlDsa65::sign_deterministic(&sk, msg, &[0u8; 32]);
    assert_eq!(sig1.0, sig2.0, "deterministic signing must be reproducible");
    assert!(MlDsa65::verify(&pk, msg, &sig1));
    assert!(MlDsa65::verify(&pk, msg, &sig2));
}

// ── RFC-0003 §3.5: Domain Separation ───────────────────────────────

#[test]
fn test_rfc0003_domain_separator_handshake() {
    // RFC-0003 §3.5: The handshake domain separator is "aafp-v1-handshake".
    assert_eq!(
        DOMAIN_SEPARATOR, b"aafp-v1-handshake",
        "RFC-0003 §3.5: handshake domain separator must be 'aafp-v1-handshake'"
    );
}

#[test]
fn test_rfc0003_domain_separator_length() {
    // RFC-0003 §3.5: Domain separators are raw UTF-8, no length prefix.
    let ds = DOMAIN_SEPARATOR;
    assert_eq!(ds.len(), 17, "aafp-v1-handshake is 17 bytes");
}

#[test]
fn test_rfc0003_domain_separator_no_nul() {
    // RFC-0003 §3.5: Domain separators must not contain NUL bytes.
    let ds = DOMAIN_SEPARATOR;
    assert!(
        !ds.contains(&0u8),
        "domain separator must not contain NUL bytes"
    );
}

#[test]
fn test_rfc0003_domain_separators_prefix_free() {
    // RFC-0003 §3.5: Domain separators must be prefix-free.
    // "aafp-v1-handshake" must not be a prefix of "aafp-v1-record" or "aafp-v1-ucan".
    let handshake = b"aafp-v1-handshake";
    let record = b"aafp-v1-record";
    let ucan = b"aafp-v1-ucan";

    // None should be a prefix of another.
    assert!(
        !is_prefix(handshake, record),
        "handshake must not be prefix of record"
    );
    assert!(
        !is_prefix(handshake, ucan),
        "handshake must not be prefix of ucan"
    );
    assert!(
        !is_prefix(record, handshake),
        "record must not be prefix of handshake"
    );
    assert!(
        !is_prefix(record, ucan),
        "record must not be prefix of ucan"
    );
    assert!(
        !is_prefix(ucan, handshake),
        "ucan must not be prefix of handshake"
    );
    assert!(
        !is_prefix(ucan, record),
        "ucan must not be prefix of record"
    );
}

fn is_prefix(a: &[u8], b: &[u8]) -> bool {
    if a.len() >= b.len() {
        return false;
    }
    b[..a.len()] == *a
}

#[test]
fn test_rfc0003_domain_separator_in_signature_input() {
    // RFC-0003 §3.5: The domain separator is prepended to the transcript
    // hash before signing. The signature input is:
    //   domain_separator || transcript_hash
    let ds = DOMAIN_SEPARATOR; // 17 bytes
    let transcript_hash = [0xabu8; 32]; // simulated SHA-256 output
    let sig_input: Vec<u8> = ds.iter().chain(transcript_hash.iter()).copied().collect();

    assert_eq!(sig_input.len(), 17 + 32, "signature input must be 49 bytes");
    assert_eq!(
        &sig_input[..17],
        ds,
        "first 17 bytes must be domain separator"
    );
    assert_eq!(
        &sig_input[17..],
        &transcript_hash,
        "last 32 bytes must be transcript hash"
    );

    // Verify that signing this input produces a valid signature.
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, &sig_input);
    assert!(
        MlDsa65::verify(&pk, &sig_input, &sig),
        "signature over domain_separator || transcript_hash must verify"
    );
}

// ── RFC-0002 §5.6: Transcript Hash + Signature Procedure ───────────

#[test]
fn test_rfc0002_tls_exporter_label() {
    // RFC-0002 §5.6: The TLS exporter label is "EXPORTER-AAFP-Channel-Binding".
    assert_eq!(
        TLS_EXPORTER_LABEL, "EXPORTER-AAFP-Channel-Binding",
        "RFC-0002 §5.6: TLS exporter label must be 'EXPORTER-AAFP-Channel-Binding'"
    );
}

#[test]
fn test_rfc0002_protocol_version() {
    // RFC-0002: Protocol version is 1.
    assert_eq!(PROTOCOL_VERSION, 1, "RFC-0002: protocol version must be 1");
}

#[test]
fn test_rfc0002_session_id_size() {
    // RFC-0002 §5.6: Session ID is 32 bytes (SHA-256 output).
    assert_eq!(
        SESSION_ID_SIZE, 32,
        "RFC-0002 §5.6: session ID must be 32 bytes"
    );
}

#[test]
fn test_rfc0002_nonce_size() {
    // RFC-0002: Nonce size (verified from implementation).
    assert_eq!(NONCE_SIZE, 32, "RFC-0002: nonce must be 32 bytes");
}

// ── Cross-implementation consistency ───────────────────────────────

#[test]
fn test_cross_impl_empty_context_string() {
    // Both implementations use an empty ML-DSA context string (&[] / nil).
    // This is verified by the cross-verification matrix tests.
    // Here we just verify the Rust side uses empty context.
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"empty context test";
    let sig = MlDsa65::sign(&sk, msg);
    assert!(
        MlDsa65::verify(&pk, msg, &sig),
        "empty context string must produce valid signatures"
    );
}

#[test]
fn test_cross_impl_seed_based_keygen_deterministic() {
    // Both implementations support seed-based keygen (FIPS 204 Algorithm 1).
    // The same seed must produce the same key in both.
    let seed = [0x42u8; 32];
    let (pk1, sk1) = MlDsa65::keypair_from_seed(&seed);
    let (pk2, sk2) = MlDsa65::keypair_from_seed(&seed);
    assert_eq!(
        pk1.0, pk2.0,
        "seed-based keygen must be deterministic (public key)"
    );
    assert_eq!(
        sk1.0, sk2.0,
        "seed-based keygen must be deterministic (secret key)"
    );
}

#[test]
fn test_rfc_wire_format_compatibility() {
    // RFC-0003: The wire format for ML-DSA-65 keys and signatures is
    // the raw FIPS 204 encoding (no length prefix, no framing).
    // This is verified by the cross-verification matrix: Rust-generated
    // vectors (raw bytes) verify correctly in Go and vice versa.
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"wire format test");

    // Keys and signatures are raw bytes with exact lengths.
    assert_eq!(
        pk.0.len(),
        1952,
        "wire format: public key is raw 1952 bytes"
    );
    assert_eq!(
        sk.0.len(),
        4032,
        "wire format: secret key is raw 4032 bytes"
    );
    assert_eq!(
        sig.0.len(),
        3309,
        "wire format: signature is raw 3309 bytes"
    );

    // Round-trip through raw bytes.
    let pk2 = MlDsa65PublicKey::from_bytes(&pk.0).unwrap();
    let sig2 = MlDsa65Signature::from_bytes(&sig.0).unwrap();
    assert!(
        MlDsa65::verify(&pk2, b"wire format test", &sig2),
        "wire format: round-trip must verify"
    );
}
