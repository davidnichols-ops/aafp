//! Cross-language interop test: Rust decodes Go-produced AAFP fixtures.
//!
//! This test spawns the Go fixture generator (`go run ./cmd/generate_interop_fixtures`),
//! captures the generated binary fixtures, and verifies them using the Rust
//! reference implementation. It proves bidirectional wire-format compatibility
//! at Level 2 (frame/CBOR/handshake level).
//!
//! The Go implementation is an independent implementation written from the RFCs
//! alone, making this a true two-implementation conformance check.
//!
//! Per D3 plan: Level 2 interop (frame-level). Level 1 (live QUIC) is not
//! possible because the Go implementation does not have a QUIC transport layer.

#![allow(clippy::all)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use aafp_cbor::{decode, encode, Value};
use aafp_crypto::handshake_v1::{
    derive_session_id, ClientFinished, ClientHello, ServerHello, TranscriptHash,
};
use aafp_identity::identity_v1::{AgentId, AgentRecord};
use aafp_messaging::{decode_frame, encode_frame};

/// Shared fixture directory — generated once, reused by all tests.
static FIXTURES_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Check if Go is installed and the Go implementation directory exists.
fn go_available() -> bool {
    let go_dir = go_impl_dir();
    go_dir.exists() && go_dir.join("go.mod").exists()
}

/// Get the Go implementation directory path.
fn go_impl_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| {
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string()
    });
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("go")
}

/// Get the shared fixtures directory, generating it if necessary.
/// Uses OnceLock to ensure fixtures are generated only once per test run.
fn fixtures_dir() -> &'static PathBuf {
    FIXTURES_DIR.get_or_init(|| {
        let go_dir = go_impl_dir();
        let output_dir = go_dir.join("go_interop_fixtures_test");

        if output_dir.exists() {
            fs::remove_dir_all(&output_dir).ok();
        }

        let output = Command::new("go")
            .arg("run")
            .arg("./cmd/generate_interop_fixtures")
            .arg(output_dir.to_str().unwrap())
            .current_dir(&go_dir)
            .output()
            .expect("failed to run Go fixture generator");

        if !output.status.success() {
            panic!(
                "Go fixture generator failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        output_dir
    })
}

fn read_fixture(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

fn check_roundtrip_cbor(dir: &Path, name: &str) -> Result<(), String> {
    let go_bytes = read_fixture(dir, name);
    let (value, consumed) = decode(&go_bytes).map_err(|e| format!("CBOR decode failed: {}", e))?;
    if consumed != go_bytes.len() {
        return Err(format!(
            "CBOR decode consumed {} bytes, expected {}",
            consumed,
            go_bytes.len()
        ));
    }
    let rust_bytes = encode(&value).map_err(|e| format!("CBOR re-encode failed: {}", e))?;
    if rust_bytes != go_bytes {
        return Err(format!(
            "Byte mismatch: Go {} bytes, Rust {} bytes\n  Go:   {}\n  Rust: {}",
            go_bytes.len(),
            rust_bytes.len(),
            hex::encode(&go_bytes),
            hex::encode(&rust_bytes)
        ));
    }
    Ok(())
}

fn check_roundtrip_frame(dir: &Path, name: &str) -> Result<(), String> {
    let go_bytes = read_fixture(dir, name);
    let (frame, consumed) =
        decode_frame(&go_bytes).map_err(|e| format!("Frame decode failed: {}", e))?;
    if consumed != go_bytes.len() {
        return Err(format!(
            "Frame decode consumed {} bytes, expected {}",
            consumed,
            go_bytes.len()
        ));
    }
    let rust_bytes = encode_frame(&frame).map_err(|e| format!("Frame re-encode failed: {}", e))?;
    if rust_bytes != go_bytes {
        return Err(format!(
            "Frame byte mismatch: Go {} bytes, Rust {} bytes",
            go_bytes.len(),
            rust_bytes.len()
        ));
    }
    Ok(())
}

/// Test that Go is available and fixtures can be generated.
#[test]
fn test_go_fixtures_generatable() {
    if !go_available() {
        eprintln!(
            "SKIPPED: Go implementation not found at {}",
            go_impl_dir().display()
        );
        return;
    }

    let fixtures_dir = fixtures_dir();
    assert!(
        fixtures_dir.join("manifest.json").exists(),
        "Go fixture generator should produce manifest.json"
    );
    assert!(
        fixtures_dir.join("cbor").exists(),
        "Go fixture generator should produce cbor/ directory"
    );
    assert!(
        fixtures_dir.join("frames").exists(),
        "Go fixture generator should produce frames/ directory"
    );

    // Clean up
}

/// Test CBOR round-trip: Go encodes, Rust decodes and re-encodes, bytes match.
#[test]
fn test_go_cbor_roundtrip() {
    if !go_available() {
        eprintln!("SKIPPED: Go implementation not found");
        return;
    }

    let fixtures_dir = fixtures_dir();
    let cbor_dir = fixtures_dir.join("cbor");

    let cbor_fixtures = [
        "uint_5",
        "uint_24",
        "uint_100",
        "uint_1000",
        "negative_1",
        "negative_100",
        "bool_true",
        "bool_false",
        "null",
        "bstr_32",
        "tstr_hello",
        "empty_array",
        "empty_map",
        "int_map_sorted",
        "int_map_same_length",
        "str_map_sorted",
    ];

    let mut passed = 0;
    for name in &cbor_fixtures {
        match check_roundtrip_cbor(&cbor_dir, &format!("{}.bin", name)) {
            Ok(()) => passed += 1,
            Err(e) => panic!("CBOR round-trip failed for {}: {}", name, e),
        }
    }

    assert_eq!(
        passed,
        cbor_fixtures.len(),
        "All CBOR fixtures should round-trip"
    );
    println!("CBOR round-trip: {}/{} passed", passed, cbor_fixtures.len());
}

/// Test frame round-trip: Go encodes, Rust decodes and re-encodes, bytes match.
#[test]
fn test_go_frame_roundtrip() {
    if !go_available() {
        eprintln!("SKIPPED: Go implementation not found");
        return;
    }

    let fixtures_dir = fixtures_dir();
    let frame_dir = fixtures_dir.join("frames");

    let frame_fixtures = [
        "data_empty",
        "data_stream42",
        "handshake",
        "rpc_request",
        "ping",
        "data_flags_more",
    ];

    let mut passed = 0;
    for name in &frame_fixtures {
        match check_roundtrip_frame(&frame_dir, &format!("{}.bin", name)) {
            Ok(()) => passed += 1,
            Err(e) => panic!("Frame round-trip failed for {}: {}", name, e),
        }
    }

    assert_eq!(
        passed,
        frame_fixtures.len(),
        "All frame fixtures should round-trip"
    );
    println!(
        "Frame round-trip: {}/{} passed",
        passed,
        frame_fixtures.len()
    );
}

/// Test handshake message decode: Go encodes ClientHello/ServerHello/ClientFinished,
/// Rust decodes and re-encodes, bytes match.
#[test]
fn test_go_handshake_decode() {
    if !go_available() {
        eprintln!("SKIPPED: Go implementation not found");
        return;
    }

    let fixtures_dir = fixtures_dir();
    let hs_dir = fixtures_dir.join("handshake");

    // ClientHello (without sig)
    {
        let go_bytes = read_fixture(&hs_dir, "client_hello_without_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());

        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(&val, k) };
        let pv = match get(1) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("protocol_version"),
        };
        let agent_id = match get(2) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("agent_id"),
        };
        let pubkey = match get(3) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("public_key"),
        };
        let nonce = match get(4) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("nonce"),
        };
        let expires = match get(8) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("expires_at"),
        };
        let key_alg = match get(10) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("key_algorithm"),
        };

        assert_eq!(pv, 1);
        assert_eq!(pubkey.len(), 1952);
        assert_eq!(nonce.len(), 32);
        assert_eq!(expires, 1736294400);
        assert_eq!(key_alg, 1);
        let expected_id = AgentId::from_public_key(&pubkey);
        assert_eq!(agent_id, expected_id.0.to_vec());
        assert!(get(7).is_none(), "signature key 7 should be absent");
        assert!(get(9).is_none(), "receiver_mac key 9 should be absent");

        let ch = ClientHello {
            protocol_version: pv,
            agent_id: agent_id.clone(),
            public_key: pubkey.clone(),
            nonce: {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&nonce);
                arr
            },
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: expires,
            receiver_mac: None,
            key_algorithm: key_alg,
        };
        let rust_bytes = encode(&ch.to_cbor_without_sig_and_mac()).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "ClientHello byte mismatch: Go and Rust produce different CBOR"
        );
    }

    // ServerHello (without sig)
    {
        let go_bytes = read_fixture(&hs_dir, "server_hello_without_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());

        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(&val, k) };
        let pv = match get(1) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("protocol_version"),
        };
        let agent_id = match get(2) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("agent_id"),
        };
        let pubkey = match get(3) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("public_key"),
        };
        let nonce = match get(4) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("nonce"),
        };
        let session_id = match get(7) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("session_id"),
        };
        let expires = match get(9) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("expires_at"),
        };
        let key_alg = match get(10) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("key_algorithm"),
        };

        assert_eq!(pv, 1);
        assert_eq!(pubkey.len(), 1952);
        assert_eq!(nonce.len(), 32);
        assert_eq!(session_id.len(), 32);
        assert_eq!(expires, 1736294400);
        assert_eq!(key_alg, 1);
        assert!(get(8).is_none(), "signature key 8 should be absent");

        let expected_id = AgentId::from_public_key(&pubkey);
        assert_eq!(agent_id, expected_id.0.to_vec());

        let sh = ServerHello {
            protocol_version: pv,
            agent_id: agent_id.clone(),
            public_key: pubkey.clone(),
            nonce: {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&nonce);
                arr
            },
            capabilities: vec![],
            extensions: vec![],
            session_id: {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&session_id);
                arr
            },
            signature: vec![],
            expires_at: expires,
            key_algorithm: key_alg,
        };
        let rust_bytes = encode(&sh.to_cbor_without_sig()).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "ServerHello byte mismatch: Go and Rust produce different CBOR"
        );
    }

    // ClientFinished (without sig)
    {
        let go_bytes = read_fixture(&hs_dir, "client_finished_without_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());

        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(&val, k) };
        let session_id = match get(1) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("session_id"),
        };
        assert_eq!(session_id.len(), 32);
        assert!(get(2).is_none(), "signature key 2 should be absent");

        let cf = ClientFinished {
            session_id: {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&session_id);
                arr
            },
            signature: vec![],
        };
        let rust_bytes = encode(&cf.to_cbor_without_sig()).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "ClientFinished byte mismatch: Go and Rust produce different CBOR"
        );
    }

    println!("Handshake decode: 3/3 passed");
}

/// Test AgentRecord decode: Go encodes AgentRecord, Rust decodes and re-encodes.
#[test]
fn test_go_agent_record_decode() {
    if !go_available() {
        eprintln!("SKIPPED: Go implementation not found");
        return;
    }

    let fixtures_dir = fixtures_dir();
    let ar_dir = fixtures_dir.join("agent_record");

    // without_sig — key 8 (signature) is absent, so we can't use from_cbor.
    // Instead, decode manually and reconstruct the record.
    {
        let go_bytes = read_fixture(&ar_dir, "without_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());

        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(&val, k) };
        let record_type = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => panic!("record_type"),
        };
        let agent_id_bytes = match get(2) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("agent_id"),
        };
        let pubkey = match get(3) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => panic!("public_key"),
        };
        let caps_arr = match get(4) {
            Some(Value::Array(a)) => a.clone(),
            _ => panic!("capabilities"),
        };
        let endpoints_arr = match get(5) {
            Some(Value::Array(a)) => a.clone(),
            _ => panic!("endpoints"),
        };
        let created = match get(6) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("created_at"),
        };
        let expires = match get(7) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("expires_at"),
        };
        let key_alg = match get(9) {
            Some(Value::Unsigned(n)) => *n,
            _ => panic!("key_algorithm"),
        };

        assert_eq!(record_type, "aafp-record-v1");
        assert_eq!(pubkey.len(), 1952);
        assert_eq!(caps_arr.len(), 1);
        assert_eq!(endpoints_arr.len(), 1);
        assert_eq!(created, 1735689600);
        assert_eq!(expires, 1736294400);
        assert_eq!(key_alg, 1);
        assert!(get(8).is_none(), "signature key 8 should be absent");

        let expected_id = AgentId::from_public_key(&pubkey);
        assert_eq!(agent_id_bytes, expected_id.0.to_vec());

        use aafp_identity::identity_v1::CapabilityDescriptor;
        let record = AgentRecord {
            record_type,
            agent_id: AgentId::from_bytes(&agent_id_bytes).unwrap(),
            public_key: pubkey,
            capabilities: caps_arr
                .iter()
                .map(|c| CapabilityDescriptor::from_cbor(c).unwrap())
                .collect(),
            endpoints: endpoints_arr
                .iter()
                .map(|e| match e {
                    Value::TextString(s) => s.clone(),
                    _ => panic!("endpoint"),
                })
                .collect(),
            created_at: created,
            expires_at: expires,
            signature: vec![],
            key_algorithm: key_alg,
            record_version: match get(10) {
                Some(Value::Unsigned(n)) => *n,
                _ => 0,
            },
        };
        let rust_bytes = encode(&record.to_cbor_without_sig()).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "AgentRecord without_sig byte mismatch"
        );
    }

    // with_sig
    {
        let go_bytes = read_fixture(&ar_dir, "with_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());
        let record = AgentRecord::from_cbor(&val).expect("AgentRecord::from_cbor");
        assert_eq!(record.signature.len(), 3309);
        let rust_bytes = encode(&record.to_cbor()).unwrap();
        assert_eq!(rust_bytes, go_bytes, "AgentRecord with_sig byte mismatch");
    }

    println!("AgentRecord decode: 2/2 passed");
}

/// Test transcript hash and session ID: Go computes transcript hashes and
/// session ID, Rust independently computes them from the same inputs, values match.
#[test]
fn test_go_transcript_and_session_id() {
    if !go_available() {
        eprintln!("SKIPPED: Go implementation not found");
        return;
    }

    let fixtures_dir = fixtures_dir();
    let hs_dir = fixtures_dir.join("handshake");
    let transcript_dir = fixtures_dir.join("transcript");

    // Read Go-produced CBOR for handshake messages
    let ch_bytes = read_fixture(&hs_dir, "client_hello_without_sig.bin");
    let sh_bytes = read_fixture(&hs_dir, "server_hello_without_sig.bin");
    let cf_bytes = read_fixture(&hs_dir, "client_finished_without_sig.bin");

    // Verify transcript hash init
    {
        let go_hash = read_fixture(&transcript_dir, "hash_init.bin");
        let tls_binding = [0x05u8; 32];
        let th = TranscriptHash::from_tls_binding(&tls_binding);
        assert_eq!(
            th.current(),
            go_hash.as_slice(),
            "Transcript hash init mismatch"
        );
    }

    // Verify transcript hash after ClientHello
    {
        let go_hash = read_fixture(&transcript_dir, "hash_after_clienthello.bin");
        let tls_binding = [0x05u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);
        th.fold(&ch_bytes);
        assert_eq!(
            th.current(),
            go_hash.as_slice(),
            "Transcript hash after ClientHello mismatch"
        );
    }

    // Verify transcript hash after ServerHello
    {
        let go_hash = read_fixture(&transcript_dir, "hash_after_serverhello.bin");
        let tls_binding = [0x05u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);
        th.fold(&ch_bytes);
        th.fold(&sh_bytes);
        assert_eq!(
            th.current(),
            go_hash.as_slice(),
            "Transcript hash after ServerHello mismatch"
        );
    }

    // Verify transcript hash after ClientFinished
    {
        let go_hash = read_fixture(&transcript_dir, "hash_after_clientfinished.bin");
        let tls_binding = [0x05u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);
        th.fold(&ch_bytes);
        th.fold(&sh_bytes);
        th.fold(&cf_bytes);
        assert_eq!(
            th.current(),
            go_hash.as_slice(),
            "Transcript hash after ClientFinished mismatch"
        );
    }

    // Verify session ID
    {
        let go_session_id = read_fixture(&transcript_dir, "session_id.bin");
        let go_hash_after_ch = read_fixture(&transcript_dir, "hash_after_clienthello.bin");

        let mut h_arr = [0u8; 32];
        h_arr.copy_from_slice(&go_hash_after_ch);
        let server_agent_id = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(&[0x43u8; 1952]);
            hasher.finalize().to_vec()
        };
        let rust_session_id = derive_session_id(&h_arr, &[0x03; 32], &[0x04; 32], &server_agent_id);
        assert_eq!(
            rust_session_id.as_slice(),
            go_session_id.as_slice(),
            "Session ID mismatch: Go and Rust derive different session IDs"
        );
    }

    println!("Transcript hash + session ID: 5/5 passed");
}

/// Test RPC message round-trip: Go encodes RPC messages, Rust decodes and
/// re-encodes, bytes match.
#[test]
fn test_go_rpc_roundtrip() {
    if !go_available() {
        eprintln!("SKIPPED: Go implementation not found");
        return;
    }

    let fixtures_dir = fixtures_dir();
    let rpc_dir = fixtures_dir.join("rpc");

    let rpc_fixtures = [
        "request_basic",
        "request_with_params",
        "response_success",
        "response_error",
        "close_message",
        "error_message_fatal",
    ];

    let mut passed = 0;
    for name in &rpc_fixtures {
        match check_roundtrip_cbor(&rpc_dir, &format!("{}.bin", name)) {
            Ok(()) => passed += 1,
            Err(e) => panic!("RPC round-trip failed for {}: {}", name, e),
        }
    }

    assert_eq!(passed, rpc_fixtures.len());
    println!("RPC round-trip: {}/{} passed", passed, rpc_fixtures.len());
}
