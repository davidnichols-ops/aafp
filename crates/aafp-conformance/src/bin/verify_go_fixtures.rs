#![allow(clippy::all)]

//! Verify Go-generated interop fixtures by decoding them with the Rust
//! reference implementation and checking byte-for-byte equality after
//! re-encoding.
//!
//! Usage: cargo run --bin verify_go_fixtures -- <go_fixtures_dir>
//!
//! This binary:
//!   1. Reads each binary fixture produced by the Go implementation
//!   2. Decodes it using Rust's CBOR/frame/handshake decoders
//!   3. Re-encodes the decoded value
//!   4. Compares the re-encoded bytes against the original Go bytes
//!   5. Verifies transcript hashes and session ID match
//!   6. Reports any discrepancies

use std::fs;
use std::path::PathBuf;

use aafp_cbor::{decode, encode, Value};
use aafp_crypto::handshake_v1::{
    derive_session_id, ClientFinished, ClientHello, ServerHello, TranscriptHash,
};
use aafp_identity::identity_v1::{AgentId, AgentRecord, CapabilityDescriptor};
use aafp_messaging::{decode_frame, encode_frame};

fn read_fixture(dir: &PathBuf, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

fn check_roundtrip_cbor(dir: &PathBuf, name: &str) -> Result<(), String> {
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

fn check_roundtrip_frame(dir: &PathBuf, name: &str) -> Result<(), String> {
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

fn check_transcript_hash(
    fixtures_dir: &PathBuf,
    stage: &str,
    expected_name: &str,
    inputs: &[&[u8]],
) -> Result<(), String> {
    let expected = read_fixture(&fixtures_dir.join("transcript"), expected_name);

    // Recompute from the Go-produced CBOR fixtures
    let tls_binding = [0x05u8; 32];
    let mut th = TranscriptHash::from_tls_binding(&tls_binding);
    for input in inputs {
        th.fold(input);
    }
    let computed = th.current();

    if computed.as_slice() != expected.as_slice() {
        return Err(format!(
            "Transcript hash {} mismatch:\n  Go:   {}\n  Rust: {}",
            stage,
            hex::encode(&expected),
            hex::encode(computed)
        ));
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fixtures_dir = match args.get(1) {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from("go_interop_fixtures"),
    };

    println!(
        "Verifying Go-generated fixtures in: {}\n",
        fixtures_dir.display()
    );

    let mut passed = 0;
    let mut failed = 0;

    // === CBOR round-trip ===
    println!("=== CBOR round-trip ===");
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
    for name in &cbor_fixtures {
        match check_roundtrip_cbor(&cbor_dir, &format!("{}.bin", name)) {
            Ok(()) => {
                println!("  PASS: {}", name);
                passed += 1;
            }
            Err(e) => {
                println!("  FAIL: {}: {}", name, e);
                failed += 1;
            }
        }
    }

    // === Frame round-trip ===
    println!("\n=== Frame round-trip ===");
    let frame_dir = fixtures_dir.join("frames");
    let frame_fixtures = [
        "data_empty",
        "data_stream42",
        "handshake",
        "rpc_request",
        "ping",
        "data_flags_more",
    ];
    for name in &frame_fixtures {
        match check_roundtrip_frame(&frame_dir, &format!("{}.bin", name)) {
            Ok(()) => {
                println!("  PASS: {}", name);
                passed += 1;
            }
            Err(e) => {
                println!("  FAIL: {}: {}", name, e);
                failed += 1;
            }
        }
    }

    // === Handshake decode ===
    println!("\n=== Handshake decode ===");
    let hs_dir = fixtures_dir.join("handshake");

    // ClientHello (without sig — key 7 absent, key 9 absent)
    // We decode the CBOR directly and verify fields, then re-encode
    // using the same to_cbor_without_sig_and_mac logic.
    {
        let go_bytes = read_fixture(&hs_dir, "client_hello_without_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());

        // Verify semantic fields
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
        // Verify agent_id matches SHA-256(public_key)
        let expected_id = AgentId::from_public_key(&pubkey);
        assert_eq!(agent_id, expected_id.0.to_vec());
        // Verify key 7 (signature) is absent
        assert!(get(7).is_none(), "signature key 7 should be absent");
        // Verify key 9 (receiver_mac) is absent
        assert!(get(9).is_none(), "receiver_mac key 9 should be absent");

        // Re-encode using Rust's to_cbor_without_sig_and_mac
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
        if rust_bytes == go_bytes {
            println!("  PASS: client_hello_without_sig");
            passed += 1;
        } else {
            println!("  FAIL: client_hello_without_sig (byte mismatch)");
            println!(
                "    Go:   {} ({} bytes)",
                hex::encode(&go_bytes[..32]),
                go_bytes.len()
            );
            println!(
                "    Rust: {} ({} bytes)",
                hex::encode(&rust_bytes[..32]),
                rust_bytes.len()
            );
            failed += 1;
        }
    }

    // ServerHello (without sig — key 8 absent)
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
        if rust_bytes == go_bytes {
            println!("  PASS: server_hello_without_sig");
            passed += 1;
        } else {
            println!("  FAIL: server_hello_without_sig (byte mismatch)");
            failed += 1;
        }
    }

    // ClientFinished (without sig — key 2 absent)
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
        if rust_bytes == go_bytes {
            println!("  PASS: client_finished_without_sig");
            passed += 1;
        } else {
            println!("  FAIL: client_finished_without_sig (byte mismatch)");
            failed += 1;
        }
    }

    // === AgentRecord decode ===
    println!("\n=== AgentRecord decode ===");
    let ar_dir = fixtures_dir.join("agent_record");

    // without_sig — key 8 (signature) is absent
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

        // Verify agent_id matches SHA-256(public_key)
        let expected_id = AgentId::from_public_key(&pubkey);
        assert_eq!(agent_id_bytes, expected_id.0.to_vec());

        // Re-encode using Rust's to_cbor_without_sig
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
        if rust_bytes == go_bytes {
            println!("  PASS: without_sig");
            passed += 1;
        } else {
            println!("  FAIL: without_sig (byte mismatch)");
            println!(
                "    Go:   {} ({} bytes)",
                hex::encode(&go_bytes[..32.min(go_bytes.len())]),
                go_bytes.len()
            );
            println!(
                "    Rust: {} ({} bytes)",
                hex::encode(&rust_bytes[..32.min(rust_bytes.len())]),
                rust_bytes.len()
            );
            failed += 1;
        }
    }

    // empty_capabilities
    {
        let go_bytes = read_fixture(&ar_dir, "empty_capabilities.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());

        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(&val, k) };
        let caps_arr = match get(4) {
            Some(Value::Array(a)) => a.clone(),
            _ => panic!("capabilities"),
        };
        let endpoints_arr = match get(5) {
            Some(Value::Array(a)) => a.clone(),
            _ => panic!("endpoints"),
        };
        assert_eq!(caps_arr.len(), 0);
        assert_eq!(endpoints_arr.len(), 0);

        // Re-encode using Rust's to_cbor_without_sig with empty record
        let record = AgentRecord {
            record_type: match get(1) {
                Some(Value::TextString(s)) => s.clone(),
                _ => panic!("record_type"),
            },
            agent_id: AgentId::from_bytes(&match get(2) {
                Some(Value::ByteString(b)) => b.clone(),
                _ => panic!("agent_id"),
            })
            .unwrap(),
            public_key: match get(3) {
                Some(Value::ByteString(b)) => b.clone(),
                _ => panic!("public_key"),
            },
            capabilities: vec![],
            endpoints: vec![],
            created_at: match get(6) {
                Some(Value::Unsigned(n)) => *n,
                _ => panic!("created_at"),
            },
            expires_at: match get(7) {
                Some(Value::Unsigned(n)) => *n,
                _ => panic!("expires_at"),
            },
            signature: vec![],
            key_algorithm: match get(9) {
                Some(Value::Unsigned(n)) => *n,
                _ => panic!("key_algorithm"),
            },
            record_version: match get(10) {
                Some(Value::Unsigned(n)) => *n,
                _ => 0,
            },
        };
        let rust_bytes = encode(&record.to_cbor_without_sig()).unwrap();
        if rust_bytes == go_bytes {
            println!("  PASS: empty_capabilities");
            passed += 1;
        } else {
            println!("  FAIL: empty_capabilities (byte mismatch)");
            failed += 1;
        }
    }

    // with_sig — key 8 present
    {
        let go_bytes = read_fixture(&ar_dir, "with_sig.bin");
        let (val, consumed) = decode(&go_bytes).expect("decode");
        assert_eq!(consumed, go_bytes.len());
        let record = AgentRecord::from_cbor(&val).expect("AgentRecord::from_cbor");
        assert_eq!(record.signature.len(), 3309);
        let rust_bytes = encode(&record.to_cbor()).unwrap();
        if rust_bytes == go_bytes {
            println!("  PASS: with_sig");
            passed += 1;
        } else {
            println!("  FAIL: with_sig (byte mismatch)");
            failed += 1;
        }
    }

    // === RPC round-trip ===
    println!("\n=== RPC round-trip ===");
    let rpc_dir = fixtures_dir.join("rpc");
    let rpc_fixtures = [
        "request_basic",
        "request_with_params",
        "response_success",
        "response_error",
        "close_message",
        "error_message_fatal",
    ];
    for name in &rpc_fixtures {
        match check_roundtrip_cbor(&rpc_dir, &format!("{}.bin", name)) {
            Ok(()) => {
                println!("  PASS: {}", name);
                passed += 1;
            }
            Err(e) => {
                println!("  FAIL: {}: {}", name, e);
                failed += 1;
            }
        }
    }

    // === Transcript hash verification ===
    println!("\n=== Transcript hash verification ===");

    // Read the Go-produced CBOR for each handshake message
    let ch_bytes = read_fixture(&hs_dir, "client_hello_without_sig.bin");
    let sh_bytes = read_fixture(&hs_dir, "server_hello_without_sig.bin");
    let cf_bytes = read_fixture(&hs_dir, "client_finished_without_sig.bin");

    // hash_init: SHA-256(tls_binding)
    {
        let expected = read_fixture(&fixtures_dir.join("transcript"), "hash_init.bin");
        let tls_binding = [0x05u8; 32];
        let th = TranscriptHash::from_tls_binding(&tls_binding);
        if th.current() == expected.as_slice() {
            println!("  PASS: hash_init");
            passed += 1;
        } else {
            println!("  FAIL: hash_init");
            println!("    Go:   {}", hex::encode(&expected));
            println!("    Rust: {}", hex::encode(th.current()));
            failed += 1;
        }
    }

    // hash_after_clienthello
    match check_transcript_hash(
        &fixtures_dir,
        "after_clienthello",
        "hash_after_clienthello.bin",
        &[&ch_bytes],
    ) {
        Ok(()) => {
            println!("  PASS: hash_after_clienthello");
            passed += 1;
        }
        Err(e) => {
            println!("  FAIL: hash_after_clienthello: {}", e);
            failed += 1;
        }
    }

    // hash_after_serverhello
    match check_transcript_hash(
        &fixtures_dir,
        "after_serverhello",
        "hash_after_serverhello.bin",
        &[&ch_bytes, &sh_bytes],
    ) {
        Ok(()) => {
            println!("  PASS: hash_after_serverhello");
            passed += 1;
        }
        Err(e) => {
            println!("  FAIL: hash_after_serverhello: {}", e);
            failed += 1;
        }
    }

    // hash_after_clientfinished
    match check_transcript_hash(
        &fixtures_dir,
        "after_clientfinished",
        "hash_after_clientfinished.bin",
        &[&ch_bytes, &sh_bytes, &cf_bytes],
    ) {
        Ok(()) => {
            println!("  PASS: hash_after_clientfinished");
            passed += 1;
        }
        Err(e) => {
            println!("  FAIL: hash_after_clientfinished: {}", e);
            failed += 1;
        }
    }

    // === Session ID verification ===
    println!("\n=== Session ID verification ===");
    {
        let go_session_id = read_fixture(&fixtures_dir.join("transcript"), "session_id.bin");
        let go_hash_after_ch = read_fixture(
            &fixtures_dir.join("transcript"),
            "hash_after_clienthello.bin",
        );

        // Rust derives session ID from the Go-produced transcript hash
        // A-4: session ID is bound to server_agent_id = SHA-256(publicKeyB)
        // where publicKeyB = [0x43; 1952] (matching Go's generate_interop_fixtures)
        let mut h_arr = [0u8; 32];
        h_arr.copy_from_slice(&go_hash_after_ch);
        let server_agent_id = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(&[0x43u8; 1952]);
            hasher.finalize().to_vec()
        };
        let rust_session_id = derive_session_id(&h_arr, &[0x03; 32], &[0x04; 32], &server_agent_id);

        if rust_session_id == go_session_id.as_slice() {
            println!("  PASS: session_id");
            passed += 1;
        } else {
            println!("  FAIL: session_id");
            println!("    Go:   {}", hex::encode(&go_session_id));
            println!("    Rust: {}", hex::encode(rust_session_id));
            failed += 1;
        }
    }

    // === Summary ===
    println!("\n=== Summary ===");
    println!("  Passed: {}", passed);
    println!("  Failed: {}", failed);
    if failed > 0 {
        std::process::exit(1);
    } else {
        println!(
            "\n  All Go-generated fixtures verified by Rust. Bidirectional interop confirmed."
        );
    }
}
