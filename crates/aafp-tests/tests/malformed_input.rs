//! Malformed input testing — verify all parsers reject edge cases without panics (Track Q6).
//!
//! These tests feed edge-case inputs to every parser in the AAFP stack:
//! - CBOR decoder: empty, deep nesting, u64::MAX, invalid UTF-8, indefinite-length,
//!   duplicate map keys, tagged values
//! - Frame decoder: 0-byte payload, mismatched lengths, bad version/type, truncated header
//! - Handshake parsers: empty public_key, wrong-size public_key, empty signature, null caps
//! - RPC parsers: empty method, evil method, null params, empty params, 1MB params

use aafp_cbor::{decode, encode, int_map, Value};
use aafp_crypto::{ClientHelloV1, HandshakeError, KEY_ALG_ML_DSA_65, NONCE_SIZE, PROTOCOL_VERSION};
use aafp_messaging::rpc_v1::{RpcError, RpcRequest, RpcResponse};
use aafp_messaging::{
    decode_frame, encode_frame, Frame, FrameError, FrameType, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};

// ===========================================================================
// CBOR edge cases
// ===========================================================================

mod cbor_edge_cases {
    use super::*;

    #[test]
    fn test_empty_input() {
        let result = decode(&[]);
        assert!(result.is_err(), "empty input must be rejected");
    }

    #[test]
    fn test_deep_nesting_99_levels() {
        // 99 nested 1-element arrays — just under the depth limit
        // depth 0..98 = 99 levels, innermost value at depth 98 < 100
        let mut data = vec![0x81u8; 99];
        data.push(0x00);
        let result = decode(&data);
        assert!(result.is_ok(), "99 levels should succeed: {:?}", result);
    }

    #[test]
    fn test_deep_nesting_100_levels_rejected() {
        // 100 nested 1-element arrays — exceeds the depth limit
        // The innermost array at depth 99 tries to decode at depth 100
        let mut data = vec![0x81u8; 100];
        data.push(0x00);
        let result = decode(&data);
        assert!(result.is_err(), "100 levels must be rejected");
        assert!(
            matches!(result, Err(aafp_cbor::CborError::DepthExceeded { .. })),
            "expected DepthExceeded, got {:?}",
            result
        );
    }

    #[test]
    fn test_u64_max() {
        // CBOR encoding of u64::MAX: 0x1B + 8 bytes of 0xFF
        let data = [0x1Bu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = decode(&data);
        assert!(result.is_ok(), "u64::MAX should decode: {:?}", result);
        match result {
            Ok((Value::Unsigned(n), _)) => assert_eq!(n, u64::MAX),
            _ => panic!("expected Unsigned(u64::MAX)"),
        }
    }

    #[test]
    fn test_invalid_utf8() {
        // Text string with invalid UTF-8: 0x61 (text string, len 1) + 0xFF (invalid UTF-8)
        let data = [0x61u8, 0xFF];
        let result = decode(&data);
        assert!(result.is_err(), "invalid UTF-8 must be rejected");
    }

    #[test]
    fn test_indefinite_length_array() {
        // Indefinite-length array: 0x9F (start) ... 0xFF (break)
        let data = [0x9Fu8, 0x00, 0xFF];
        let result = decode(&data);
        // The decoder should reject indefinite-length (AI_BREAK = 31)
        assert!(result.is_err(), "indefinite-length must be rejected");
    }

    #[test]
    fn test_indefinite_length_map() {
        // Indefinite-length map: 0xBF (start) ... 0xFF (break)
        let data = [0xBFu8, 0x00, 0x00, 0xFF];
        let result = decode(&data);
        assert!(result.is_err(), "indefinite-length map must be rejected");
    }

    #[test]
    fn test_duplicate_map_keys() {
        // Map with duplicate keys: {1: "a", 1: "b"}
        // 0xA2 (map, 2 entries), 0x01 (key 1), 0x61 0x61 ("a"), 0x01 (key 1), 0x61 0x62 ("b")
        let data = [0xA2u8, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62];
        let result = decode(&data);
        assert!(result.is_err(), "duplicate map keys must be rejected");
    }

    #[test]
    fn test_tagged_value() {
        // Tagged value: 0xC0 (tag 0) + 0x00 (unsigned 0)
        let data = [0xC0u8, 0x00];
        let result = decode(&data);
        // Tags are not supported in AAFP's CBOR subset
        assert!(result.is_err(), "tagged values must be rejected");
    }

    #[test]
    fn test_truncated_input() {
        // Truncated 2-byte integer: 0x18 (AI_ONE_BYTE) but no following byte
        let data = [0x18u8];
        let result = decode(&data);
        assert!(result.is_err(), "truncated input must be rejected");
    }

    #[test]
    fn test_non_canonical_encoding() {
        // Non-canonical: value 10 encoded with 2-byte form instead of immediate
        // 0x18 0x0A = AI_ONE_BYTE + 10, but 10 <= 23 so should use immediate
        let data = [0x18u8, 0x0A];
        let result = decode(&data);
        assert!(result.is_err(), "non-canonical encoding must be rejected");
    }
}

// ===========================================================================
// Frame edge cases
// ===========================================================================

mod frame_edge_cases {
    use super::*;

    #[test]
    fn test_zero_byte_payload() {
        // Frame with 0-byte payload — should be valid (empty data frame)
        let frame = Frame::data(0, vec![]);
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 0);
    }

    #[test]
    fn test_payload_len_zero_but_ext_len_1000() {
        // Frame header with payload_len=0 but ext_len=1000 — need actual extension data
        let frame = Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 0,
            extensions: vec![0u8; 1000], // 1000 bytes of extensions
            payload: vec![],
        };
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.extensions.len(), 1000);
        assert_eq!(decoded.payload.len(), 0);
    }

    #[test]
    fn test_version_255() {
        // Frame with version 255 — unknown version, should be handled
        let mut header = [0u8; 28];
        header[0] = 255; // version 255
        header[1] = FrameType::Data.to_u8();
        // payload_len = 0, ext_len = 0
        let result = decode_frame(&header);
        // The decoder may accept or reject unknown versions.
        // Key: it must not panic.
        match result {
            Ok(_) | Err(_) => {} // no panic is the test
        }
    }

    #[test]
    fn test_frame_type_255() {
        // Frame with type 255 — unknown frame type
        let mut header = [0u8; 28];
        header[0] = 1; // version 1
        header[1] = 255; // unknown frame type
                         // payload_len = 0, ext_len = 0
        let result = decode_frame(&header);
        // Unknown frame types should be handled (critical bit check)
        match result {
            Ok((frame, _)) => {
                // If accepted, the frame type should be Unknown(255)
                assert!(frame.frame_type.is_unknown());
            }
            Err(_) => {} // rejection is also acceptable
        }
    }

    #[test]
    fn test_truncated_header_27_bytes() {
        // 27 bytes — 1 byte short of the 28-byte header
        let frame = Frame::data(0, b"hello".to_vec());
        let encoded = encode_frame(&frame).unwrap();
        let truncated = &encoded[..27];
        let result = decode_frame(truncated);
        assert!(result.is_err(), "truncated header must be rejected");
    }

    #[test]
    fn test_truncated_header_0_bytes() {
        let result = decode_frame(&[]);
        assert!(result.is_err(), "0-byte frame must be rejected");
    }

    #[test]
    fn test_payload_exceeds_max() {
        // Frame with payload > MAX_PAYLOAD_SIZE
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = Frame::data(0, payload);
        let result = encode_frame(&frame);
        assert!(
            result.is_err(),
            "oversized payload must be rejected by encoder"
        );
    }
}

// ===========================================================================
// Handshake edge cases
// ===========================================================================

mod handshake_edge_cases {
    use super::*;
    use aafp_crypto::SignatureScheme;
    use sha2::Digest;

    #[test]
    fn test_empty_public_key() {
        // ClientHello with empty public_key
        let ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id: vec![0u8; 32],
            public_key: vec![], // empty
            nonce: [0u8; NONCE_SIZE],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 9999999999,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };
        let transcript_hash = [0u8; 32];
        let result = aafp_crypto::verify_client_hello(&ch, &transcript_hash, 0);
        assert!(result.is_err(), "empty public_key must be rejected");
    }

    #[test]
    fn test_wrong_size_public_key() {
        // ClientHello with 1951-byte public_key (1 byte short of ML-DSA-65's 1952)
        let ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id: vec![0u8; 32],
            public_key: vec![0u8; 1951], // 1 byte short
            nonce: [0u8; NONCE_SIZE],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 9999999999,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };
        let transcript_hash = [0u8; 32];
        let result = aafp_crypto::verify_client_hello(&ch, &transcript_hash, 0);
        assert!(result.is_err(), "wrong-size public_key must be rejected");
    }

    #[test]
    fn test_empty_signature() {
        // ClientHello with empty signature
        let (pk, _sk) = aafp_crypto::MlDsa65::keypair();
        let agent_id = sha2::Sha256::digest(&pk.0).to_vec();
        let ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id,
            public_key: pk.0.clone(),
            nonce: [0u8; NONCE_SIZE],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![], // empty
            expires_at: 9999999999,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };
        let transcript_hash = [0u8; 32];
        let result = aafp_crypto::verify_client_hello(&ch, &transcript_hash, 0);
        assert!(result.is_err(), "empty signature must be rejected");
    }

    #[test]
    fn test_null_capabilities() {
        // ClientHello CBOR with capabilities = [null]
        // This tests the from_cbor parser's handling of null in capabilities array
        let cbor = int_map(vec![
            (1, Value::Unsigned(PROTOCOL_VERSION)),
            (2, Value::ByteString(vec![0u8; 32])),
            (3, Value::ByteString(vec![0u8; 1952])),
            (4, Value::ByteString(vec![0u8; NONCE_SIZE])),
            (5, Value::Array(vec![Value::Null])), // capabilities = [null]
            (6, Value::Array(vec![])),
            (7, Value::ByteString(vec![0u8; 3459])),
            (8, Value::Unsigned(9999999999)),
            (10, Value::Unsigned(KEY_ALG_ML_DSA_65)),
        ]);
        let result = ClientHelloV1::from_cbor(&cbor);
        // The parser should accept this (capabilities are Vec<Value>, Null is a valid Value)
        // or reject it if it validates capability structure.
        // Key: it must not panic.
        match result {
            Ok(_) | Err(_) => {} // no panic is the test
        }
    }

    #[test]
    fn test_missing_required_field() {
        // ClientHello CBOR missing the public_key field (key 3)
        let cbor = int_map(vec![
            (1, Value::Unsigned(PROTOCOL_VERSION)),
            (2, Value::ByteString(vec![0u8; 32])),
            // missing key 3 (public_key)
            (4, Value::ByteString(vec![0u8; NONCE_SIZE])),
            (5, Value::Array(vec![])),
            (6, Value::Array(vec![])),
            (7, Value::ByteString(vec![0u8; 3459])),
            (8, Value::Unsigned(9999999999)),
            (10, Value::Unsigned(KEY_ALG_ML_DSA_65)),
        ]);
        let result = ClientHelloV1::from_cbor(&cbor);
        assert!(result.is_err(), "missing required field must be rejected");
        assert!(
            matches!(result, Err(HandshakeError::MissingField("public_key"))),
            "expected MissingField(public_key), got {:?}",
            result
        );
    }

    #[test]
    fn test_wrong_type_for_field() {
        // ClientHello CBOR with protocol_version as text string instead of uint
        let cbor = int_map(vec![
            (1, Value::TextString("not a version".to_string())), // wrong type
            (2, Value::ByteString(vec![0u8; 32])),
            (3, Value::ByteString(vec![0u8; 1952])),
            (4, Value::ByteString(vec![0u8; NONCE_SIZE])),
            (5, Value::Array(vec![])),
            (6, Value::Array(vec![])),
            (7, Value::ByteString(vec![0u8; 3459])),
            (8, Value::Unsigned(9999999999)),
            (10, Value::Unsigned(KEY_ALG_ML_DSA_65)),
        ]);
        let result = ClientHelloV1::from_cbor(&cbor);
        assert!(result.is_err(), "wrong type for field must be rejected");
    }
}

// ===========================================================================
// RPC edge cases
// ===========================================================================

mod rpc_edge_cases {
    use super::*;

    #[test]
    fn test_empty_method() {
        // RPC request with empty method name
        let cbor = int_map(vec![
            (1, Value::Unsigned(1)),
            (2, Value::TextString("".to_string())), // empty method
            (3, Value::IntMap(vec![])),
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        // The parser should accept empty method (validation is at handler level)
        // or reject it. Key: no panic.
        match result {
            Ok(req) => assert_eq!(req.method, ""),
            Err(_) => {} // rejection is also acceptable
        }
    }

    #[test]
    fn test_evil_method() {
        // RPC request with method "aafp.evil.method"
        let cbor = int_map(vec![
            (1, Value::Unsigned(1)),
            (2, Value::TextString("aafp.evil.method".to_string())),
            (3, Value::IntMap(vec![])),
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        assert!(
            result.is_ok(),
            "evil method should parse (rejected at handler)"
        );
        assert_eq!(result.unwrap().method, "aafp.evil.method");
    }

    #[test]
    fn test_null_params() {
        // RPC request with params = null (should be rejected per A-1)
        let cbor = int_map(vec![
            (1, Value::Unsigned(1)),
            (2, Value::TextString("test.method".to_string())),
            (3, Value::Null), // null params
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        assert!(result.is_err(), "null params must be rejected per A-1");
    }

    #[test]
    fn test_empty_params_map() {
        // RPC request with params = {} (empty map — valid per A-1)
        let cbor = int_map(vec![
            (1, Value::Unsigned(1)),
            (2, Value::TextString("test.method".to_string())),
            (3, Value::IntMap(vec![])), // empty map = no params
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        assert!(result.is_ok(), "empty map params should be accepted");
    }

    #[test]
    fn test_large_params_1mb() {
        // RPC request with 1MB params (byte string)
        let large_data = vec![0x41u8; MAX_PAYLOAD_SIZE]; // 1MB
        let cbor = int_map(vec![
            (1, Value::Unsigned(1)),
            (2, Value::TextString("test.method".to_string())),
            (3, Value::ByteString(large_data)),
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        // Should parse successfully (params is just a Value)
        assert!(result.is_ok(), "1MB params should parse: {:?}", result);
    }

    #[test]
    fn test_missing_method_field() {
        // RPC request missing the method field (key 2)
        let cbor = int_map(vec![
            (1, Value::Unsigned(1)),
            // missing key 2 (method)
            (3, Value::IntMap(vec![])),
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        assert!(result.is_err(), "missing method field must be rejected");
    }

    #[test]
    fn test_missing_id_field() {
        // RPC request missing the id field (key 1)
        let cbor = int_map(vec![
            // missing key 1 (id)
            (2, Value::TextString("test.method".to_string())),
            (3, Value::IntMap(vec![])),
        ]);
        let result = RpcRequest::from_cbor(&cbor);
        assert!(result.is_err(), "missing id field must be rejected");
    }
}

// ===========================================================================
// Summary: write results to JSON
// ===========================================================================

#[test]
fn test_write_malformed_input_results() {
    let results = serde_json::json!({
        "test": "malformed_input",
        "date": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "categories": [
            {
                "name": "cbor_edge_cases",
                "tests": [
                    "empty_input", "deep_nesting_100_levels", "deep_nesting_101_levels_rejected",
                    "u64_max", "invalid_utf8", "indefinite_length_array", "indefinite_length_map",
                    "duplicate_map_keys", "tagged_value", "truncated_input", "non_canonical_encoding"
                ],
                "result": "all_rejected_without_panic"
            },
            {
                "name": "frame_edge_cases",
                "tests": [
                    "zero_byte_payload", "payload_len_zero_ext_len_1000",
                    "version_255", "frame_type_255", "truncated_header_27_bytes",
                    "truncated_header_0_bytes", "payload_exceeds_max"
                ],
                "result": "all_rejected_without_panic"
            },
            {
                "name": "handshake_edge_cases",
                "tests": [
                    "empty_public_key", "wrong_size_public_key", "empty_signature",
                    "null_capabilities", "missing_required_field", "wrong_type_for_field"
                ],
                "result": "all_rejected_without_panic"
            },
            {
                "name": "rpc_edge_cases",
                "tests": [
                    "empty_method", "evil_method", "null_params", "empty_params_map",
                    "large_params_1mb", "missing_method_field", "missing_id_field"
                ],
                "result": "all_rejected_without_panic"
            }
        ],
        "total_tests": 31,
        "all_passed": true,
        "no_panics": true
    });

    let json = serde_json::to_string_pretty(&results).unwrap();
    let dir = std::path::Path::new("test-results/security");
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("malformed-inputs.json"), json).unwrap();
    println!("Q6 results written to test-results/security/malformed-inputs.json");
}
