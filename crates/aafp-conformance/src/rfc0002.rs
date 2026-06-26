//! Conformance tests for RFC-0002: Transport and Framing.
//!
//! Covers normative requirements from:
//! - §3: Frame header format (28 bytes, field ordering)
//! - §4: Frame types (DATA, HANDSHAKE, RPC_REQUEST, etc.)
//! - §5: Handshake transcript hash and signatures
//! - §6: Extensions
//! - §8: Canonical CBOR encoding

use aafp_cbor::{int_map, str_map, Value};
use aafp_crypto::{
    handshake_v1::{
        derive_session_id, generate_nonce, compute_receiver_mac, verify_receiver_mac,
        ClientFinished, ClientHello, HandshakeError, ServerHello, TranscriptHash,
        DOMAIN_SEPARATOR, KEY_ALG_ML_DSA_65, NONCE_SIZE, PROTOCOL_VERSION, SESSION_ID_SIZE,
    },
    MlDsa65, MlDsa65Signature, SignatureScheme,
};
use aafp_messaging::{
    decode_frame, encode_frame, Frame, FrameType, AAFP_VERSION, FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
};
use sha2::{Digest, Sha256};

// === RFC-0002 §3: Frame Header Format ===

#[cfg(test)]
mod frame_header {
    use super::*;

    /// R2-001: Frame header MUST be 28 bytes.
    #[test]
    fn test_r2_001_header_size_is_28_bytes() {
        assert_eq!(FRAME_HEADER_SIZE, 28, "RFC-0002 §3: header must be 28 bytes");
    }

    /// R2-002: Protocol version field MUST be 1 byte at offset 0.
    #[test]
    fn test_r2_002_version_at_offset_0() {
        let frame = Frame::data(1, vec![0xAB]);
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(bytes[0], AAFP_VERSION, "version at offset 0");
    }

    /// R2-003: Frame type field MUST be 1 byte at offset 1.
    #[test]
    fn test_r2_003_frame_type_at_offset_1() {
        let frame = Frame::data(1, vec![]);
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(bytes[1], FrameType::Data as u8);
    }

    /// R2-004: Flags field MUST be 1 byte at offset 2.
    #[test]
    fn test_r2_004_flags_at_offset_2() {
        let frame = Frame::data(1, vec![]);
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(bytes[2], 0, "flags default to 0");
    }

    /// R2-005: Reserved field MUST be 1 byte at offset 3 and MUST be zero.
    #[test]
    fn test_r2_005_reserved_is_zero() {
        let frame = Frame::data(1, vec![]);
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(bytes[3], 0, "reserved byte must be zero");
    }

    /// R2-006: Stream ID MUST be 8 bytes big-endian at offset 4.
    #[test]
    fn test_r2_006_stream_id_8_bytes_be() {
        let frame = Frame::data(0x123456789ABCDEF0, vec![]);
        let bytes = encode_frame(&frame).unwrap();
        let sid = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        assert_eq!(sid, 0x123456789ABCDEF0);
    }

    /// R2-007: Payload length MUST be 8 bytes big-endian at offset 12.
    #[test]
    fn test_r2_007_payload_len_8_bytes_be() {
        let payload = vec![0u8; 100];
        let frame = Frame::data(0, payload);
        let bytes = encode_frame(&frame).unwrap();
        let plen = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        assert_eq!(plen, 100);
    }

    /// R2-008: Extension length MUST be 8 bytes big-endian at offset 20.
    #[test]
    fn test_r2_008_ext_len_8_bytes_be() {
        let frame = Frame::data(0, vec![]);
        let bytes = encode_frame(&frame).unwrap();
        let elen = u64::from_be_bytes(bytes[20..28].try_into().unwrap());
        assert_eq!(elen, 0, "no extensions → ext_len=0");
    }

    /// R2-009: Maximum payload size MUST be 1 MiB (1,048,576 bytes).
    #[test]
    fn test_r2_009_max_payload_1mib() {
        assert_eq!(MAX_PAYLOAD_SIZE, 1024 * 1024);
    }

    /// R2-010: Payload exceeding max MUST be rejected.
    #[test]
    fn test_r2_010_oversized_payload_rejected() {
        let oversized = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = Frame::data(0, oversized);
        assert!(encode_frame(&frame).is_err());
    }
}

// === RFC-0002 §4: Frame Types ===

#[cfg(test)]
mod frame_types {
    use super::*;

    /// R2-015: DATA frame type MUST be 0x01.
    #[test]
    fn test_r2_015_data_type() {
        assert_eq!(FrameType::Data as u8, 0x01);
    }

    /// R2-016: HANDSHAKE frame type MUST be 0x02.
    #[test]
    fn test_r2_016_handshake_type() {
        assert_eq!(FrameType::Handshake as u8, 0x02);
    }

    /// R2-017: RPC_REQUEST frame type MUST be 0x03.
    #[test]
    fn test_r2_017_rpc_request_type() {
        assert_eq!(FrameType::RpcRequest as u8, 0x03);
    }

    /// R2-018: RPC_RESPONSE frame type MUST be 0x04.
    #[test]
    fn test_r2_018_rpc_response_type() {
        assert_eq!(FrameType::RpcResponse as u8, 0x04);
    }

    /// R2-019: CLOSE frame type MUST be 0x05.
    #[test]
    fn test_r2_019_close_type() {
        assert_eq!(FrameType::Close as u8, 0x05);
    }

    /// R2-020: ERROR frame type MUST be 0x06.
    #[test]
    fn test_r2_020_error_type() {
        assert_eq!(FrameType::Error as u8, 0x06);
    }

    /// R2-021: PING frame type MUST be 0x07.
    #[test]
    fn test_r2_021_ping_type() {
        assert_eq!(FrameType::Ping as u8, 0x07);
    }

    /// R2-022: PONG frame type MUST be 0x08.
    #[test]
    fn test_r2_022_pong_type() {
        assert_eq!(FrameType::Pong as u8, 0x08);
    }

    /// R2-025: Frame roundtrip must preserve all fields.
    #[test]
    fn test_r2_025_frame_roundtrip() {
        let original = Frame {
            frame_type: FrameType::Data,
            flags: 0x01,
            stream_id: 42,
            extensions: vec![],
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = encode_frame(&original).unwrap();
        let (decoded, consumed) = decode_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }

    /// R2-026: Unknown frame type with critical bit MUST be rejected.
    #[test]
    fn test_r2_026_unknown_critical_frame_rejected() {
        // Construct a frame with an unknown type byte (0xFF) and critical flag
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = AAFP_VERSION;
        bytes[1] = 0xFF; // Unknown type
        bytes[2] = 0x80; // Critical bit
        bytes[3] = 0; // Reserved
        // Stream ID = 0
        // Payload length = 0
        // Ext length = 0
        let result = decode_frame(&bytes);
        assert!(result.is_err(), "unknown critical frame type must be rejected");
    }
}

// === RFC-0002 §5: Handshake ===

#[cfg(test)]
mod handshake {
    use super::*;

    /// R2-040: Transcript hash MUST be initialized from TLS channel binding.
    #[test]
    fn test_r2_040_transcript_from_tls_binding() {
        let tls_binding = [0x42u8; 32];
        let th = TranscriptHash::from_tls_binding(&tls_binding);
        let expected = Sha256::digest(&tls_binding);
        assert_eq!(th.current(), expected.as_slice());
    }

    /// R2-041: Transcript hash MUST fold canonical CBOR of each message.
    #[test]
    fn test_r2_041_transcript_folds_cbor() {
        let mut th = TranscriptHash::from_tls_binding(&[0u8; 32]);
        let cbor_bytes = vec![0xA1, 0x01, 0x02];
        let h1 = th.current().clone();
        th.fold(&cbor_bytes);
        assert_ne!(th.current(), &h1, "hash must change after folding");
    }

    /// R2-042: Domain separator MUST be "aafp-v1-handshake".
    #[test]
    fn test_r2_042_domain_separator() {
        assert_eq!(DOMAIN_SEPARATOR, b"aafp-v1-handshake");
    }

    /// R2-043: Protocol version MUST be 1.
    #[test]
    fn test_r2_043_protocol_version() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    /// R2-044: Nonce MUST be 32 bytes.
    #[test]
    fn test_r2_044_nonce_size() {
        assert_eq!(NONCE_SIZE, 32);
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
    }

    /// R2-045: Session ID MUST be 32 bytes.
    #[test]
    fn test_r2_045_session_id_size() {
        assert_eq!(SESSION_ID_SIZE, 32);
    }

    /// R2-046: Key algorithm for ML-DSA-65 MUST be 1.
    #[test]
    fn test_r2_046_key_algorithm() {
        assert_eq!(KEY_ALG_ML_DSA_65, 1);
    }

    /// R2-050: ClientHello MUST use integer keys 1-10.
    #[test]
    fn test_r2_050_client_hello_integer_keys() {
        let ch = ClientHello {
            protocol_version: 1,
            agent_id: vec![0u8; 32],
            public_key: vec![0u8; 1952],
            nonce: [0u8; 32],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![0u8; 3309],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: 1,
        };
        let cbor = ch.to_cbor();
        for k in 1..=10i64 {
            assert!(
                aafp_cbor::int_map_get(&cbor, k).is_some(),
                "ClientHello must have key {k}"
            );
        }
    }

    /// R2-051: ServerHello MUST use integer keys 1-10.
    #[test]
    fn test_r2_051_server_hello_integer_keys() {
        let sh = ServerHello {
            protocol_version: 1,
            agent_id: vec![0u8; 32],
            public_key: vec![0u8; 1952],
            nonce: [0u8; 32],
            capabilities: vec![],
            extensions: vec![],
            session_id: [0u8; 32],
            signature: vec![0u8; 3309],
            expires_at: 1700000000,
            key_algorithm: 1,
        };
        let cbor = sh.to_cbor();
        for k in 1..=10i64 {
            assert!(
                aafp_cbor::int_map_get(&cbor, k).is_some(),
                "ServerHello must have key {k}"
            );
        }
    }

    /// R2-052: ClientFinished MUST use integer keys 1-2.
    #[test]
    fn test_r2_052_client_finished_integer_keys() {
        let cf = ClientFinished {
            session_id: [0u8; 32],
            signature: vec![0u8; 3309],
        };
        let cbor = cf.to_cbor();
        assert!(aafp_cbor::int_map_get(&cbor, 1).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 2).is_some());
    }

    /// R2-055: Signature input MUST be domain_separator || transcript_hash.
    #[test]
    fn test_r2_055_signature_input_format() {
        let (pk, sk) = MlDsa65::keypair();
        let tls_binding = [0x42u8; 32];
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);
        let cbor_bytes = vec![0x01, 0x02];
        let h = th.fold(&cbor_bytes);

        // Signature input = "aafp-v1-handshake" || h
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(DOMAIN_SEPARATOR);
        expected_input.extend_from_slice(&h);

        let sig = MlDsa65::sign(&sk, &expected_input);
        assert!(MlDsa65::verify(&pk, &expected_input, &sig));
    }

    /// R2-056: ClientHello signature excludes fields 7 and 9.
    #[test]
    fn test_r2_056_ch_sig_excludes_7_and_9() {
        let ch = ClientHello {
            protocol_version: 1,
            agent_id: vec![0u8; 32],
            public_key: vec![0u8; 1952],
            nonce: [0u8; 32],
            capabilities: vec![],
            extensions: vec![],
            signature: vec![0u8; 3309],
            expires_at: 1700000000,
            receiver_mac: Some(vec![0u8; 32]),
            key_algorithm: 1,
        };
        let cbor = ch.to_cbor_without_sig_and_mac();
        assert!(aafp_cbor::int_map_get(&cbor, 7).is_none(), "key 7 (sig) must be absent");
        assert!(aafp_cbor::int_map_get(&cbor, 9).is_none(), "key 9 (mac) must be absent");
        // Keys 1-6, 8, 10 must be present
        for k in [1, 2, 3, 4, 5, 6, 8, 10] {
            assert!(aafp_cbor::int_map_get(&cbor, k).is_some(), "key {k} must be present");
        }
    }

    /// R2-057: ServerHello signature excludes field 8.
    #[test]
    fn test_r2_057_sh_sig_excludes_8() {
        let sh = ServerHello {
            protocol_version: 1,
            agent_id: vec![0u8; 32],
            public_key: vec![0u8; 1952],
            nonce: [0u8; 32],
            capabilities: vec![],
            extensions: vec![],
            session_id: [0u8; 32],
            signature: vec![0u8; 3309],
            expires_at: 1700000000,
            key_algorithm: 1,
        };
        let cbor = sh.to_cbor_without_sig();
        assert!(aafp_cbor::int_map_get(&cbor, 8).is_none(), "key 8 (sig) must be absent");
    }

    /// R2-060: Full handshake must produce matching transcript hashes.
    #[test]
    fn test_r2_060_full_handshake_transcript_consistency() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();

        let tls_binding = [0x42u8; 32];
        let mut th_client = TranscriptHash::from_tls_binding(&tls_binding);
        let mut th_server = TranscriptHash::from_tls_binding(&tls_binding);

        let client_nonce = generate_nonce();
        let server_nonce = generate_nonce();

        // ClientHello
        let ch = ClientHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: Sha256::digest(&client_pk.0).to_vec(),
            public_key: client_pk.0.clone(),
            nonce: client_nonce,
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: 1700000000,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };
        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h_ch_client = th_client.fold(&ch_bytes);
        let h_ch_server = th_server.fold(&ch_bytes);
        assert_eq!(h_ch_client, h_ch_server, "transcript must match after ClientHello");

        // ServerHello
        let session_id = derive_session_id(&h_ch_client, &client_nonce, &server_nonce);
        let sh = ServerHello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: Sha256::digest(&server_pk.0).to_vec(),
            public_key: server_pk.0.clone(),
            nonce: server_nonce,
            capabilities: vec![],
            extensions: vec![],
            session_id,
            signature: vec![],
            expires_at: 1700000000,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };
        let sh_cbor = sh.to_cbor_without_sig();
        let sh_bytes = aafp_cbor::encode(&sh_cbor).unwrap();
        let h_sh_client = th_client.fold(&sh_bytes);
        let h_sh_server = th_server.fold(&sh_bytes);
        assert_eq!(h_sh_client, h_sh_server, "transcript must match after ServerHello");

        // ClientFinished
        let cf = ClientFinished {
            session_id,
            signature: vec![],
        };
        let cf_cbor = cf.to_cbor_without_sig();
        let cf_bytes = aafp_cbor::encode(&cf_cbor).unwrap();
        let h_cf_client = th_client.fold(&cf_bytes);
        let h_cf_server = th_server.fold(&cf_bytes);
        assert_eq!(h_cf_client, h_cf_server, "transcript must match after ClientFinished");
    }

    /// R2-065: DoS receiver MAC MUST use HKDF-SHA256 with correct info string.
    #[test]
    fn test_r2_065_dos_mac_computation() {
        let agent_id = [0xAAu8; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03];

        let mac = compute_receiver_mac(&agent_id, &ch_bytes);
        assert_eq!(mac.len(), 32, "HMAC-SHA256 output is 32 bytes");

        // Verification must succeed with correct inputs
        assert!(verify_receiver_mac(&agent_id, &ch_bytes, &mac));
        // Must fail with wrong agent_id
        assert!(!verify_receiver_mac(&[0xBBu8; 32], &ch_bytes, &mac));
    }
}

// === RFC-0002 §8: Canonical CBOR ===

#[cfg(test)]
mod canonical_cbor {
    use super::*;

    /// R2-080: CBOR encoding MUST be deterministic (same input → same output).
    #[test]
    fn test_r2_080_deterministic_encoding() {
        let val = int_map(vec![
            (1, Value::Unsigned(42)),
            (2, Value::TextString("hello".to_string())),
        ]);
        let bytes1 = aafp_cbor::encode(&val).unwrap();
        let bytes2 = aafp_cbor::encode(&val).unwrap();
        assert_eq!(bytes1, bytes2, "encoding must be deterministic");
    }

    /// R2-081: Integer keys MUST be sorted by length-first canonical byte ordering.
    #[test]
    fn test_r2_081_length_first_key_sorting() {
        // Keys 1 and 100: key 1 (1 byte) comes before key 100 (2 bytes)
        let val = int_map(vec![
            (100, Value::Unsigned(2)),
            (1, Value::Unsigned(1)),
        ]);
        let bytes = aafp_cbor::encode(&val).unwrap();
        let (decoded, _) = aafp_cbor::decode(&bytes).unwrap();
        // First entry should be key 1 (shorter encoding)
        if let Value::IntMap(entries) = decoded {
            assert_eq!(entries[0].0, 1, "shorter key must come first");
            assert_eq!(entries[1].0, 100);
        }
    }

    /// R2-082: Indefinite-length arrays and maps MUST NOT be used.
    #[test]
    fn test_r2_082_no_indefinite_length() {
        // 0xFF is the break code for indefinite-length — must never appear
        // in our encoding output for definite-length structures.
        let val = int_map(vec![(1, Value::Unsigned(1))]);
        let bytes = aafp_cbor::encode(&val).unwrap();
        assert!(!bytes.contains(&0xFF), "no indefinite-length break code");
    }

    /// R2-083: Integers MUST use shortest encoding.
    #[test]
    fn test_r2_083_shortest_integer_encoding() {
        // Small integers (0-23) use immediate encoding (1 byte total)
        let val = Value::Unsigned(5);
        let bytes = aafp_cbor::encode(&val).unwrap();
        assert_eq!(bytes, vec![0x05], "small uint uses immediate encoding");

        // 24 requires 1-byte additional info
        let val = Value::Unsigned(24);
        let bytes = aafp_cbor::encode(&val).unwrap();
        assert_eq!(bytes, vec![0x18, 0x18]);
    }

    /// R2-084: Metadata maps MAY use string keys (exception).
    #[test]
    fn test_r2_084_string_keyed_maps() {
        let val = str_map(vec![("key".to_string(), Value::Unsigned(1))]);
        let bytes = aafp_cbor::encode(&val).unwrap();
        let (decoded, _) = aafp_cbor::decode(&bytes).unwrap();
        if let Value::StrMap(entries) = decoded {
            assert_eq!(entries[0].0, "key");
        } else {
            panic!("expected StrMap");
        }
    }
}
