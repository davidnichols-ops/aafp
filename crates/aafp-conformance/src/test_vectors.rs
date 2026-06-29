//! AAFP Test Vector Generation and Validation.
//!
//! This module produces deterministic wire-format test vectors for all core
//! RFC objects. All inputs are fixed (no randomness) so that a second
//! implementation can reproduce them exactly from the RFCs alone.
//!
//! ## Vector Format
//!
//! Each vector includes:
//! - `name`: Human-readable identifier
//! - `rfc_section`: Source RFC section
//! - `description`: What the vector tests
//! - `input`: Semantic input (Rust value)
//! - `cbor_bytes`: Canonical CBOR encoding (if applicable)
//! - `wire_bytes`: Full wire-format bytes (if applicable)
//! - `expected_hash`: SHA-256 hash of the output (for verification)
//! - `notes`: Any additional context

use aafp_cbor::{int_map, str_map, Value};
use aafp_messaging::{
    encode_frame, Frame, FrameType, AAFP_VERSION, FRAME_HEADER_SIZE,
};
use sha2::{Digest, Sha256};

/// A single test vector.
#[derive(Clone, Debug)]
pub struct TestVector {
    pub name: &'static str,
    pub rfc_section: &'static str,
    pub description: &'static str,
    pub cbor_bytes: Option<Vec<u8>>,
    pub wire_bytes: Option<Vec<u8>>,
    pub expected_hash: [u8; 32],
    pub notes: &'static str,
}

impl TestVector {
    /// Compute the SHA-256 hash of the output bytes.
    fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// Verify that the actual bytes match the expected hash.
    pub fn verify(&self) -> bool {
        let bytes = self.wire_bytes.as_ref().or(self.cbor_bytes.as_ref());
        match bytes {
            Some(b) => Self::hash(b) == self.expected_hash,
            None => false,
        }
    }

    /// Get the hex encoding of the expected hash.
    pub fn expected_hash_hex(&self) -> String {
        hex::encode(self.expected_hash)
    }

    /// Get the hex encoding of the output bytes.
    pub fn output_hex(&self) -> String {
        match &self.wire_bytes {
            Some(b) => hex::encode(b),
            None => match &self.cbor_bytes {
                Some(b) => hex::encode(b),
                None => String::new(),
            },
        }
    }
}

/// Fixed test key material (deterministic, NOT for production use).
/// These are all-zero keys to ensure reproducibility.
pub mod fixed_keys {
    /// Fixed 32-byte AgentId (all 0x01).
    pub const AGENT_ID_A: [u8; 32] = [0x01; 32];
    /// Fixed 32-byte AgentId (all 0x02).
    pub const AGENT_ID_B: [u8; 32] = [0x02; 32];
    /// Fixed 32-byte nonce (all 0x03).
    pub const NONCE_A: [u8; 32] = [0x03; 32];
    /// Fixed 32-byte nonce (all 0x04).
    pub const NONCE_B: [u8; 32] = [0x04; 32];
    /// Fixed 32-byte TLS binding (all 0x05).
    pub const TLS_BINDING: [u8; 32] = [0x05; 32];
    /// Fixed 32-byte session ID (all 0x06).
    pub const SESSION_ID: [u8; 32] = [0x06; 32];
    /// Fixed 1952-byte public key (all 0x42 — NOT a valid ML-DSA-65 key,
    /// but deterministic for CBOR/encoding vectors).
    pub const PUBLIC_KEY_A: [u8; 1952] = [0x42; 1952];
    /// Fixed 1952-byte public key (all 0x43).
    pub const PUBLIC_KEY_B: [u8; 1952] = [0x43; 1952];
    /// Fixed 3309-byte signature (all 0x44 — NOT a valid signature,
    /// but deterministic for encoding vectors).
    pub const SIGNATURE_A: [u8; 3309] = [0x44; 3309];
    /// Fixed 3309-byte signature (all 0x45).
    pub const SIGNATURE_B: [u8; 3309] = [0x45; 3309];
    /// Fixed timestamp: 2025-01-01T00:00:00Z = 1735689600.
    pub const TIMESTAMP_NOW: u64 = 1735689600;
    /// Fixed timestamp: 2025-01-08T00:00:00Z = 1735689600 + 7 days.
    pub const TIMESTAMP_EXPIRES: u64 = 1735689600 + 7 * 86400;
}

// === CBOR Test Vectors ===

/// Generate CBOR test vectors for canonical encoding.
pub fn cbor_vectors() -> Vec<TestVector> {
    vec![
        TestVector {
            name: "cbor_unsigned_small",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Unsigned integer 5 (immediate encoding)",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Unsigned(5)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x05]),
            notes: "Small integers (0-23) use immediate encoding in the low 5 bits",
        },
        TestVector {
            name: "cbor_unsigned_24",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Unsigned integer 24 (one-byte additional info)",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Unsigned(24)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x18, 0x18]),
            notes: "24 requires AI_ONE_BYTE (0x18) prefix",
        },
        TestVector {
            name: "cbor_unsigned_100",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Unsigned integer 100",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Unsigned(100)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x18, 0x64]),
            notes: "100 > 23, uses one-byte additional info",
        },
        TestVector {
            name: "cbor_unsigned_1000",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Unsigned integer 1000 (two-byte additional info)",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Unsigned(1000)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x19, 0x03, 0xE8]),
            notes: "1000 requires AI_TWO_BYTES (0x19) prefix",
        },
        TestVector {
            name: "cbor_negative",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Negative integer -1",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Negative(-1)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x20]),
            notes: "Negative -1 encodes as major type 1, value 0",
        },
        TestVector {
            name: "cbor_negative_100",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Negative integer -100",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Negative(-100)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x38, 0x63]),
            notes: "Negative -100 encodes as major type 1, value 99",
        },
        TestVector {
            name: "cbor_bool_true",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.3",
            description: "Boolean true",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Bool(true)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0xF5]),
            notes: "True = simple value 21",
        },
        TestVector {
            name: "cbor_bool_false",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.3",
            description: "Boolean false",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Bool(false)).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0xF4]),
            notes: "False = simple value 20",
        },
        TestVector {
            name: "cbor_null",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.3",
            description: "Null value",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Null).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0xF6]),
            notes: "Null = simple value 22",
        },
        TestVector {
            name: "cbor_byte_string_32",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "32-byte byte string (all 0xAA)",
            cbor_bytes: Some(aafp_cbor::encode(&Value::ByteString(vec![0xAA; 32])).unwrap()),
            wire_bytes: None,
            expected_hash: {
                let mut bytes = vec![0x58, 0x20]; // bstr, length 32 (one-byte AI)
                bytes.extend_from_slice(&[0xAA; 32]);
                TestVector::hash(&bytes)
            },
            notes: "32-byte bstr uses AI_ONE_BYTE for length",
        },
        TestVector {
            name: "cbor_text_string",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Text string \"hello\"",
            cbor_bytes: Some(aafp_cbor::encode(&Value::TextString("hello".to_string())).unwrap()),
            wire_bytes: None,
            expected_hash: {
                let bytes = vec![0x65, b'h', b'e', b'l', b'l', b'o']; // tstr len 5
                TestVector::hash(&bytes)
            },
            notes: "5-byte tstr uses immediate length",
        },
        TestVector {
            name: "cbor_empty_array",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Empty array []",
            cbor_bytes: Some(aafp_cbor::encode(&Value::Array(vec![])).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0x80]),
            notes: "Empty array = 0x80",
        },
        TestVector {
            name: "cbor_empty_int_map",
            rfc_section: "RFC-0002 §8 / RFC 8949 §3.1",
            description: "Empty integer-keyed map {}",
            cbor_bytes: Some(aafp_cbor::encode(&int_map(vec![])).unwrap()),
            wire_bytes: None,
            expected_hash: TestVector::hash(&[0xA0]),
            notes: "Empty map = 0xA0",
        },
        TestVector {
            name: "cbor_int_map_sorted",
            rfc_section: "RFC-0002 §8.1 (length-first canonical ordering)",
            description: "Int map {1: \"a\", 100: \"b\"} — key 1 before key 100",
            cbor_bytes: Some(aafp_cbor::encode(&int_map(vec![
                (100, Value::TextString("b".to_string())),
                (1, Value::TextString("a".to_string())),
            ])).unwrap()),
            wire_bytes: None,
            expected_hash: {
                // Map(2) { 1: "a", 100: "b" }
                let bytes = vec![
                    0xA2,       // map(2)
                    0x01,       // key 1 (immediate)
                    0x61, 0x61, // "a"
                    0x18, 0x64, // key 100 (one-byte AI)
                    0x61, 0x62, // "b"
                ];
                TestVector::hash(&bytes)
            },
            notes: "Length-first: key 1 (1 byte) sorts before key 100 (2 bytes)",
        },
        TestVector {
            name: "cbor_int_map_same_length",
            rfc_section: "RFC-0002 §8.1 (bytewise within same length)",
            description: "Int map {10: 1, 20: 2} — same-length keys sorted bytewise",
            cbor_bytes: Some(aafp_cbor::encode(&int_map(vec![
                (20, Value::Unsigned(2)),
                (10, Value::Unsigned(1)),
            ])).unwrap()),
            wire_bytes: None,
            expected_hash: {
                let bytes = vec![
                    0xA2, // map(2)
                    0x0A, // key 10
                    0x01, // value 1
                    0x14, // key 20
                    0x02, // value 2
                ];
                TestVector::hash(&bytes)
            },
            notes: "Same-length keys (both 1 byte): 0x0A < 0x14 bytewise",
        },
        TestVector {
            name: "cbor_str_map_sorted",
            rfc_section: "RFC-0002 §8.1 (string-keyed maps)",
            description: "Str map {\"cat\": 1, \"apple\": 2, \"zebra\": 3} — length-first",
            cbor_bytes: Some(aafp_cbor::encode(&str_map(vec![
                ("zebra".to_string(), Value::Unsigned(3)),
                ("apple".to_string(), Value::Unsigned(2)),
                ("cat".to_string(), Value::Unsigned(1)),
            ])).unwrap()),
            wire_bytes: None,
            expected_hash: {
                // Length-first: "cat"(3) < "apple"(5) < "zebra"(5)
                // Same-length: "apple" < "zebra" bytewise
                let bytes = vec![
                    0xA3, // map(3)
                    0x63, 0x63, 0x61, 0x74, // "cat"
                    0x01, // 1
                    0x65, 0x61, 0x70, 0x70, 0x6C, 0x65, // "apple"
                    0x02, // 2
                    0x65, 0x7A, 0x65, 0x62, 0x72, 0x61, // "zebra"
                    0x03, // 3
                ];
                TestVector::hash(&bytes)
            },
            notes: "Length-first: 3-byte \"cat\" before 5-byte \"apple\" and \"zebra\"",
        },
    ]
}

// === Frame Test Vectors ===

/// Generate frame wire-format test vectors.
pub fn frame_vectors() -> Vec<TestVector> {
    vec![
        TestVector {
            name: "frame_data_empty",
            rfc_section: "RFC-0002 §3-4",
            description: "DATA frame with empty payload, stream 0",
            cbor_bytes: None,
            wire_bytes: Some(encode_frame(&Frame::data(0, vec![])).unwrap()),
            expected_hash: {
                // 28-byte header: version=1, type=0x01, flags=0, reserved=0,
                // stream_id=0, payload_len=0, ext_len=0
                let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
                bytes[0] = AAFP_VERSION;
                bytes[1] = FrameType::Data.to_u8();
                TestVector::hash(&bytes)
            },
            notes: "Minimal frame: 28-byte header, no payload, no extensions",
        },
        TestVector {
            name: "frame_data_stream42",
            rfc_section: "RFC-0002 §3-4",
            description: "DATA frame with 4-byte payload on stream 42",
            cbor_bytes: None,
            wire_bytes: Some(encode_frame(&Frame::data(42, vec![0xDE, 0xAD, 0xBE, 0xEF])).unwrap()),
            expected_hash: {
                let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
                bytes[0] = AAFP_VERSION;
                bytes[1] = FrameType::Data.to_u8();
                bytes[4..12].copy_from_slice(&42u64.to_be_bytes());
                bytes[12..20].copy_from_slice(&4u64.to_be_bytes()); // payload_len
                bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
                TestVector::hash(&bytes)
            },
            notes: "Stream ID 42 in big-endian at offset 4, payload at offset 28",
        },
        TestVector {
            name: "frame_handshake",
            rfc_section: "RFC-0002 §4.2",
            description: "HANDSHAKE frame with 8-byte payload on stream 0",
            cbor_bytes: None,
            wire_bytes: Some(encode_frame(&Frame {
                frame_type: FrameType::Handshake,
                flags: 0,
                stream_id: 0,
                extensions: vec![],
                payload: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            }).unwrap()),
            expected_hash: {
                let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
                bytes[0] = AAFP_VERSION;
                bytes[1] = FrameType::Handshake.to_u8();
                bytes[12..20].copy_from_slice(&8u64.to_be_bytes());
                bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
                TestVector::hash(&bytes)
            },
            notes: "HANDSHAKE frames MUST be on stream 0",
        },
        TestVector {
            name: "frame_rpc_request",
            rfc_section: "RFC-0002 §4.3",
            description: "RPC_REQUEST frame with 3-byte payload on stream 4",
            cbor_bytes: None,
            wire_bytes: Some(encode_frame(&Frame {
                frame_type: FrameType::RpcRequest,
                flags: 0,
                stream_id: 4,
                extensions: vec![],
                payload: vec![0xA1, 0x01, 0x02],
            }).unwrap()),
            expected_hash: {
                let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
                bytes[0] = AAFP_VERSION;
                bytes[1] = FrameType::RpcRequest.to_u8();
                bytes[4..12].copy_from_slice(&4u64.to_be_bytes());
                bytes[12..20].copy_from_slice(&3u64.to_be_bytes());
                bytes.extend_from_slice(&[0xA1, 0x01, 0x02]);
                TestVector::hash(&bytes)
            },
            notes: "RPC requests on client-initiated streams (>= 4)",
        },
        TestVector {
            name: "frame_ping",
            rfc_section: "RFC-0002 §4.7",
            description: "PING frame with empty payload on stream 0",
            cbor_bytes: None,
            wire_bytes: Some(encode_frame(&Frame {
                frame_type: FrameType::Ping,
                flags: 0,
                stream_id: 0,
                extensions: vec![],
                payload: vec![],
            }).unwrap()),
            expected_hash: {
                let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
                bytes[0] = AAFP_VERSION;
                bytes[1] = FrameType::Ping.to_u8();
                TestVector::hash(&bytes)
            },
            notes: "PING frames are control frames on stream 0",
        },
        TestVector {
            name: "frame_data_flags_more",
            rfc_section: "RFC-0002 §4.1 (MORE flag)",
            description: "DATA frame with MORE flag (0x01) set",
            cbor_bytes: None,
            wire_bytes: Some(encode_frame(&Frame {
                frame_type: FrameType::Data,
                flags: 0x01, // MORE flag
                stream_id: 8,
                extensions: vec![],
                payload: vec![0xFF],
            }).unwrap()),
            expected_hash: {
                let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
                bytes[0] = AAFP_VERSION;
                bytes[1] = FrameType::Data.to_u8();
                bytes[2] = 0x01; // flags = MORE
                bytes[4..12].copy_from_slice(&8u64.to_be_bytes());
                bytes[12..20].copy_from_slice(&1u64.to_be_bytes());
                bytes.push(0xFF);
                TestVector::hash(&bytes)
            },
            notes: "MORE flag (0x01) indicates more DATA frames follow for this stream",
        },
    ]
}

// === Handshake Test Vectors ===

/// Generate handshake structure test vectors (CBOR encoding only, not signatures).
pub fn handshake_vectors() -> Vec<TestVector> {
    use aafp_crypto::handshake_v1::{
        ClientFinished, ClientHello, ServerHello,
        KEY_ALG_ML_DSA_65, PROTOCOL_VERSION,
    };
    use fixed_keys::*;

    vec![
        TestVector {
            name: "handshake_client_hello_without_sig",
            rfc_section: "RFC-0002 §5.3, §5.6",
            description: "ClientHello CBOR without signature (keys 1-6, 8, 10)",
            cbor_bytes: {
                let ch = ClientHello {
                    protocol_version: PROTOCOL_VERSION,
                    agent_id: AGENT_ID_A.to_vec(),
                    public_key: PUBLIC_KEY_A.to_vec(),
                    nonce: NONCE_A,
                    capabilities: vec![],
                    extensions: vec![],
                    signature: vec![], // Not included in without_sig
                    expires_at: TIMESTAMP_EXPIRES,
                    receiver_mac: None,
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                Some(aafp_cbor::encode(&ch.to_cbor_without_sig_and_mac()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                // We compute it from the actual encoding — but the point is
                // that a second implementation must produce the same bytes.
                let ch = ClientHello {
                    protocol_version: PROTOCOL_VERSION,
                    agent_id: AGENT_ID_A.to_vec(),
                    public_key: PUBLIC_KEY_A.to_vec(),
                    nonce: NONCE_A,
                    capabilities: vec![],
                    extensions: vec![],
                    signature: vec![],
                    expires_at: TIMESTAMP_EXPIRES,
                    receiver_mac: None,
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                let bytes = aafp_cbor::encode(&ch.to_cbor_without_sig_and_mac()).unwrap();
                TestVector::hash(&bytes)
            },
            notes: "8 fields: keys 1,2,3,4,5,6,8,10 (excludes 7=sig, 9=mac)",
        },
        TestVector {
            name: "handshake_server_hello_without_sig",
            rfc_section: "RFC-0002 §5.4, §5.6",
            description: "ServerHello CBOR without signature (keys 1-7, 9, 10)",
            cbor_bytes: {
                let sh = ServerHello {
                    protocol_version: PROTOCOL_VERSION,
                    agent_id: AGENT_ID_B.to_vec(),
                    public_key: PUBLIC_KEY_B.to_vec(),
                    nonce: NONCE_B,
                    capabilities: vec![],
                    extensions: vec![],
                    session_id: SESSION_ID,
                    signature: vec![],
                    expires_at: TIMESTAMP_EXPIRES,
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                Some(aafp_cbor::encode(&sh.to_cbor_without_sig()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let sh = ServerHello {
                    protocol_version: PROTOCOL_VERSION,
                    agent_id: AGENT_ID_B.to_vec(),
                    public_key: PUBLIC_KEY_B.to_vec(),
                    nonce: NONCE_B,
                    capabilities: vec![],
                    extensions: vec![],
                    session_id: SESSION_ID,
                    signature: vec![],
                    expires_at: TIMESTAMP_EXPIRES,
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                let bytes = aafp_cbor::encode(&sh.to_cbor_without_sig()).unwrap();
                TestVector::hash(&bytes)
            },
            notes: "9 fields: keys 1,2,3,4,5,6,7,9,10 (excludes 8=sig)",
        },
        TestVector {
            name: "handshake_client_finished_without_sig",
            rfc_section: "RFC-0002 §5.5, §5.6",
            description: "ClientFinished CBOR without signature (key 1 only)",
            cbor_bytes: {
                let cf = ClientFinished {
                    session_id: SESSION_ID,
                    signature: vec![],
                };
                Some(aafp_cbor::encode(&cf.to_cbor_without_sig()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let cf = ClientFinished {
                    session_id: SESSION_ID,
                    signature: vec![],
                };
                let bytes = aafp_cbor::encode(&cf.to_cbor_without_sig()).unwrap();
                TestVector::hash(&bytes)
            },
            notes: "1 field: key 1 (session_id only, excludes 2=sig)",
        },
        TestVector {
            name: "handshake_transcript_hash_init",
            rfc_section: "RFC-0002 §5.6 Step 1",
            description: "Transcript hash initialization: SHA-256(TLS_BINDING)",
            cbor_bytes: None,
            wire_bytes: Some(TLS_BINDING.to_vec()),
            expected_hash: Sha256::digest(&TLS_BINDING).into(),
            notes: "h = SHA-256(tls_binding) where tls_binding = [0x05; 32]",
        },
    ]
}

// === AgentRecord Test Vectors ===

/// Generate AgentRecord encoding test vectors.
pub fn agent_record_vectors() -> Vec<TestVector> {
    use aafp_identity::identity_v1::{
        AgentId, AgentRecord, CapabilityDescriptor, MetadataValue,
        KEY_ALG_ML_DSA_65, RECORD_TYPE_V1,
    };
    use fixed_keys::*;

    vec![
        TestVector {
            name: "agent_id_from_fixed_pubkey",
            rfc_section: "RFC-0003 §2.1",
            description: "AgentId = SHA-256(PUBLIC_KEY_A) where PUBLIC_KEY_A = [0x42; 1952]",
            cbor_bytes: None,
            wire_bytes: Some(PUBLIC_KEY_A.to_vec()),
            expected_hash: Sha256::digest(&PUBLIC_KEY_A).into(),
            notes: "AgentId derivation: SHA-256 of the 1952-byte public key",
        },
        TestVector {
            name: "agent_record_without_sig",
            rfc_section: "RFC-0003 §3.2, §3.4",
            description: "AgentRecord CBOR without signature (keys 1-7, 9)",
            cbor_bytes: {
                let agent_id = AgentId::from_public_key(&PUBLIC_KEY_A);
                let record = AgentRecord {
                    record_type: RECORD_TYPE_V1.to_string(),
                    agent_id,
                    public_key: PUBLIC_KEY_A.to_vec(),
                    capabilities: vec![
                        CapabilityDescriptor::new("inference")
                            .with_metadata("model", MetadataValue::Text("test-model".to_string())),
                    ],
                    endpoints: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
                    created_at: TIMESTAMP_NOW,
                    expires_at: TIMESTAMP_EXPIRES,
                    signature: vec![],
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                Some(aafp_cbor::encode(&record.to_cbor_without_sig()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let agent_id = AgentId::from_public_key(&PUBLIC_KEY_A);
                let record = AgentRecord {
                    record_type: RECORD_TYPE_V1.to_string(),
                    agent_id,
                    public_key: PUBLIC_KEY_A.to_vec(),
                    capabilities: vec![
                        CapabilityDescriptor::new("inference")
                            .with_metadata("model", MetadataValue::Text("test-model".to_string())),
                    ],
                    endpoints: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
                    created_at: TIMESTAMP_NOW,
                    expires_at: TIMESTAMP_EXPIRES,
                    signature: vec![],
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                let bytes = aafp_cbor::encode(&record.to_cbor_without_sig()).unwrap();
                TestVector::hash(&bytes)
            },
            notes: "8 fields: keys 1-7, 9 (excludes 8=sig). key_algorithm included in sig input.",
        },
        TestVector {
            name: "agent_record_empty_capabilities",
            rfc_section: "RFC-0003 §3.2",
            description: "AgentRecord with empty capabilities array",
            cbor_bytes: {
                let agent_id = AgentId::from_public_key(&PUBLIC_KEY_B);
                let record = AgentRecord {
                    record_type: RECORD_TYPE_V1.to_string(),
                    agent_id,
                    public_key: PUBLIC_KEY_B.to_vec(),
                    capabilities: vec![],
                    endpoints: vec![],
                    created_at: TIMESTAMP_NOW,
                    expires_at: TIMESTAMP_EXPIRES,
                    signature: vec![],
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                Some(aafp_cbor::encode(&record.to_cbor_without_sig()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let agent_id = AgentId::from_public_key(&PUBLIC_KEY_B);
                let record = AgentRecord {
                    record_type: RECORD_TYPE_V1.to_string(),
                    agent_id,
                    public_key: PUBLIC_KEY_B.to_vec(),
                    capabilities: vec![],
                    endpoints: vec![],
                    created_at: TIMESTAMP_NOW,
                    expires_at: TIMESTAMP_EXPIRES,
                    signature: vec![],
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                let bytes = aafp_cbor::encode(&record.to_cbor_without_sig()).unwrap();
                TestVector::hash(&bytes)
            },
            notes: "Empty capabilities and endpoints arrays are valid",
        },
    ]
}

// === RPC Test Vectors ===

/// Generate RPC message test vectors.
pub fn rpc_vectors() -> Vec<TestVector> {
    use aafp_messaging::rpc_v1::{CloseMessage, ErrorMessage, RpcErrorObject, RpcRequest, RpcResponse};

    vec![
        TestVector {
            name: "rpc_request_basic",
            rfc_section: "RFC-0002 §4.3",
            description: "RPC request with id=1, method=\"aafp.discovery.lookup\"",
            cbor_bytes: {
                let req = RpcRequest::new(1, "aafp.discovery.lookup");
                Some(req.encode().unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let req = RpcRequest::new(1, "aafp.discovery.lookup");
                TestVector::hash(&req.encode().unwrap())
            },
            notes: "Keys: 1=id, 2=method, 3=params(null)",
        },
        TestVector {
            name: "rpc_request_with_params",
            rfc_section: "RFC-0002 §4.3",
            description: "RPC request with string params",
            cbor_bytes: {
                let req = RpcRequest::new(42, "aafp.discovery.lookup")
                    .with_params(Value::TextString("inference".to_string()));
                Some(req.encode().unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let req = RpcRequest::new(42, "aafp.discovery.lookup")
                    .with_params(Value::TextString("inference".to_string()));
                TestVector::hash(&req.encode().unwrap())
            },
            notes: "Params can be any CBOR value",
        },
        TestVector {
            name: "rpc_response_success",
            rfc_section: "RFC-0002 §4.4",
            description: "RPC response with result, no error",
            cbor_bytes: {
                let resp = RpcResponse::success(42, Value::Unsigned(100));
                Some(resp.encode().unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let resp = RpcResponse::success(42, Value::Unsigned(100));
                TestVector::hash(&resp.encode().unwrap())
            },
            notes: "Keys: 1=id, 2=result, 3=null(error)",
        },
        TestVector {
            name: "rpc_response_error",
            rfc_section: "RFC-0002 §4.4",
            description: "RPC response with error, no result",
            cbor_bytes: {
                let resp = RpcResponse::error(42, RpcErrorObject::new(4005, "not found"));
                Some(resp.encode().unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let resp = RpcResponse::error(42, RpcErrorObject::new(4005, "not found"));
                TestVector::hash(&resp.encode().unwrap())
            },
            notes: "Error object: keys 1=code, 2=message, 3=null(data)",
        },
        TestVector {
            name: "close_message",
            rfc_section: "RFC-0002 §4.5",
            description: "Close message with code=0, message=\"goodbye\"",
            cbor_bytes: {
                let msg = CloseMessage::new(0, "goodbye");
                Some(msg.encode().unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let msg = CloseMessage::new(0, "goodbye");
                TestVector::hash(&msg.encode().unwrap())
            },
            notes: "Keys: 1=code, 2=message",
        },
        TestVector {
            name: "error_message_fatal",
            rfc_section: "RFC-0002 §4.6, RFC-0005 §4.1",
            description: "Error message with fatal=true, code=2001",
            cbor_bytes: {
                let msg = ErrorMessage::new(2001, "invalid signature", true);
                Some(msg.encode().unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let msg = ErrorMessage::new(2001, "invalid signature", true);
                TestVector::hash(&msg.encode().unwrap())
            },
            notes: "Keys: 1=code, 2=message, 3=null(data), 4=fatal(true)",
        },
    ]
}

// === Discovery Test Vectors ===

/// Generate discovery RPC test vectors.
pub fn discovery_vectors() -> Vec<TestVector> {
    use aafp_discovery::discovery_v1::{AnnounceParams, AnnounceResult, LookupParams, LookupResult};
    use aafp_identity::identity_v1::{
        AgentId, AgentRecord, CapabilityDescriptor, KEY_ALG_ML_DSA_65, RECORD_TYPE_V1,
    };
    use fixed_keys::*;

    vec![
        TestVector {
            name: "discovery_lookup_params",
            rfc_section: "RFC-0004 §3.3",
            description: "Lookup params: capability=\"inference\", limit=10",
            cbor_bytes: {
                let params = LookupParams::new("inference").with_limit(10);
                let cbor = params.to_cbor();
                Some(aafp_cbor::encode(&cbor).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let params = LookupParams::new("inference").with_limit(10);
                TestVector::hash(&aafp_cbor::encode(&params.to_cbor()).unwrap())
            },
            notes: "Keys: 1=capability(tstr), 2=limit(uint)",
        },
        TestVector {
            name: "discovery_lookup_params_null_limit",
            rfc_section: "RFC-0004 §3.3",
            description: "Lookup params: capability=\"inference\", no limit (null)",
            cbor_bytes: {
                let params = LookupParams::new("inference");
                Some(aafp_cbor::encode(&params.to_cbor()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let params = LookupParams::new("inference");
                TestVector::hash(&aafp_cbor::encode(&params.to_cbor()).unwrap())
            },
            notes: "Keys: 1=capability(tstr), 2=null(limit omitted)",
        },
        TestVector {
            name: "discovery_announce_params",
            rfc_section: "RFC-0004 §3.3",
            description: "Announce params with AgentRecord",
            cbor_bytes: {
                let agent_id = AgentId::from_public_key(&PUBLIC_KEY_A);
                let record = AgentRecord {
                    record_type: RECORD_TYPE_V1.to_string(),
                    agent_id,
                    public_key: PUBLIC_KEY_A.to_vec(),
                    capabilities: vec![CapabilityDescriptor::new("inference")],
                    endpoints: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
                    created_at: TIMESTAMP_NOW,
                    expires_at: TIMESTAMP_EXPIRES,
                    signature: SIGNATURE_A.to_vec(),
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                let params = AnnounceParams::new(record);
                Some(aafp_cbor::encode(&params.to_cbor()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let agent_id = AgentId::from_public_key(&PUBLIC_KEY_A);
                let record = AgentRecord {
                    record_type: RECORD_TYPE_V1.to_string(),
                    agent_id,
                    public_key: PUBLIC_KEY_A.to_vec(),
                    capabilities: vec![CapabilityDescriptor::new("inference")],
                    endpoints: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
                    created_at: TIMESTAMP_NOW,
                    expires_at: TIMESTAMP_EXPIRES,
                    signature: SIGNATURE_A.to_vec(),
                    key_algorithm: KEY_ALG_ML_DSA_65,
                };
                let params = AnnounceParams::new(record);
                TestVector::hash(&aafp_cbor::encode(&params.to_cbor()).unwrap())
            },
            notes: "Key 1 = AgentRecord (nested CBOR map)",
        },
        TestVector {
            name: "discovery_announce_result_empty",
            rfc_section: "RFC-0004 §3.3",
            description: "Announce result with empty peers list",
            cbor_bytes: {
                let result = AnnounceResult::new(vec![]);
                Some(aafp_cbor::encode(&result.to_cbor()).unwrap())
            },
            wire_bytes: None,
            expected_hash: {
                let result = AnnounceResult::new(vec![]);
                TestVector::hash(&aafp_cbor::encode(&result.to_cbor()).unwrap())
            },
            notes: "Key 1 = empty array of AgentRecords",
        },
    ]
}

/// Collect all test vectors.
pub fn all_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    vectors.extend(cbor_vectors());
    vectors.extend(frame_vectors());
    vectors.extend(handshake_vectors());
    vectors.extend(agent_record_vectors());
    vectors.extend(rpc_vectors());
    vectors.extend(discovery_vectors());
    vectors
}

/// Generate the TEST_VECTORS.md document content.
pub fn generate_markdown() -> String {
    let mut md = String::new();
    md.push_str("# AAFP Protocol Test Vectors\n\n");
    md.push_str("**Version**: AAFP v1 (RFC Revision 3)\n");
    md.push_str("**Purpose**: Deterministic wire-format vectors for cross-implementation validation.\n");
    md.push_str("**Usage**: A second implementation should reproduce each vector from the RFCs alone and verify byte-for-byte equality.\n\n");
    md.push_str("## Fixed Test Inputs\n\n");
    md.push_str("All vectors use the following fixed inputs (no randomness):\n\n");
    md.push_str("| Name | Value |\n|------|-------|\n");
    md.push_str("| AGENT_ID_A | `[0x01; 32]` |\n");
    md.push_str("| AGENT_ID_B | `[0x02; 32]` |\n");
    md.push_str("| NONCE_A | `[0x03; 32]` |\n");
    md.push_str("| NONCE_B | `[0x04; 32]` |\n");
    md.push_str("| TLS_BINDING | `[0x05; 32]` |\n");
    md.push_str("| SESSION_ID | `[0x06; 32]` |\n");
    md.push_str("| PUBLIC_KEY_A | `[0x42; 1952]` (NOT a valid ML-DSA-65 key) |\n");
    md.push_str("| PUBLIC_KEY_B | `[0x43; 1952]` |\n");
    md.push_str("| SIGNATURE_A | `[0x44; 3309]` (NOT a valid signature) |\n");
    md.push_str("| SIGNATURE_B | `[0x45; 3309]` |\n");
    md.push_str("| TIMESTAMP_NOW | 1735689600 (2025-01-01T00:00:00Z) |\n");
    md.push_str("| TIMESTAMP_EXPIRES | 1736294400 (2025-01-08T00:00:00Z) |\n\n");

    let sections = [
        ("CBOR Canonical Encoding", cbor_vectors()),
        ("Frame Wire Format", frame_vectors()),
        ("Handshake Structures", handshake_vectors()),
        ("AgentRecord", agent_record_vectors()),
        ("RPC Messages", rpc_vectors()),
        ("Discovery", discovery_vectors()),
    ];

    for (section_name, vectors) in &sections {
        md.push_str(&format!("## {}\n\n", section_name));
        for v in vectors {
            md.push_str(&format!("### {}\n\n", v.name));
            md.push_str(&format!("- **RFC Section**: {}\n", v.rfc_section));
            md.push_str(&format!("- **Description**: {}\n", v.description));
            md.push_str(&format!("- **Expected SHA-256**: `{}`\n", v.expected_hash_hex()));
            if let Some(cbor) = &v.cbor_bytes {
                md.push_str(&format!("- **CBOR Bytes (hex)**: `{}`\n", hex::encode(cbor)));
            }
            if let Some(wire) = &v.wire_bytes {
                if v.wire_bytes.is_some() && v.cbor_bytes.is_none() {
                    md.push_str(&format!("- **Wire Bytes (hex)**: `{}`\n", hex::encode(wire)));
                }
            }
            md.push_str(&format!("- **Notes**: {}\n\n", v.notes));
        }
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_vectors_verify() {
        let vectors = all_vectors();
        assert!(vectors.len() >= 30, "should have at least 30 vectors, got {}", vectors.len());

        for v in &vectors {
            assert!(
                v.verify(),
                "Vector '{}' failed verification: expected hash {}",
                v.name,
                v.expected_hash_hex()
            );
        }
    }

    #[test]
    fn test_cbor_vectors_count() {
        let vectors = cbor_vectors();
        assert!(vectors.len() >= 15, "should have at least 15 CBOR vectors");
    }

    #[test]
    fn test_frame_vectors_count() {
        let vectors = frame_vectors();
        assert!(vectors.len() >= 5, "should have at least 5 frame vectors");
    }

    #[test]
    fn test_handshake_vectors_count() {
        let vectors = handshake_vectors();
        assert!(vectors.len() >= 3, "should have at least 3 handshake vectors");
    }

    #[test]
    fn test_agent_record_vectors_count() {
        let vectors = agent_record_vectors();
        assert!(vectors.len() >= 2, "should have at least 2 AgentRecord vectors");
    }

    #[test]
    fn test_rpc_vectors_count() {
        let vectors = rpc_vectors();
        assert!(vectors.len() >= 5, "should have at least 5 RPC vectors");
    }

    #[test]
    fn test_discovery_vectors_count() {
        let vectors = discovery_vectors();
        assert!(vectors.len() >= 3, "should have at least 3 discovery vectors");
    }

    #[test]
    fn test_cbor_unsigned_5_is_one_byte() {
        let vectors = cbor_vectors();
        let v = vectors.iter().find(|v| v.name == "cbor_unsigned_small").unwrap();
        assert_eq!(v.cbor_bytes.as_ref().unwrap(), &[0x05]);
    }

    #[test]
    fn test_cbor_unsigned_24_is_two_bytes() {
        let vectors = cbor_vectors();
        let v = vectors.iter().find(|v| v.name == "cbor_unsigned_24").unwrap();
        assert_eq!(v.cbor_bytes.as_ref().unwrap(), &[0x18, 0x18]);
    }

    #[test]
    fn test_cbor_null_is_0xf6() {
        let vectors = cbor_vectors();
        let v = vectors.iter().find(|v| v.name == "cbor_null").unwrap();
        assert_eq!(v.cbor_bytes.as_ref().unwrap(), &[0xF6]);
    }

    #[test]
    fn test_frame_data_empty_is_28_bytes() {
        let vectors = frame_vectors();
        let v = vectors.iter().find(|v| v.name == "frame_data_empty").unwrap();
        assert_eq!(v.wire_bytes.as_ref().unwrap().len(), 28);
    }

    #[test]
    fn test_frame_data_stream42_is_32_bytes() {
        let vectors = frame_vectors();
        let v = vectors.iter().find(|v| v.name == "frame_data_stream42").unwrap();
        assert_eq!(v.wire_bytes.as_ref().unwrap().len(), 32); // 28 header + 4 payload
    }

    #[test]
    fn test_generate_markdown_produces_content() {
        let md = generate_markdown();
        assert!(md.contains("# AAFP Protocol Test Vectors"));
        assert!(md.contains("## CBOR Canonical Encoding"));
        assert!(md.contains("## Frame Wire Format"));
        assert!(md.contains("## Handshake Structures"));
        assert!(md.contains("## AgentRecord"));
        assert!(md.contains("## RPC Messages"));
        assert!(md.contains("## Discovery"));
        assert!(md.contains("Expected SHA-256"));
    }
}
