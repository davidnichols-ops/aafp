//! Generate binary interop fixtures for cross-implementation testing.
//!
//! This binary encodes AAFP protocol messages using the Rust reference
//! implementation and writes them as binary files. A second implementation
//! (e.g., the Go implementation) can then decode these files and verify
//! that it produces the same logical values.
//!
//! Usage: cargo run --bin generate_interop_fixtures -- <output_dir>

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use aafp_cbor::{encode, Value};
use aafp_crypto::handshake_v1::{
    derive_session_id, ClientFinished, ClientHello, ServerHello, TranscriptHash,
};
use aafp_identity::identity_v1::{
    AgentId, AgentRecord, CapabilityDescriptor, MetadataValue,
};
use aafp_messaging::{encode_frame, Frame, FrameType};

// Fixed test inputs (must match TEST_VECTORS.md and Go implementation)
const PUBLIC_KEY_A: [u8; 1952] = [0x42; 1952];
const PUBLIC_KEY_B: [u8; 1952] = [0x43; 1952];
const SIGNATURE_A: [u8; 3309] = [0x44; 3309];
const NONCE_A: [u8; 32] = [0x03; 32];
const NONCE_B: [u8; 32] = [0x04; 32];
const TLS_BINDING: [u8; 32] = [0x05; 32];
const SESSION_ID: [u8; 32] = [0x06; 32];
const TIMESTAMP_NOW: u64 = 1735689600;
const TIMESTAMP_EXPIRES: u64 = 1736294400;
const KEY_ALG_ML_DSA_65: u64 = 1;

fn write_fixture(dir: &PathBuf, name: &str, data: &[u8]) {
    let path = dir.join(name);
    let mut file = fs::File::create(&path)
        .unwrap_or_else(|e| panic!("Failed to create {:?}: {}", path, e));
    file.write_all(data)
        .unwrap_or_else(|e| panic!("Failed to write {:?}: {}", path, e));
    println!("  wrote {} ({} bytes)", path.display(), data.len());
}

fn write_cbor(dir: &PathBuf, name: &str, val: &Value) {
    let data = encode(val).expect("CBOR encode failed");
    write_fixture(dir, name, &data);
}

fn write_frame(dir: &PathBuf, name: &str, frame: &Frame) {
    let data = encode_frame(frame).expect("Frame encode failed");
    write_fixture(dir, name, &data);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = match args.get(1) {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from("interop_fixtures"),
    };

    println!("Generating interop fixtures in: {}", output_dir.display());

    // === CBOR fixtures ===
    let cbor_dir = output_dir.join("cbor");
    fs::create_dir_all(&cbor_dir).unwrap();

    write_cbor(&cbor_dir, "uint_5.bin", &Value::Unsigned(5));
    write_cbor(&cbor_dir, "uint_24.bin", &Value::Unsigned(24));
    write_cbor(&cbor_dir, "uint_100.bin", &Value::Unsigned(100));
    write_cbor(&cbor_dir, "uint_1000.bin", &Value::Unsigned(1000));
    write_cbor(&cbor_dir, "negative_1.bin", &Value::Negative(-1));
    write_cbor(&cbor_dir, "negative_100.bin", &Value::Negative(-100));
    write_cbor(&cbor_dir, "bool_true.bin", &Value::Bool(true));
    write_cbor(&cbor_dir, "bool_false.bin", &Value::Bool(false));
    write_cbor(&cbor_dir, "null.bin", &Value::Null);
    write_cbor(
        &cbor_dir,
        "bstr_32.bin",
        &Value::ByteString(vec![0xaa; 32]),
    );
    write_cbor(
        &cbor_dir,
        "tstr_hello.bin",
        &Value::TextString("hello".to_string()),
    );
    write_cbor(&cbor_dir, "empty_array.bin", &Value::Array(vec![]));
    write_cbor(&cbor_dir, "empty_map.bin", &Value::IntMap(vec![]));

    write_cbor(
        &cbor_dir,
        "int_map_sorted.bin",
        &Value::IntMap(vec![
            (1, Value::TextString("a".to_string())),
            (100, Value::TextString("b".to_string())),
        ]),
    );

    write_cbor(
        &cbor_dir,
        "int_map_same_length.bin",
        &Value::IntMap(vec![
            (10, Value::Unsigned(1)),
            (20, Value::Unsigned(2)),
        ]),
    );

    write_cbor(
        &cbor_dir,
        "str_map_sorted.bin",
        &Value::StrMap(vec![
            ("cat".to_string(), Value::Unsigned(1)),
            ("apple".to_string(), Value::Unsigned(2)),
            ("zebra".to_string(), Value::Unsigned(3)),
        ]),
    );

    // === Frame fixtures ===
    let frame_dir = output_dir.join("frames");
    fs::create_dir_all(&frame_dir).unwrap();

    write_frame(
        &frame_dir,
        "data_empty.bin",
        &Frame::data(0, vec![]),
    );

    write_frame(
        &frame_dir,
        "data_stream42.bin",
        &Frame::data(42, vec![0xde, 0xad, 0xbe, 0xef]),
    );

    write_frame(
        &frame_dir,
        "handshake.bin",
        &Frame::handshake(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
    );

    // RPC_REQUEST frame, 3-byte payload, stream 4
    write_frame(
        &frame_dir,
        "rpc_request.bin",
        &Frame {
            frame_type: FrameType::RpcRequest,
            flags: 0,
            stream_id: 4,
            extensions: vec![],
            payload: vec![0xa1, 0x01, 0x02],
        },
    );

    write_frame(
        &frame_dir,
        "ping.bin",
        &Frame::ping(0),
    );

    // DATA frame with MORE flag
    write_frame(
        &frame_dir,
        "data_flags_more.bin",
        &Frame {
            frame_type: FrameType::Data,
            flags: 0x01, // MORE flag
            stream_id: 8,
            extensions: vec![],
            payload: vec![0xff],
        },
    );

    // === Handshake fixtures ===
    let hs_dir = output_dir.join("handshake");
    fs::create_dir_all(&hs_dir).unwrap();

    let ch = ClientHello {
        protocol_version: 1,
        agent_id: AgentId::from_public_key(&PUBLIC_KEY_A).0.to_vec(),
        public_key: PUBLIC_KEY_A.to_vec(),
        nonce: NONCE_A,
        capabilities: vec![],
        extensions: vec![],
        signature: vec![],
        expires_at: TIMESTAMP_EXPIRES,
        receiver_mac: None,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };
    write_cbor(
        &hs_dir,
        "client_hello_without_sig.bin",
        &ch.to_cbor_without_sig_and_mac(),
    );

    let sh = ServerHello {
        protocol_version: 1,
        agent_id: AgentId::from_public_key(&PUBLIC_KEY_B).0.to_vec(),
        public_key: PUBLIC_KEY_B.to_vec(),
        nonce: NONCE_B,
        capabilities: vec![],
        extensions: vec![],
        session_id: SESSION_ID,
        signature: vec![],
        expires_at: TIMESTAMP_EXPIRES,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };
    write_cbor(
        &hs_dir,
        "server_hello_without_sig.bin",
        &sh.to_cbor_without_sig(),
    );

    let cf = ClientFinished {
        session_id: SESSION_ID,
        signature: vec![],
    };
    write_cbor(
        &hs_dir,
        "client_finished_without_sig.bin",
        &cf.to_cbor_without_sig(),
    );

    // === AgentRecord fixtures ===
    let ar_dir = output_dir.join("agent_record");
    fs::create_dir_all(&ar_dir).unwrap();

    let record_a = AgentRecord {
        record_type: "aafp-record-v1".to_string(),
        agent_id: AgentId::from_public_key(&PUBLIC_KEY_A),
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
    write_cbor(&ar_dir, "without_sig.bin", &record_a.to_cbor_without_sig());

    let record_b = AgentRecord {
        record_type: "aafp-record-v1".to_string(),
        agent_id: AgentId::from_public_key(&PUBLIC_KEY_B),
        public_key: PUBLIC_KEY_B.to_vec(),
        capabilities: vec![],
        endpoints: vec![],
        created_at: TIMESTAMP_NOW,
        expires_at: TIMESTAMP_EXPIRES,
        signature: vec![],
        key_algorithm: KEY_ALG_ML_DSA_65,
    };
    write_cbor(
        &ar_dir,
        "empty_capabilities.bin",
        &record_b.to_cbor_without_sig(),
    );

    let record_with_sig = AgentRecord {
        record_type: "aafp-record-v1".to_string(),
        agent_id: AgentId::from_public_key(&PUBLIC_KEY_A),
        public_key: PUBLIC_KEY_A.to_vec(),
        capabilities: vec![CapabilityDescriptor::new("inference")],
        endpoints: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
        created_at: TIMESTAMP_NOW,
        expires_at: TIMESTAMP_EXPIRES,
        signature: SIGNATURE_A.to_vec(),
        key_algorithm: KEY_ALG_ML_DSA_65,
    };
    write_cbor(&ar_dir, "with_sig.bin", &record_with_sig.to_cbor());

    // === RPC fixtures ===
    let rpc_dir = output_dir.join("rpc");
    fs::create_dir_all(&rpc_dir).unwrap();

    write_cbor(
        &rpc_dir,
        "request_basic.bin",
        &Value::IntMap(vec![
            (1, Value::Unsigned(1)),
            (2, Value::TextString("aafp.discovery.lookup".to_string())),
            (3, Value::Null),
        ]),
    );

    write_cbor(
        &rpc_dir,
        "request_with_params.bin",
        &Value::IntMap(vec![
            (1, Value::Unsigned(42)),
            (2, Value::TextString("aafp.discovery.lookup".to_string())),
            (3, Value::TextString("inference".to_string())),
        ]),
    );

    write_cbor(
        &rpc_dir,
        "response_success.bin",
        &Value::IntMap(vec![
            (1, Value::Unsigned(42)),
            (2, Value::Unsigned(100)),
            (3, Value::Null),
        ]),
    );

    write_cbor(
        &rpc_dir,
        "response_error.bin",
        &Value::IntMap(vec![
            (1, Value::Unsigned(42)),
            (2, Value::Null),
            (
                3,
                Value::IntMap(vec![
                    (1, Value::Unsigned(4005)),
                    (2, Value::TextString("not found".to_string())),
                    (3, Value::Null),
                ]),
            ),
        ]),
    );

    write_cbor(
        &rpc_dir,
        "close_message.bin",
        &Value::IntMap(vec![
            (1, Value::Unsigned(0)),
            (2, Value::TextString("goodbye".to_string())),
        ]),
    );

    write_cbor(
        &rpc_dir,
        "error_message_fatal.bin",
        &Value::IntMap(vec![
            (1, Value::Unsigned(2001)),
            (2, Value::TextString("invalid signature".to_string())),
            (3, Value::Null),
            (4, Value::Bool(true)),
        ]),
    );

    // === Transcript hash fixtures ===
    let transcript_dir = output_dir.join("transcript");
    fs::create_dir_all(&transcript_dir).unwrap();

    let th = TranscriptHash::from_tls_binding(&TLS_BINDING);
    write_fixture(&transcript_dir, "hash_init.bin", th.current());

    let ch_bytes = encode(&ch.to_cbor_without_sig_and_mac()).unwrap();
    let mut th_after_ch = TranscriptHash::from_tls_binding(&TLS_BINDING);
    th_after_ch.fold(&ch_bytes);
    let h_after_ch = *th_after_ch.current();
    write_fixture(
        &transcript_dir,
        "hash_after_clienthello.bin",
        &h_after_ch,
    );

    let sh_bytes = encode(&sh.to_cbor_without_sig()).unwrap();
    let mut th_after_sh = th_after_ch;
    th_after_sh.fold(&sh_bytes);
    write_fixture(
        &transcript_dir,
        "hash_after_serverhello.bin",
        th_after_sh.current(),
    );

    let cf_bytes = encode(&cf.to_cbor_without_sig()).unwrap();
    let mut th_after_cf = th_after_sh;
    th_after_cf.fold(&cf_bytes);
    write_fixture(
        &transcript_dir,
        "hash_after_clientfinished.bin",
        th_after_cf.current(),
    );

    let session_id = derive_session_id(&h_after_ch, &NONCE_A, &NONCE_B);
    write_fixture(&transcript_dir, "session_id.bin", &session_id);

    // === Manifest ===
    let manifest = format!(
        r#"{{"version":"aafp-v1-interop-fixtures-1","generated_by":"rust-reference"}}"#
    );
    let manifest_path = output_dir.join("manifest.json");
    fs::write(&manifest_path, manifest).unwrap();
    println!("  wrote {} (manifest)", manifest_path.display());

    println!("\nDone. Interop fixtures generated in {}", output_dir.display());
}
