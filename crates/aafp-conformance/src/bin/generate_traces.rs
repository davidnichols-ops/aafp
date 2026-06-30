#![allow(unused_imports)]
#![allow(clippy::all)]

//! Generate canonical golden wire traces for AAFP v1 protocol messages.
//!
//! Produces trace directories with trace.bin, trace.hex, and meta.json.
//! These are the canonical interoperability vectors.
//!
//! Usage: cargo run --bin generate_traces -- <output_dir>
//!
//! Each trace directory contains:
//! - trace.bin: Raw bytes of the entire exchange
//! - trace.hex: Hex dump with frame boundaries and annotations
//! - meta.json: Machine-readable metadata

use aafp_cbor::{encode, int_map, Value};
use aafp_crypto::handshake_v1::{
    derive_session_id, ClientFinished, ClientHello, ServerHello, TranscriptHash,
};
use aafp_messaging::{
    encode_frame, CloseMessage, ErrorMessage, Frame, FrameType, RpcRequest, RpcResponse,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// Fixed deterministic inputs (must match across implementations)
const TLS_BINDING: [u8; 32] = [0xAA; 32];
const CLIENT_NONCE: [u8; 32] = [0x01; 32];
const SERVER_NONCE: [u8; 32] = [0x02; 32];
const PUBLIC_KEY_A: [u8; 1952] = [0x42; 1952];
const PUBLIC_KEY_B: [u8; 1952] = [0x43; 1952];
const SIGNATURE_A: [u8; 3309] = [0x44; 3309];
const SIGNATURE_B: [u8; 3309] = [0x45; 3309];
const TIMESTAMP_NOW: u64 = 1735689600;
const TIMESTAMP_EXP: u64 = 1736294400;

#[derive(Serialize, Deserialize)]
struct TraceMeta {
    name: String,
    description: String,
    rfc_reference: String,
    total_bytes: usize,
    outcome: String,
    frames: Vec<FrameMeta>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transcript_hashes: Vec<TranscriptMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct FrameMeta {
    index: usize,
    offset: usize,
    length: usize,
    #[serde(rename = "type")]
    frame_type: String,
    type_name: String,
    flags: String,
    stream_id: u64,
    payload_length: usize,
    extension_length: usize,
    description: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct TranscriptMeta {
    stage: String,
    hash: String,
}

fn agent_id(pk: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(pk).to_vec()
}

fn make_client_hello() -> (ClientHello, Vec<u8>) {
    let ch = ClientHello {
        protocol_version: 1,
        agent_id: agent_id(&PUBLIC_KEY_A),
        public_key: PUBLIC_KEY_A.to_vec(),
        nonce: CLIENT_NONCE,
        capabilities: vec![],
        extensions: vec![],
        signature: SIGNATURE_A.to_vec(),
        expires_at: TIMESTAMP_EXP,
        receiver_mac: None,
        key_algorithm: 1,
    };
    let cbor = ch.to_cbor();
    let bytes = encode(&cbor).unwrap();
    (ch, bytes)
}

fn make_server_hello() -> (ServerHello, Vec<u8>) {
    let mut th = TranscriptHash::from_tls_binding(&TLS_BINDING);
    let (_, ch_bytes) = make_client_hello();
    let h_after_ch = th.fold(&ch_bytes);
    let session_id = derive_session_id(&h_after_ch, &CLIENT_NONCE, &SERVER_NONCE, &[0xAAu8; 32]);

    let sh = ServerHello {
        protocol_version: 1,
        agent_id: agent_id(&PUBLIC_KEY_B),
        public_key: PUBLIC_KEY_B.to_vec(),
        nonce: SERVER_NONCE,
        capabilities: vec![],
        extensions: vec![],
        session_id,
        signature: SIGNATURE_B.to_vec(),
        expires_at: TIMESTAMP_EXP,
        key_algorithm: 1,
    };
    let cbor = sh.to_cbor();
    let bytes = encode(&cbor).unwrap();
    (sh, bytes)
}

fn make_client_finished() -> (ClientFinished, Vec<u8>) {
    let mut th = TranscriptHash::from_tls_binding(&TLS_BINDING);
    let (_, ch_bytes) = make_client_hello();
    let h_after_ch = th.fold(&ch_bytes);
    let (_, sh_bytes) = make_server_hello();
    let _h_after_sh = th.fold(&sh_bytes);
    let session_id = derive_session_id(&h_after_ch, &CLIENT_NONCE, &SERVER_NONCE, &[0xAAu8; 32]);

    let cf = ClientFinished {
        session_id,
        signature: SIGNATURE_A.to_vec(),
    };
    let cbor = cf.to_cbor();
    let bytes = encode(&cbor).unwrap();
    (cf, bytes)
}

fn frame_type_name(ft: FrameType) -> &'static str {
    match ft {
        FrameType::Data => "DATA",
        FrameType::Handshake => "HANDSHAKE",
        FrameType::RpcRequest => "RPC_REQUEST",
        FrameType::RpcResponse => "RPC_RESPONSE",
        FrameType::Close => "CLOSE",
        FrameType::Error => "ERROR",
        FrameType::Ping => "PING",
        FrameType::Pong => "PONG",
        FrameType::Unknown(_) => "UNKNOWN",
    }
}

struct TraceBuilder {
    frames: Vec<Frame>,
    description: String,
    rfc_reference: String,
    outcome: String,
    transcript_hashes: Vec<TranscriptMeta>,
    session_id: Option<String>,
}

impl TraceBuilder {
    fn new(desc: &str, rfc: &str, outcome: &str) -> Self {
        Self {
            frames: vec![],
            description: desc.to_string(),
            rfc_reference: rfc.to_string(),
            outcome: outcome.to_string(),
            transcript_hashes: vec![],
            session_id: None,
        }
    }

    fn add_frame(&mut self, frame: Frame) -> &mut Self {
        self.frames.push(frame);
        self
    }

    fn with_session_id(&mut self, sid: &str) -> &mut Self {
        self.session_id = Some(sid.to_string());
        self
    }

    fn with_transcript(&mut self, stage: &str, hash: &[u8]) -> &mut Self {
        self.transcript_hashes.push(TranscriptMeta {
            stage: stage.to_string(),
            hash: hex::encode(hash),
        });
        self
    }

    fn build(&self, name: &str, output_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let dir = output_dir.join(name);
        fs::create_dir_all(&dir)?;

        // Build trace.bin
        let mut trace_bytes = Vec::new();
        let mut frame_metas = Vec::new();
        let mut offset = 0;

        for (i, frame) in self.frames.iter().enumerate() {
            let frame_bytes = encode_frame(frame)?;
            let length = frame_bytes.len();
            trace_bytes.extend_from_slice(&frame_bytes);

            frame_metas.push(FrameMeta {
                index: i,
                offset,
                length,
                frame_type: format!("0x{:02x}", frame.frame_type.to_u8()),
                type_name: frame_type_name(frame.frame_type).to_string(),
                flags: format!("0x{:02x}", frame.flags),
                stream_id: frame.stream_id,
                payload_length: frame.payload.len(),
                extension_length: frame.extensions.len(),
                description: format!("{} frame", frame_type_name(frame.frame_type)),
            });
            offset += length;
        }

        // Write trace.bin
        fs::write(dir.join("trace.bin"), &trace_bytes)?;

        // Write trace.hex
        let mut hex_content = String::new();
        hex_content.push_str(&format!("# Golden trace: {}\n", name));
        hex_content.push_str(&format!("# Description: {}\n", self.description));
        hex_content.push_str(&format!("# RFC reference: {}\n", self.rfc_reference));
        hex_content.push_str(&format!("# Total bytes: {}\n", trace_bytes.len()));
        hex_content.push_str(&format!("# Frames: {}\n\n", self.frames.len()));

        for (i, frame) in self.frames.iter().enumerate() {
            let frame_bytes = encode_frame(frame)?;
            let meta = &frame_metas[i];
            hex_content.push_str(&format!(
                "# --- Frame {} (offset {}, {} bytes) ---\n",
                i, meta.offset, meta.length
            ));
            hex_content.push_str(&format!(
                "#   Type: {} ({})\n",
                meta.frame_type, meta.type_name
            ));
            hex_content.push_str(&format!("#   Flags: {}\n", meta.flags));
            hex_content.push_str(&format!("#   StreamID: {}\n", meta.stream_id));
            hex_content.push_str(&format!("#   PayloadLen: {}\n", meta.payload_length));
            hex_content.push_str(&format!("#   ExtLen: {}\n", meta.extension_length));
            hex_content.push_str(&format!("#   Description: {}\n", meta.description));

            // Hex dump (16 bytes per line)
            for chunk in frame_bytes.chunks(16) {
                let hex_str: String = chunk.iter().map(|b| format!("{:02x} ", b)).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() || *b == b' ' {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                hex_content.push_str(&format!("  {:08x}  {:<48}   {}\n", offset, hex_str, ascii));
            }
            hex_content.push('\n');
        }

        fs::write(dir.join("trace.hex"), hex_content)?;

        // Write meta.json
        let meta = TraceMeta {
            name: name.to_string(),
            description: self.description.clone(),
            rfc_reference: self.rfc_reference.clone(),
            total_bytes: trace_bytes.len(),
            outcome: self.outcome.clone(),
            frames: frame_metas,
            transcript_hashes: self.transcript_hashes.clone(),
            session_id: self.session_id.clone(),
        };
        let meta_json = serde_json::to_string_pretty(&meta)?;
        fs::write(dir.join("meta.json"), meta_json)?;

        println!(
            "  Generated: {} ({} bytes, {} frames)",
            name,
            trace_bytes.len(),
            self.frames.len()
        );
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = if args.len() >= 2 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("golden_traces")
    };

    println!("=== AAFP Golden Trace Generation ===");
    println!("Output: {}\n", output_dir.display());
    fs::create_dir_all(&output_dir).unwrap();

    // Compute transcript hashes for handshake traces
    let mut th = TranscriptHash::from_tls_binding(&TLS_BINDING);
    let (_, ch_bytes) = make_client_hello();
    let h_after_ch = th.fold(&ch_bytes);
    let (_, sh_bytes) = make_server_hello();
    let h_after_sh = th.fold(&sh_bytes);
    let session_id = derive_session_id(&h_after_ch, &CLIENT_NONCE, &SERVER_NONCE, &[0xAAu8; 32]);

    // 10: PING/PONG keepalive exchange
    let mut tb = TraceBuilder::new(
        "PING/PONG keepalive exchange",
        "RFC-0002 §4.7-4.8",
        "success",
    );
    tb.add_frame(Frame {
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: vec![],
    });
    tb.add_frame(Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: vec![],
    });
    tb.build("10_ping_pong", &output_dir).unwrap();

    // 11: Graceful CLOSE (standalone)
    let mut tb = TraceBuilder::new(
        "Graceful CLOSE frame (standalone shutdown)",
        "RFC-0002 §4.5",
        "session terminated (graceful close)",
    );
    let close_msg = CloseMessage::new(0, "normal shutdown");
    let close_payload = close_msg.encode().unwrap();
    tb.add_frame(Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: close_payload,
    });
    tb.build("11_graceful_close", &output_dir).unwrap();

    // 12: ERROR frame (fatal authentication error)
    let mut tb = TraceBuilder::new(
        "Fatal ERROR frame (INVALID_SIGNATURE 2001)",
        "RFC-0002 §4.6, RFC-0005 §3.3",
        "failure (2001, fatal)",
    );
    let err_msg = ErrorMessage::new(2001, "ML-DSA-65 signature verification failed", true);
    let err_payload = err_msg.encode().unwrap();
    tb.add_frame(Frame {
        frame_type: FrameType::Error,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: err_payload,
    });
    tb.build("12_fatal_error", &output_dir).unwrap();

    // 13: Non-fatal ERROR frame
    let mut tb = TraceBuilder::new(
        "Non-fatal ERROR frame (UNKNOWN_METHOD 5002)",
        "RFC-0002 §4.6, RFC-0005 §3.6",
        "non-fatal error (connection continues)",
    );
    let err_msg = ErrorMessage::new(5002, "RPC method not recognized", false);
    let err_payload = err_msg.encode().unwrap();
    tb.add_frame(Frame {
        frame_type: FrameType::Error,
        flags: 0,
        stream_id: 42,
        extensions: vec![],
        payload: err_payload,
    });
    tb.build("13_nonfatal_error", &output_dir).unwrap();

    // 14: Capability exchange RPC
    let mut tb = TraceBuilder::new(
        "Capability exchange RPC (lookup + response with capabilities)",
        "RFC-0003 §4, RFC-0004 §3",
        "success",
    );
    let req = RpcRequest::new(1, "aafp.capability.lookup")
        .with_params(Value::TextString("inference".to_string()));
    let req_payload = req.encode().unwrap();
    tb.add_frame(Frame {
        frame_type: FrameType::RpcRequest,
        flags: 0,
        stream_id: 5,
        extensions: vec![],
        payload: req_payload,
    });
    // Response with capability list
    let caps = Value::Array(vec![
        Value::TextString("inference".to_string()),
        Value::TextString("translation".to_string()),
    ]);
    let resp = RpcResponse::success(1, caps);
    let resp_payload = resp.encode().unwrap();
    tb.add_frame(Frame {
        frame_type: FrameType::RpcResponse,
        flags: 0,
        stream_id: 5,
        extensions: vec![],
        payload: resp_payload,
    });
    tb.build("14_capability_exchange", &output_dir).unwrap();

    // 15: DATA frame with extension
    let mut tb = TraceBuilder::new(
        "DATA frame with extension (timestamp extension)",
        "RFC-0002 §3.3, §6",
        "success",
    );
    // Create a simple extension: type=1 (timestamp), critical=false, data=8 bytes
    let ext_data: [u8; 8] = TIMESTAMP_NOW.to_be_bytes();
    let mut ext_bytes = Vec::new();
    // Extension format: type(2 bytes) | flags(1 byte) | len(4 bytes) | data
    ext_bytes.extend_from_slice(&1u16.to_be_bytes()); // type
    ext_bytes.push(0); // flags (non-critical)
    ext_bytes.extend_from_slice(&(ext_data.len() as u32).to_be_bytes()); // length
    ext_bytes.extend_from_slice(&ext_data);
    tb.add_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 10,
        extensions: ext_bytes,
        payload: b"hello world".to_vec(),
    });
    tb.build("15_data_with_extension", &output_dir).unwrap();

    // 16: Full handshake with transcript hashes
    let mut tb = TraceBuilder::new(
        "Complete successful handshake with transcript hashes",
        "RFC-0002 §5",
        "success",
    );
    tb.with_transcript("after_client_hello", &h_after_ch);
    tb.with_transcript("after_server_hello", &h_after_sh);
    tb.with_session_id(&hex::encode(&session_id));
    tb.add_frame(Frame {
        frame_type: FrameType::Handshake,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: ch_bytes.clone(),
    });
    tb.add_frame(Frame {
        frame_type: FrameType::Handshake,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: sh_bytes.clone(),
    });
    let (_cf, cf_bytes) = make_client_finished();
    tb.add_frame(Frame {
        frame_type: FrameType::Handshake,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: cf_bytes,
    });
    tb.build("16_full_handshake_with_transcripts", &output_dir)
        .unwrap();

    // 17: Fragmented DATA frame (MORE flag)
    let mut tb = TraceBuilder::new(
        "Fragmented DATA frames (MORE flag set on first fragment)",
        "RFC-0002 §4.1 (MORE flag)",
        "success",
    );
    let payload1 = b"Hello, ".to_vec();
    let payload2 = b"World!".to_vec();
    tb.add_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0x01, // MORE flag
        stream_id: 20,
        extensions: vec![],
        payload: payload1,
    });
    tb.add_frame(Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 20,
        extensions: vec![],
        payload: payload2,
    });
    tb.build("17_fragmented_data", &output_dir).unwrap();

    println!("\n=== Generation Complete ===");
    println!("Traces written to: {}", output_dir.display());
}
