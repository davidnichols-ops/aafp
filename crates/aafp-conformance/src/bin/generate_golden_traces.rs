//! Generate canonical golden traces for AAFP v1 protocol messages.
//!
//! These traces are normative conformance vectors. An independent implementation
//! (e.g., Go) must produce and accept these exact byte sequences.
//!
//! Output format: JSON with hex-encoded bytes and field breakdowns.

use aafp_cbor::{int_map, Value};
use aafp_crypto::{
    derive_session_id, generate_nonce, ClientFinished, ClientHelloV1, HandshakeError,
    ServerHelloV1, TranscriptHash, DOMAIN_SEPARATOR, KEY_ALG_ML_DSA_65, PROTOCOL_VERSION,
};
use aafp_crypto::{MlDsa65, MlDsa65SecretKey, SignatureScheme};
use aafp_messaging::{encode_frame, Frame, FrameType, AAFP_VERSION, FRAME_HEADER_SIZE};
use sha2::Digest;
use std::collections::BTreeMap;

/// Deterministic test keypair for golden trace generation.
/// Using fixed keys so traces are reproducible.
struct FixedKeypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

fn main() {
    println!("=== AAFP v1 Golden Trace Generation ===\n");

    // Generate deterministic keypairs (fresh each run, but traces are
    // self-consistent within a run)
    let client = generate_keypair("client");
    let server = generate_keypair("server");

    // Fixed TLS binding for reproducibility
    let tls_binding = [0x42u8; 32];

    // Fixed nonces for reproducibility
    let client_nonce = [0xAAu8; 32];
    let server_nonce = [0xBBu8; 32];

    let now: u64 = 1700000000;

    // --- ClientHello ---
    let mut th = TranscriptHash::from_tls_binding(&tls_binding);

    let client_agent_id = sha2::Sha256::digest(&client.public_key).to_vec();

    let mut ch = ClientHelloV1 {
        protocol_version: PROTOCOL_VERSION,
        agent_id: client_agent_id.clone(),
        public_key: client.public_key.clone(),
        nonce: client_nonce,
        capabilities: vec![],
        extensions: vec![],
        signature: vec![],
        expires_at: now + 3600,
        receiver_mac: None,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    // Compute signature input
    let ch_cbor = ch.to_cbor_without_sig_and_mac();
    let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
    let h_after_ch = th.fold(&ch_cbor_bytes);

    let sig_input = {
        let mut v = Vec::new();
        v.extend_from_slice(DOMAIN_SEPARATOR);
        v.extend_from_slice(&h_after_ch);
        v
    };
    let sk = MlDsa65SecretKey::from_bytes(&client.secret_key).unwrap();
    let sig = MlDsa65::sign(&sk, &sig_input);
    ch.signature = sig.0;

    println!("--- ClientHello ---");
    println!("agent_id (hex): {}", hex::encode(&ch.agent_id));
    println!("public_key (hex, first 32 bytes): {}", hex::encode(&ch.public_key[..32]));
    println!("nonce (hex): {}", hex::encode(&ch.nonce));
    println!("protocol_version: {}", ch.protocol_version);
    println!("expires_at: {}", ch.expires_at);
    println!("key_algorithm: {}", ch.key_algorithm);
    println!("signature (hex, first 32 bytes): {}", hex::encode(&ch.signature[..32]));
    println!("signature_len: {}", ch.signature.len());
    println!();

    // CBOR of ClientHello (without sig and mac) — this is the signature input base
    println!("ClientHello CBOR (without sig+mac, hex):");
    println!("{}", hex::encode(&ch_cbor_bytes));
    println!("ClientHello CBOR length: {} bytes", ch_cbor_bytes.len());
    println!();

    // Transcript hash after ClientHello
    println!("Transcript hash after ClientHello (hex):");
    println!("{}", hex::encode(&h_after_ch));
    println!();

    // Signature input
    println!("Signature input (domain_sep || transcript_hash, hex):");
    println!("{}", hex::encode(&sig_input));
    println!();

    // Full ClientHello CBOR (with signature)
    let ch_full_cbor = ch.to_cbor();
    let ch_full_bytes = aafp_cbor::encode(&ch_full_cbor).unwrap();
    println!("Full ClientHello CBOR (hex):");
    println!("{}", hex::encode(&ch_full_bytes));
    println!("Full ClientHello CBOR length: {} bytes", ch_full_bytes.len());
    println!();

    // --- ServerHello ---
    let server_agent_id = sha2::Sha256::digest(&server.public_key).to_vec();
    let session_id = derive_session_id(&h_after_ch, &client_nonce, &server_nonce);

    let mut sh = ServerHelloV1 {
        protocol_version: PROTOCOL_VERSION,
        agent_id: server_agent_id.clone(),
        public_key: server.public_key.clone(),
        nonce: server_nonce,
        capabilities: vec![],
        extensions: vec![],
        session_id,
        signature: vec![],
        expires_at: now + 3600,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    let sh_cbor = sh.to_cbor_without_sig();
    let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).unwrap();
    let h_after_sh = th.fold(&sh_cbor_bytes);

    let sh_sig_input = {
        let mut v = Vec::new();
        v.extend_from_slice(DOMAIN_SEPARATOR);
        v.extend_from_slice(&h_after_sh);
        v
    };
    let sk_server = MlDsa65SecretKey::from_bytes(&server.secret_key).unwrap();
    let sh_sig = MlDsa65::sign(&sk_server, &sh_sig_input);
    sh.signature = sh_sig.0;

    println!("--- ServerHello ---");
    println!("agent_id (hex): {}", hex::encode(&sh.agent_id));
    println!("nonce (hex): {}", hex::encode(&sh.nonce));
    println!("session_id (hex): {}", hex::encode(&sh.session_id));
    println!("signature_len: {}", sh.signature.len());
    println!();

    println!("ServerHello CBOR (without sig, hex):");
    println!("{}", hex::encode(&sh_cbor_bytes));
    println!("ServerHello CBOR length: {} bytes", sh_cbor_bytes.len());
    println!();

    println!("Transcript hash after ServerHello (hex):");
    println!("{}", hex::encode(&h_after_sh));
    println!();

    // Full ServerHello CBOR
    let sh_full_cbor = sh.to_cbor();
    let sh_full_bytes = aafp_cbor::encode(&sh_full_cbor).unwrap();
    println!("Full ServerHello CBOR (hex):");
    println!("{}", hex::encode(&sh_full_bytes));
    println!("Full ServerHello CBOR length: {} bytes", sh_full_bytes.len());
    println!();

    // --- ClientFinished ---
    let cf = ClientFinished {
        session_id,
        signature: {
            let cf_sig_input = {
                let mut v = Vec::new();
                v.extend_from_slice(DOMAIN_SEPARATOR);
                v.extend_from_slice(&h_after_sh);
                v
            };
            MlDsa65::sign(&sk, &cf_sig_input).0
        },
    };

    let cf_cbor = cf.to_cbor();
    let cf_bytes = aafp_cbor::encode(&cf_cbor).unwrap();

    println!("--- ClientFinished ---");
    println!("session_id (hex): {}", hex::encode(&cf.session_id));
    println!("signature_len: {}", cf.signature.len());
    println!();
    println!("ClientFinished CBOR (hex):");
    println!("{}", hex::encode(&cf_bytes));
    println!("ClientFinished CBOR length: {} bytes", cf_bytes.len());
    println!();

    // --- Session ID derivation ---
    println!("--- Session ID Derivation ---");
    println!("salt = client_nonce || server_nonce (hex):");
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&client_nonce);
    salt.extend_from_slice(&server_nonce);
    println!("{}", hex::encode(&salt));
    println!("IKM = h_after_clienthello (hex):");
    println!("{}", hex::encode(&h_after_ch));
    println!("info = \"aafp-session-id-v1\" (hex):");
    println!("{}", hex::encode(b"aafp-session-id-v1"));
    println!("session_id (hex):");
    println!("{}", hex::encode(&session_id));
    println!();

    // --- Frame Format Examples ---
    println!("--- Frame Format ---");

    // DATA frame with "hello" payload
    let data_frame = Frame::data(0, b"hello".to_vec());
    let data_bytes = encode_frame(&data_frame).unwrap();
    println!("DATA frame (payload=\"hello\", hex):");
    println!("{}", hex::encode(&data_bytes));
    println!("DATA frame length: {} bytes", data_bytes.len());
    println!("  Header: {} bytes, Payload: 5 bytes", FRAME_HEADER_SIZE);
    println!();

    // Frame header breakdown
    println!("Frame header breakdown (28 bytes):");
    println!("  [0] Version: 0x{:02x} ({})", data_bytes[0], data_bytes[0]);
    println!("  [1] FrameType: 0x{:02x} (DATA)", data_bytes[1]);
    println!("  [2] Flags: 0x{:02x}", data_bytes[2]);
    println!("  [3] Reserved: 0x{:02x}", data_bytes[3]);
    let stream_id = u64::from_be_bytes(data_bytes[4..12].try_into().unwrap());
    println!("  [4-11] Stream ID: {} (0x{:016x})", stream_id, stream_id);
    let payload_len = u64::from_be_bytes(data_bytes[12..20].try_into().unwrap());
    println!("  [12-19] Payload Length: {}", payload_len);
    let ext_len = u64::from_be_bytes(data_bytes[20..28].try_into().unwrap());
    println!("  [20-27] Extension Length: {}", ext_len);
    println!();

    // HANDSHAKE frame wrapping ClientHello CBOR
    let hs_frame = Frame {
        frame_type: FrameType::Handshake,
        flags: 0,
        stream_id: 0,
        extensions: vec![],
        payload: ch_full_bytes.clone(),
    };
    let hs_bytes = encode_frame(&hs_frame).unwrap();
    println!("HANDSHAKE frame wrapping ClientHello (hex):");
    println!("  (first 64 bytes): {}", hex::encode(&hs_bytes[..64.min(hs_bytes.len())]));
    println!("  Total length: {} bytes (28 header + {} payload)", hs_bytes.len(), ch_full_bytes.len());
    println!();

    // --- CBOR Integer Key Mapping ---
    println!("--- CBOR Integer Key Mapping (RFC-0002 §8.4) ---");
    println!("ClientHello fields:");
    println!("  1: protocol_version (uint) = {}", ch.protocol_version);
    println!("  2: agent_id (bstr, 32 bytes)");
    println!("  3: public_key (bstr, 1952 bytes)");
    println!("  4: nonce (bstr, 32 bytes)");
    println!("  5: capabilities (array, empty)");
    println!("  6: extensions (array, empty)");
    println!("  7: signature (bstr, {} bytes)", ch.signature.len());
    println!("  8: expires_at (uint) = {}", ch.expires_at);
    println!("  9: receiver_mac (null)");
    println!("  10: key_algorithm (uint) = {}", ch.key_algorithm);
    println!();

    // --- Canonical CBOR Ordering ---
    println!("--- Canonical CBOR Ordering (RFC-0002 §8.1) ---");
    println!("Keys are sorted by length-first canonical byte ordering:");
    println!("  1-byte keys (0-23): 1, 2, 3, 4, 5, 6, 8, 10 (all < 24)");
    println!("  Key 7 (signature) is 1-byte, sorts between 6 and 8");
    println!("  Key 9 (receiver_mac) is 1-byte, sorts between 8 and 10");
    println!("  Key 10 is 1-byte (10 < 24)");
    println!("  Full order: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10");
    println!();

    // --- RPC Request Example ---
    println!("--- RPC Request (RFC-0002 §4.3) ---");
    let rpc_req = aafp_messaging::RpcRequest::new(42, "aafp.discovery.lookup")
        .with_params(aafp_cbor::Value::TextString("inference".to_string()));
    let rpc_bytes = rpc_req.encode().unwrap();
    println!("RpcRequest CBOR (hex):");
    println!("{}", hex::encode(&rpc_bytes));
    println!("RpcRequest CBOR length: {} bytes", rpc_bytes.len());
    println!("  1: id (uint) = 42");
    println!("  2: method (tstr) = \"aafp.discovery.lookup\"");
    println!("  3: params (any) = TextString(\"inference\")");
    println!();

    // --- Error Frame Example ---
    println!("--- Error Message (RFC-0002 §4.6) ---");
    let err_msg = aafp_messaging::ErrorMessage {
        code: 2007,
        message: "AgentId does not match SHA-256(public_key)".to_string(),
        data: None,
        fatal: true,
    };
    let err_cbor = err_msg.to_cbor();
    let err_bytes = aafp_cbor::encode(&err_cbor).unwrap();
    println!("ErrorMessage CBOR (hex):");
    println!("{}", hex::encode(&err_bytes));
    println!("ErrorMessage CBOR length: {} bytes", err_bytes.len());
    println!("  1: code (uint) = 2007 (INVALID_AGENT_ID)");
    println!("  2: message (tstr)");
    println!("  3: data (null)");
    println!("  4: fatal (bool) = true");
    println!();

    // --- Close Frame Example ---
    println!("--- Close Message (RFC-0002 §4.5) ---");
    let close_msg = aafp_messaging::CloseMessage {
        code: 0,
        message: "normal close".to_string(),
    };
    let close_cbor = close_msg.to_cbor();
    let close_bytes = aafp_cbor::encode(&close_cbor).unwrap();
    println!("CloseMessage CBOR (hex):");
    println!("{}", hex::encode(&close_bytes));
    println!("CloseMessage CBOR length: {} bytes", close_bytes.len());
    println!("  1: code (uint) = 0 (OK)");
    println!("  2: message (tstr) = \"normal close\"");
    println!();

    println!("=== Golden Trace Generation Complete ===");
}

fn generate_keypair(_label: &str) -> FixedKeypair {
    let (pk, sk) = MlDsa65::keypair();
    FixedKeypair {
        public_key: pk.0,
        secret_key: sk.0,
    }
}
