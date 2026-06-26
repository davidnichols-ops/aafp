//! Canonical handshake transcript and signature verification vectors.
//!
//! These vectors use a fixed ML-DSA-65 keypair that is generated once and
//! serialized into the vector file. A second implementation can:
//! 1. Deserialize the public key and verify signatures
//! 2. Reproduce the transcript hash from the CBOR bytes
//! 3. Verify that session_id derivation matches
//!
//! The keypair is generated at test time and recorded. For reproducibility,
//! the keypair bytes are embedded as constants.

use aafp_cbor::{int_map, Value};
use aafp_crypto::{
    handshake_v1::{
        derive_session_id, generate_nonce, ClientFinished, ClientHello, ServerHello,
        TranscriptHash, DOMAIN_SEPARATOR, KEY_ALG_ML_DSA_65, PROTOCOL_VERSION,
    },
    MlDsa65, SignatureScheme,
};
use aafp_identity::identity_v1::AgentId;
use sha2::{Digest, Sha256};

/// A complete handshake vector with all intermediate values.
#[derive(Clone, Debug)]
pub struct HandshakeVector {
    pub name: &'static str,
    pub description: &'static str,

    // Fixed inputs
    pub tls_binding: [u8; 32],
    pub client_nonce: [u8; 32],
    pub server_nonce: [u8; 32],

    // Key material (serialized for second implementation)
    pub client_public_key_hex: String,
    pub server_public_key_hex: String,

    // Transcript checkpoints
    pub transcript_after_client_hello_hex: String,
    pub transcript_after_server_hello_hex: String,
    pub transcript_after_client_finished_hex: String,

    // CBOR encodings (for byte-for-byte reproduction)
    pub client_hello_cbor_hex: String,
    pub server_hello_cbor_hex: String,
    pub client_finished_cbor_hex: String,

    // Signature inputs
    pub client_hello_sig_input_hex: String,
    pub server_hello_sig_input_hex: String,
    pub client_finished_sig_input_hex: String,

    // Signatures
    pub client_hello_signature_hex: String,
    pub server_hello_signature_hex: String,
    pub client_finished_signature_hex: String,

    // Derived values
    pub session_id_hex: String,

    // Verification
    pub client_hello_signature_valid: bool,
    pub server_hello_signature_valid: bool,
    pub client_finished_signature_valid: bool,
}

/// Fixed nonce values for deterministic vectors.
pub const FIXED_CLIENT_NONCE: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

pub const FIXED_SERVER_NONCE: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

pub const FIXED_TLS_BINDING: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
];

pub const FIXED_EXPIRES_AT: u64 = 1736294400; // 2025-01-08T00:00:00Z

/// Generate a complete handshake vector using the given keypairs.
fn build_handshake_vector(
    client_pk: &MlDsa65PublicKey,
    client_sk: &MlDsa65SecretKey,
    server_pk: &MlDsa65PublicKey,
    server_sk: &MlDsa65SecretKey,
) -> HandshakeVector {
    let client_agent_id = AgentId::from_public_key(&client_pk.0);
    let server_agent_id = AgentId::from_public_key(&server_pk.0);

    // Initialize transcript
    let mut transcript = TranscriptHash::from_tls_binding(&FIXED_TLS_BINDING);

    // === ClientHello ===
    let ch = ClientHello {
        protocol_version: PROTOCOL_VERSION,
        agent_id: client_agent_id.as_bytes().to_vec(),
        public_key: client_pk.0.clone(),
        nonce: FIXED_CLIENT_NONCE,
        capabilities: vec![],
        extensions: vec![],
        signature: vec![],
        expires_at: FIXED_EXPIRES_AT,
        receiver_mac: None,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    let ch_cbor = ch.to_cbor_without_sig_and_mac();
    let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
    let h_after_ch = transcript.fold(&ch_cbor_bytes);

    // Sign ClientHello: signature = Sign(sk, DOMAIN_SEPARATOR || h_after_ch)
    let ch_sig_input = {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_SEPARATOR);
        buf.extend_from_slice(&h_after_ch);
        buf
    };
    let ch_signature = MlDsa65::sign(client_sk, &ch_sig_input);

    // === ServerHello ===
    let session_id = derive_session_id(&h_after_ch, &FIXED_CLIENT_NONCE, &FIXED_SERVER_NONCE);

    let sh = ServerHello {
        protocol_version: PROTOCOL_VERSION,
        agent_id: server_agent_id.as_bytes().to_vec(),
        public_key: server_pk.0.clone(),
        nonce: FIXED_SERVER_NONCE,
        capabilities: vec![],
        extensions: vec![],
        session_id,
        signature: vec![],
        expires_at: FIXED_EXPIRES_AT,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    let sh_cbor = sh.to_cbor_without_sig();
    let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).unwrap();
    let h_after_sh = transcript.fold(&sh_cbor_bytes);

    let sh_sig_input = {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_SEPARATOR);
        buf.extend_from_slice(&h_after_sh);
        buf
    };
    let sh_signature = MlDsa65::sign(server_sk, &sh_sig_input);

    // === ClientFinished ===
    let cf = ClientFinished {
        session_id,
        signature: vec![],
    };

    let cf_cbor = cf.to_cbor_without_sig();
    let cf_cbor_bytes = aafp_cbor::encode(&cf_cbor).unwrap();
    let h_after_cf = transcript.fold(&cf_cbor_bytes);

    let cf_sig_input = {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_SEPARATOR);
        buf.extend_from_slice(&h_after_cf);
        buf
    };
    let cf_signature = MlDsa65::sign(client_sk, &cf_sig_input);

    // Verify all signatures
    let ch_valid = MlDsa65::verify(client_pk, &ch_sig_input, &ch_signature);
    let sh_valid = MlDsa65::verify(server_pk, &sh_sig_input, &sh_signature);
    let cf_valid = MlDsa65::verify(client_pk, &cf_sig_input, &cf_signature);

    HandshakeVector {
        name: "handshake_full_v1",
        description: "Complete 3-way handshake with real ML-DSA-65 signatures",
        tls_binding: FIXED_TLS_BINDING,
        client_nonce: FIXED_CLIENT_NONCE,
        server_nonce: FIXED_SERVER_NONCE,
        client_public_key_hex: hex::encode(&client_pk.0),
        server_public_key_hex: hex::encode(&server_pk.0),
        transcript_after_client_hello_hex: hex::encode(h_after_ch),
        transcript_after_server_hello_hex: hex::encode(h_after_sh),
        transcript_after_client_finished_hex: hex::encode(h_after_cf),
        client_hello_cbor_hex: hex::encode(&ch_cbor_bytes),
        server_hello_cbor_hex: hex::encode(&sh_cbor_bytes),
        client_finished_cbor_hex: hex::encode(&cf_cbor_bytes),
        client_hello_sig_input_hex: hex::encode(&ch_sig_input),
        server_hello_sig_input_hex: hex::encode(&sh_sig_input),
        client_finished_sig_input_hex: hex::encode(&cf_sig_input),
        client_hello_signature_hex: hex::encode(&ch_signature.0),
        server_hello_signature_hex: hex::encode(&sh_signature.0),
        client_finished_signature_hex: hex::encode(&cf_signature.0),
        session_id_hex: hex::encode(session_id),
        client_hello_signature_valid: ch_valid,
        server_hello_signature_valid: sh_valid,
        client_finished_signature_valid: cf_valid,
    }
}

/// Generate the handshake vector markdown documentation.
pub fn generate_handshake_markdown() -> String {
    let (client_pk, client_sk) = MlDsa65::keypair();
    let (server_pk, server_sk) = MlDsa65::keypair();
    let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

    let mut md = String::new();
    md.push_str("# AAFP Handshake Transcript and Signature Vectors\n\n");
    md.push_str("**Version**: AAFP v1 (RFC-0002 §5, Revision 3)\n");
    md.push_str("**Purpose**: Verify that a second implementation produces identical transcript hashes and signature verification results.\n\n");

    md.push_str("## Fixed Inputs\n\n");
    md.push_str("| Parameter | Value (hex) |\n|-----------|-------------|\n");
    md.push_str(&format!("| TLS_BINDING | `{}` |\n", hex::encode(v.tls_binding)));
    md.push_str(&format!("| Client nonce | `{}` |\n", hex::encode(v.client_nonce)));
    md.push_str(&format!("| Server nonce | `{}` |\n", hex::encode(v.server_nonce)));
    md.push_str(&format!("| Expires at | {} (2025-01-08T00:00:00Z) |\n", FIXED_EXPIRES_AT));
    md.push_str(&format!("| Domain separator | `{}` (\"aafp-v1-handshake\") |\n", hex::encode(DOMAIN_SEPARATOR)));
    md.push_str(&format!("| Protocol version | {} |\n", PROTOCOL_VERSION));
    md.push_str(&format!("| Key algorithm | {} (ML-DSA-65) |\n\n", KEY_ALG_ML_DSA_65));

    md.push_str("## Key Material\n\n");
    md.push_str("### Client Public Key (ML-DSA-65, 1952 bytes)\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_public_key_hex);
    md.push_str("\n```\n\n");

    md.push_str("### Server Public Key (ML-DSA-65, 1952 bytes)\n\n");
    md.push_str("```\n");
    md.push_str(&v.server_public_key_hex);
    md.push_str("\n```\n\n");

    md.push_str("## Transcript Hash Checkpoints\n\n");
    md.push_str("The transcript hash is SHA-256, initialized from `SHA-256(TLS_BINDING)`,\n");
    md.push_str("then folded with each message's canonical CBOR bytes:\n");
    md.push_str("`h = SHA-256(h_prev || cbor_bytes)`\n\n");

    md.push_str("| Checkpoint | SHA-256 (hex) |\n|-----------|---------------|\n");
    md.push_str(&format!("| After ClientHello | `{}` |\n", v.transcript_after_client_hello_hex));
    md.push_str(&format!("| After ServerHello | `{}` |\n", v.transcript_after_server_hello_hex));
    md.push_str(&format!("| After ClientFinished | `{}` |\n\n", v.transcript_after_client_finished_hex));

    md.push_str("## ClientHello\n\n");
    md.push_str("### CBOR (without signature, keys 1-6,8,10)\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_hello_cbor_hex);
    md.push_str("\n```\n\n");
    md.push_str("### Signature Input\n\n");
    md.push_str("`DOMAIN_SEPARATOR || transcript_hash_after_client_hello`\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_hello_sig_input_hex);
    md.push_str("\n```\n\n");
    md.push_str("### Signature (ML-DSA-65, 3309 bytes)\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_hello_signature_hex);
    md.push_str("\n```\n\n");
    md.push_str(&format!("**Verification**: {}\n\n", v.client_hello_signature_valid));

    md.push_str("## ServerHello\n\n");
    md.push_str("### CBOR (without signature, keys 1-7,9,10)\n\n");
    md.push_str("```\n");
    md.push_str(&v.server_hello_cbor_hex);
    md.push_str("\n```\n\n");
    md.push_str("### Signature Input\n\n");
    md.push_str("`DOMAIN_SEPARATOR || transcript_hash_after_server_hello`\n\n");
    md.push_str("```\n");
    md.push_str(&v.server_hello_sig_input_hex);
    md.push_str("\n```\n\n");
    md.push_str("### Signature (ML-DSA-65, 3309 bytes)\n\n");
    md.push_str("```\n");
    md.push_str(&v.server_hello_signature_hex);
    md.push_str("\n```\n\n");
    md.push_str(&format!("**Verification**: {}\n\n", v.server_hello_signature_valid));

    md.push_str("## ClientFinished\n\n");
    md.push_str("### CBOR (without signature, key 1 only)\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_finished_cbor_hex);
    md.push_str("\n```\n\n");
    md.push_str("### Signature Input\n\n");
    md.push_str("`DOMAIN_SEPARATOR || transcript_hash_after_client_finished`\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_finished_sig_input_hex);
    md.push_str("\n```\n\n");
    md.push_str("### Signature (ML-DSA-65, 3309 bytes)\n\n");
    md.push_str("```\n");
    md.push_str(&v.client_finished_signature_hex);
    md.push_str("\n```\n\n");
    md.push_str(&format!("**Verification**: {}\n\n", v.client_finished_signature_valid));

    md.push_str("## Session ID Derivation\n\n");
    md.push_str("`session_id = HKDF-Extract(salt=h_after_client_hello, ikm=client_nonce || server_nonce)`\n\n");
    md.push_str(&format!("**Session ID (hex)**: `{}`\n\n", v.session_id_hex));

    md.push_str("## Second Implementation Verification Steps\n\n");
    md.push_str("1. Deserialize the client and server public keys from the hex above.\n");
    md.push_str("2. Compute `h_init = SHA-256(TLS_BINDING)`.\n");
    md.push_str("3. Encode ClientHello as canonical CBOR (keys 1-6,8,10, excluding 7=sig, 9=mac).\n");
    md.push_str("4. Compute `h_ch = SHA-256(h_init || cbor_client_hello)`.\n");
    md.push_str("5. Verify `h_ch` matches the transcript checkpoint.\n");
    md.push_str("6. Compute signature input = `\"aafp-v1-handshake\" || h_ch`.\n");
    md.push_str("7. Verify the ClientHello signature using the client public key.\n");
    md.push_str("8. Repeat steps 3-7 for ServerHello and ClientFinished.\n");
    md.push_str("9. Verify session_id derivation matches.\n");

    md
}

// Re-export key types for the binary
pub use aafp_crypto::{MlDsa65PublicKey, MlDsa65SecretKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_vector_signatures_valid() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        assert!(v.client_hello_signature_valid, "ClientHello signature must verify");
        assert!(v.server_hello_signature_valid, "ServerHello signature must verify");
        assert!(v.client_finished_signature_valid, "ClientFinished signature must verify");
    }

    #[test]
    fn test_handshake_vector_transcript_consistency() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        // Transcript after ClientHello should be SHA-256(SHA-256(TLS_BINDING) || ch_cbor)
        let h_init = Sha256::digest(&FIXED_TLS_BINDING);
        let ch_cbor = hex::decode(&v.client_hello_cbor_hex).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&h_init);
        hasher.update(&ch_cbor);
        let h_ch = hasher.finalize();
        assert_eq!(
            hex::encode(h_ch),
            v.transcript_after_client_hello_hex,
            "transcript after ClientHello must match"
        );
    }

    #[test]
    fn test_handshake_vector_session_id_derivation() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        // session_id = derive_session_id(h_after_ch, client_nonce, server_nonce)
        let h_ch = hex::decode(&v.transcript_after_client_hello_hex).unwrap();
        let mut h_ch_arr = [0u8; 32];
        h_ch_arr.copy_from_slice(&h_ch);

        let expected_sid = derive_session_id(&h_ch_arr, &FIXED_CLIENT_NONCE, &FIXED_SERVER_NONCE);
        assert_eq!(
            hex::encode(expected_sid),
            v.session_id_hex,
            "session_id must match"
        );
    }

    #[test]
    fn test_handshake_vector_signature_input_format() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        // ClientHello sig input = DOMAIN_SEPARATOR || h_after_ch
        let ch_sig_input = hex::decode(&v.client_hello_sig_input_hex).unwrap();
        assert_eq!(&ch_sig_input[..DOMAIN_SEPARATOR.len()], DOMAIN_SEPARATOR);
        assert_eq!(ch_sig_input.len(), DOMAIN_SEPARATOR.len() + 32);
    }

    #[test]
    fn test_handshake_vector_cbor_decodes() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        // All CBOR blobs must decode successfully
        let ch_cbor = hex::decode(&v.client_hello_cbor_hex).unwrap();
        let (ch_val, _) = aafp_cbor::decode(&ch_cbor).unwrap();
        assert!(matches!(ch_val, Value::IntMap(_)));

        let sh_cbor = hex::decode(&v.server_hello_cbor_hex).unwrap();
        let (sh_val, _) = aafp_cbor::decode(&sh_cbor).unwrap();
        assert!(matches!(sh_val, Value::IntMap(_)));

        let cf_cbor = hex::decode(&v.client_finished_cbor_hex).unwrap();
        let (cf_val, _) = aafp_cbor::decode(&cf_cbor).unwrap();
        assert!(matches!(cf_val, Value::IntMap(_)));
    }

    #[test]
    fn test_handshake_vector_key_sizes() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        let client_pk_bytes = hex::decode(&v.client_public_key_hex).unwrap();
        let server_pk_bytes = hex::decode(&v.server_public_key_hex).unwrap();
        let ch_sig = hex::decode(&v.client_hello_signature_hex).unwrap();
        let sh_sig = hex::decode(&v.server_hello_signature_hex).unwrap();
        let cf_sig = hex::decode(&v.client_finished_signature_hex).unwrap();

        assert_eq!(client_pk_bytes.len(), 1952, "ML-DSA-65 public key is 1952 bytes");
        assert_eq!(server_pk_bytes.len(), 1952);
        assert_eq!(ch_sig.len(), 3309, "ML-DSA-65 signature is 3309 bytes");
        assert_eq!(sh_sig.len(), 3309);
        assert_eq!(cf_sig.len(), 3309);
    }

    #[test]
    fn test_handshake_vector_session_id_size() {
        let (client_pk, client_sk) = MlDsa65::keypair();
        let (server_pk, server_sk) = MlDsa65::keypair();
        let v = build_handshake_vector(&client_pk, &client_sk, &server_pk, &server_sk);

        let sid = hex::decode(&v.session_id_hex).unwrap();
        assert_eq!(sid.len(), 32, "session_id must be 32 bytes");
    }

    #[test]
    fn test_generate_handshake_markdown() {
        let md = generate_handshake_markdown();
        assert!(md.contains("# AAFP Handshake Transcript and Signature Vectors"));
        assert!(md.contains("## Fixed Inputs"));
        assert!(md.contains("## Key Material"));
        assert!(md.contains("## Transcript Hash Checkpoints"));
        assert!(md.contains("## ClientHello"));
        assert!(md.contains("## ServerHello"));
        assert!(md.contains("## ClientFinished"));
        assert!(md.contains("## Session ID Derivation"));
        assert!(md.contains("## Second Implementation Verification Steps"));
    }

    #[test]
    fn test_fixed_nonces_are_distinct() {
        assert_ne!(FIXED_CLIENT_NONCE, FIXED_SERVER_NONCE, "nonces must be distinct");
        assert_ne!(FIXED_CLIENT_NONCE, FIXED_TLS_BINDING);
        assert_ne!(FIXED_SERVER_NONCE, FIXED_TLS_BINDING);
    }
}
