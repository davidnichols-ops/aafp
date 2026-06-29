//! Handshake driver: orchestrates the AAFP v1 handshake over a QUIC stream
//! and drives the Session state machine.
//!
//! This module replaces the MVP placeholder identity derivation (which hashed
//! the remote address) with real cryptographic identity verification using
//! ML-DSA-65 signatures and the AgentId ↔ public_key invariant.
//!
//! ## Flow
//!
//! ```text
//! [QUIC connection established]
//!     ↓
//! Session::new() → Connecting
//!     ↓
//! on_transport_established() → TransportEstablished
//!     ↓
//! Exchange ClientHello / ServerHello / ClientFinished over stream 0
//!     ↓
//! verify_client_hello() / verify_server_hello() → IdentityVerified
//!     ↓
//! (AuthorizationProvider will transition to AuthorizationVerified)
//!     ↓
//! (SDK will transition to Authenticated → MessagingEnabled)
//! ```

use crate::SdkError;
use aafp_core::{
    NegotiatedFeatures, Session, SessionId, TransportHandle, SESSION_ID_SIZE,
};
use aafp_crypto::{
    derive_session_id, generate_nonce, verify_client_finished, verify_client_hello,
    verify_server_hello, ClientFinished, ClientHelloV1,
    HandshakeError, ServerHelloV1, TranscriptHash,
    DOMAIN_SEPARATOR, KEY_ALG_ML_DSA_65, NONCE_SIZE, PROTOCOL_VERSION,
    TLS_EXPORTER_LABEL,
};
use aafp_crypto::{MlDsa65, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use aafp_identity::{AgentId, AgentKeypair};
use aafp_transport_quic::QuicConnection;
use sha2::Digest;
use std::time::SystemTime;

/// Information about the verified peer, returned after a successful handshake.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Cryptographically verified peer AgentId.
    pub agent_id: AgentId,
    /// Peer's ML-DSA-65 public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// Session ID derived from the handshake transcript.
    pub session_id: SessionId,
}

/// A TransportHandle backed by a QUIC connection.
struct QuicTransportHandle {
    remote_addr: String,
    closed: bool,
}

impl TransportHandle for QuicTransportHandle {
    fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Get the current time as Unix epoch seconds.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read a length-prefixed CBOR message from a QUIC receive stream.
///
/// Format: 4-byte big-endian length prefix, then CBOR bytes.
async fn read_message(
    recv: &mut aafp_transport_quic::QuicRecvStream,
) -> Result<Vec<u8>, SdkError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(SdkError::Handshake(format!(
            "handshake message too large: {len} bytes"
        )));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed CBOR message to a QUIC send stream.
async fn write_message(
    send: &mut aafp_transport_quic::QuicSendStream,
    msg: &[u8],
) -> Result<(), SdkError> {
    use tokio::io::AsyncWriteExt;
    let len = msg.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(msg).await?;
    Ok(())
}

/// Encode a ClientHello to CBOR bytes.
fn encode_client_hello(ch: &ClientHelloV1) -> Vec<u8> {
    aafp_cbor::encode(&ch.to_cbor()).expect("CBOR encoding of ClientHello must succeed")
}

/// Encode a ServerHello to CBOR bytes.
fn encode_server_hello(sh: &ServerHelloV1) -> Vec<u8> {
    aafp_cbor::encode(&sh.to_cbor()).expect("CBOR encoding of ServerHello must succeed")
}

/// Encode a ClientFinished to CBOR bytes.
fn encode_client_finished(cf: &ClientFinished) -> Vec<u8> {
    aafp_cbor::encode(&cf.to_cbor()).expect("CBOR encoding of ClientFinished must succeed")
}

/// Decode a ClientHello from CBOR bytes.
fn decode_client_hello(data: &[u8]) -> Result<ClientHelloV1, HandshakeError> {
    let (val, _) = aafp_cbor::decode(data).map_err(HandshakeError::Cbor)?;
    ClientHelloV1::from_cbor(&val)
}

/// Decode a ServerHello from CBOR bytes.
fn decode_server_hello(data: &[u8]) -> Result<ServerHelloV1, HandshakeError> {
    let (val, _) = aafp_cbor::decode(data).map_err(HandshakeError::Cbor)?;
    ServerHelloV1::from_cbor(&val)
}

/// Decode a ClientFinished from CBOR bytes.
fn decode_client_finished(data: &[u8]) -> Result<ClientFinished, HandshakeError> {
    let (val, _) = aafp_cbor::decode(data).map_err(HandshakeError::Cbor)?;
    ClientFinished::from_cbor(&val)
}

/// Compute the signature input: domain_separator || transcript_hash.
fn signature_input(h: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 32);
    input.extend_from_slice(DOMAIN_SEPARATOR);
    input.extend_from_slice(h);
    input
}

/// Sign a message using the agent's secret key (converting from Vec<u8>).
fn sign_with_keypair(keypair: &AgentKeypair, msg: &[u8]) -> Vec<u8> {
    let sk = MlDsa65SecretKey::from_bytes(&keypair.secret_key)
        .expect("agent secret key must be valid ML-DSA-65");
    MlDsa65::sign(&sk, msg).0
}

/// Drive the client-side AAFP v1 handshake over a QUIC connection.
///
/// This function:
/// 1. Creates a Session in `Connecting` state
/// 2. Opens stream 0 and transitions to `TransportEstablished`
/// 3. Sends ClientHello, receives ServerHello, verifies it → `IdentityVerified`
/// 4. Sends ClientFinished
/// 5. Returns the populated Session and verified peer info
///
/// The caller is responsible for:
/// - Transitioning to `AuthorizationVerified` (via AuthorizationProvider)
/// - Transitioning to `Authenticated` and `MessagingEnabled`
pub async fn drive_client_handshake(
    conn: QuicConnection,
    keypair: &AgentKeypair,
    tls_binding: [u8; 32],
) -> Result<(Session, PeerInfo), SdkError> {
    let mut session = Session::new();

    // --- TransportEstablished ---
    let remote_addr = conn.remote_multiaddr();
    session.on_transport_established(
        Box::new(QuicTransportHandle {
            remote_addr: remote_addr.clone(),
            closed: false,
        }),
        NegotiatedFeatures {
            protocol_version: PROTOCOL_VERSION as u8,
            extensions: vec![],
        },
    )
    .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;

    // Open stream 0 for the handshake
    let (mut send, mut recv) = conn.open_bi().await?;

    // --- Build and send ClientHello ---
    let client_nonce = generate_nonce();
    let agent_id = sha2::Sha256::digest(&keypair.public_key).to_vec();

    let mut th = TranscriptHash::from_tls_binding(&tls_binding);

    let mut ch = ClientHelloV1 {
        protocol_version: PROTOCOL_VERSION,
        agent_id: agent_id.clone(),
        public_key: keypair.public_key.clone(),
        nonce: client_nonce,
        capabilities: vec![],
        extensions: vec![],
        signature: vec![],
        expires_at: now_unix() + 3600, // 1 hour expiry
        receiver_mac: None,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    // Fold ClientHello into transcript and sign
    let ch_cbor = ch.to_cbor_without_sig_and_mac();
    let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).map_err(|e| {
        SdkError::Handshake(format!("CBOR encoding error: {e}"))
    })?;
    let h_after_ch = th.fold(&ch_cbor_bytes);

    let sig = sign_with_keypair(keypair, &signature_input(&h_after_ch));
    ch.signature = sig;

    // Send ClientHello
    write_message(&mut send, &encode_client_hello(&ch)).await?;

    // --- Receive and verify ServerHello ---
    let sh_bytes = read_message(&mut recv).await?;
    let sh = decode_server_hello(&sh_bytes).map_err(|e| {
        SdkError::Handshake(format!("ServerHello decode error: {e}"))
    })?;

    // Fold ServerHello into transcript
    let sh_cbor = sh.to_cbor_without_sig();
    let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).map_err(|e| {
        SdkError::Handshake(format!("CBOR encoding error: {e}"))
    })?;
    let h_after_sh = th.fold(&sh_cbor_bytes);

    // Verify ServerHello (checks agent_id ↔ public_key, signature, version, expiry)
    let (server_agent_id, session_id) =
        verify_server_hello(&sh, &h_after_sh, now_unix()).map_err(|e| {
            SdkError::Handshake(format!("ServerHello verification failed: {e}"))
        })?;

    // --- Send ClientFinished ---
    let cf = ClientFinished {
        session_id,
        signature: sign_with_keypair(keypair, &signature_input(&h_after_sh)),
    };
    write_message(&mut send, &encode_client_finished(&cf)).await?;

    // --- IdentityVerified ---
    session
        .on_identity_verified(server_agent_id, session_id)
        .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;

    let peer_info = PeerInfo {
        agent_id: server_agent_id,
        public_key: sh.public_key.clone(),
        session_id,
    };

    Ok((session, peer_info))
}

/// Drive the server-side AAFP v1 handshake over a QUIC connection.
///
/// This function:
/// 1. Creates a Session in `Connecting` state
/// 2. Accepts stream 0 and transitions to `TransportEstablished`
/// 3. Receives ClientHello, verifies it → prepares ServerHello
/// 4. Sends ServerHello, receives ClientFinished, verifies it → `IdentityVerified`
/// 5. Returns the populated Session and verified peer info
pub async fn drive_server_handshake(
    conn: QuicConnection,
    keypair: &AgentKeypair,
    tls_binding: [u8; 32],
) -> Result<(Session, PeerInfo), SdkError> {
    let mut session = Session::new();

    // --- TransportEstablished ---
    let remote_addr = conn.remote_multiaddr();
    session.on_transport_established(
        Box::new(QuicTransportHandle {
            remote_addr: remote_addr.clone(),
            closed: false,
        }),
        NegotiatedFeatures {
            protocol_version: PROTOCOL_VERSION as u8,
            extensions: vec![],
        },
    )
    .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;

    // Accept stream 0 for the handshake
    let (mut send, mut recv) = conn.accept_bi().await?;

    // --- Receive and verify ClientHello ---
    let ch_bytes = read_message(&mut recv).await?;
    let ch = decode_client_hello(&ch_bytes).map_err(|e| {
        SdkError::Handshake(format!("ClientHello decode error: {e}"))
    })?;

    let mut th = TranscriptHash::from_tls_binding(&tls_binding);

    // Fold ClientHello into transcript
    let ch_cbor = ch.to_cbor_without_sig_and_mac();
    let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).map_err(|e| {
        SdkError::Handshake(format!("CBOR encoding error: {e}"))
    })?;
    let h_after_ch = th.fold(&ch_cbor_bytes);

    // Verify ClientHello (checks agent_id ↔ public_key, signature, version, expiry)
    let client_agent_id =
        verify_client_hello(&ch, &h_after_ch, now_unix()).map_err(|e| {
            SdkError::Handshake(format!("ClientHello verification failed: {e}"))
        })?;

    // --- Build and send ServerHello ---
    let server_nonce = generate_nonce();
    let server_agent_id = sha2::Sha256::digest(&keypair.public_key).to_vec();
    let session_id = derive_session_id(&h_after_ch, &ch.nonce, &server_nonce);

    let mut sh = ServerHelloV1 {
        protocol_version: PROTOCOL_VERSION,
        agent_id: server_agent_id,
        public_key: keypair.public_key.clone(),
        nonce: server_nonce,
        capabilities: vec![],
        extensions: vec![],
        session_id,
        signature: vec![],
        expires_at: now_unix() + 3600,
        key_algorithm: KEY_ALG_ML_DSA_65,
    };

    // Fold ServerHello into transcript and sign
    let sh_cbor = sh.to_cbor_without_sig();
    let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).map_err(|e| {
        SdkError::Handshake(format!("CBOR encoding error: {e}"))
    })?;
    let h_after_sh = th.fold(&sh_cbor_bytes);

    let sig = sign_with_keypair(keypair, &signature_input(&h_after_sh));
    sh.signature = sig;

    // Send ServerHello
    write_message(&mut send, &encode_server_hello(&sh)).await?;

    // --- Receive and verify ClientFinished ---
    let cf_bytes = read_message(&mut recv).await?;
    let cf = decode_client_finished(&cf_bytes).map_err(|e| {
        SdkError::Handshake(format!("ClientFinished decode error: {e}"))
    })?;

    verify_client_finished(&cf, &h_after_sh, &ch.public_key, &session_id).map_err(|e| {
        SdkError::Handshake(format!("ClientFinished verification failed: {e}"))
    })?;

    // --- IdentityVerified ---
    session
        .on_identity_verified(client_agent_id, session_id)
        .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;

    let peer_info = PeerInfo {
        agent_id: client_agent_id,
        public_key: ch.public_key.clone(),
        session_id,
    };

    Ok((session, peer_info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_identity::AgentKeypair;

    /// Test that a full client ↔ server handshake completes successfully
    /// and both sessions reach IdentityVerified with matching state.
    #[tokio::test]
    async fn test_full_handshake_state_machine() {
        let client_kp = AgentKeypair::generate();
        let server_kp = AgentKeypair::generate();
        let tls_binding = [0x42u8; 32];

        // We can't test with real QUIC connections in a unit test,
        // but we can test the handshake logic by simulating the message
        // exchange directly.
        let client_agent_id: AgentId =
            sha2::Sha256::digest(&client_kp.public_key).into();
        let server_agent_id: AgentId =
            sha2::Sha256::digest(&server_kp.public_key).into();

        // --- Simulate client side: build ClientHello ---
        let client_nonce = generate_nonce();
        let mut th_client = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id: client_agent_id.to_vec(),
            public_key: client_kp.public_key.clone(),
            nonce: client_nonce,
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: now_unix() + 3600,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h_after_ch = th_client.fold(&ch_cbor_bytes);
        ch.signature = sign_with_keypair(&client_kp, &signature_input(&h_after_ch));

        // --- Simulate server side: verify ClientHello ---
        let mut th_server = TranscriptHash::from_tls_binding(&tls_binding);
        let ch_cbor_verify = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_verify_bytes = aafp_cbor::encode(&ch_cbor_verify).unwrap();
        let h_after_ch_server = th_server.fold(&ch_cbor_verify_bytes);
        assert_eq!(h_after_ch_server, h_after_ch);

        let verified_client_id =
            verify_client_hello(&ch, &h_after_ch_server, now_unix()).unwrap();
        assert_eq!(verified_client_id, client_agent_id);

        // --- Simulate server side: build ServerHello ---
        let server_nonce = generate_nonce();
        let session_id = derive_session_id(&h_after_ch, &client_nonce, &server_nonce);

        let mut sh = ServerHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id: server_agent_id.to_vec(),
            public_key: server_kp.public_key.clone(),
            nonce: server_nonce,
            capabilities: vec![],
            extensions: vec![],
            session_id,
            signature: vec![],
            expires_at: now_unix() + 3600,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let sh_cbor = sh.to_cbor_without_sig();
        let sh_cbor_bytes = aafp_cbor::encode(&sh_cbor).unwrap();
        let h_after_sh = th_server.fold(&sh_cbor_bytes);
        sh.signature = sign_with_keypair(&server_kp, &signature_input(&h_after_sh));

        // --- Simulate client side: verify ServerHello ---
        let sh_cbor_verify = sh.to_cbor_without_sig();
        let sh_cbor_verify_bytes = aafp_cbor::encode(&sh_cbor_verify).unwrap();
        let h_after_sh_client = th_client.fold(&sh_cbor_verify_bytes);
        assert_eq!(h_after_sh_client, h_after_sh);

        let (verified_server_id, verified_session_id) =
            verify_server_hello(&sh, &h_after_sh_client, now_unix()).unwrap();
        assert_eq!(verified_server_id, server_agent_id);
        assert_eq!(verified_session_id, session_id);

        // --- Simulate client side: build ClientFinished ---
        let cf = ClientFinished {
            session_id,
            signature: sign_with_keypair(&client_kp, &signature_input(&h_after_sh)),
        };

        // --- Simulate server side: verify ClientFinished ---
        verify_client_finished(&cf, &h_after_sh, &client_kp.public_key, &session_id).unwrap();

        // --- Verify both sessions would be in IdentityVerified ---
        let mut client_session = Session::new();
        client_session
            .on_transport_established(
                Box::new(QuicTransportHandle {
                    remote_addr: "quic://test".into(),
                    closed: false,
                }),
                NegotiatedFeatures {
                    protocol_version: 1,
                    extensions: vec![],
                },
            )
            .unwrap();
        client_session
            .on_identity_verified(verified_server_id, session_id)
            .unwrap();
        assert_eq!(client_session.state(), aafp_core::SessionState::IdentityVerified);
        assert_eq!(client_session.peer_agent_id(), Some(&server_agent_id));
        assert_eq!(client_session.session_id(), Some(&session_id));

        let mut server_session = Session::new();
        server_session
            .on_transport_established(
                Box::new(QuicTransportHandle {
                    remote_addr: "quic://test".into(),
                    closed: false,
                }),
                NegotiatedFeatures {
                    protocol_version: 1,
                    extensions: vec![],
                },
            )
            .unwrap();
        server_session
            .on_identity_verified(verified_client_id, session_id)
            .unwrap();
        assert_eq!(server_session.state(), aafp_core::SessionState::IdentityVerified);
        assert_eq!(server_session.peer_agent_id(), Some(&client_agent_id));
        assert_eq!(server_session.session_id(), Some(&session_id));
    }

    #[test]
    fn test_handshake_rejects_mismatched_identity() {
        let client_kp = AgentKeypair::generate();
        let tls_binding = [0x42u8; 32];
        let now = now_unix();

        // Build a ClientHello with a WRONG agent_id (not SHA-256 of public_key)
        let client_nonce = generate_nonce();
        let mut th = TranscriptHash::from_tls_binding(&tls_binding);

        let mut ch = ClientHelloV1 {
            protocol_version: PROTOCOL_VERSION,
            agent_id: vec![0xFFu8; 32], // Wrong! Not SHA-256(public_key)
            public_key: client_kp.public_key.clone(),
            nonce: client_nonce,
            capabilities: vec![],
            extensions: vec![],
            signature: vec![],
            expires_at: now + 3600,
            receiver_mac: None,
            key_algorithm: KEY_ALG_ML_DSA_65,
        };

        let ch_cbor = ch.to_cbor_without_sig_and_mac();
        let ch_cbor_bytes = aafp_cbor::encode(&ch_cbor).unwrap();
        let h_after_ch = th.fold(&ch_cbor_bytes);
        ch.signature = sign_with_keypair(&client_kp, &signature_input(&h_after_ch));

        // Verification must fail with InvalidAgentId
        let err = verify_client_hello(&ch, &h_after_ch, now).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAgentId), "got {err:?}");
    }
}
