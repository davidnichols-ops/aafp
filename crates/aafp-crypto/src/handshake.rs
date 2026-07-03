#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::all)]

//! PQ hybrid 1-RTT application-layer handshake (LEGACY v0).
//!
//! This is the pre-RFC v0 handshake implementation. It is kept for
//! backward compatibility with existing tests and benchmarks only.
//! The RFC-0002 compliant handshake is in [`crate::handshake_v1`].
//! This module uses a binary (non-CBOR) wire format that is NOT
//! RFC-0002 compliant. Do NOT use for wire serialization.
//!
//! ## Wire format
//! See `AAFP_Architecture_Deliverable.md` Phase 2.2 for the handshake flow.
//!
//! ```text
//! ClientHello:
//!   [1 byte: version = 0x01]
//!   [1 byte: handshake_type = 0x01 (client_hello)]
//!   [2 bytes: key_exchange_count (u16 BE)]
//!   For each key exchange:
//!     [2 bytes: algorithm_id (u16 BE)]  // 0x0001 = X25519MLKEM768
//!     [2 bytes: key_share_len (u16 BE)]
//!     [key_share_len bytes: key_share data]
//!   [2 bytes: signature_algorithm (u16 BE)]  // 0x0001 = ML-DSA-65
//!   [8 bytes: nonce (random)]
//!
//! ServerHello:
//!   [1 byte: version = 0x01]
//!   [1 byte: handshake_type = 0x02 (server_hello)]
//!   [2 bytes: selected_kex_algorithm (u16 BE)]
//!   [2 bytes: key_share_len (u16 BE)]
//!   [key_share_len bytes: server key_share]
//!   [2 bytes: pubkey_len (u16 BE)]
//!   [pubkey_len bytes: server ML-DSA-65 public key (1952 bytes)]
//!   [4 bytes: signature_len (u32 BE)]
//!   [signature_len bytes: ML-DSA-65 signature over transcript]
//!   [8 bytes: nonce (random)]
//! ```

use crate::dsa::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use crate::kdf::derive_key;
use crate::kem::{
    X25519Ciphertext, X25519Kem, X25519PublicKeyOwned, X25519SecretKeyOwned, X25519SharedSecret,
};
use crate::traits::{CryptoError, KeyEncapsulation, SignatureScheme};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Handshake protocol version.
pub const HANDSHAKE_VERSION: u8 = 0x01;
/// ClientHello message type.
pub const TYPE_CLIENT_HELLO: u8 = 0x01;
/// ServerHello message type.
pub const TYPE_SERVER_HELLO: u8 = 0x02;
/// Algorithm ID for X25519MLKEM768 hybrid KEX.
pub const ALG_X25519MLKEM768: u16 = 0x0001;
/// Algorithm ID for ML-DSA-65 signatures.
pub const ALG_ML_DSA_65: u16 = 0x0001;

/// Result of a completed handshake.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// 32-byte shared secret derived via HKDF-SHA256.
    pub shared_secret: [u8; 32],
    /// Peer's ML-DSA-65 public key (1952 bytes).
    pub peer_public_key: Vec<u8>,
    /// SHA-256 transcript hash (binds the handshake to prevent MITM).
    pub transcript_hash: [u8; 32],
}

/// ClientHello message.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Protocol version byte.
    pub version: u8,
    /// List of `(algorithm_id, key_share)` pairs offered by the client.
    pub key_shares: Vec<(u16, Vec<u8>)>,
    /// Signature algorithm identifier negotiated by the client.
    pub signature_algorithm: u16,
    /// Random 8-byte nonce for replay protection.
    pub nonce: [u8; 8],
}

/// ServerHello message.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Protocol version byte.
    pub version: u8,
    /// Key exchange algorithm selected by the server.
    pub selected_kex_algorithm: u16,
    /// Server's key share bytes.
    pub key_share: Vec<u8>,
    /// Server's ML-DSA-65 public key.
    pub server_public_key: Vec<u8>,
    /// ML-DSA-65 signature over the transcript hash.
    pub signature: Vec<u8>,
    /// Random 8-byte nonce for replay protection.
    pub nonce: [u8; 8],
}

/// Client-side handshake state (held between init and finish).
pub struct ClientState {
    /// Client's KEM secret key (for standalone X25519 KEM).
    kem_secret: X25519SecretKeyOwned,
    /// Client's KEM public key (sent in ClientHello).
    kem_public: X25519PublicKeyOwned,
    /// ClientHello nonce.
    client_nonce: [u8; 8],
    /// Running transcript hash.
    transcript: Sha256,
    /// Client's ML-DSA-65 keypair for authentication.
    client_secret: MlDsa65SecretKey,
    client_public: MlDsa65PublicKey,
}

/// Server-side handshake state.
pub struct ServerState {
    /// Server's KEM secret key (for standalone X25519 KEM).
    kem_secret: X25519SecretKeyOwned,
    /// Shared secret derived from ECDH with client's public key.
    shared_secret: X25519SharedSecret,
    /// Running transcript hash.
    transcript: Sha256,
}

/// PQ hybrid handshake driver.
pub struct PqHandshake;

impl PqHandshake {
    /// Client side: generate ClientHello with a KEM key share.
    ///
    /// Uses X25519 KEM for standalone operation. In production, the key share
    /// comes from the TLS layer (X25519MLKEM768).
    pub fn client_init() -> (ClientHello, ClientState) {
        let (kem_public, kem_secret) = X25519Kem::keypair();
        let mut client_nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut client_nonce);

        let (client_public, client_secret) = MlDsa65::keypair();

        let hello = ClientHello {
            version: HANDSHAKE_VERSION,
            key_shares: vec![(ALG_X25519MLKEM768, kem_public.0.to_vec())],
            signature_algorithm: ALG_ML_DSA_65,
            nonce: client_nonce,
        };

        let mut transcript = Sha256::new();
        transcript.update(&serialize_client_hello(&hello));

        let state = ClientState {
            kem_secret,
            kem_public,
            client_nonce,
            transcript,
            client_secret,
            client_public,
        };

        (hello, state)
    }

    /// Client side with an existing keypair (for persistent identity).
    pub fn client_init_with_keypair(
        client_public: MlDsa65PublicKey,
        client_secret: MlDsa65SecretKey,
    ) -> (ClientHello, ClientState) {
        let (kem_public, kem_secret) = X25519Kem::keypair();
        let mut client_nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut client_nonce);

        let hello = ClientHello {
            version: HANDSHAKE_VERSION,
            key_shares: vec![(ALG_X25519MLKEM768, kem_public.0.to_vec())],
            signature_algorithm: ALG_ML_DSA_65,
            nonce: client_nonce,
        };

        let mut transcript = Sha256::new();
        transcript.update(&serialize_client_hello(&hello));

        let state = ClientState {
            kem_secret,
            kem_public,
            client_nonce,
            transcript,
            client_secret,
            client_public,
        };

        (hello, state)
    }

    /// Server side: process ClientHello, generate ServerHello.
    ///
    /// Uses static-static ECDH: server generates a static X25519 keypair,
    /// computes ECDH(server_secret, client_public) for the shared secret,
    /// and signs the transcript (ClientHello || ServerHello_unsigned) with
    /// ML-DSA-65.
    pub fn server_handle(
        client_hello: &ClientHello,
        server_keypair: &(MlDsa65PublicKey, MlDsa65SecretKey),
    ) -> Result<(ServerHello, ServerState), CryptoError> {
        if client_hello.version != HANDSHAKE_VERSION {
            return Err(CryptoError::Handshake(format!(
                "unsupported version: {}",
                client_hello.version
            )));
        }
        if client_hello.signature_algorithm != ALG_ML_DSA_65 {
            return Err(CryptoError::Handshake(
                "unsupported signature algorithm".into(),
            ));
        }

        // Find the X25519MLKEM768 key share.
        let client_kex = client_hello
            .key_shares
            .iter()
            .find(|(alg, _)| *alg == ALG_X25519MLKEM768)
            .ok_or_else(|| CryptoError::Handshake("no supported KEX algorithm".into()))?;

        if client_kex.1.len() != 32 {
            return Err(CryptoError::Handshake(
                "invalid X25519 key share length".into(),
            ));
        }

        // Reconstruct client's KEM public key.
        let mut client_pub_arr = [0u8; 32];
        client_pub_arr.copy_from_slice(&client_kex.1);
        let client_kem_public = X25519PublicKeyOwned(client_pub_arr);

        // Generate server's static KEM keypair.
        let (server_kem_public, server_kem_secret) = X25519Kem::keypair();

        // Server computes shared secret via ECDH: decapsulate using the client's
        // "ciphertext" (client's public key acts as the ephemeral share).
        // In static-static ECDH, both sides compute ECDH(own_sec, peer_pub).
        // We use the KEM's decapsulate which does ECDH(server_sec, client_pub).
        let client_ct = X25519Ciphertext(client_pub_arr);
        let shared_secret = X25519Kem::decapsulate(&server_kem_secret, &client_ct);

        // Build transcript: ClientHello || ServerHello_unsigned.
        let mut transcript = Sha256::new();
        transcript.update(&serialize_client_hello(client_hello));

        let mut server_nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut server_nonce);

        // ServerHello fields (before signature).
        let server_hello_unsigned = ServerHelloUnsigned {
            version: HANDSHAKE_VERSION,
            selected_kex_algorithm: ALG_X25519MLKEM768,
            key_share: server_kem_public.0.to_vec(),
            server_public_key: server_keypair.0 .0.clone(),
            nonce: server_nonce,
        };

        // Transcript for signature: ClientHello || ServerHello_unsigned.
        transcript.update(&serialize_server_hello_unsigned(&server_hello_unsigned));
        let transcript_hash = transcript.clone().finalize();

        // Sign the transcript hash with server's ML-DSA-65 key.
        let signature = MlDsa65::sign(&server_keypair.1, &transcript_hash);

        let server_hello = ServerHello {
            version: server_hello_unsigned.version,
            selected_kex_algorithm: server_hello_unsigned.selected_kex_algorithm,
            key_share: server_hello_unsigned.key_share,
            server_public_key: server_hello_unsigned.server_public_key,
            signature: signature.0,
            nonce: server_nonce,
        };

        let state = ServerState {
            kem_secret: server_kem_secret,
            shared_secret,
            transcript,
        };

        Ok((server_hello, state))
    }

    /// Client side: process ServerHello, complete handshake.
    ///
    /// Computes the same shared secret via ECDH(client_secret, server_public),
    /// verifies the server's ML-DSA-65 signature over the transcript, and
    /// derives the final key via HKDF-SHA256.
    pub fn client_finish(
        server_hello: &ServerHello,
        client_state: &mut ClientState,
    ) -> Result<HandshakeResult, CryptoError> {
        if server_hello.version != HANDSHAKE_VERSION {
            return Err(CryptoError::Handshake(format!(
                "unsupported version: {}",
                server_hello.version
            )));
        }
        if server_hello.selected_kex_algorithm != ALG_X25519MLKEM768 {
            return Err(CryptoError::Handshake("unsupported KEX algorithm".into()));
        }
        if server_hello.key_share.len() != 32 {
            return Err(CryptoError::Handshake("invalid server key share".into()));
        }

        // Reconstruct server KEM public key.
        let mut server_kem_pub_arr = [0u8; 32];
        server_kem_pub_arr.copy_from_slice(&server_hello.key_share);

        // Client computes shared secret via ECDH: decapsulate using the server's
        // "ciphertext" (server's public key). This gives ECDH(client_sec, server_pub),
        // which equals the server's ECDH(server_sec, client_pub).
        let server_ct = X25519Ciphertext(server_kem_pub_arr);
        let shared = X25519Kem::decapsulate(&client_state.kem_secret, &server_ct);

        // Verify server's signature over the transcript.
        // Transcript: ClientHello (already in client_state) || ServerHello_unsigned.
        let mut transcript = client_state.transcript.clone();
        let server_hello_unsigned = ServerHelloUnsigned {
            version: server_hello.version,
            selected_kex_algorithm: server_hello.selected_kex_algorithm,
            key_share: server_hello.key_share.clone(),
            server_public_key: server_hello.server_public_key.clone(),
            nonce: server_hello.nonce,
        };
        transcript.update(&serialize_server_hello_unsigned(&server_hello_unsigned));

        let transcript_hash = transcript.clone().finalize();

        let server_pubkey = MlDsa65PublicKey::from_bytes(&server_hello.server_public_key)?;
        let sig = MlDsa65Signature::from_bytes(&server_hello.signature)?;
        if !MlDsa65::verify(&server_pubkey, &transcript_hash, &sig) {
            return Err(CryptoError::SignatureVerificationFailed);
        }

        // Derive final shared secret via HKDF.
        let final_secret = derive_key(shared.as_ref(), b"aafp-handshake-v1");

        Ok(HandshakeResult {
            shared_secret: final_secret,
            peer_public_key: server_hello.server_public_key.clone(),
            transcript_hash: transcript_hash.into(),
        })
    }
}

/// Internal struct for the unsigned portion of ServerHello (for transcript binding).
struct ServerHelloUnsigned {
    version: u8,
    selected_kex_algorithm: u16,
    key_share: Vec<u8>,
    server_public_key: Vec<u8>,
    nonce: [u8; 8],
}

/// Serialize a ClientHello to bytes (wire format).
pub fn serialize_client_hello(hello: &ClientHello) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(hello.version);
    out.push(TYPE_CLIENT_HELLO);
    out.extend_from_slice(&(hello.key_shares.len() as u16).to_be_bytes());
    for (alg, share) in &hello.key_shares {
        out.extend_from_slice(&alg.to_be_bytes());
        out.extend_from_slice(&(share.len() as u16).to_be_bytes());
        out.extend_from_slice(share);
    }
    out.extend_from_slice(&hello.signature_algorithm.to_be_bytes());
    out.extend_from_slice(&hello.nonce);
    out
}

/// Deserialize a ClientHello from bytes.
pub fn deserialize_client_hello(data: &[u8]) -> Result<ClientHello, CryptoError> {
    if data.len() < 4 {
        return Err(CryptoError::Decode("client hello too short".into()));
    }
    let version = data[0];
    if data[1] != TYPE_CLIENT_HELLO {
        return Err(CryptoError::Decode("not a client hello".into()));
    }
    let kx_count = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut offset = 4;
    let mut key_shares = Vec::with_capacity(kx_count);
    for _ in 0..kx_count {
        if offset + 4 > data.len() {
            return Err(CryptoError::Decode("truncated key share".into()));
        }
        let alg = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + len > data.len() {
            return Err(CryptoError::Decode("key share overflow".into()));
        }
        key_shares.push((alg, data[offset..offset + len].to_vec()));
        offset += len;
    }
    if offset + 2 + 8 > data.len() {
        return Err(CryptoError::Decode("truncated client hello tail".into()));
    }
    let signature_algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&data[offset..offset + 8]);
    Ok(ClientHello {
        version,
        key_shares,
        signature_algorithm,
        nonce,
    })
}

fn serialize_server_hello_unsigned(h: &ServerHelloUnsigned) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(h.version);
    out.push(TYPE_SERVER_HELLO);
    out.extend_from_slice(&h.selected_kex_algorithm.to_be_bytes());
    out.extend_from_slice(&(h.key_share.len() as u16).to_be_bytes());
    out.extend_from_slice(&h.key_share);
    out.extend_from_slice(&(h.server_public_key.len() as u16).to_be_bytes());
    out.extend_from_slice(&h.server_public_key);
    out.extend_from_slice(&h.nonce);
    out
}

/// Serialize a ServerHello to bytes (wire format, includes signature).
pub fn serialize_server_hello(hello: &ServerHello) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(hello.version);
    out.push(TYPE_SERVER_HELLO);
    out.extend_from_slice(&hello.selected_kex_algorithm.to_be_bytes());
    out.extend_from_slice(&(hello.key_share.len() as u16).to_be_bytes());
    out.extend_from_slice(&hello.key_share);
    out.extend_from_slice(&(hello.server_public_key.len() as u16).to_be_bytes());
    out.extend_from_slice(&hello.server_public_key);
    out.extend_from_slice(&(hello.signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&hello.signature);
    out.extend_from_slice(&hello.nonce);
    out
}

/// Deserialize a ServerHello from bytes.
pub fn deserialize_server_hello(data: &[u8]) -> Result<ServerHello, CryptoError> {
    if data.len() < 6 {
        return Err(CryptoError::Decode("server hello too short".into()));
    }
    let version = data[0];
    if data[1] != TYPE_SERVER_HELLO {
        return Err(CryptoError::Decode("not a server hello".into()));
    }
    let selected_kex_algorithm = u16::from_be_bytes([data[2], data[3]]);
    let key_share_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut offset = 6;
    if offset + key_share_len > data.len() {
        return Err(CryptoError::Decode("key share overflow".into()));
    }
    let key_share = data[offset..offset + key_share_len].to_vec();
    offset += key_share_len;
    if offset + 2 > data.len() {
        return Err(CryptoError::Decode("truncated pubkey len".into()));
    }
    let pubkey_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if offset + pubkey_len > data.len() {
        return Err(CryptoError::Decode("pubkey overflow".into()));
    }
    let server_public_key = data[offset..offset + pubkey_len].to_vec();
    offset += pubkey_len;
    if offset + 4 > data.len() {
        return Err(CryptoError::Decode("truncated sig len".into()));
    }
    let sig_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + sig_len + 8 > data.len() {
        return Err(CryptoError::Decode("signature/nonce overflow".into()));
    }
    let signature = data[offset..offset + sig_len].to_vec();
    offset += sig_len;
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&data[offset..offset + 8]);
    Ok(ServerHello {
        version,
        selected_kex_algorithm,
        key_share,
        server_public_key,
        signature,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_roundtrip() {
        let server_kp = MlDsa65::keypair();
        let (hello, mut client_state) = PqHandshake::client_init();
        let (server_hello, _server_state) =
            PqHandshake::server_handle(&hello, &server_kp).expect("server handle");

        let result =
            PqHandshake::client_finish(&server_hello, &mut client_state).expect("client finish");

        assert_eq!(result.shared_secret.len(), 32);
        assert_eq!(result.peer_public_key, server_kp.0 .0);
        assert_eq!(result.transcript_hash.len(), 32);
    }

    #[test]
    fn client_hello_serialization_roundtrip() {
        let (hello, _state) = PqHandshake::client_init();
        let bytes = serialize_client_hello(&hello);
        let decoded = deserialize_client_hello(&bytes).unwrap();
        assert_eq!(decoded.version, hello.version);
        assert_eq!(decoded.key_shares.len(), hello.key_shares.len());
        assert_eq!(decoded.key_shares[0].0, hello.key_shares[0].0);
        assert_eq!(decoded.key_shares[0].1, hello.key_shares[0].1);
        assert_eq!(decoded.signature_algorithm, hello.signature_algorithm);
        assert_eq!(decoded.nonce, hello.nonce);
    }

    #[test]
    fn server_hello_serialization_roundtrip() {
        let server_kp = MlDsa65::keypair();
        let (hello, _state) = PqHandshake::client_init();
        let (server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
        let bytes = serialize_server_hello(&server_hello);
        let decoded = deserialize_server_hello(&bytes).unwrap();
        assert_eq!(decoded.version, server_hello.version);
        assert_eq!(
            decoded.selected_kex_algorithm,
            server_hello.selected_kex_algorithm
        );
        assert_eq!(decoded.key_share, server_hello.key_share);
        assert_eq!(decoded.server_public_key, server_hello.server_public_key);
        assert_eq!(decoded.signature, server_hello.signature);
        assert_eq!(decoded.nonce, server_hello.nonce);
    }

    #[test]
    fn rejects_tampered_signature() {
        let server_kp = MlDsa65::keypair();
        let (hello, mut client_state) = PqHandshake::client_init();
        let (mut server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
        // Tamper with the signature.
        server_hello.signature[0] ^= 0xff;
        let result = PqHandshake::client_finish(&server_hello, &mut client_state);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_server_key() {
        let server_kp1 = MlDsa65::keypair();
        let server_kp2 = MlDsa65::keypair();
        let (hello, mut client_state) = PqHandshake::client_init();
        let (mut server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp1).unwrap();
        // Swap in a different server public key (signature won't verify).
        server_hello.server_public_key = server_kp2.0 .0.clone();
        let result = PqHandshake::client_finish(&server_hello, &mut client_state);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let server_kp = MlDsa65::keypair();
        let (mut hello, _state) = PqHandshake::client_init();
        hello.version = 0x99;
        let result = PqHandshake::server_handle(&hello, &server_kp);
        assert!(result.is_err());
    }
}
