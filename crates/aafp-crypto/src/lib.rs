//! AAFP cryptography layer: post-quantum hybrid KEX, ML-DSA-65 signatures,
//! AEAD, HKDF, and the PQ hybrid 1-RTT application-layer handshake.
//!
//! ## Production PQ path
//! The post-quantum key exchange (`X25519MLKEM768`) is performed inside the
//! TLS 1.3 handshake by `quinn` + `rustls` (with the `prefer-post-quantum`
//! feature and `aws-lc-rs` backend). This crate provides:
//! - ML-DSA-65 signatures (FIPS 204) for authentication
//! - ChaCha20-Poly1305 / AES-256-GCM AEAD
//! - HKDF-SHA256 key derivation
//! - An application-layer handshake that binds the TLS secret to agent identity
//!
//! See `AAFP_Architecture_Deliverable.md` Phase 2.2 for the handshake design.

pub mod aead;
pub mod dsa;
/// Legacy v0 handshake module. Uses binary (non-CBOR) wire format — NOT
/// RFC-compliant. Kept for benchmarks only. Use [`handshake_v1`] instead.
#[deprecated = "Use handshake_v1 instead. Legacy v0 handshake is not RFC-compliant."]
#[allow(deprecated)]
pub mod handshake;
pub mod handshake_v1;
pub mod kdf;
pub mod kem;
pub mod replay_cache;
pub mod traits;

pub use aead::{Aead, AeadAlgorithm, NONCE_LEN};
pub use dsa::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, ML_DSA_65_PUBKEY_LEN,
    ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
pub use handshake_v1::{
    compute_receiver_mac, derive_session_id, generate_nonce, verify_client_finished,
    verify_client_hello, verify_receiver_mac, verify_server_hello, ClientFinished,
    ClientHello as ClientHelloV1, HandshakeError, ServerHello as ServerHelloV1, TranscriptHash,
    DOMAIN_SEPARATOR, KEY_ALG_ML_DSA_65, NONCE_SIZE, PROTOCOL_VERSION, SESSION_ID_SIZE,
    TLS_EXPORTER_LABEL,
};
pub use kdf::{derive_key, hkdf_sha256};
pub use kem::{HybridKem, X25519Kem};
pub use replay_cache::{
    NonceReuseError, ReplayCache, ReplayCacheError, DEFAULT_MAX_ENTRIES, DEFAULT_RETENTION,
    MAX_MAX_ENTRIES, MAX_RETENTION, MIN_MAX_ENTRIES, MIN_RETENTION,
};
pub use traits::{CryptoError, KeyEncapsulation, SignatureScheme};
