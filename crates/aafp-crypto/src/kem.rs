#![allow(clippy::all)]

//! Key Encapsulation Mechanisms (KEMs).
//!
//! ## Production path
//! The real post-quantum hybrid key exchange (`X25519MLKEM768`) is performed
//! inside the TLS 1.3 handshake by `quinn` + `rustls` (with the
//! `prefer-post-quantum` feature and `aws-lc-rs` backend). The resulting
//! shared secret is exported via the TLS exporter and fed into the
//! application-layer handshake in [`crate::handshake`].
//!
//! ## Standalone path (this module)
//! For unit-testing the [`KeyEncapsulation`] trait and the application-layer
//! handshake in isolation, [`X25519Kem`] provides a classical X25519 KEM.
//! This is NOT post-quantum on its own; PQ security comes from the TLS path.
//! The trait abstraction lets us swap in a pure-PQ or hybrid standalone KEM
//! later without changing call sites.

use crate::kdf::derive_key;
use crate::traits::KeyEncapsulation;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// X25519 KEM (classical, for standalone testing).
///
/// Encapsulation = ephemeral X25519 keypair + ECDH against peer public key.
/// Shared secret = HKDF-SHA256(X25519_shared_secret).
#[derive(Debug, Clone)]
pub struct X25519Kem;

/// X25519 public key (32 bytes).
#[derive(Clone)]
pub struct X25519PublicKeyOwned(pub [u8; 32]);

/// X25519 secret key (32 bytes).
#[derive(Clone)]
pub struct X25519SecretKeyOwned(pub [u8; 32]);

/// X25519 ciphertext = ephemeral public key (32 bytes).
#[derive(Clone)]
pub struct X25519Ciphertext(pub [u8; 32]);

/// 32-byte shared secret.
#[derive(Clone)]
pub struct X25519SharedSecret(pub [u8; 32]);

impl AsRef<[u8]> for X25519PublicKeyOwned {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for X25519SecretKeyOwned {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for X25519Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for X25519SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl KeyEncapsulation for X25519Kem {
    type PublicKey = X25519PublicKeyOwned;
    type SecretKey = X25519SecretKeyOwned;
    type Ciphertext = X25519Ciphertext;
    type SharedSecret = X25519SharedSecret;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = X25519PublicKey::from(&secret);
        (
            X25519PublicKeyOwned(public.to_bytes()),
            X25519SecretKeyOwned(secret.to_bytes()),
        )
    }

    fn encapsulate(public: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let ephemeral = EphemeralSecret::random_from_rng(&mut OsRng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral);
        let peer_pub = X25519PublicKey::from(public.0);
        let shared = ephemeral.diffie_hellman(&peer_pub);
        let derived = derive_key(shared.as_bytes(), b"aafp-x25519-kem");
        (
            X25519Ciphertext(ephemeral_pub.to_bytes()),
            X25519SharedSecret(derived),
        )
    }

    fn decapsulate(secret: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        let sk = StaticSecret::from(secret.0);
        let peer_eph_pub = X25519PublicKey::from(ct.0);
        let shared = sk.diffie_hellman(&peer_eph_pub);
        let derived = derive_key(shared.as_bytes(), b"aafp-x25519-kem");
        X25519SharedSecret(derived)
    }

    fn algorithm_name() -> &'static str {
        "X25519"
    }
}

/// Marker type for the production hybrid KEM (X25519MLKEM768).
///
/// The actual KEX is performed by rustls inside the TLS handshake; this type
/// exists for documentation and as a placeholder in algorithm negotiation.
/// Use [`X25519Kem`] for standalone tests.
#[derive(Debug, Clone)]
pub struct HybridKem;

impl HybridKem {
    /// Algorithm identifier used in handshake negotiation.
    pub const ALGORITHM_ID: u16 = 0x0001;
    /// Algorithm name.
    pub const NAME: &'static str = "X25519MLKEM768";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_kem_roundtrip() {
        let (pk, sk) = X25519Kem::keypair();
        assert_eq!(pk.0.len(), 32);
        assert_eq!(sk.0.len(), 32);
        let (ct, ss1) = X25519Kem::encapsulate(&pk);
        assert_eq!(ct.0.len(), 32);
        let ss2 = X25519Kem::decapsulate(&sk, &ct);
        assert_eq!(ss1.0, ss2.0, "shared secrets must match");
    }

    #[test]
    fn x25519_kem_different_keys_different_secrets() {
        let (pk1, _sk1) = X25519Kem::keypair();
        let (pk2, _sk2) = X25519Kem::keypair();
        let (_ct1, ss1) = X25519Kem::encapsulate(&pk1);
        let (_ct2, ss2) = X25519Kem::encapsulate(&pk2);
        assert_ne!(ss1.0, ss2.0);
    }

    #[test]
    fn algorithm_name() {
        assert_eq!(X25519Kem::algorithm_name(), "X25519");
        assert_eq!(HybridKem::NAME, "X25519MLKEM768");
    }
}
