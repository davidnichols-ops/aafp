//! Cryptographic trait abstractions for AAFP.
//!
//! These traits decouple the algorithm choices from the protocol logic,
//! enabling algorithm agility (hybrid vs pure-PQ vs classical fallback).

/// A digital signature scheme.
pub trait SignatureScheme: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    type Signature: AsRef<[u8]> + Clone + Send + Sync;

    /// Generate a fresh keypair.
    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    /// Sign a message with the secret key.
    fn sign(secret: &Self::SecretKey, msg: &[u8]) -> Self::Signature;
    /// Verify a signature against a public key.
    fn verify(public: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
    /// Algorithm name for negotiation/serialization.
    fn algorithm_name() -> &'static str;
}

/// A key encapsulation mechanism (KEM).
pub trait KeyEncapsulation: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    type Ciphertext: AsRef<[u8]> + Clone + Send + Sync;
    type SharedSecret: AsRef<[u8]> + Clone + Send + Sync;

    /// Generate a fresh keypair.
    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    /// Encapsulate a shared secret against a public key.
    fn encapsulate(public: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret);
    /// Decapsulate a ciphertext with a secret key.
    fn decapsulate(secret: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
    /// Algorithm name for negotiation/serialization.
    fn algorithm_name() -> &'static str;
}

/// Errors emitted by the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    #[error("invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength { expected: usize, actual: usize },
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("AEAD decryption failed")]
    AeadDecryptionFailed,
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("decoding error: {0}")]
    Decode(String),
}
