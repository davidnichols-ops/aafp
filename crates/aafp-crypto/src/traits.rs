//! Cryptographic trait abstractions for AAFP.
//!
//! These traits decouple the algorithm choices from the protocol logic,
//! enabling algorithm agility (hybrid vs pure-PQ vs classical fallback).

/// A digital signature scheme.
pub trait SignatureScheme: Send + Sync {
    /// Public key type for this signature scheme.
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Secret key type for this signature scheme.
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Signature type for this signature scheme.
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
    /// Public key type for this KEM.
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Secret key type for this KEM.
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Ciphertext type produced by encapsulation.
    type Ciphertext: AsRef<[u8]> + Clone + Send + Sync;
    /// Shared secret type produced by decapsulation.
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
    /// A key had an unexpected length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length received.
        actual: usize,
    },
    /// A signature had an unexpected length.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length received.
        actual: usize,
    },
    /// A ciphertext had an unexpected length.
    #[error("invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength {
        /// Expected ciphertext length in bytes.
        expected: usize,
        /// Actual ciphertext length received.
        actual: usize,
    },
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// AEAD decryption failed (authentication tag mismatch).
    #[error("AEAD decryption failed")]
    AeadDecryptionFailed,
    /// A handshake protocol error occurred.
    #[error("handshake error: {0}")]
    Handshake(String),
    /// A decoding (deserialization) error occurred.
    #[error("decoding error: {0}")]
    Decode(String),
}
