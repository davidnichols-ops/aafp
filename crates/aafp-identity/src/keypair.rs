//! ML-DSA-65 keypair management for agent identity.

use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, SignatureScheme};
use thiserror::Error;

/// Identity-layer errors.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid keypair: {0}")]
    /// The keypair is invalid or incomplete.
    InvalidKeypair(String),
    #[error("serialization error: {0}")]
    /// An error occurred during serialization.
    Serialization(String),
    #[error("deserialization error: {0}")]
    /// An error occurred during deserialization.
    Deserialization(String),
    #[error("signature verification failed")]
    /// The signature could not be verified.
    SignatureVerificationFailed,
    #[error("agent ID mismatch")]
    /// The agent ID does not match the expected value.
    AgentIdMismatch,
    #[error("UCAN error: {0}")]
    /// A UCAN token error occurred.
    Ucan(String),
    #[error("crypto error: {0}")]
    /// An underlying cryptographic error occurred.
    Crypto(#[from] aafp_crypto::CryptoError),
}

/// An agent's ML-DSA-65 keypair (root identity).
#[derive(Clone)]
pub struct AgentKeypair {
    /// ML-DSA-65 public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// ML-DSA-65 secret key (4032 bytes).
    pub secret_key: Vec<u8>,
}

impl AgentKeypair {
    /// Generate a fresh ML-DSA-65 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = MlDsa65::keypair();
        Self {
            public_key: pk.0,
            secret_key: sk.0,
        }
    }

    /// Reconstruct a keypair from secret key bytes.
    pub fn from_bytes(secret: &[u8]) -> Result<Self, IdentityError> {
        let _sk = MlDsa65SecretKey::from_bytes(secret)?;
        // We cannot derive the public key from the secret key in ML-DSA-65
        // without signing, so we require both. Use from_secret_and_public.
        Err(IdentityError::InvalidKeypair(
            "use from_secret_and_public to reconstruct a keypair".into(),
        ))
    }

    /// Reconstruct a keypair from both secret and public key bytes.
    pub fn from_secret_and_public(secret: &[u8], public: &[u8]) -> Result<Self, IdentityError> {
        let _sk = MlDsa65SecretKey::from_bytes(secret)?;
        let _pk = MlDsa65PublicKey::from_bytes(public)?;
        Ok(Self {
            public_key: public.to_vec(),
            secret_key: secret.to_vec(),
        })
    }

    /// Serialize the keypair to bytes (secret || public).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.secret_key.len() + self.public_key.len() + 8);
        out.extend_from_slice(&(self.secret_key.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.secret_key);
        out.extend_from_slice(&self.public_key);
        out
    }

    /// Deserialize a keypair from bytes (secret || public).
    pub fn from_bytes_full(data: &[u8]) -> Result<Self, IdentityError> {
        if data.len() < 4 {
            return Err(IdentityError::Deserialization("keypair too short".into()));
        }
        let sk_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + sk_len {
            return Err(IdentityError::Deserialization(
                "truncated secret key".into(),
            ));
        }
        let secret_key = data[4..4 + sk_len].to_vec();
        let public_key = data[4 + sk_len..].to_vec();
        Self::from_secret_and_public(&secret_key, &public_key)
    }

    /// Sign a message with the secret key.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sk = MlDsa65SecretKey::from_bytes(&self.secret_key).expect("valid secret key");
        let sig = MlDsa65::sign(&sk, msg);
        sig.0
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let pk = match MlDsa65PublicKey::from_bytes(&self.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match aafp_crypto::MlDsa65Signature::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        MlDsa65::verify(&pk, msg, &sig)
    }

    /// Get the public key as a typed wrapper.
    pub fn public_key(&self) -> Result<MlDsa65PublicKey, IdentityError> {
        Ok(MlDsa65PublicKey::from_bytes(&self.public_key)?)
    }

    /// Get the secret key as a typed wrapper.
    pub fn secret_key(&self) -> Result<MlDsa65SecretKey, IdentityError> {
        Ok(MlDsa65SecretKey::from_bytes(&self.secret_key)?)
    }
}

impl std::fmt::Debug for AgentKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeypair")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key_len", &self.secret_key.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign() {
        let kp = AgentKeypair::generate();
        assert_eq!(kp.public_key.len(), 1952);
        assert_eq!(kp.secret_key.len(), 4032);
        let msg = b"agent identity test";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), 3309);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn serialization_roundtrip() {
        let kp = AgentKeypair::generate();
        let bytes = kp.to_bytes();
        let kp2 = AgentKeypair::from_bytes_full(&bytes).unwrap();
        assert_eq!(kp.public_key, kp2.public_key);
        assert_eq!(kp.secret_key, kp2.secret_key);
        let msg = b"roundtrip";
        let sig = kp2.sign(msg);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn from_secret_and_public_validates() {
        let kp = AgentKeypair::generate();
        let kp2 = AgentKeypair::from_secret_and_public(&kp.secret_key, &kp.public_key).unwrap();
        assert_eq!(kp.public_key, kp2.public_key);
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(AgentKeypair::from_secret_and_public(&[0u8; 10], &[0u8; 10]).is_err());
        assert!(AgentKeypair::from_bytes_full(&[0u8; 3]).is_err());
    }
}
