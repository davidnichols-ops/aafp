//! ML-DSA-65 signature scheme (FIPS 204, L3 post-quantum security).
//!
//! Wraps `pqcrypto-mldsa` to implement the `SignatureScheme` trait.
//! Public key = 1952 bytes, signature = 3309 bytes.

use crate::traits::{CryptoError, SignatureScheme};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// ML-DSA-65 public key bytes (FIPS 204).
pub const ML_DSA_65_PUBKEY_LEN: usize = 1952;
/// ML-DSA-65 secret key bytes.
pub const ML_DSA_65_SECRETKEY_LEN: usize = 4032;
/// ML-DSA-65 detached signature bytes.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// ML-DSA-65 signature scheme.
#[derive(Debug, Clone)]
pub struct MlDsa65;

/// Owned public key bytes.
#[derive(Clone)]
pub struct MlDsa65PublicKey(pub Vec<u8>);

/// Owned secret key bytes.
#[derive(Clone)]
pub struct MlDsa65SecretKey(pub Vec<u8>);

/// Owned detached signature bytes.
#[derive(Clone)]
pub struct MlDsa65Signature(pub Vec<u8>);

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa65SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsa65Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl MlDsa65PublicKey {
    /// Decode from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_65_PUBKEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ML_DSA_65_PUBKEY_LEN,
                actual: bytes.len(),
            });
        }
        // Validate by attempting to construct the pqcrypto type.
        let _ = mldsa65::PublicKey::from_bytes(bytes)
            .map_err(|e| CryptoError::Decode(format!("mldsa65 pubkey: {:?}", e)))?;
        Ok(Self(bytes.to_vec()))
    }
}

impl MlDsa65SecretKey {
    /// Decode from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_65_SECRETKEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ML_DSA_65_SECRETKEY_LEN,
                actual: bytes.len(),
            });
        }
        let _ = mldsa65::SecretKey::from_bytes(bytes)
            .map_err(|e| CryptoError::Decode(format!("mldsa65 secretkey: {:?}", e)))?;
        Ok(Self(bytes.to_vec()))
    }
}

impl MlDsa65Signature {
    /// Decode from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(CryptoError::InvalidSignatureLength {
                expected: ML_DSA_65_SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl SignatureScheme for MlDsa65 {
    type PublicKey = MlDsa65PublicKey;
    type SecretKey = MlDsa65SecretKey;
    type Signature = MlDsa65Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (pk, sk) = mldsa65::keypair();
        (
            MlDsa65PublicKey(pk.as_bytes().to_vec()),
            MlDsa65SecretKey(sk.as_bytes().to_vec()),
        )
    }

    fn sign(secret: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let sk = mldsa65::SecretKey::from_bytes(&secret.0).expect("valid secret key");
        let sig = mldsa65::detached_sign(msg, &sk);
        MlDsa65Signature(sig.as_bytes().to_vec())
    }

    fn verify(public: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        let pk = match mldsa65::PublicKey::from_bytes(&public.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match mldsa65::DetachedSignature::from_bytes(&sig.0) {
            Ok(s) => s,
            Err(_) => return false,
        };
        mldsa65::verify_detached_signature(&sig, msg, &pk).is_ok()
    }

    fn algorithm_name() -> &'static str {
        "ML-DSA-65"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = MlDsa65::keypair();
        assert_eq!(pk.0.len(), ML_DSA_65_PUBKEY_LEN);
        assert_eq!(sk.0.len(), ML_DSA_65_SECRETKEY_LEN);
        let msg = b"post-quantum aafp";
        let sig = MlDsa65::sign(&sk, msg);
        assert_eq!(sig.0.len(), ML_DSA_65_SIGNATURE_LEN);
        assert!(MlDsa65::verify(&pk, msg, &sig));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (pk, sk) = MlDsa65::keypair();
        let sig = MlDsa65::sign(&sk, b"original");
        assert!(!MlDsa65::verify(&pk, b"tampered", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (pk1, sk1) = MlDsa65::keypair();
        let (pk2, _sk2) = MlDsa65::keypair();
        let sig = MlDsa65::sign(&sk1, b"msg");
        assert!(!MlDsa65::verify(&pk2, b"msg", &sig));
        assert!(MlDsa65::verify(&pk1, b"msg", &sig));
    }

    #[test]
    fn serialization_roundtrip() {
        let (pk, sk) = MlDsa65::keypair();
        let pk2 = MlDsa65PublicKey::from_bytes(&pk.0).unwrap();
        let sk2 = MlDsa65SecretKey::from_bytes(&sk.0).unwrap();
        let sig = MlDsa65::sign(&sk2, b"roundtrip");
        assert!(MlDsa65::verify(&pk2, b"roundtrip", &sig));
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(MlDsa65PublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(MlDsa65SecretKey::from_bytes(&[0u8; 10]).is_err());
        assert!(MlDsa65Signature::from_bytes(&[0u8; 10]).is_err());
    }
}
