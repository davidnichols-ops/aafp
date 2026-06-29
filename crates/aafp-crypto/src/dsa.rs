//! ML-DSA-65 signature scheme (FIPS 204, L3 post-quantum security).
//!
//! Wraps the `fips204` crate to implement the `SignatureScheme` trait.
//! Public key = 1952 bytes, signature = 3309 bytes.
//!
//! This replaced the unmaintained `pqcrypto-mldsa` (RUSTSEC-2026-0162/0163/0166)
//! with a pure-Rust, FIPS 204-compliant implementation. Key and signature byte
//! formats are identical (raw FIPS 204 encoding), so wire compatibility is
//! preserved. An empty context string (`&[]`) is used for signing and
//! verification, matching the previous pqcrypto/PQClean behavior.

use crate::traits::{CryptoError, SignatureScheme};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

/// ML-DSA-65 public key bytes (FIPS 204).
pub const ML_DSA_65_PUBKEY_LEN: usize = ml_dsa_65::PK_LEN;
/// ML-DSA-65 secret key bytes.
pub const ML_DSA_65_SECRETKEY_LEN: usize = ml_dsa_65::SK_LEN;
/// ML-DSA-65 detached signature bytes.
pub const ML_DSA_65_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

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
        // Validate by attempting to construct the fips204 type.
        let arr: [u8; ML_DSA_65_PUBKEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::Decode("mldsa65 pubkey: length mismatch".into()))?;
        let _ = ml_dsa_65::PublicKey::try_from_bytes(arr)
            .map_err(|e| CryptoError::Decode(format!("mldsa65 pubkey: {e}")))?;
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
        let arr: [u8; ML_DSA_65_SECRETKEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::Decode("mldsa65 secretkey: length mismatch".into()))?;
        let _ = ml_dsa_65::PrivateKey::try_from_bytes(arr)
            .map_err(|e| CryptoError::Decode(format!("mldsa65 secretkey: {e}")))?;
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
        let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA-65 keygen must succeed");
        (
            MlDsa65PublicKey(pk.into_bytes().to_vec()),
            MlDsa65SecretKey(sk.into_bytes().to_vec()),
        )
    }

    fn sign(secret: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let arr: [u8; ML_DSA_65_SECRETKEY_LEN] = secret
            .0
            .as_slice()
            .try_into()
            .expect("valid secret key length");
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(arr).expect("valid secret key");
        // Empty context string matches PQClean's detached_sign behavior.
        let sig = sk.try_sign(msg, &[]).expect("ML-DSA-65 signing must succeed");
        MlDsa65Signature(sig.to_vec())
    }

    fn verify(public: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        let pk_arr: [u8; ML_DSA_65_PUBKEY_LEN] = match public.0.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let pk = match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig_arr: [u8; ML_DSA_65_SIGNATURE_LEN] = match sig.0.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        // Empty context string matches PQClean's detached_sign behavior.
        pk.verify(msg, &sig_arr, &[])
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
