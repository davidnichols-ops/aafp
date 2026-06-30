//! Authenticated Encryption with Associated Data (AEAD).
//!
//! Default: ChaCha20-Poly1305. Optional: AES-256-GCM (hardware-accelerated).

use crate::traits::CryptoError;
use aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as AesKeyInit, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};

/// AEAD algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 (default, constant-time, no hardware dependency).
    ChaCha20Poly1305,
    /// AES-256-GCM (hardware-accelerated on x86_64/aarch64 with AES-NI).
    Aes256Gcm,
}

/// AEAD cipher wrapping a 32-byte key.
pub struct Aead {
    key: [u8; 32],
    algorithm: AeadAlgorithm,
}

/// 12-byte nonce (standard for both ChaCha20-Poly1305 and AES-256-GCM).
pub const NONCE_LEN: usize = 12;

impl Aead {
    /// Create a new AEAD instance from a 32-byte key.
    pub fn new(key: [u8; 32], algorithm: AeadAlgorithm) -> Self {
        Self { key, algorithm }
    }

    /// Encrypt `plaintext` with associated data. Returns ciphertext+tag.
    pub fn encrypt(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self.algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("32-byte key for chacha20poly1305");
                let nonce = ChachaNonce::from_slice(nonce);
                cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .expect("encryption succeeds")
            }
            AeadAlgorithm::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).expect("32-byte key for aes256gcm");
                let nonce = AesNonce::from_slice(nonce);
                cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .expect("encryption succeeds")
            }
        }
    }

    /// Decrypt `ciphertext` with associated data. Returns plaintext or error.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match self.algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("32-byte key for chacha20poly1305");
                let nonce = ChachaNonce::from_slice(nonce);
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadDecryptionFailed)
            }
            AeadAlgorithm::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).expect("32-byte key for aes256gcm");
                let nonce = AesNonce::from_slice(nonce);
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| CryptoError::AeadDecryptionFailed)
            }
        }
    }

    /// Algorithm in use.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut n);
        n
    }

    #[test]
    fn chacha20_roundtrip() {
        let key = [0x42u8; 32];
        let aead = Aead::new(key, AeadAlgorithm::ChaCha20Poly1305);
        let nonce = random_nonce();
        let aad = b"associated-data";
        let pt = b"post-quantum agent message";
        let ct = aead.encrypt(&nonce, aad, pt);
        assert_ne!(ct, pt);
        let decrypted = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn aes256_roundtrip() {
        let key = [0x42u8; 32];
        let aead = Aead::new(key, AeadAlgorithm::Aes256Gcm);
        let nonce = random_nonce();
        let aad = b"associated-data";
        let pt = b"post-quantum agent message";
        let ct = aead.encrypt(&nonce, aad, pt);
        let decrypted = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let aead = Aead::new(key, AeadAlgorithm::ChaCha20Poly1305);
        let nonce = random_nonce();
        let aad = b"aad";
        let ct = aead.encrypt(&nonce, aad, b"secret");
        let mut tampered = ct.clone();
        tampered[0] ^= 0xff;
        assert!(aead.decrypt(&nonce, aad, &tampered).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x42u8; 32];
        let aead = Aead::new(key, AeadAlgorithm::Aes256Gcm);
        let nonce = random_nonce();
        let ct = aead.encrypt(&nonce, b"aad-1", b"secret");
        assert!(aead.decrypt(&nonce, b"aad-2", &ct).is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let aead = Aead::new(key, AeadAlgorithm::ChaCha20Poly1305);
        let nonce1 = random_nonce();
        let nonce2 = random_nonce();
        let ct = aead.encrypt(&nonce1, b"aad", b"secret");
        assert!(aead.decrypt(&nonce2, b"aad", &ct).is_err());
    }
}
