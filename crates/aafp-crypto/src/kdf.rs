//! HKDF-SHA256 key derivation.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256 extract-and-expand.
///
/// Returns `output_len` bytes of derived key material.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .expect("hkdf expand output <= 255*hash_len");
    okm
}

/// Derive a 32-byte key from input key material.
pub fn derive_key(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let out = hkdf_sha256(&[], ikm, info, 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_deterministic() {
        let a = hkdf_sha256(b"salt", b"ikm", b"info", 32);
        let b = hkdf_sha256(b"salt", b"ikm", b"info", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_different_info_diverges() {
        let a = hkdf_sha256(b"salt", b"ikm", b"info-a", 32);
        let b = hkdf_sha256(b"salt", b"ikm", b"info-b", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_key_is_32_bytes() {
        let k = derive_key(b"secret", b"label");
        assert_eq!(k.len(), 32);
    }
}
