//! Property testing for ML-DSA-65 (A-10 Phase 6).
//!
//! Verifies the core property: sign(message) → verify(message) always
//! succeeds, and mutating any component causes verification to fail.
//!
//! Uses a deterministic PRNG (xorshift64) for reproducibility.

#![allow(unused_imports)]
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};

// Deterministic PRNG (xorshift64*).
struct Prng {
    state: u64,
}

impl Prng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let len = chunk.len().min(8);
            chunk.copy_from_slice(&v[..len]);
        }
    }

    fn next_vec(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.fill_bytes(&mut v);
        v
    }
}

#[test]
fn test_property_sign_verify_always_succeeds() {
    let mut prng = Prng::new(0x1234567890ABCDEF);
    let iterations = 1000; // 1000 iterations (100K would be too slow for ML-DSA)

    for i in 0..iterations {
        let mut seed = [0u8; 32];
        prng.fill_bytes(&mut seed);
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);

        let msg_len = (prng.next_u64() % 256) as usize;
        let msg = prng.next_vec(msg_len);

        let sig = MlDsa65::sign(&sk, &msg);
        assert!(
            MlDsa65::verify(&pk, &msg, &sig),
            "iteration {}: sign→verify must always succeed",
            i
        );
    }
    eprintln!(
        "Property: {}/{} sign→verify succeeded",
        iterations, iterations
    );
}

#[test]
fn test_property_mutate_message_fails() {
    let mut prng = Prng::new(0xDEADBEEFCAFEBABE);
    let iterations = 500;

    for i in 0..iterations {
        let mut seed = [0u8; 32];
        prng.fill_bytes(&mut seed);
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);

        let msg = prng.next_vec(32);
        let sig = MlDsa65::sign(&sk, &msg);

        // Mutate one byte of the message.
        let mut mutated = msg.clone();
        let bit_pos = (prng.next_u64() % 256) as usize;
        let idx = bit_pos % mutated.len();
        mutated[idx] ^= 0x01 << (prng.next_u64() % 8);

        assert!(
            !MlDsa65::verify(&pk, &mutated, &sig),
            "iteration {}: mutated message must fail verification",
            i
        );
    }
    eprintln!(
        "Property: {}/{} mutated messages correctly rejected",
        iterations, iterations
    );
}

#[test]
fn test_property_mutate_signature_fails() {
    let mut prng = Prng::new(0xCAFED00DBAADF00D);
    let iterations = 500;

    for i in 0..iterations {
        let mut seed = [0u8; 32];
        prng.fill_bytes(&mut seed);
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);

        let msg = prng.next_vec(32);
        let mut sig = MlDsa65::sign(&sk, &msg);

        // Mutate one byte of the signature.
        let bit_pos = (prng.next_u64() % ML_DSA_65_SIGNATURE_LEN as u64) as usize;
        sig.0[bit_pos] ^= 0x01 << (prng.next_u64() % 8);

        assert!(
            !MlDsa65::verify(&pk, &msg, &sig),
            "iteration {}: mutated signature must fail verification",
            i
        );
    }
    eprintln!(
        "Property: {}/{} mutated signatures correctly rejected",
        iterations, iterations
    );
}

#[test]
fn test_property_mutate_public_key_fails() {
    let mut prng = Prng::new(0xFEEDFACE12345678);
    let iterations = 500;

    for i in 0..iterations {
        let mut seed = [0u8; 32];
        prng.fill_bytes(&mut seed);
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);

        let msg = prng.next_vec(32);
        let sig = MlDsa65::sign(&sk, &msg);

        // Mutate one byte of the public key.
        let mut mutated_pk = pk.0.clone();
        let bit_pos = (prng.next_u64() % ML_DSA_65_PUBKEY_LEN as u64) as usize;
        mutated_pk[bit_pos] ^= 0x01 << (prng.next_u64() % 8);
        let bad_pk = MlDsa65PublicKey(mutated_pk);

        assert!(
            !MlDsa65::verify(&bad_pk, &msg, &sig),
            "iteration {}: mutated public key must fail verification",
            i
        );
    }
    eprintln!(
        "Property: {}/{} mutated public keys correctly rejected",
        iterations, iterations
    );
}

#[test]
fn test_property_different_keys_different_signatures() {
    let mut prng = Prng::new(0xABCDEF0123456789);
    let iterations = 100;

    for i in 0..iterations {
        let mut seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        prng.fill_bytes(&mut seed1);
        prng.fill_bytes(&mut seed2);
        if seed1 == seed2 {
            seed2[0] ^= 0x01;
        }

        let (_, sk1) = MlDsa65::keypair_from_seed(&seed1);
        let (_, sk2) = MlDsa65::keypair_from_seed(&seed2);

        let msg = prng.next_vec(32);
        let sig1 = MlDsa65::sign(&sk1, &msg);
        let sig2 = MlDsa65::sign(&sk2, &msg);

        // Different keys should produce different signatures (with overwhelming probability).
        assert_ne!(
            sig1.0, sig2.0,
            "iteration {}: different keys should produce different signatures",
            i
        );
    }
    eprintln!(
        "Property: {}/{} different keys produced different signatures",
        iterations, iterations
    );
}

#[test]
fn test_property_key_sizes_constant() {
    for _ in 0..100 {
        let (pk, sk) = MlDsa65::keypair();
        assert_eq!(
            pk.0.len(),
            ML_DSA_65_PUBKEY_LEN,
            "public key size must be constant"
        );
        assert_eq!(
            sk.0.len(),
            ML_DSA_65_SECRETKEY_LEN,
            "secret key size must be constant"
        );
        let sig = MlDsa65::sign(&sk, b"test");
        assert_eq!(
            sig.0.len(),
            ML_DSA_65_SIGNATURE_LEN,
            "signature size must be constant"
        );
    }
    eprintln!("Property: 100/100 key sizes constant");
}
