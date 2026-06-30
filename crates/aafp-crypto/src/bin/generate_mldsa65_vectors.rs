//! Generate canonical ML-DSA-65 cross-language test vectors (A-10).
//!
//! This binary generates JSON test vectors using deterministic key
//! generation and deterministic signing. The same vectors can be
//! verified by both the Rust and Go implementations.
//!
//! Usage: cargo run -p aafp-crypto --bin generate_mldsa65_vectors > test-vectors/mldsa65/vectors.json

use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, SignatureScheme, ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN,
    ML_DSA_65_SIGNATURE_LEN,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestVector {
    id: String,
    seed: String,
    message_hex: String,
    context_hex: String,
    public_key_hex: String,
    secret_key_hex: String,
    signature_hex: String,
    expected_verify: bool,
    description: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn make_vector(id: &str, seed: &[u8; 32], message: &[u8], description: &str) -> TestVector {
    let (pk, sk) = MlDsa65::keypair_from_seed(seed);
    let sig = MlDsa65::sign_deterministic(&sk, message, &[0u8; 32]);
    let verify = MlDsa65::verify(&pk, message, &sig);

    TestVector {
        id: id.to_string(),
        seed: hex(seed),
        message_hex: hex(message),
        context_hex: hex(&[]), // empty context
        public_key_hex: hex(&pk.0),
        secret_key_hex: hex(&sk.0),
        signature_hex: hex(&sig.0),
        expected_verify: verify,
        description: description.to_string(),
    }
}

fn main() {
    // Verify key sizes
    assert_eq!(ML_DSA_65_PUBKEY_LEN, 1952);
    assert_eq!(ML_DSA_65_SECRETKEY_LEN, 4032);
    assert_eq!(ML_DSA_65_SIGNATURE_LEN, 3309);

    let mut vectors = Vec::new();

    // 1. Valid signature — basic message
    vectors.push(make_vector(
        "valid_basic",
        &[0x42u8; 32],
        b"post-quantum aafp handshake",
        "Valid signature over a basic message",
    ));

    // 2. Valid signature — empty message
    vectors.push(make_vector(
        "valid_empty_message",
        &[0x42u8; 32],
        b"",
        "Valid signature over an empty message",
    ));

    // 3. Valid signature — domain separator + transcript hash (simulated)
    let mut msg = b"aafp-v1-handshake".to_vec();
    msg.extend_from_slice(&[0xabu8; 32]); // simulated transcript hash
    vectors.push(make_vector(
        "valid_handshake_input",
        &[0x42u8; 32],
        &msg,
        "Valid signature over domain_separator || transcript_hash (49 bytes)",
    ));

    // 4. Valid signature — different seed
    vectors.push(make_vector(
        "valid_different_seed",
        &[0x99u8; 32],
        b"another test message",
        "Valid signature with a different key seed",
    ));

    // 5. Valid signature — all-zeros seed
    vectors.push(make_vector(
        "valid_zero_seed",
        &[0x00u8; 32],
        b"zero seed test",
        "Valid signature with all-zeros seed",
    ));

    // 6. Valid signature — all-FF seed
    vectors.push(make_vector(
        "valid_ff_seed",
        &[0xFFu8; 32],
        b"ff seed test",
        "Valid signature with all-FF seed",
    ));

    // 7. Valid signature — maximum-length message (65535 bytes, FIPS 204 max)
    let max_msg = vec![0xa5u8; 65535];
    vectors.push(make_vector(
        "valid_max_message",
        &[0x42u8; 32],
        &max_msg,
        "Valid signature over maximum-length message (65535 bytes)",
    ));

    // 8. Valid signature — single byte message
    vectors.push(make_vector(
        "valid_single_byte",
        &[0x42u8; 32],
        &[0x00u8],
        "Valid signature over a single byte message",
    ));

    // 9. Valid signature — all-zeros message
    vectors.push(make_vector(
        "valid_zero_message",
        &[0x42u8; 32],
        &[0u8; 32],
        "Valid signature over all-zeros message (32 bytes)",
    ));

    // 10. Valid signature — all-FF message
    vectors.push(make_vector(
        "valid_ff_message",
        &[0x42u8; 32],
        &[0xFFu8; 32],
        "Valid signature over all-FF message (32 bytes)",
    ));

    // 11. Invalid signature — altered message (signature over msg1, verify against msg2)
    {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);
        let sig = MlDsa65::sign_deterministic(&sk, b"original message", &[0u8; 32]);
        let verify = MlDsa65::verify(&pk, b"altered message", &sig);
        vectors.push(TestVector {
            id: "invalid_altered_message".to_string(),
            seed: hex(&seed),
            message_hex: hex(b"altered message"),
            context_hex: hex(&[]),
            public_key_hex: hex(&pk.0),
            secret_key_hex: hex(&sk.0),
            signature_hex: hex(&sig.0),
            expected_verify: verify, // should be false
            description:
                "Invalid: signature over 'original message', verified against 'altered message'"
                    .to_string(),
        });
    }

    // 12. Invalid signature — corrupted signature (flip first byte)
    {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);
        let mut sig = MlDsa65::sign_deterministic(&sk, b"test message", &[0u8; 32]);
        sig.0[0] ^= 0xFF; // corrupt first byte
        let verify = MlDsa65::verify(&pk, b"test message", &sig);
        vectors.push(TestVector {
            id: "invalid_corrupted_signature".to_string(),
            seed: hex(&seed),
            message_hex: hex(b"test message"),
            context_hex: hex(&[]),
            public_key_hex: hex(&pk.0),
            secret_key_hex: hex(&sk.0),
            signature_hex: hex(&sig.0),
            expected_verify: verify, // should be false
            description: "Invalid: first byte of signature flipped".to_string(),
        });
    }

    // 13. Invalid signature — wrong key (sign with key1, verify with key2)
    {
        let seed1 = [0x01u8; 32];
        let seed2 = [0x02u8; 32];
        let (_pk1, sk1) = MlDsa65::keypair_from_seed(&seed1);
        let (pk2, _) = MlDsa65::keypair_from_seed(&seed2);
        let sig = MlDsa65::sign_deterministic(&sk1, b"cross key test", &[0u8; 32]);
        let verify = MlDsa65::verify(&pk2, b"cross key test", &sig);
        vectors.push(TestVector {
            id: "invalid_wrong_key".to_string(),
            seed: hex(&seed1),
            message_hex: hex(b"cross key test"),
            context_hex: hex(&[]),
            public_key_hex: hex(&pk2.0), // different public key
            secret_key_hex: hex(&sk1.0),
            signature_hex: hex(&sig.0),
            expected_verify: verify, // should be false
            description: "Invalid: signature verified with wrong public key".to_string(),
        });
    }

    // 14. Invalid signature — corrupted public key (flip last byte)
    {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);
        let sig = MlDsa65::sign_deterministic(&sk, b"corrupted pk test", &[0u8; 32]);
        let mut corrupted_pk_bytes = pk.0.clone();
        let last_idx = corrupted_pk_bytes.len() - 1;
        corrupted_pk_bytes[last_idx] ^= 0xFF;
        let corrupted = MlDsa65PublicKey(corrupted_pk_bytes);
        let verify = MlDsa65::verify(&corrupted, b"corrupted pk test", &sig);
        vectors.push(TestVector {
            id: "invalid_corrupted_public_key".to_string(),
            seed: hex(&seed),
            message_hex: hex(b"corrupted pk test"),
            context_hex: hex(&[]),
            public_key_hex: hex(&corrupted.0),
            secret_key_hex: hex(&sk.0),
            signature_hex: hex(&sig.0),
            expected_verify: verify, // should be false
            description: "Invalid: last byte of public key flipped".to_string(),
        });
    }

    // 15. Valid signature — randomized messages (deterministic signing for reproducibility)
    for i in 0..5u8 {
        let seed = [i + 1; 32];
        let msg = format!("randomized test message #{}", i).into_bytes();
        vectors.push(make_vector(
            &format!("valid_random_{}", i),
            &seed,
            &msg,
            &format!("Valid signature over randomized message #{}", i),
        ));
    }

    // Print JSON
    let json = serde_json::to_string_pretty(&vectors).unwrap();
    println!("{}", json);

    eprintln!("Generated {} test vectors", vectors.len());
    eprintln!("Public key size: {} bytes", ML_DSA_65_PUBKEY_LEN);
    eprintln!("Secret key size: {} bytes", ML_DSA_65_SECRETKEY_LEN);
    eprintln!("Signature size: {} bytes", ML_DSA_65_SIGNATURE_LEN);
}
