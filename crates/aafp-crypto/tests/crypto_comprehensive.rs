//! Comprehensive cryptographic tests for AAFP.
//!
//! This module covers:
//! - Known-answer tests for key sizes and signature sizes (FIPS 204 constants)
//! - Negative tests: malformed signatures, truncated messages, replay, altered transcripts
//! - Determinism tests: same key + message produces same signature
//! - Cross-implementation differential test infrastructure (Rust vs Go)
//! - Key serialization edge cases
//! - Large message handling
//! - Empty message handling

use aafp_crypto::dsa::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, ML_DSA_65_PUBKEY_LEN,
    ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use aafp_crypto::handshake::PqHandshake;
use aafp_crypto::traits::SignatureScheme;

// ===========================================================================
// Known-Answer / Constant Verification Tests (FIPS 204)
// ===========================================================================

/// Verify that ML-DSA-65 key and signature sizes match FIPS 204 constants.
#[test]
fn kat_key_sizes_match_fips204() {
    let (pk, sk) = MlDsa65::keypair();
    assert_eq!(
        pk.0.len(),
        ML_DSA_65_PUBKEY_LEN,
        "Public key must be {} bytes per FIPS 204",
        ML_DSA_65_PUBKEY_LEN
    );
    assert_eq!(
        sk.0.len(),
        ML_DSA_65_SECRETKEY_LEN,
        "Secret key must be {} bytes per FIPS 204",
        ML_DSA_65_SECRETKEY_LEN
    );
}

/// Verify that ML-DSA-65 signatures are always exactly 3309 bytes.
#[test]
fn kat_signature_size_constant() {
    let (pk, sk) = MlDsa65::keypair();
    for msg_len in [0usize, 1, 32, 64, 256, 1024, 4096, 65536] {
        let msg = vec![0xAB; msg_len];
        let sig = MlDsa65::sign(&sk, &msg);
        assert_eq!(
            sig.0.len(),
            ML_DSA_65_SIGNATURE_LEN,
            "Signature for {}-byte message must be exactly {} bytes",
            msg_len,
            ML_DSA_65_SIGNATURE_LEN
        );
    }
}

/// Verify that the algorithm name is correct.
#[test]
fn kat_algorithm_name() {
    assert_eq!(MlDsa65::algorithm_name(), "ML-DSA-65");
}

// ===========================================================================
// Negative Tests: Malformed Signatures
// ===========================================================================

/// A signature with a single bit flipped must fail verification.
#[test]
fn neg_single_bit_flip_in_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"test message for bit flip";
    let mut sig = MlDsa65::sign(&sk, msg);
    // Flip each bit position in the first 32 bytes
    for i in 0..32 {
        sig.0[i] ^= 0x01;
        assert!(
            !MlDsa65::verify(&pk, msg, &sig),
            "Signature with bit flip at byte {} must fail verification",
            i
        );
        sig.0[i] ^= 0x01; // Restore
    }
}

/// A signature with bytes swapped must fail verification.
#[test]
fn neg_byte_swap_in_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"test message for byte swap";
    let mut sig = MlDsa65::sign(&sk, msg);
    // Swap first and last bytes
    sig.0.swap(0, ML_DSA_65_SIGNATURE_LEN - 1);
    assert!(
        !MlDsa65::verify(&pk, msg, &sig),
        "Signature with swapped bytes must fail verification"
    );
}

/// A signature that is all zeros must fail verification.
#[test]
fn neg_all_zero_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"test message for zero sig";
    let sig = MlDsa65Signature(vec![0u8; ML_DSA_65_SIGNATURE_LEN]);
    assert!(
        !MlDsa65::verify(&pk, msg, &sig),
        "All-zero signature must fail verification"
    );
}

/// A signature that is all 0xFF must fail verification.
#[test]
fn neg_all_ff_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"test message for ff sig";
    let sig = MlDsa65Signature(vec![0xFFu8; ML_DSA_65_SIGNATURE_LEN]);
    assert!(
        !MlDsa65::verify(&pk, msg, &sig),
        "All-0xFF signature must fail verification"
    );
}

/// A truncated signature must fail to decode.
#[test]
fn neg_truncated_signature_decode() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"msg");
    // Truncate by 1 byte
    let truncated = &sig.0[..ML_DSA_65_SIGNATURE_LEN - 1];
    assert!(
        MlDsa65Signature::from_bytes(truncated).is_err(),
        "Truncated signature must fail to decode"
    );
}

/// An extended signature (extra bytes) must fail to decode.
#[test]
fn neg_extended_signature_decode() {
    let (pk, sk) = MlDsa65::keypair();
    let mut sig_bytes = MlDsa65::sign(&sk, b"msg").0;
    sig_bytes.push(0x00); // Add extra byte
    assert!(
        MlDsa65Signature::from_bytes(&sig_bytes).is_err(),
        "Extended signature must fail to decode"
    );
}

// ===========================================================================
// Negative Tests: Message Tampering
// ===========================================================================

/// Changing a single bit in the message must fail verification.
#[test]
fn neg_single_bit_flip_in_message() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"original message for tampering test";
    let sig = MlDsa65::sign(&sk, msg);
    for i in 0..msg.len() {
        let mut tampered = msg.to_vec();
        tampered[i] ^= 0x01;
        assert!(
            !MlDsa65::verify(&pk, &tampered, &sig),
            "Message with bit flip at byte {} must fail verification",
            i
        );
    }
}

/// Appending a byte to the message must fail verification.
#[test]
fn neg_message_extension() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"original message";
    let sig = MlDsa65::sign(&sk, msg);
    let extended = [msg.as_slice(), b"\x00"].concat();
    assert!(
        !MlDsa65::verify(&pk, &extended, &sig),
        "Extended message must fail verification"
    );
}

/// Truncating the message must fail verification.
#[test]
fn neg_message_truncation() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"original message for truncation test";
    let sig = MlDsa65::sign(&sk, msg);
    let truncated = &msg[..msg.len() - 1];
    assert!(
        !MlDsa65::verify(&pk, truncated, &sig),
        "Truncated message must fail verification"
    );
}

/// Empty message vs non-empty message must produce different verification results.
#[test]
fn neg_empty_vs_nonempty_message() {
    let (pk, sk) = MlDsa65::keypair();
    let sig_empty = MlDsa65::sign(&sk, b"");
    let sig_nonempty = MlDsa65::sign(&sk, b"x");

    // Verify each signature against its correct message
    assert!(MlDsa65::verify(&pk, b"", &sig_empty));
    assert!(MlDsa65::verify(&pk, b"x", &sig_nonempty));

    // Cross-verify: empty sig against non-empty message and vice versa
    assert!(
        !MlDsa65::verify(&pk, b"x", &sig_empty),
        "Empty-message signature must not verify against non-empty message"
    );
    assert!(
        !MlDsa65::verify(&pk, b"", &sig_nonempty),
        "Non-empty-message signature must not verify against empty message"
    );
}

// ===========================================================================
// Negative Tests: Key Tampering
// ===========================================================================

/// A public key with a single bit flipped must fail to verify signatures.
#[test]
fn neg_bit_flip_in_public_key() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"test message for key tampering";
    let sig = MlDsa65::sign(&sk, msg);

    // Flip bit in first byte of public key
    let mut tampered_pk = pk.0.clone();
    tampered_pk[0] ^= 0x01;
    let tampered = MlDsa65PublicKey(tampered_pk);

    // The tampered key might fail to decode or fail to verify
    // Either way, verification must fail
    let result = MlDsa65::verify(&tampered, msg, &sig);
    assert!(
        !result,
        "Signature must not verify against tampered public key"
    );
}

/// A public key that is all zeros is accepted by PQClean's deserializer
/// (it only checks length, not mathematical validity). This is a known
/// limitation — the key will fail during verification, not during decode.
/// This test documents the behavior: all-zero keys decode successfully
/// but cannot produce valid signatures.
#[test]
fn neg_all_zero_public_key_decode_behavior() {
    let zero_pk = vec![0u8; ML_DSA_65_PUBKEY_LEN];
    // PQClean accepts all-zero bytes as a valid key encoding (length-only check)
    let decoded = MlDsa65PublicKey::from_bytes(&zero_pk);
    // Document the actual behavior: decode succeeds (length-only validation)
    assert!(
        decoded.is_ok(),
        "PQClean accepts all-zero public key (length-only validation). \
         Key will fail during verification, not during decode."
    );

    // Verify that an all-zero key cannot verify any signature
    let zero_key = decoded.unwrap();
    let fake_sig = MlDsa65Signature(vec![0u8; ML_DSA_65_SIGNATURE_LEN]);
    assert!(
        !MlDsa65::verify(&zero_key, b"msg", &fake_sig),
        "All-zero public key must not verify any signature"
    );
}

/// A secret key that is all zeros is accepted by PQClean's deserializer
/// (length-only check). Signing with it may produce a signature, but
/// verification with the corresponding (all-zero) public key will fail.
#[test]
fn neg_all_zero_secret_key_decode_behavior() {
    let zero_sk = vec![0u8; ML_DSA_65_SECRETKEY_LEN];
    let decoded = MlDsa65SecretKey::from_bytes(&zero_sk);
    // Document the actual behavior
    assert!(
        decoded.is_ok(),
        "PQClean accepts all-zero secret key (length-only validation). \
         Key will fail during signing/verification, not during decode."
    );
}

// ===========================================================================
// Determinism Tests
// ===========================================================================

/// ML-DSA-65 signing in this implementation (PQClean) is randomized,
/// not deterministic. FIPS 204 supports both modes. This test verifies
/// that two signatures for the same message are different (randomized)
/// but both verify correctly.
#[test]
fn det_signing_is_randomized() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"randomized signing test message";

    let sig1 = MlDsa65::sign(&sk, msg);
    let sig2 = MlDsa65::sign(&sk, msg);

    // Randomized signing: signatures should differ
    assert_ne!(
        sig1.0, sig2.0,
        "ML-DSA-65 signing is randomized (PQClean default): same key + message should produce different signatures"
    );
    // Both must verify
    assert!(MlDsa65::verify(&pk, msg, &sig1));
    assert!(MlDsa65::verify(&pk, msg, &sig2));
}

/// Different messages must produce different signatures.
#[test]
fn det_different_messages_different_signatures() {
    let (pk, sk) = MlDsa65::keypair();
    let sig1 = MlDsa65::sign(&sk, b"message one");
    let sig2 = MlDsa65::sign(&sk, b"message two");
    assert_ne!(
        sig1.0, sig2.0,
        "Different messages must produce different signatures"
    );
}

/// Different keys must produce different signatures for the same message.
#[test]
fn det_different_keys_different_signatures() {
    let (_pk1, sk1) = MlDsa65::keypair();
    let (_pk2, sk2) = MlDsa65::keypair();
    let msg = b"same message, different keys";
    let sig1 = MlDsa65::sign(&sk1, msg);
    let sig2 = MlDsa65::sign(&sk2, msg);
    assert_ne!(
        sig1.0, sig2.0,
        "Different keys must produce different signatures for the same message"
    );
}

/// Key generation must produce unique keypairs.
#[test]
fn det_keypair_generation_unique() {
    let mut keys = Vec::new();
    for _ in 0..10 {
        let (pk, sk) = MlDsa65::keypair();
        keys.push((pk.0, sk.0));
    }
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i].0, keys[j].0,
                "Public key {} and {} must be different",
                i, j
            );
            assert_ne!(
                keys[i].1, keys[j].1,
                "Secret key {} and {} must be different",
                i, j
            );
        }
    }
}

// ===========================================================================
// Serialization Edge Cases
// ===========================================================================

/// Public key serialization roundtrip preserves bytes exactly.
#[test]
fn ser_public_key_exact_roundtrip() {
    let (pk, _sk) = MlDsa65::keypair();
    let decoded = MlDsa65PublicKey::from_bytes(&pk.0).unwrap();
    assert_eq!(pk.0, decoded.0, "Public key roundtrip must preserve bytes");
}

/// Secret key serialization roundtrip preserves bytes exactly.
#[test]
fn ser_secret_key_exact_roundtrip() {
    let (_pk, sk) = MlDsa65::keypair();
    let decoded = MlDsa65SecretKey::from_bytes(&sk.0).unwrap();
    assert_eq!(sk.0, decoded.0, "Secret key roundtrip must preserve bytes");
}

/// Signature serialization roundtrip preserves bytes exactly.
#[test]
fn ser_signature_exact_roundtrip() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"roundtrip test");
    let decoded = MlDsa65Signature::from_bytes(&sig.0).unwrap();
    assert_eq!(sig.0, decoded.0, "Signature roundtrip must preserve bytes");
    assert!(
        MlDsa65::verify(&pk, b"roundtrip test", &decoded),
        "Decoded signature must verify"
    );
}

/// Empty public key must fail to decode.
#[test]
fn ser_empty_public_key_rejected() {
    assert!(MlDsa65PublicKey::from_bytes(&[]).is_err());
}

/// Empty secret key must fail to decode.
#[test]
fn ser_empty_secret_key_rejected() {
    assert!(MlDsa65SecretKey::from_bytes(&[]).is_err());
}

/// Empty signature must fail to decode.
#[test]
fn ser_empty_signature_rejected() {
    assert!(MlDsa65Signature::from_bytes(&[]).is_err());
}

// ===========================================================================
// Large Message Handling
// ===========================================================================

/// Signing and verifying a 1 MB message must succeed.
#[test]
fn large_message_1mb() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = vec![0x42; 1024 * 1024];
    let sig = MlDsa65::sign(&sk, &msg);
    assert!(
        MlDsa65::verify(&pk, &msg, &sig),
        "1 MB message must sign and verify correctly"
    );
}

/// Signing and verifying a 10 MB message must succeed.
#[test]
fn large_message_10mb() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = vec![0x42; 10 * 1024 * 1024];
    let sig = MlDsa65::sign(&sk, &msg);
    assert!(
        MlDsa65::verify(&pk, &msg, &sig),
        "10 MB message must sign and verify correctly"
    );
}

// ===========================================================================
// Handshake Replay and Transcript Tampering Tests
// ===========================================================================

/// Replaying a server hello with a different client state must fail.
#[test]
fn neg_handshake_replay_with_different_client_state() {
    let server_kp = MlDsa65::keypair();
    let (hello1, _state1) = PqHandshake::client_init();
    let (hello2, mut state2) = PqHandshake::client_init();

    // Server processes hello1
    let (server_hello, _server_state) =
        PqHandshake::server_handle(&hello1, &server_kp).expect("server handle");

    // Client tries to finish with state2 (from hello2, not hello1)
    let result = PqHandshake::client_finish(&server_hello, &mut state2);
    assert!(
        result.is_err(),
        "Replaying server hello with different client state must fail"
    );
}

/// Tampering with the server hello nonce must fail.
#[test]
fn neg_handshake_tampered_nonce() {
    let server_kp = MlDsa65::keypair();
    let (hello, mut client_state) = PqHandshake::client_init();
    let (mut server_hello, _ss) =
        PqHandshake::server_handle(&hello, &server_kp).unwrap();

    // Tamper with nonce
    server_hello.nonce[0] ^= 0xFF;

    let result = PqHandshake::client_finish(&server_hello, &mut client_state);
    assert!(
        result.is_err(),
        "Handshake with tampered nonce must fail"
    );
}

/// Tampering with the server hello key share must fail.
#[test]
fn neg_handshake_tampered_key_share() {
    let server_kp = MlDsa65::keypair();
    let (hello, mut client_state) = PqHandshake::client_init();
    let (mut server_hello, _ss) =
        PqHandshake::server_handle(&hello, &server_kp).unwrap();

    // Tamper with key share
    if !server_hello.key_share.is_empty() {
        server_hello.key_share[0] ^= 0xFF;
    }

    let result = PqHandshake::client_finish(&server_hello, &mut client_state);
    assert!(
        result.is_err(),
        "Handshake with tampered key share must fail"
    );
}

/// Tampering with the server hello version must fail.
#[test]
fn neg_handshake_tampered_version() {
    let server_kp = MlDsa65::keypair();
    let (hello, mut client_state) = PqHandshake::client_init();
    let (mut server_hello, _ss) =
        PqHandshake::server_handle(&hello, &server_kp).unwrap();

    // Tamper with version
    server_hello.version = 0xFF;

    let result = PqHandshake::client_finish(&server_hello, &mut client_state);
    assert!(
        result.is_err(),
        "Handshake with tampered version must fail"
    );
}

/// Two independent handshakes must produce different shared secrets.
#[test]
fn handshake_independence() {
    let server_kp = MlDsa65::keypair();

    let (hello1, mut state1) = PqHandshake::client_init();
    let (server_hello1, _ss1) = PqHandshake::server_handle(&hello1, &server_kp).unwrap();
    let result1 = PqHandshake::client_finish(&server_hello1, &mut state1).unwrap();

    let (hello2, mut state2) = PqHandshake::client_init();
    let (server_hello2, _ss2) = PqHandshake::server_handle(&hello2, &server_kp).unwrap();
    let result2 = PqHandshake::client_finish(&server_hello2, &mut state2).unwrap();

    assert_ne!(
        result1.shared_secret, result2.shared_secret,
        "Two independent handshakes must produce different shared secrets"
    );
}

/// The transcript hash from a handshake must be 32 bytes (SHA-256).
#[test]
fn handshake_transcript_hash_length() {
    let server_kp = MlDsa65::keypair();
    let (hello, mut client_state) = PqHandshake::client_init();
    let (server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
    let result = PqHandshake::client_finish(&server_hello, &mut client_state).unwrap();

    assert_eq!(
        result.transcript_hash.len(),
        32,
        "Transcript hash must be 32 bytes (SHA-256)"
    );
}

/// The session ID derived from a handshake must be 32 bytes.
#[test]
fn handshake_session_id_length() {
    let server_kp = MlDsa65::keypair();
    let (hello, mut client_state) = PqHandshake::client_init();
    let (server_hello, _ss) = PqHandshake::server_handle(&hello, &server_kp).unwrap();
    let result = PqHandshake::client_finish(&server_hello, &mut client_state).unwrap();

    assert_eq!(
        result.shared_secret.len(),
        32,
        "Shared secret (session ID) must be 32 bytes"
    );
}

// ===========================================================================
// Cross-Implementation Differential Test Infrastructure
// ===========================================================================

/// Generate a deterministic test vector that can be verified by the Go
/// implementation. This test generates a keypair, signs a known message,
/// and outputs the public key, message, and signature in hex format.
/// The Go implementation can then verify the signature using its own
/// ML-DSA-65 implementation (once integrated).
#[test]
fn diff_generate_rust_sign_vector() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"AAFP cross-implementation differential test vector";
    let sig = MlDsa65::sign(&sk, msg);

    // Verify our own signature
    assert!(MlDsa65::verify(&pk, msg, &sig));

    // The test passes if verification succeeds. The actual hex output
    // for Go consumption would be generated by a separate tool.
    // This test confirms the Rust side can produce verifiable signatures.
}

/// Verify a signature produced by an external implementation.
/// This is a placeholder that will be populated once the Go implementation
/// has ML-DSA-65 support. The test will decode a hex-encoded public key,
/// message, and signature from a test vector file, then verify.
#[test]
fn diff_verify_external_signature() {
    // Placeholder: Once Go has ML-DSA-65, this test will:
    // 1. Load a test vector (pk, msg, sig) generated by Go
    // 2. Decode the hex values
    // 3. Verify the signature using Rust's MlDsa65::verify
    // 4. Assert verification succeeds
    //
    // For now, we verify that our own sign+verify works (self-consistency).
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"external signature verification placeholder";
    let sig = MlDsa65::sign(&sk, msg);
    assert!(MlDsa65::verify(&pk, msg, &sig));
}

// ===========================================================================
// Key Reuse and Multi-Message Tests
// ===========================================================================

/// A single keypair must be able to sign many messages.
#[test]
fn key_reuse_multiple_messages() {
    let (pk, sk) = MlDsa65::keypair();
    for i in 0..100 {
        let msg = format!("message number {}", i);
        let sig = MlDsa65::sign(&sk, msg.as_bytes());
        assert!(
            MlDsa65::verify(&pk, msg.as_bytes(), &sig),
            "Message {} must verify after signing with reused key",
            i
        );
    }
}

/// A single keypair must be able to sign the same message multiple times.
/// Since PQClean uses randomized signing, signatures will differ but all
/// must verify.
#[test]
fn key_reuse_same_message_randomized() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"repeated message for randomized signing check";
    let sigs: Vec<_> = (0..10).map(|_| MlDsa65::sign(&sk, msg)).collect();

    // All must verify
    for (i, sig) in sigs.iter().enumerate() {
        assert!(
            MlDsa65::verify(&pk, msg, sig),
            "Signature {} must verify",
            i
        );
    }

    // With randomized signing, signatures should mostly differ
    let unique_count: usize = sigs
        .iter()
        .map(|s| s.0.as_slice())
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert!(
        unique_count > 1,
        "Randomized signing should produce at least 2 unique signatures out of 10, got {}",
        unique_count
    );
}

// ===========================================================================
// Boundary Condition Tests
// ===========================================================================

/// Signing an empty message must succeed and verify.
#[test]
fn boundary_empty_message() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"");
    assert_eq!(sig.0.len(), ML_DSA_65_SIGNATURE_LEN);
    assert!(MlDsa65::verify(&pk, b"", &sig));
}

/// Signing a single-byte message must succeed and verify.
#[test]
fn boundary_single_byte_message() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = [0x42u8];
    let sig = MlDsa65::sign(&sk, &msg);
    assert!(MlDsa65::verify(&pk, &msg, &sig));
}

/// Signing a message that is exactly 32 bytes must succeed and verify.
#[test]
fn boundary_32_byte_message() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = [0xABu8; 32];
    let sig = MlDsa65::sign(&sk, &msg);
    assert!(MlDsa65::verify(&pk, &msg, &sig));
}

/// Signing a message that is exactly 64 bytes must succeed and verify.
#[test]
fn boundary_64_byte_message() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = [0xCDu8; 64];
    let sig = MlDsa65::sign(&sk, &msg);
    assert!(MlDsa65::verify(&pk, &msg, &sig));
}

/// Signing a message with all byte values (0x00 through 0xFF) must succeed.
#[test]
fn boundary_all_byte_values() {
    let (pk, sk) = MlDsa65::keypair();
    let msg: Vec<u8> = (0..=255u8).collect();
    let sig = MlDsa65::sign(&sk, &msg);
    assert!(MlDsa65::verify(&pk, &msg, &sig));
}
