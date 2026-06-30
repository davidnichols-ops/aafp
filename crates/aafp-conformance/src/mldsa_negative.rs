//! Negative testing for ML-DSA-65 (A-10 Phase 5).
//!
//! Tests that malformed inputs are handled gracefully:
//! - truncated signature
//! - oversized signature
//! - corrupted signature
//! - corrupted message
//! - corrupted public key
//! - invalid key length
//! - malformed encoding

#![allow(unused_imports)]
use aafp_crypto::{
    MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme,
    ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SECRETKEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};

#[test]
fn test_neg_truncated_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"test message");
    let truncated = &sig.0[..ML_DSA_65_SIGNATURE_LEN - 1];
    let bad_sig = MlDsa65Signature(truncated.to_vec());
    assert!(
        !MlDsa65::verify(&pk, b"test message", &bad_sig),
        "truncated signature must not verify"
    );
}

#[test]
fn test_neg_oversized_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"test message");
    let mut oversized = sig.0.clone();
    oversized.push(0x00);
    let bad_sig = MlDsa65Signature(oversized);
    assert!(
        !MlDsa65::verify(&pk, b"test message", &bad_sig),
        "oversized signature must not verify"
    );
}

#[test]
fn test_neg_corrupted_signature_single_byte() {
    let (pk, sk) = MlDsa65::keypair();
    let mut sig = MlDsa65::sign(&sk, b"test message");
    sig.0[0] ^= 0x01;
    assert!(
        !MlDsa65::verify(&pk, b"test message", &sig),
        "corrupted signature (1 bit) must not verify"
    );
}

#[test]
fn test_neg_corrupted_signature_all_bytes() {
    let (pk, sk) = MlDsa65::keypair();
    let mut sig = MlDsa65::sign(&sk, b"test message");
    for b in sig.0.iter_mut() {
        *b ^= 0xFF;
    }
    assert!(
        !MlDsa65::verify(&pk, b"test message", &sig),
        "fully corrupted signature must not verify"
    );
}

#[test]
fn test_neg_corrupted_message() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"original message");
    assert!(
        !MlDsa65::verify(&pk, b"corrupted message", &sig),
        "corrupted message must not verify"
    );
}

#[test]
fn test_neg_single_bit_message_change() {
    let (pk, sk) = MlDsa65::keypair();
    let msg = b"test message for bit flip";
    let sig = MlDsa65::sign(&sk, msg);
    let mut corrupted = msg.to_vec();
    corrupted[0] ^= 0x01;
    assert!(
        !MlDsa65::verify(&pk, &corrupted, &sig),
        "single-bit message change must not verify"
    );
}

#[test]
fn test_neg_corrupted_public_key() {
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"test message");
    let mut corrupted_pk = pk.0.clone();
    corrupted_pk[0] ^= 0x01;
    let bad_pk = MlDsa65PublicKey(corrupted_pk);
    assert!(
        !MlDsa65::verify(&bad_pk, b"test message", &sig),
        "corrupted public key must not verify"
    );
}

#[test]
fn test_neg_wrong_key() {
    let (pk1, sk1) = MlDsa65::keypair();
    let (pk2, _sk2) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk1, b"test message");
    assert!(
        !MlDsa65::verify(&pk2, b"test message", &sig),
        "wrong key must not verify"
    );
    assert!(
        MlDsa65::verify(&pk1, b"test message", &sig),
        "correct key must verify"
    );
}

#[test]
fn test_neg_invalid_public_key_length() {
    assert!(
        MlDsa65PublicKey::from_bytes(&[0u8; 10]).is_err(),
        "10-byte public key must be rejected"
    );
    assert!(
        MlDsa65PublicKey::from_bytes(&[0u8; 1951]).is_err(),
        "1951-byte public key must be rejected"
    );
    assert!(
        MlDsa65PublicKey::from_bytes(&[0u8; 1953]).is_err(),
        "1953-byte public key must be rejected"
    );
}

#[test]
fn test_neg_invalid_secret_key_length() {
    assert!(
        MlDsa65SecretKey::from_bytes(&[0u8; 10]).is_err(),
        "10-byte secret key must be rejected"
    );
    assert!(
        MlDsa65SecretKey::from_bytes(&[0u8; 4031]).is_err(),
        "4031-byte secret key must be rejected"
    );
    assert!(
        MlDsa65SecretKey::from_bytes(&[0u8; 4033]).is_err(),
        "4033-byte secret key must be rejected"
    );
}

#[test]
fn test_neg_invalid_signature_length() {
    assert!(
        MlDsa65Signature::from_bytes(&[0u8; 10]).is_err(),
        "10-byte signature must be rejected"
    );
    assert!(
        MlDsa65Signature::from_bytes(&[0u8; 3308]).is_err(),
        "3308-byte signature must be rejected"
    );
    assert!(
        MlDsa65Signature::from_bytes(&[0u8; 3310]).is_err(),
        "3310-byte signature must be rejected"
    );
}

#[test]
fn test_neg_empty_message_valid_sig() {
    // Empty message should still produce a valid signature.
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"");
    assert!(
        MlDsa65::verify(&pk, b"", &sig),
        "empty message with valid signature should verify"
    );
    assert!(
        !MlDsa65::verify(&pk, b"x", &sig),
        "empty message sig should not verify against non-empty message"
    );
}

#[test]
fn test_neg_all_zero_signature() {
    let (pk, _) = MlDsa65::keypair();
    let sig = MlDsa65Signature(vec![0u8; ML_DSA_65_SIGNATURE_LEN]);
    assert!(
        !MlDsa65::verify(&pk, b"test message", &sig),
        "all-zero signature must not verify"
    );
}

#[test]
fn test_neg_all_ff_signature() {
    let (pk, _) = MlDsa65::keypair();
    let sig = MlDsa65Signature(vec![0xFFu8; ML_DSA_65_SIGNATURE_LEN]);
    assert!(
        !MlDsa65::verify(&pk, b"test message", &sig),
        "all-FF signature must not verify"
    );
}

#[test]
fn test_neg_all_zero_public_key() {
    // All-zero public key may or may not be valid encoding.
    // If it's valid, verification should still fail for a real signature.
    let (_pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"test message");
    let zero_pk = MlDsa65PublicKey(vec![0u8; ML_DSA_65_PUBKEY_LEN]);
    // This should not verify (all-zero pk is not a valid key).
    let _ = MlDsa65::verify(&zero_pk, b"test message", &sig);
    // We don't assert here because the behavior depends on the library.
    // The key point is it must not panic.
}

#[test]
fn test_neg_no_panic_on_malformed_inputs() {
    // Ensure no panics on various malformed inputs.
    let (pk, sk) = MlDsa65::keypair();
    let sig = MlDsa65::sign(&sk, b"test");

    // Various malformed signatures — must not panic.
    let _ = MlDsa65::verify(&pk, b"test", &MlDsa65Signature(vec![]));
    let _ = MlDsa65::verify(&pk, b"test", &MlDsa65Signature(vec![0u8; 1]));
    let _ = MlDsa65::verify(&pk, b"test", &MlDsa65Signature(vec![0u8; 3309]));
    let _ = MlDsa65::verify(&pk, b"test", &MlDsa65Signature(vec![0xFFu8; 3309]));

    // Various malformed public keys — must not panic.
    let _ = MlDsa65::verify(&MlDsa65PublicKey(vec![]), b"test", &sig);
    let _ = MlDsa65::verify(&MlDsa65PublicKey(vec![0u8; 1]), b"test", &sig);
    let _ = MlDsa65::verify(&MlDsa65PublicKey(vec![0u8; 1952]), b"test", &sig);
}
