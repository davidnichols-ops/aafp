//! Conformance tests for RFC-0003: Identity and Authentication.
//!
//! Covers:
//! - §2: AgentId derivation (SHA-256 of public key)
//! - §2.6: AgentId fingerprint format
//! - §3: AgentRecord CBOR schema and signature
//! - §3.5: Domain separation
//! - §4: CapabilityDescriptor
//! - §8.4: Record expiry limits

use aafp_cbor::Value;
use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_identity::identity_v1::{
    AgentId, AgentRecord, CapabilityDescriptor, IdentityError, MetadataValue,
    KEY_ALG_ML_DSA_65, MAX_RECORD_EXPIRY, RECORD_DOMAIN_SEPARATOR, RECORD_TYPE_V1,
};
use sha2::{Digest, Sha256};

/// R3-001: AgentId MUST be SHA-256(public_key).
#[test]
fn test_r3_001_agent_id_is_sha256_of_pubkey() {
    let (pk, _) = MlDsa65::keypair();
    let agent_id = AgentId::from_public_key(&pk.0);
    let expected = Sha256::digest(&pk.0);
    assert_eq!(agent_id.as_bytes(), expected.as_slice());
}

/// R3-002: AgentId MUST be 32 bytes.
#[test]
fn test_r3_002_agent_id_32_bytes() {
    let (pk, _) = MlDsa65::keypair();
    let agent_id = AgentId::from_public_key(&pk.0);
    assert_eq!(agent_id.as_bytes().len(), 32);
}

/// R3-003: AgentId hex encoding MUST be 64 lowercase characters.
#[test]
fn test_r3_003_agent_id_hex_encoding() {
    let agent_id = AgentId([0xabu8; 32]);
    let hex = agent_id.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(hex, "ab".repeat(32));
    assert!(hex.chars().all(|c| c.is_lowercase() || c.is_numeric()));
}

/// R3-004: AgentId fingerprint MUST follow AAFP-base32-CRC32 format.
#[test]
fn test_r3_004_fingerprint_format() {
    let agent_id = AgentId([0u8; 32]);
    let fp = agent_id.to_fingerprint();
    assert!(fp.starts_with("AAFP-"), "must start with AAFP-");
    // Format: AAFP-<base32>-<8 hex chars>
    let parts: Vec<&str> = fp.split('-').collect();
    assert_eq!(parts.len(), 3, "must have 3 parts separated by -");
    assert!(parts[2].len() == 8, "CRC32 must be 8 hex chars");
}

/// R3-010: AgentRecord MUST use record_type "aafp-record-v1".
#[test]
fn test_r3_010_record_type_string() {
    assert_eq!(RECORD_TYPE_V1, "aafp-record-v1");
}

/// R3-011: AgentRecord MUST use integer keys 1-9.
#[test]
fn test_r3_011_record_integer_keys() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 86400, 1);
    record.sign(&sk);
    let cbor = record.to_cbor();
    for k in 1..=9i64 {
        assert!(
            aafp_cbor::int_map_get(&cbor, k).is_some(),
            "AgentRecord must have key {k}"
        );
    }
}

/// R3-012: AgentRecord signature MUST exclude field 8 (signature).
#[test]
fn test_r3_012_record_sig_excludes_field_8() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 86400, 1);
    record.sign(&sk);
    let cbor = record.to_cbor_without_sig();
    assert!(aafp_cbor::int_map_get(&cbor, 8).is_none(), "field 8 must be absent");
}

/// R3-013: AgentRecord signature MUST include field 9 (key_algorithm).
#[test]
fn test_r3_013_record_sig_includes_key_algorithm() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 86400, 1);
    record.sign(&sk);
    let cbor = record.to_cbor_without_sig();
    assert!(
        aafp_cbor::int_map_get(&cbor, 9).is_some(),
        "key_algorithm must be in signature input"
    );
}

/// R3-014: Domain separator MUST be "aafp-v1-record".
#[test]
fn test_r3_014_record_domain_separator() {
    assert_eq!(RECORD_DOMAIN_SEPARATOR, b"aafp-v1-record");
}

/// R3-015: AgentRecord verification MUST check agent_id == SHA-256(public_key).
#[test]
fn test_r3_015_verify_rejects_bad_agent_id() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 86400, 1);
    record.sign(&sk);
    record.agent_id = AgentId([0xFFu8; 32]); // Tamper
    let err = record.verify(0).unwrap_err();
    assert!(matches!(err, IdentityError::InvalidAgentId));
}

/// R3-016: AgentRecord verification MUST check expiry.
#[test]
fn test_r3_016_verify_rejects_expired() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 100, 1);
    record.sign(&sk);
    let err = record.verify(200).unwrap_err();
    assert!(matches!(err, IdentityError::Expired { .. }));
}

/// R3-017: AgentRecord verification MUST check signature.
#[test]
fn test_r3_017_verify_rejects_bad_signature() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 86400, 1);
    record.sign(&sk);
    record.signature[0] ^= 0xFF; // Tamper
    let err = record.verify(0).unwrap_err();
    assert!(matches!(err, IdentityError::SignatureVerificationFailed));
}

/// R3-018: AgentRecord verification MUST check record_type.
#[test]
fn test_r3_018_verify_rejects_wrong_record_type() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(&pk.0, vec![], vec![], 0, 86400, 1);
    record.sign(&sk);
    record.record_type = "wrong".to_string();
    let err = record.verify(0).unwrap_err();
    assert!(matches!(err, IdentityError::InvalidRecordType { .. }));
}

/// R3-019: ML-DSA-65 key_algorithm MUST be 1.
#[test]
fn test_r3_019_key_algorithm_value() {
    assert_eq!(KEY_ALG_ML_DSA_65, 1);
}

/// R3-020: Max record expiry MUST be 30 days.
#[test]
fn test_r3_020_max_expiry_30_days() {
    assert_eq!(MAX_RECORD_EXPIRY, 30 * 24 * 60 * 60);
}

/// R3-025: CapabilityDescriptor MUST use integer keys 1-2.
#[test]
fn test_r3_025_capability_descriptor_keys() {
    let cap = CapabilityDescriptor::new("inference");
    let cbor = cap.to_cbor();
    assert!(aafp_cbor::int_map_get(&cbor, 1).is_some(), "key 1 (name)");
    assert!(aafp_cbor::int_map_get(&cbor, 2).is_some(), "key 2 (metadata)");
}

/// R3-026: CapabilityDescriptor metadata map MUST use string keys.
#[test]
fn test_r3_026_metadata_uses_string_keys() {
    let cap = CapabilityDescriptor::new("inference")
        .with_metadata("model", MetadataValue::Text("gpt-4".to_string()));
    let cbor = cap.to_cbor();
    // Key 2 should be a StrMap, not IntMap
    let metadata = aafp_cbor::int_map_get(&cbor, 2).unwrap();
    assert!(matches!(metadata, Value::StrMap(_)), "metadata must use string keys");
}

/// R3-030: AgentRecord CBOR roundtrip must preserve all fields.
#[test]
fn test_r3_030_record_cbor_roundtrip() {
    let (pk, sk) = MlDsa65::keypair();
    let mut record = AgentRecord::new(
        &pk.0,
        vec![CapabilityDescriptor::new("inference")],
        vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
        1700000000,
        1700000000 + 86400,
        1,
    );
    record.sign(&sk);

    let cbor = record.to_cbor();
    let encoded = aafp_cbor::encode(&cbor).unwrap();
    let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
    let record2 = AgentRecord::from_cbor(&decoded).unwrap();

    assert_eq!(record2.agent_id, record.agent_id);
    assert_eq!(record2.public_key, record.public_key);
    assert_eq!(record2.signature, record.signature);
    assert_eq!(record2.capabilities.len(), 1);
    assert!(record2.verify(1700000000).is_ok());
}
