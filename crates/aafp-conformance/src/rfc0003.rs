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

// ===========================================================================
// Revision 4 Conformance Tests (SA-0001 and SA-0002)
// ===========================================================================

/// R4-001 (SA-0001): CapabilityDescriptor metadata (key 2) MUST always
/// be present on the wire, even when empty.
#[test]
fn test_r4_001_metadata_always_present() {
    let cap = CapabilityDescriptor::new("inference");
    let cbor = cap.to_cbor();
    // Key 2 MUST be present
    assert!(
        aafp_cbor::int_map_get(&cbor, 2).is_some(),
        "metadata (key 2) MUST always be present per RFC-0003 §4.4 (Revision 4)"
    );
}

/// R4-002 (SA-0001): Empty metadata MUST be encoded as an empty CBOR map
/// (`a0`), not omitted.
#[test]
fn test_r4_002_empty_metadata_encoded_as_empty_map() {
    let cap = CapabilityDescriptor::new("inference");
    let cbor = cap.to_cbor();
    let metadata = aafp_cbor::int_map_get(&cbor, 2).expect("key 2 must be present");

    // Empty metadata must be an empty StrMap (encoded as 0xa0 on the wire)
    match metadata {
        Value::StrMap(entries) => {
            assert!(
                entries.is_empty(),
                "empty metadata must have zero entries"
            );
        }
        Value::IntMap(entries) => {
            assert!(
                entries.is_empty(),
                "empty metadata must have zero entries"
            );
        }
        _ => panic!(
            "metadata must be a map, got {:?}",
            metadata
        ),
    }

    // Verify the encoded bytes contain 0xa0 for the empty map
    let encoded = aafp_cbor::encode(&cbor).unwrap();
    // The empty map byte 0xa0 must appear in the encoding
    assert!(
        encoded.contains(&0xa0),
        "encoded bytes must contain 0xa0 for empty metadata map"
    );
}

/// R4-003 (SA-0001): Two CapabilityDescriptors with empty metadata must
/// produce identical CBOR byte sequences (deterministic encoding).
#[test]
fn test_r4_003_empty_metadata_deterministic() {
    let cap1 = CapabilityDescriptor::new("inference");
    let cap2 = CapabilityDescriptor::new("inference");

    let encoded1 = aafp_cbor::encode(&cap1.to_cbor()).unwrap();
    let encoded2 = aafp_cbor::encode(&cap2.to_cbor()).unwrap();

    assert_eq!(
        encoded1, encoded2,
        "two CapabilityDescriptors with same name and empty metadata must produce identical bytes"
    );
}

/// R4-004 (SA-0001): AgentRecord with empty-metadata CapabilityDescriptor
/// must round-trip and preserve the metadata field.
#[test]
fn test_r4_004_record_with_empty_metadata_roundtrip() {
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

    let encoded = aafp_cbor::encode(&record.to_cbor()).unwrap();
    let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
    let record2 = AgentRecord::from_cbor(&decoded).unwrap();

    // The CapabilityDescriptor must still have metadata present
    assert_eq!(record2.capabilities.len(), 1);
    let cap = &record2.capabilities[0];
    assert_eq!(cap.name, "inference");
    assert!(
        cap.metadata.is_empty(),
        "metadata should be empty after roundtrip"
    );
    // Verify the record still verifies (signature covers the CBOR with key 2 present)
    assert!(record2.verify(1700000000).is_ok());
}

/// R4-005 (SA-0002): An empty CBOR map in the metadata field must be
/// decoded as a string-keyed map, not rejected as a type mismatch.
/// This tests the schema-driven key-type interpretation rule.
#[test]
fn test_r4_005_empty_map_schema_driven_keytype() {
    // Manually construct a CapabilityDescriptor CBOR with an empty map
    // at key 2. The empty map encodes as 0xa0 (major type 5).
    // Per RFC-0002 §8.1 (Revision 4), the decoder must interpret this
    // as a string-keyed map because the schema says map<tstr, MetadataValue>.
    let cbor = Value::IntMap(vec![
        (1, Value::TextString("inference".to_string())),
        (2, Value::StrMap(vec![])), // empty string-keyed map
    ]);

    let encoded = aafp_cbor::encode(&cbor).unwrap();
    let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
    let cap = CapabilityDescriptor::from_cbor(&decoded).expect(
        "decoder must accept empty metadata map per SA-0002",
    );

    assert_eq!(cap.name, "inference");
    assert!(cap.metadata.is_empty());
}

/// R4-006 (SA-0002): An empty CBOR map encoded as IntMap (major type 5)
/// in a string-keyed schema field must also be accepted, since the
/// schema defines the key type, not the CBOR major type.
#[test]
fn test_r4_006_empty_intmap_in_string_field_accepted() {
    // Construct CBOR with key 2 as an empty IntMap instead of StrMap.
    // On the wire, both encode as 0xa0. The decoder must accept either
    // representation in a schema-defined string-keyed field.
    let cbor = Value::IntMap(vec![
        (1, Value::TextString("inference".to_string())),
        (2, Value::IntMap(vec![])), // empty int-keyed map (same bytes as empty StrMap)
    ]);

    let encoded = aafp_cbor::encode(&cbor).unwrap();
    let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();

    // The decoder should accept this because:
    // 1. On the wire, empty IntMap and empty StrMap are both 0xa0
    // 2. The schema says key 2 is map<tstr, MetadataValue>
    // 3. Per SA-0002, the key type comes from the schema, not the major type
    let cap = CapabilityDescriptor::from_cbor(&decoded).expect(
        "decoder must accept empty map regardless of CBOR major type per SA-0002",
    );

    assert_eq!(cap.name, "inference");
    assert!(cap.metadata.is_empty());
}

// =============================================================================
// RFC Revision 5 Conformance Tests (SA-0003: 30-day expiry clarification)
//
// RFC-0003 §8.4 (Revision 5) clarifies that the 30-day limit is a deployment
// mitigation (warn users), NOT a verification-rejection requirement. The
// verification procedure in §3.6 does NOT reject records whose lifetime
// exceeds 30 days. The warning predicate is expires_at - now > 30 days.
// =============================================================================

/// R5-001: verify() MUST accept an unexpired record whose lifetime
/// (expires_at - created_at) exceeds 30 days. Per RFC-0003 §8.4 (Rev 5),
/// the 30-day limit is a warning, not a verification rejection.
#[test]
fn test_r5_001_verify_accepts_over_30day_lifetime_unexpired_record() {
    let (pk, sk) = MlDsa65::keypair();
    let now = 1735689600u64; // 2025-01-01
    // Lifetime = 60 days, well over the 30-day advisory, but unexpired.
    let mut record = AgentRecord::new(
        &pk.0,
        vec![CapabilityDescriptor::new("inference")],
        vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
        now,
        now + 60 * 86400,
        KEY_ALG_ML_DSA_65,
    );
    record.sign(&sk);

    // verify() must accept this: it is unexpired, and §3.6 has no
    // 30-day rejection step.
    let result = record.verify(now);
    assert!(
        result.is_ok(),
        "verify() must accept unexpired record with >30-day lifetime per RFC-0003 §8.4 (Rev 5): {:?}",
        result
    );
}

/// R5-002: exceeds_max_expiry_warning(now) MUST return true when
/// expires_at - now > 30 days (2,592,000 seconds).
#[test]
fn test_r5_002_warning_true_when_exceeds_30_days_from_now() {
    let (pk, _) = MlDsa65::keypair();
    let now = 1735689600u64;
    let record = AgentRecord::new(
        &pk.0,
        vec![],
        vec![],
        now,
        now + MAX_RECORD_EXPIRY + 1, // 30 days + 1 second
        KEY_ALG_ML_DSA_65,
    );
    assert!(
        record.exceeds_max_expiry_warning(now),
        "warning must fire when expires_at - now > 30 days"
    );
}

/// R5-003: exceeds_max_expiry_warning(now) MUST return false when
/// expires_at - now <= 30 days (boundary inclusive).
#[test]
fn test_r5_003_warning_false_when_within_30_days_from_now() {
    let (pk, _) = MlDsa65::keypair();
    let now = 1735689600u64;

    // Exactly 30 days: boundary, not exceeding
    let record = AgentRecord::new(
        &pk.0,
        vec![],
        vec![],
        now,
        now + MAX_RECORD_EXPIRY,
        KEY_ALG_ML_DSA_65,
    );
    assert!(
        !record.exceeds_max_expiry_warning(now),
        "warning must NOT fire at exactly 30 days (boundary)"
    );

    // 7 days: well within
    let record = AgentRecord::new(&pk.0, vec![], vec![], now, now + 7 * 86400, KEY_ALG_ML_DSA_65);
    assert!(
        !record.exceeds_max_expiry_warning(now),
        "warning must NOT fire for 7-day record"
    );
}

/// R5-004: exceeds_max_expiry_warning(now) MUST return false for an
/// already-expired record (expires_at <= now). The warning is about
/// future lifetime, not past records.
#[test]
fn test_r5_004_warning_false_for_already_expired_record() {
    let (pk, _) = MlDsa65::keypair();
    let now = 1735689600u64;
    // Record that expired 1 second ago
    let record = AgentRecord::new(&pk.0, vec![], vec![], now - 86400, now - 1, KEY_ALG_ML_DSA_65);
    assert!(
        !record.exceeds_max_expiry_warning(now),
        "warning must NOT fire for an already-expired record (saturates to 0)"
    );
}
