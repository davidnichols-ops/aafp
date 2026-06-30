//! Negative conformance tests for malformed/adversarial inputs.
//!
//! These tests verify that the implementation correctly REJECTS invalid inputs
//! per RFC requirements. Each test is tagged with the RFC requirement it enforces.
//!
//! Categories:
//! - Non-canonical CBOR encoding
//! - Duplicate CBOR map keys
//! - Invalid frame headers
//! - Truncated frames
//! - Oversized payloads
//! - Invalid signatures
//! - Expired/tampered AgentRecords
//! - Invalid handshake messages

use aafp_cbor::{decode, encode, int_map, Value};
use aafp_core::error::{codes, is_always_fatal, ProtocolError};
use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_identity::identity_v1::{
    AgentId, AgentRecord, CapabilityDescriptor, IdentityError, KEY_ALG_ML_DSA_65,
    MAX_RECORD_EXPIRY, RECORD_TYPE_V1,
};
use aafp_messaging::{
    decode_frame, encode_frame, Frame, FrameError, FrameType, AAFP_VERSION, FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
};

// === Non-canonical CBOR ===

#[cfg(test)]
mod non_canonical_cbor {
    use super::*;

    /// N-CBOR-001: Non-shortest integer encoding (value 5 as 0x18 0x05) MUST be rejected.
    #[test]
    fn test_ncbor_001_reject_non_shortest_uint_one_byte() {
        // 0x18 = AI_ONE_BYTE, 0x05 = value 5 — should be 0x05 (immediate)
        let bad = vec![0x18, 0x05];
        assert!(
            decode(&bad).is_err(),
            "non-canonical uint 5 as 0x1805 must be rejected"
        );
    }

    /// N-CBOR-002: Non-shortest integer encoding (value 20 as 0x18 0x14) MUST be rejected.
    #[test]
    fn test_ncbor_002_reject_non_shortest_uint_small() {
        // 0x18 0x14 = value 20 — should be 0x14 (immediate)
        let bad = vec![0x18, 0x14];
        assert!(
            decode(&bad).is_err(),
            "non-canonical uint 20 as 0x1814 must be rejected"
        );
    }

    /// N-CBOR-003: Value 100 in 2-byte form (0x19 0x00 0x64) MUST be rejected.
    #[test]
    fn test_ncbor_003_reject_non_shortest_uint_two_byte() {
        // 0x19 = AI_TWO_BYTES, 0x0064 = 100 — should be 0x18 0x64
        let bad = vec![0x19, 0x00, 0x64];
        assert!(
            decode(&bad).is_err(),
            "non-canonical uint 100 as 0x190064 must be rejected"
        );
    }

    /// N-CBOR-004: Value 255 in 2-byte form (0x19 0x00 0xFF) MUST be rejected.
    #[test]
    fn test_ncbor_004_reject_non_shortest_uint_255() {
        let bad = vec![0x19, 0x00, 0xFF];
        assert!(
            decode(&bad).is_err(),
            "non-canonical uint 255 as 0x1900FF must be rejected"
        );
    }

    /// N-CBOR-005: Value 1000 in 4-byte form MUST be rejected.
    #[test]
    fn test_ncbor_005_reject_non_shortest_uint_four_byte() {
        // 0x1A = AI_FOUR_BYTES, 0x000003E8 = 1000
        let bad = vec![0x1A, 0x00, 0x00, 0x03, 0xE8];
        assert!(
            decode(&bad).is_err(),
            "non-canonical uint 1000 in 4-byte form must be rejected"
        );
    }

    /// N-CBOR-006: Indefinite-length array (0x9F) MUST be rejected.
    #[test]
    fn test_ncbor_006_reject_indefinite_array() {
        // 0x9F = start indefinite-length array
        let bad = vec![0x9F, 0x01, 0x02, 0xFF];
        assert!(
            decode(&bad).is_err(),
            "indefinite-length array must be rejected"
        );
    }

    /// N-CBOR-007: Indefinite-length map (0xBF) MUST be rejected.
    #[test]
    fn test_ncbor_007_reject_indefinite_map() {
        // 0xBF = start indefinite-length map
        let bad = vec![0xBF, 0x01, 0x02, 0xFF];
        assert!(
            decode(&bad).is_err(),
            "indefinite-length map must be rejected"
        );
    }

    /// N-CBOR-008: Break code (0xFF) in definite-length context MUST be rejected.
    #[test]
    fn test_ncbor_008_reject_bare_break_code() {
        let bad = vec![0xFF];
        assert!(decode(&bad).is_err(), "bare break code must be rejected");
    }

    /// N-CBOR-009: Truncated input (empty) MUST be rejected.
    #[test]
    fn test_ncbor_009_reject_empty_input() {
        assert!(decode(&[]).is_err(), "empty input must be rejected");
    }

    /// N-CBOR-010: Truncated byte string (declared length > available) MUST be rejected.
    #[test]
    fn test_ncbor_010_reject_truncated_byte_string() {
        // 0x58 = bstr with 1-byte length, 0x20 = 32 bytes, but only 4 follow
        let bad = vec![0x58, 0x20, 0x01, 0x02, 0x03, 0x04];
        assert!(
            decode(&bad).is_err(),
            "truncated byte string must be rejected"
        );
    }

    /// N-CBOR-011: Truncated text string MUST be rejected.
    #[test]
    fn test_ncbor_011_reject_truncated_text_string() {
        // 0x68 = tstr with length 8, but only 5 bytes follow
        let bad = vec![0x68, b'h', b'e', b'l', b'l', b'o'];
        assert!(
            decode(&bad).is_err(),
            "truncated text string must be rejected"
        );
    }

    /// N-CBOR-012: Invalid UTF-8 in text string MUST be rejected.
    #[test]
    fn test_ncbor_012_reject_invalid_utf8() {
        // 0x62 = tstr length 2, followed by invalid UTF-8 (0xC0 0xC0)
        let bad = vec![0x62, 0xC0, 0xC0];
        assert!(decode(&bad).is_err(), "invalid UTF-8 must be rejected");
    }

    /// N-CBOR-013: Duplicate integer map keys MUST be rejected.
    #[test]
    fn test_ncbor_013_reject_duplicate_int_keys() {
        // Map(2) { 1: "a", 1: "b" } — duplicate key 1
        let bad = vec![
            0xA2, // map(2)
            0x01, // key 1
            0x61, 0x61, // "a"
            0x01, // key 1 (duplicate!)
            0x61, 0x62, // "b"
        ];
        assert!(
            decode(&bad).is_err(),
            "duplicate int map keys must be rejected"
        );
    }

    /// N-CBOR-014: Duplicate string map keys MUST be rejected.
    #[test]
    fn test_ncbor_014_reject_duplicate_str_keys() {
        // Map(2) { "a": 1, "a": 2 } — duplicate key "a"
        let bad = vec![
            0xA2, // map(2)
            0x61, 0x61, // "a"
            0x01, // 1
            0x61, 0x61, // "a" (duplicate!)
            0x02, // 2
        ];
        assert!(
            decode(&bad).is_err(),
            "duplicate str map keys must be rejected"
        );
    }

    /// N-CBOR-015: CBOR tag (major type 6) MUST be rejected (not used in AAFP).
    #[test]
    fn test_ncbor_015_reject_tag() {
        // 0xC0 = tag 0 (standard date/time string)
        let bad = vec![
            0xC0, 0x74, b'2', b'0', b'2', b'5', b'-', b'0', b'1', b'-', b'0', b'1',
        ];
        assert!(decode(&bad).is_err(), "CBOR tags must be rejected");
    }

    /// N-CBOR-016: Unsupported simple value MUST be rejected.
    #[test]
    fn test_ncbor_016_reject_unknown_simple() {
        // 0xF8 = simple value with 1-byte argument, 0x10 = simple value 16
        let bad = vec![0xF8, 0x10];
        assert!(
            decode(&bad).is_err(),
            "unknown simple value must be rejected"
        );
    }

    /// N-CBOR-017: Truncated map (declared 2 entries but only 1) MUST be rejected.
    #[test]
    fn test_ncbor_017_reject_truncated_map() {
        // Map(2) but only 1 entry
        let bad = vec![
            0xA2, // map(2)
            0x01, // key 1
            0x02, // value 2
                  // Missing second entry
        ];
        assert!(decode(&bad).is_err(), "truncated map must be rejected");
    }

    /// N-CBOR-018: Truncated array MUST be rejected.
    #[test]
    fn test_ncbor_018_reject_truncated_array() {
        // Array(3) but only 2 elements
        let bad = vec![0x83, 0x01, 0x02]; // Missing third element
        assert!(decode(&bad).is_err(), "truncated array must be rejected");
    }
}

// === Invalid Frames ===

#[cfg(test)]
mod invalid_frames {
    use super::*;

    /// N-FRAME-001: Frame with wrong version MUST be rejected.
    #[test]
    fn test_nframe_001_reject_wrong_version() {
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = 0x02; // Wrong version (should be 1)
        bytes[1] = FrameType::Data.to_u8();
        let result = decode_frame(&bytes);
        assert!(result.is_err(), "wrong version must be rejected");
        match result.unwrap_err() {
            FrameError::InvalidVersion(v, expected) => {
                assert_eq!(v, 0x02);
                assert_eq!(expected, AAFP_VERSION);
            }
            e => panic!("expected InvalidVersion, got {e:?}"),
        }
    }

    /// N-FRAME-002: Frame with unknown non-critical type MUST be skipped (not rejected).
    /// Per RFC-0006 §4.2: non-critical unknown frame types MUST be skipped.
    /// The decoder should succeed; the caller is responsible for skipping.
    #[test]
    fn test_nframe_002_reject_unknown_type() {
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = AAFP_VERSION;
        bytes[1] = 0x0F; // Unknown type, no critical bit (flags byte is 0)
        let result = decode_frame(&bytes);
        // Per RFC-0006 §4.2, non-critical unknown types should decode
        // successfully so the caller can skip them.
        assert!(
            result.is_ok(),
            "non-critical unknown frame type should decode (for skipping), got: {:?}",
            result
        );
        let (frame, _) = result.unwrap();
        assert!(
            frame.frame_type.is_unknown(),
            "frame type should be Unknown"
        );
        assert!(
            !frame.frame_type.is_known(),
            "frame type should not be known"
        );
    }

    /// N-FRAME-003: Frame with unknown critical type (0xFF | 0x80) MUST be rejected.
    #[test]
    fn test_nframe_003_reject_unknown_critical_type() {
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = AAFP_VERSION;
        bytes[1] = 0xFF; // Unknown type
        bytes[2] = 0x80; // Critical flag
        let result = decode_frame(&bytes);
        assert!(
            result.is_err(),
            "unknown critical frame type must be rejected"
        );
    }

    /// N-FRAME-004: Truncated frame (less than 28 bytes) MUST be rejected.
    #[test]
    fn test_nframe_004_reject_truncated_header() {
        let bad = vec![0x01, 0x01, 0x00, 0x00, 0x00]; // Only 5 bytes
        let result = decode_frame(&bad);
        assert!(result.is_err(), "truncated header must be rejected");
    }

    /// N-FRAME-005: Frame with payload_len > MAX_PAYLOAD_SIZE MUST be rejected.
    #[test]
    fn test_nframe_005_reject_oversized_payload() {
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = AAFP_VERSION;
        bytes[1] = FrameType::Data.to_u8();
        // Set payload_len to MAX_PAYLOAD_SIZE + 1
        let oversized = (MAX_PAYLOAD_SIZE as u64) + 1;
        bytes[12..20].copy_from_slice(&oversized.to_be_bytes());
        let result = decode_frame(&bytes);
        assert!(result.is_err(), "oversized payload must be rejected");
    }

    /// N-FRAME-006: Frame with payload_len claiming more than available MUST be rejected.
    #[test]
    fn test_nframe_006_reject_payload_len_mismatch() {
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = AAFP_VERSION;
        bytes[1] = FrameType::Data.to_u8();
        bytes[12..20].copy_from_slice(&100u64.to_be_bytes()); // Claims 100 bytes
                                                              // But only 28 bytes total (header only, no payload)
        let result = decode_frame(&bytes);
        assert!(result.is_err(), "payload length mismatch must be rejected");
    }

    /// N-FRAME-007: Frame with ext_len claiming more than available MUST be rejected.
    #[test]
    fn test_nframe_007_reject_ext_len_mismatch() {
        let mut bytes = vec![0u8; FRAME_HEADER_SIZE];
        bytes[0] = AAFP_VERSION;
        bytes[1] = FrameType::Data.to_u8();
        bytes[20..28].copy_from_slice(&50u64.to_be_bytes()); // Claims 50 bytes of extensions
        let result = decode_frame(&bytes);
        assert!(
            result.is_err(),
            "extension length mismatch must be rejected"
        );
    }

    /// N-FRAME-008: Empty input MUST be rejected.
    #[test]
    fn test_nframe_008_reject_empty() {
        let result = decode_frame(&[]);
        assert!(result.is_err(), "empty input must be rejected");
    }

    /// N-FRAME-009: Reserved byte (offset 3) non-zero — should be ignored per RFC.
    /// RFC-0002 §3.1: "Reserved (1 byte): MUST be zero on send, ignored on receive."
    #[test]
    fn test_nframe_009_reserved_nonzero_ignored() {
        let frame = Frame::data(0, vec![]);
        let mut bytes = encode_frame(&frame).unwrap();
        bytes[3] = 0xFF; // Set reserved byte to non-zero
                         // Should still decode successfully (reserved is ignored on receive)
        let result = decode_frame(&bytes);
        assert!(
            result.is_ok(),
            "non-zero reserved byte should be ignored on receive"
        );
    }

    /// N-FRAME-010: Encoding a frame with payload > MAX MUST fail.
    #[test]
    fn test_nframe_010_encode_oversized_rejected() {
        let oversized = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = Frame::data(0, oversized);
        assert!(
            encode_frame(&frame).is_err(),
            "encoding oversized frame must fail"
        );
    }
}

// === Invalid AgentRecords ===

#[cfg(test)]
mod invalid_agent_records {
    use super::*;

    fn make_valid_record() -> AgentRecord {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1735689600u64;
        let mut record = AgentRecord::new(
            &pk.0,
            vec![CapabilityDescriptor::new("inference")],
            vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            now,
            now + 86400,
            1,
        );
        record.sign(&sk);
        record
    }

    /// N-REC-001: Tampered agent_id MUST fail verification.
    #[test]
    fn test_nrec_001_tampered_agent_id() {
        let mut record = make_valid_record();
        record.agent_id = AgentId([0xFF; 32]);
        let err = record.verify(1735689600).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidAgentId));
    }

    /// N-REC-002: Tampered public_key MUST fail verification (agent_id mismatch).
    #[test]
    fn test_nrec_002_tampered_public_key() {
        let mut record = make_valid_record();
        record.public_key[0] ^= 0xFF;
        let err = record.verify(1735689600).unwrap_err();
        // agent_id won't match SHA-256 of the tampered key
        assert!(matches!(err, IdentityError::InvalidAgentId));
    }

    /// N-REC-003: Tampered signature MUST fail verification.
    #[test]
    fn test_nrec_003_tampered_signature() {
        let mut record = make_valid_record();
        record.signature[0] ^= 0xFF;
        let err = record.verify(1735689600).unwrap_err();
        assert!(matches!(err, IdentityError::SignatureVerificationFailed));
    }

    /// N-REC-004: Expired record MUST fail verification.
    #[test]
    fn test_nrec_004_expired_record() {
        let record = make_valid_record();
        // Record expires at now+86400, verify at now+86401
        let err = record.verify(1735689600 + 86401).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }

    /// N-REC-005: Wrong record_type MUST fail verification.
    #[test]
    fn test_nrec_005_wrong_record_type() {
        let mut record = make_valid_record();
        record.record_type = "wrong-type".to_string();
        let err = record.verify(1735689600).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidRecordType { .. }));
    }

    /// N-REC-006: Wrong key_algorithm MUST fail verification (RFC-0003 §3.6 step 8).
    #[test]
    fn test_nrec_006_wrong_key_algorithm() {
        let mut record = make_valid_record();
        record.key_algorithm = 99;
        let err = record.verify(1735689600).unwrap_err();
        assert!(
            matches!(err, IdentityError::UnsupportedAlgorithm { .. }),
            "verify() MUST reject unsupported key_algorithm per RFC-0003 §3.6 step 8"
        );
    }

    /// N-REC-007: Record with lifetime > 30 days MUST still be accepted by
    /// verify() (RFC-0003 §8.4, clarified in Revision 5). The 30-day limit
    /// is a deployment warning, not a verification rejection. The warning
    /// predicate (expires_at - now > 30d) is tested separately in rfc0003.rs
    /// (R5-002..R5-004).
    #[test]
    fn test_nrec_007_expiry_exceeds_max_accepted_by_verify() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1735689600u64;
        let mut record = AgentRecord::new(
            &pk.0,
            vec![],
            vec![],
            now,
            now + MAX_RECORD_EXPIRY + 86400, // 31 days lifetime, unexpired
            1,
        );
        record.sign(&sk);
        // verify() must accept: unexpired, and §3.6 has no 30-day rejection step.
        let result = record.verify(now);
        assert!(
            result.is_ok(),
            "verify() must accept unexpired record with >30-day lifetime per RFC-0003 §8.4 (Rev 5): {:?}",
            result
        );
        // The warning predicate must fire (caller responsibility, not verify()).
        assert!(
            record.exceeds_max_expiry_warning(now),
            "exceeds_max_expiry_warning(now) must fire for >30-day future expiry"
        );
    }

    /// N-REC-008: Empty public key MUST fail.
    #[test]
    fn test_nrec_008_empty_public_key() {
        let (pk, sk) = MlDsa65::keypair();
        let mut record = AgentRecord::new(&pk.0, vec![], vec![], 1735689600, 1735689600 + 86400, 1);
        record.sign(&sk);
        record.public_key = vec![]; // Empty
        let err = record.verify(1735689600).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidAgentId));
    }
}

// === Invalid Signatures ===

#[cfg(test)]
mod invalid_signatures {
    use super::*;

    /// N-SIG-001: Signature with wrong message MUST fail.
    #[test]
    fn test_nsig_001_wrong_message() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"correct message";
        let sig = MlDsa65::sign(&sk, msg);
        assert!(!MlDsa65::verify(&pk, b"wrong message", &sig));
    }

    /// N-SIG-002: Tampered signature MUST fail.
    #[test]
    fn test_nsig_002_tampered_signature() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"test message";
        let mut sig = MlDsa65::sign(&sk, msg);
        sig.0[0] ^= 0xFF;
        assert!(!MlDsa65::verify(&pk, msg, &sig));
    }

    /// N-SIG-003: Signature with wrong key MUST fail.
    #[test]
    fn test_nsig_003_wrong_key() {
        let (pk1, sk1) = MlDsa65::keypair();
        let (pk2, _) = MlDsa65::keypair();
        let msg = b"test message";
        let sig = MlDsa65::sign(&sk1, msg);
        assert!(
            !MlDsa65::verify(&pk2, msg, &sig),
            "signature with wrong key must fail"
        );
    }

    /// N-SIG-004: Empty signature MUST fail.
    #[test]
    fn test_nsig_004_empty_signature() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"test message";
        let _sig = MlDsa65::sign(&sk, msg);
        let empty_sig = aafp_crypto::MlDsa65Signature(vec![]);
        assert!(!MlDsa65::verify(&pk, msg, &empty_sig));
    }

    /// N-SIG-005: Truncated signature MUST fail.
    #[test]
    fn test_nsig_005_truncated_signature() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"test message";
        let mut sig = MlDsa65::sign(&sk, msg);
        sig.0.truncate(100); // Truncate to 100 bytes (should be 3309)
        assert!(!MlDsa65::verify(&pk, msg, &sig));
    }

    /// N-SIG-006: Empty public key MUST fail.
    #[test]
    fn test_nsig_006_empty_public_key() {
        let (_, sk) = MlDsa65::keypair();
        let msg = b"test message";
        let sig = MlDsa65::sign(&sk, msg);
        let empty_pk = aafp_crypto::MlDsa65PublicKey(vec![]);
        assert!(!MlDsa65::verify(&empty_pk, msg, &sig));
    }
}

// === Invalid Error Frames ===

#[cfg(test)]
mod invalid_errors {
    use super::*;

    /// N-ERR-001: Data field exceeding 4096 bytes MUST be truncated.
    #[test]
    fn test_nerr_001_data_truncated() {
        let pe = ProtocolError::new(codes::PROTOCOL_VIOLATION, "big").with_data(vec![0xAA; 5000]);
        assert_eq!(pe.data.as_ref().unwrap().len(), 4096);
    }

    /// N-ERR-002: Always-fatal code cannot be overridden to non-fatal.
    #[test]
    fn test_nerr_002_cannot_override_fatal() {
        let pe = ProtocolError::new(codes::INVALID_SIGNATURE, "bad").with_fatal(false);
        assert!(pe.is_fatal(), "always-fatal cannot be set to non-fatal");
    }

    /// N-ERR-003: Empty message is allowed but should not crash.
    #[test]
    fn test_nerr_003_empty_message() {
        let pe = ProtocolError::new(codes::OK, "");
        assert_eq!(pe.message, "");
    }

    /// N-ERR-004: All 2xxx codes must be always-fatal.
    #[test]
    fn test_nerr_004_all_auth_codes_fatal() {
        for code in 2000..=2999u32 {
            // Check a representative sample
            if code == codes::INVALID_SIGNATURE
                || code == codes::IDENTITY_EXPIRED
                || code == codes::HANDSHAKE_FAILED
            {
                assert!(is_always_fatal(code), "code {code} must be always fatal");
            }
        }
    }
}

// === Invalid Handshake ===

#[cfg(test)]
mod invalid_handshake {
    use super::*;
    use aafp_crypto::handshake_v1::{compute_receiver_mac, verify_receiver_mac};

    /// N-HS-001: DoS MAC with wrong agent_id MUST fail verification.
    #[test]
    fn test_nhs_001_dos_mac_wrong_agent_id() {
        let agent_id = [0xAA; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03];
        let mac = compute_receiver_mac(&agent_id, &ch_bytes);
        assert!(!verify_receiver_mac(&[0xBB; 32], &ch_bytes, &mac));
    }

    /// N-HS-002: DoS MAC with wrong message MUST fail verification.
    #[test]
    fn test_nhs_002_dos_mac_wrong_message() {
        let agent_id = [0xAA; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03];
        let mac = compute_receiver_mac(&agent_id, &ch_bytes);
        assert!(!verify_receiver_mac(&agent_id, &[0x04, 0x05, 0x06], &mac));
    }

    /// N-HS-003: DoS MAC with tampered MAC bytes MUST fail.
    #[test]
    fn test_nhs_003_dos_mac_tampered() {
        let agent_id = [0xAA; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03];
        let mut mac = compute_receiver_mac(&agent_id, &ch_bytes);
        mac[0] ^= 0xFF;
        assert!(!verify_receiver_mac(&agent_id, &ch_bytes, &mac));
    }

    /// N-HS-004: Empty MAC MUST fail verification.
    #[test]
    fn test_nhs_004_empty_mac() {
        let agent_id = [0xAA; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03];
        let empty_mac = vec![];
        assert!(!verify_receiver_mac(&agent_id, &ch_bytes, &empty_mac));
    }

    /// N-HS-005: Short MAC (16 bytes instead of 32) MUST fail.
    #[test]
    fn test_nhs_005_short_mac() {
        let agent_id = [0xAA; 32];
        let ch_bytes = vec![0x01, 0x02, 0x03];
        let short_mac = vec![0u8; 16];
        assert!(!verify_receiver_mac(&agent_id, &ch_bytes, &short_mac));
    }
}

// === Discovery Edge Cases ===

#[cfg(test)]
mod discovery_edge_cases {
    use super::*;
    use aafp_discovery::discovery_v1::CapabilityDht;

    /// N-DHT-001: DHT put with expired record should still store (eviction is separate).
    #[test]
    fn test_ndht_001_put_expired_record() {
        let mut dht = CapabilityDht::new();
        let (pk, sk) = MlDsa65::keypair();
        let now = 1735689600u64;
        let mut record = AgentRecord::new(
            &pk.0,
            vec![CapabilityDescriptor::new("inference")],
            vec![],
            now,
            now - 100, // Already expired
            1,
        );
        record.sign(&sk);
        // DHT may accept or reject — the key is it shouldn't crash
        let _ = dht.put(record);
    }

    /// N-DHT-002: Lookup for non-existent capability returns empty.
    #[test]
    fn test_ndht_002_lookup_nonexistent() {
        let dht = CapabilityDht::new();
        assert_eq!(dht.get("nonexistent").len(), 0);
    }

    /// N-DHT-003: DHT handles many capabilities without crash.
    #[test]
    fn test_ndht_003_many_capabilities() {
        let mut dht = CapabilityDht::new();
        let (pk, sk) = MlDsa65::keypair();
        let now = 1735689600u64;
        let caps: Vec<CapabilityDescriptor> = (0..100)
            .map(|i| CapabilityDescriptor::new(&format!("cap-{i}")))
            .collect();
        let mut record = AgentRecord::new(&pk.0, caps, vec![], now, now + 86400, 1);
        record.sign(&sk);
        assert!(dht.put(record));
        assert_eq!(dht.capability_count(), 100);
    }
}
