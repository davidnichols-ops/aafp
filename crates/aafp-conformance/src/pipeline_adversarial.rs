//! Adversarial tests for the normative extension processing order
//! (RFC-0002 §6.5, A-7).
//!
//! These tests verify the pipeline's resistance to attacks:
//! - Frame truncation (incomplete header, payload, extensions)
//! - Extension injection (critical extension after auth bypass attempt)
//! - Extension reordering (trying to process extensions before auth)
//! - Duplicate extensions (same type appearing multiple times)
//! - Oversized frame injection (memory exhaustion attempts)
//! - CBOR injection (non-canonical, duplicate keys, indefinite-length)
//! - Reserved field manipulation
//! - Version field manipulation
//!
//! All adversarial tests verify that the security invariant holds:
//! extension callbacks are NEVER invoked before authentication.

#![allow(unused_imports)]

use aafp_core::error::codes;
use aafp_messaging::extensions::{self, Extension};
use aafp_messaging::framing::{encode_frame, Frame, FrameType, FRAME_HEADER_SIZE};
use aafp_messaging::pipeline::{
    ExtensionCallback, FrameProcessingPipeline, PipelineError, PipelinePhase, TestingContext,
};
use std::collections::HashSet;

fn make_data_frame(payload: Vec<u8>, extensions: Vec<u8>) -> Vec<u8> {
    let frame = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 4,
        extensions,
        payload,
    };
    encode_frame(&frame).unwrap()
}

fn make_handshake_frame(payload: Vec<u8>, extensions: Vec<u8>) -> Vec<u8> {
    let frame = Frame {
        frame_type: FrameType::Handshake,
        flags: 0,
        stream_id: 0,
        extensions,
        payload,
    };
    encode_frame(&frame).unwrap()
}

fn encode_ext(ext_type: u16, critical: bool, data: Vec<u8>) -> Vec<u8> {
    extensions::encode_extensions(&[Extension {
        ext_type,
        critical,
        data,
    }])
    .unwrap()
}

struct CountingCallback {
    ext_type: u16,
    count: std::sync::Mutex<usize>,
}

impl CountingCallback {
    fn new(ext_type: u16) -> Self {
        Self {
            ext_type,
            count: std::sync::Mutex::new(0),
        }
    }
}

impl ExtensionCallback for CountingCallback {
    fn extension_type(&self) -> u16 {
        self.ext_type
    }

    fn process(&self, _data: &[u8]) -> Result<(), PipelineError> {
        *self.count.lock().unwrap() += 1;
        Ok(())
    }
}

fn ctx_with_ext(ext_type: u16) -> TestingContext {
    let mut ctx = TestingContext::default();
    ctx.known_types.insert(ext_type);
    ctx.negotiated_types.insert(ext_type);
    ctx
}

// === Truncation attacks ===

#[test]
fn adv_truncated_header_no_allocation() {
    // Frame with only 10 bytes (less than 28-byte header)
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::MALFORMED_FRAME);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_truncated_payload_after_header() {
    // Header claims 100 bytes payload but only 10 are present
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![1u8, 0x01, 0x00, 0x00]; // header start
    data.extend_from_slice(&4u64.to_be_bytes()); // stream_id
    data.extend_from_slice(&100u64.to_be_bytes()); // payload_len = 100
    data.extend_from_slice(&0u64.to_be_bytes()); // ext_len = 0
    data.extend_from_slice(&[0u8; 10]); // only 10 bytes of payload
    let err = pipeline.process(&data).unwrap_err();
    // Should fail at Phase 4 (read_payload) because frame is incomplete
    assert!(err.error_code == codes::MALFORMED_FRAME || err.error_code == codes::FRAME_TOO_LARGE);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_truncated_extension_data() {
    // Extension header says 10 bytes of data, but only 4 present
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut ext_bytes = vec![0x00, 0x01, 0x00, 0x00]; // type=1, critical=false, reserved=0
    ext_bytes.extend_from_slice(&10u32.to_be_bytes()); // data_len=10
    ext_bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // only 4 bytes
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase15DecodeExtensions);
    assert_eq!(err.error_code, codes::MALFORMED_FRAME);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_truncated_extension_header() {
    // Extension data is only 3 bytes (less than 8-byte header)
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = vec![0x00, 0x01, 0x00]; // only 3 bytes, less than 8-byte header
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase15DecodeExtensions);
    assert_eq!(err.error_code, codes::MALFORMED_FRAME);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Extension injection attacks ===

#[test]
fn adv_critical_extension_injection_after_auth_bypass() {
    // Attacker tries to inject a critical extension after auth fails
    // The pipeline should reject at auth phase, never reaching extension processing
    let ctx = TestingContext {
        signature_verified: false, // Auth will fail
        ..Default::default()
    };
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = encode_ext(0xBEEF, true, vec![0x01, 0x02]); // Critical unknown
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    // Should fail at Phase 10 (signature), not Phase 16 (unknown critical)
    assert_eq!(err.phase, PipelinePhase::Phase10VerifySignatures);
    assert_eq!(err.error_code, codes::INVALID_SIGNATURE);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_extension_injection_in_handshake_frame() {
    // Attacker tries to inject extensions in a HANDSHAKE frame
    // Handshake frames MUST NOT carry frame extensions
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0x0001, false, vec![0x01]);
    let data = make_handshake_frame(vec![0xA0], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase15DecodeExtensions);
    assert_eq!(err.error_code, codes::PROTOCOL_VIOLATION);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_non_negotiated_extension_injection() {
    // Attacker injects an extension that wasn't negotiated during handshake
    let ctx = TestingContext {
        known_types: HashSet::from([0x0001]),
        negotiated_types: HashSet::new(), // 0x0001 not negotiated
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0x0001, false, vec![0x01]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase17CheckNonNegotiated);
    assert_eq!(err.error_code, codes::INVALID_FLAGS);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Duplicate extension attacks ===

#[test]
fn adv_duplicate_extension_types_both_processed() {
    // Two extensions of the same type — both should be processed
    // (The RFC doesn't forbid duplicates, but this is an edge case)
    let ctx = ctx_with_ext(0x0001);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = extensions::encode_extensions(&[
        Extension {
            ext_type: 0x0001,
            critical: false,
            data: vec![0x01],
        },
        Extension {
            ext_type: 0x0001,
            critical: false,
            data: vec![0x02],
        },
    ])
    .unwrap();
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 2);
}

#[test]
fn adv_duplicate_critical_extension_types_rejected() {
    // Two critical extensions of unknown type — should be rejected
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = extensions::encode_extensions(&[
        Extension {
            ext_type: 0xBEEF,
            critical: true,
            data: vec![0x01],
        },
        Extension {
            ext_type: 0xBEEF,
            critical: true,
            data: vec![0x02],
        },
    ])
    .unwrap();
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase16CheckUnknownCritical);
    assert_eq!(err.error_code, codes::UNKNOWN_CRITICAL_EXTENSION);
}

// === Oversized frame injection ===

#[test]
fn adv_oversized_payload_no_allocation() {
    // Attacker sends a frame claiming 2MB payload
    // Pipeline should reject before any allocation
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![1u8, 0x01, 0x00, 0x00];
    data.extend_from_slice(&4u64.to_be_bytes());
    data.extend_from_slice(&(2 * 1024 * 1024u64).to_be_bytes()); // 2MB payload
    data.extend_from_slice(&0u64.to_be_bytes());
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase2ValidateLengths);
    assert_eq!(err.error_code, codes::FRAME_TOO_LARGE);
    assert!(!err.fatal); // Stream-level, not connection-level
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_oversized_extension_no_allocation() {
    // Attacker sends a frame claiming 70KB extension
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![1u8, 0x01, 0x00, 0x00];
    data.extend_from_slice(&4u64.to_be_bytes());
    data.extend_from_slice(&100u64.to_be_bytes());
    data.extend_from_slice(&70000u64.to_be_bytes()); // 70KB extension
    data.extend_from_slice(&[0u8; 100]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase2ValidateLengths);
    assert_eq!(err.error_code, codes::FRAME_TOO_LARGE);
    assert!(!err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_length_overflow_attack() {
    // Attacker sends a frame where payload_len + ext_len overflows
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![1u8, 0x01, 0x00, 0x00];
    data.extend_from_slice(&4u64.to_be_bytes());
    data.extend_from_slice(&u64::MAX.to_be_bytes()); // payload_len = MAX
    data.extend_from_slice(&1u64.to_be_bytes()); // ext_len = 1
    let err = pipeline.process(&data).unwrap_err();
    // Should fail at Phase 2 (overflow check)
    assert_eq!(err.phase, PipelinePhase::Phase2ValidateLengths);
    assert_eq!(err.error_code, codes::FRAME_TOO_LARGE);
    assert!(!err.extension_callbacks_invoked());
}

// === CBOR injection attacks ===

#[test]
fn adv_non_canonical_cbor_injection() {
    // Attacker injects non-canonical CBOR (value 5 as 0x18 0x05 instead of 0x05)
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_handshake_frame(vec![0x18, 0x05], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase6DecodeCbor);
    assert_eq!(err.error_code, codes::SERIALIZATION_ERROR);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_duplicate_cbor_keys_injection() {
    // Attacker injects CBOR map with duplicate keys
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let payload = vec![0xA2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62]; // {1: "a", 1: "b"}
    let data = make_handshake_frame(payload, vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase6DecodeCbor);
    assert_eq!(err.error_code, codes::SERIALIZATION_ERROR);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_trailing_bytes_after_cbor_injection() {
    // Attacker injects CBOR with trailing bytes
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // 0xA0 = empty map, followed by trailing 0xFF
    let data = make_handshake_frame(vec![0xA0, 0xFF], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase6DecodeCbor);
    assert_eq!(err.error_code, codes::SERIALIZATION_ERROR);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Reserved field manipulation ===

#[test]
fn adv_reserved_field_nonzero_rejected() {
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = make_data_frame(vec![0x01], vec![]);
    data[3] = 0x42; // Reserved field
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::RESERVED_FIELD_NONZERO);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Version field manipulation ===

#[test]
fn adv_version_zero_rejected() {
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = make_data_frame(vec![0x01], vec![]);
    data[0] = 0; // Version 0
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::INVALID_VERSION);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_version_255_rejected() {
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = make_data_frame(vec![0x01], vec![]);
    data[0] = 255; // Version 255
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::INVALID_VERSION);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Mixed attack: multiple attack vectors simultaneously ===

#[test]
fn adv_mixed_attack_oversized_and_invalid_version() {
    // Both version AND size are invalid — version should fail first (Phase 1)
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![99u8, 0x01, 0x00, 0x00]; // Invalid version
    data.extend_from_slice(&4u64.to_be_bytes());
    data.extend_from_slice(&(2 * 1024 * 1024u64).to_be_bytes()); // Oversized
    data.extend_from_slice(&0u64.to_be_bytes());
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::INVALID_VERSION);
}

#[test]
fn adv_mixed_attack_invalid_signature_and_critical_extension() {
    // Both signature AND extension are invalid — signature should fail first
    let ctx = TestingContext {
        signature_verified: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0xBEEF, true, vec![0x01]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase10VerifySignatures);
    assert_eq!(err.error_code, codes::INVALID_SIGNATURE);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_mixed_attack_non_canonical_cbor_and_extension() {
    // Non-canonical CBOR + extension — CBOR should fail first (Phase 6)
    let ctx = TestingContext::default();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0xBEEF, true, vec![0x01]);
    // Non-canonical CBOR payload
    let data = make_handshake_frame(vec![0x18, 0x05], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase6DecodeCbor);
    assert_eq!(err.error_code, codes::SERIALIZATION_ERROR);
    assert!(!err.extension_callbacks_invoked());
}

// === Extension data injection (malicious payload in extension) ===

#[test]
fn adv_extension_with_large_data_not_allocating_before_check() {
    // Extension with data length that fits in 64KiB but is still large
    // Should pass Phase 2 (size check) and be processed normally
    let ctx = ctx_with_ext(0x0001);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let large_data = vec![0x41u8; 1000]; // 1KB of data
    let ext_bytes = encode_ext(0x0001, false, large_data);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 1);
}

#[test]
fn adv_empty_extension_data_accepted() {
    // Extension with zero-length data — should be accepted
    let ctx = ctx_with_ext(0x0001);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = encode_ext(0x0001, false, vec![]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 1);
}

// === Phase bypass attempts ===

#[test]
fn adv_cannot_bypass_auth_with_known_extension() {
    // Attacker uses a known extension type hoping it gets processed before auth
    // The pipeline MUST process auth first
    let ctx = TestingContext {
        signature_verified: false,
        known_types: HashSet::from([0x0001]),
        negotiated_types: HashSet::from([0x0001]),
        ..Default::default()
    };
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = encode_ext(0x0001, false, vec![0x01]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase10VerifySignatures);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn adv_cannot_bypass_auth_with_critical_known_extension() {
    // Attacker uses a critical known extension hoping criticality bypasses auth
    let ctx = TestingContext {
        signature_verified: false,
        known_types: HashSet::from([0x0001]),
        negotiated_types: HashSet::from([0x0001]),
        ..Default::default()
    };
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = encode_ext(0x0001, true, vec![0x01]); // Critical
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase10VerifySignatures);
    assert!(!err.extension_callbacks_invoked());
}
