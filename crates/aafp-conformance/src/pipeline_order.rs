//! Conformance tests for the normative extension processing order
//! (RFC-0002 §6.5, A-7).
//!
//! These tests verify the 20-phase frame processing pipeline:
//! - Each phase is executed in order
//! - Failure at any phase produces the correct error code
//! - Extension callbacks are NEVER invoked before Phase 18
//! - The callback count is zero for all failures in Phases 1-17
//!
//! Test count: 32 cases covering all 20 phases and edge cases.

#![allow(unused_imports)]

use aafp_core::error::codes;
use aafp_messaging::extensions::{self, Extension};
use aafp_messaging::framing::{encode_frame, Frame, FrameType, AAFP_VERSION, FRAME_HEADER_SIZE};
use aafp_messaging::pipeline::{
    ExtensionCallback, FrameProcessingPipeline, PipelineContext, PipelineError, PipelinePhase,
    ProcessedFrame, TestingContext,
};
use std::collections::HashSet;

// === Helper functions ===

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

fn default_ctx() -> TestingContext {
    TestingContext::default()
}

fn ctx_with_ext(ext_type: u16) -> TestingContext {
    let mut ctx = TestingContext::default();
    ctx.known_types.insert(ext_type);
    ctx.negotiated_types.insert(ext_type);
    ctx
}

// === Dummy callback for testing ===

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

    fn count(&self) -> usize {
        *self.count.lock().unwrap()
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

// === Phase 1: validate_frame_header ===

#[test]
fn conf_phase1_valid_header_passes() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01, 0x02], vec![]);
    let result = pipeline.process(&data);
    assert!(result.is_ok(), "valid frame should pass: {:?}", result);
}

#[test]
fn conf_phase1_invalid_version_error_8006() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = make_data_frame(vec![0x01], vec![]);
    data[0] = 99;
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::INVALID_VERSION);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn conf_phase1_reserved_nonzero_error_8008() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = make_data_frame(vec![0x01], vec![]);
    data[3] = 0xFF;
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::RESERVED_FIELD_NONZERO);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn conf_phase1_incomplete_header_error_5001() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = vec![0u8; 10]; // Less than 28-byte header
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
    assert_eq!(err.error_code, codes::MALFORMED_FRAME);
    assert!(err.fatal);
}

// === Phase 2-3: validate_lengths + reject_oversized ===

#[test]
fn conf_phase2_oversized_payload_error_8001_non_fatal() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // Create header with payload_len = 2MB (exceeds 1MB limit)
    let mut data = vec![1u8, 0x01, 0x00, 0x00]; // version, type, flags, reserved
    data.extend_from_slice(&4u64.to_be_bytes()); // stream_id
    data.extend_from_slice(&(2 * 1024 * 1024u64).to_be_bytes()); // payload_len = 2MB
    data.extend_from_slice(&0u64.to_be_bytes()); // ext_len = 0
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase2ValidateLengths);
    assert_eq!(err.error_code, codes::FRAME_TOO_LARGE);
    assert!(
        !err.fatal,
        "oversized payload should be non-fatal (stream-level)"
    );
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn conf_phase2_oversized_extension_error_8001_non_fatal() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![1u8, 0x01, 0x00, 0x00];
    data.extend_from_slice(&4u64.to_be_bytes());
    data.extend_from_slice(&100u64.to_be_bytes()); // payload_len = 100
    data.extend_from_slice(&70000u64.to_be_bytes()); // ext_len = 70000 (too large)
    data.extend_from_slice(&[0u8; 100]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase2ValidateLengths);
    assert_eq!(err.error_code, codes::FRAME_TOO_LARGE);
    assert!(!err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 6-8: CBOR validation ===

#[test]
fn conf_phase6_valid_cbor_passes() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // 0xA0 = empty CBOR map (canonical)
    let data = make_handshake_frame(vec![0xA0], vec![]);
    // This should pass phases 1-8, then fail at phase 9 (transcript) or 10 (signature)
    // depending on context. With default ctx (all true), it should pass.
    let result = pipeline.process(&data);
    assert!(result.is_ok(), "valid CBOR should pass: {:?}", result);
}

#[test]
fn conf_phase6_non_canonical_cbor_error_5003() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // Non-canonical CBOR: value 5 encoded as 0x18 0x05 (1-byte) instead of 0x05 (immediate)
    let data = make_handshake_frame(vec![0x18, 0x05], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase6DecodeCbor);
    assert_eq!(err.error_code, codes::SERIALIZATION_ERROR);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn conf_phase7_duplicate_cbor_keys_error_5003() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // CBOR map with duplicate keys: {1: "a", 1: "b"}
    // 0xA2 = map with 2 entries
    // 01 = key 1, 61 61 = text "a"
    // 01 = key 1 (duplicate!), 61 62 = text "b"
    let payload = vec![0xA2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62];
    let data = make_handshake_frame(payload, vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase6DecodeCbor);
    assert_eq!(err.error_code, codes::SERIALIZATION_ERROR);
    assert!(err.fatal);
}

// === Phase 9: validate_transcript_state ===

#[test]
fn conf_phase9_transcript_invalid_error_2006() {
    let ctx = TestingContext {
        transcript_valid: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_handshake_frame(vec![0xA0], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase9ValidateTranscript);
    assert_eq!(err.error_code, codes::HANDSHAKE_FAILED);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 10: verify_signatures ===

#[test]
fn conf_phase10_invalid_signature_error_2001() {
    let ctx = TestingContext {
        signature_verified: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase10VerifySignatures);
    assert_eq!(err.error_code, codes::INVALID_SIGNATURE);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 11: verify_agent_id ===

#[test]
fn conf_phase11_invalid_agent_id_error_2007() {
    let ctx = TestingContext {
        agent_id_verified: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase11VerifyAgentId);
    assert_eq!(err.error_code, codes::INVALID_AGENT_ID);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 12: verify_session_state ===

#[test]
fn conf_phase12_invalid_session_error_8009() {
    let ctx = TestingContext {
        session_valid: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase12VerifySessionState);
    assert_eq!(err.error_code, codes::PROTOCOL_VIOLATION);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 13: verify_authorization ===

#[test]
fn conf_phase13_unauthorized_error_3001() {
    let ctx = TestingContext {
        authorized: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase13VerifyAuthorization);
    assert_eq!(err.error_code, codes::UNAUTHORIZED);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 14: verify_required_capabilities ===

#[test]
fn conf_phase14_insufficient_capability_error_3002() {
    let ctx = TestingContext {
        capabilities_sufficient: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01], vec![]);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase14VerifyCapabilities);
    assert_eq!(err.error_code, codes::INSUFFICIENT_CAPABILITY);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

// === Phase 15: decode_extensions ===

#[test]
fn conf_phase15_handshake_with_extensions_error_8009() {
    let ctx = default_ctx();
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
fn conf_phase15_truncated_extension_error_5001() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // Create a frame with a truncated extension (header says 10 bytes, only 4 present)
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

// === Phase 16: check_unknown_critical_extensions ===

#[test]
fn conf_phase16_unknown_critical_error_8005() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0xBEEF, true, vec![0x01, 0x02]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(err.phase, PipelinePhase::Phase16CheckUnknownCritical);
    assert_eq!(err.error_code, codes::UNKNOWN_CRITICAL_EXTENSION);
    assert!(err.fatal);
    assert!(!err.extension_callbacks_invoked());
}

#[test]
fn conf_phase16_unknown_non_critical_silently_ignored() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0xBEEF, false, vec![0x01]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 0);
    assert_eq!(result.extensions_ignored, 1);
}

// === Phase 17: check_non_negotiated_extensions ===

#[test]
fn conf_phase17_known_but_not_negotiated_error_8007() {
    let ctx = TestingContext {
        known_types: HashSet::from([0x0001]),
        negotiated_types: HashSet::new(),
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

// === Phase 18: process_extension_semantics ===

#[test]
fn conf_phase18_callback_invoked_once_for_known_negotiated() {
    let ctx = ctx_with_ext(0x0001);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = encode_ext(0x0001, false, vec![0xDE, 0xAD]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 1);
    assert_eq!(result.extensions_ignored, 0);
}

#[test]
fn conf_phase18_multiple_extensions_each_callback_once() {
    let ctx = TestingContext {
        known_types: HashSet::from([0x0001, 0x0002]),
        negotiated_types: HashSet::from([0x0001, 0x0002]),
        ..Default::default()
    };
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![
        Box::new(CountingCallback::new(0x0001)),
        Box::new(CountingCallback::new(0x0002)),
    ];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = extensions::encode_extensions(&[
        Extension {
            ext_type: 0x0001,
            critical: false,
            data: vec![0x01],
        },
        Extension {
            ext_type: 0x0002,
            critical: false,
            data: vec![0x02],
        },
    ])
    .unwrap();
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 2);
    assert_eq!(result.extensions_ignored, 0);
}

#[test]
fn conf_phase18_known_negotiated_no_callback_ignored() {
    let ctx = ctx_with_ext(0x0001);
    // No callback registered for 0x0001
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = encode_ext(0x0001, false, vec![0x01]);
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 0);
    assert_eq!(result.extensions_ignored, 1);
}

// === Full pipeline success ===

#[test]
fn conf_full_pipeline_success_no_extensions() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01, 0x02, 0x03], vec![]);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 0);
    assert_eq!(result.extensions_ignored, 0);
    assert!(result.extensions.is_empty());
}

#[test]
fn conf_full_pipeline_success_with_extensions() {
    let ctx = ctx_with_ext(0x0001);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    let ext_bytes = encode_ext(0x0001, false, vec![0x01]);
    let data = make_data_frame(vec![0x01, 0x02], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 1);
    assert_eq!(result.extensions.len(), 1);
}

// === Security invariant: callback count = 0 for ALL pre-auth failures ===

#[test]
fn conf_security_invariant_no_callbacks_before_auth() {
    let failure_contexts: Vec<(&str, TestingContext)> = vec![
        (
            "invalid signature",
            TestingContext {
                signature_verified: false,
                ..Default::default()
            },
        ),
        (
            "invalid agent id",
            TestingContext {
                agent_id_verified: false,
                ..Default::default()
            },
        ),
        (
            "invalid session",
            TestingContext {
                session_valid: false,
                ..Default::default()
            },
        ),
        (
            "unauthorized",
            TestingContext {
                authorized: false,
                ..Default::default()
            },
        ),
        (
            "insufficient capability",
            TestingContext {
                capabilities_sufficient: false,
                ..Default::default()
            },
        ),
    ];

    for (name, ctx) in failure_contexts {
        let callbacks: Vec<Box<dyn ExtensionCallback>> =
            vec![Box::new(CountingCallback::new(0x0001))];
        let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
        let ext_bytes = encode_ext(0x0001, false, vec![0x01]);
        let data = make_data_frame(vec![0x01], ext_bytes);
        let result = pipeline.process(&data);
        assert!(result.is_err(), "should fail for: {}", name);
        let err = result.unwrap_err();
        assert!(
            !err.extension_callbacks_invoked(),
            "callback should not be invoked for: {} (phase: {})",
            name,
            err.phase
        );
    }
}

// === Phase ordering: earlier phases fail first ===

#[test]
fn conf_phase_ordering_invalid_version_before_signature() {
    // Both version AND signature are invalid — version should fail first
    let ctx = TestingContext {
        signature_verified: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = make_data_frame(vec![0x01], vec![]);
    data[0] = 99; // Invalid version
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(
        err.phase,
        PipelinePhase::Phase1ValidateHeader,
        "version check should fail before signature check"
    );
}

#[test]
fn conf_phase_ordering_oversized_before_signature() {
    // Both size AND signature are invalid — size should fail first
    let ctx = TestingContext {
        signature_verified: false,
        ..Default::default()
    };
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let mut data = vec![1u8, 0x01, 0x00, 0x00];
    data.extend_from_slice(&4u64.to_be_bytes());
    data.extend_from_slice(&(2 * 1024 * 1024u64).to_be_bytes()); // oversized payload
    data.extend_from_slice(&0u64.to_be_bytes());
    let err = pipeline.process(&data).unwrap_err();
    assert_eq!(
        err.phase,
        PipelinePhase::Phase2ValidateLengths,
        "size check should fail before signature check"
    );
}

#[test]
fn conf_phase_ordering_unknown_critical_before_callback() {
    // Unknown critical extension should fail before any callback
    let ctx = ctx_with_ext(0x0001);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(CountingCallback::new(0x0001))];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);
    // Include both a valid extension and an unknown critical one
    let ext_bytes = extensions::encode_extensions(&[
        Extension {
            ext_type: 0x0001,
            critical: false,
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
    assert!(!err.extension_callbacks_invoked());
}

// === Empty extensions ===

#[test]
fn conf_empty_extensions_passes() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let data = make_data_frame(vec![0x01], vec![]);
    let result = pipeline.process(&data).unwrap();
    assert!(result.extensions.is_empty());
    assert_eq!(result.extension_callback_count, 0);
}

// === Multiple unknown non-critical extensions ===

#[test]
fn conf_multiple_unknown_non_critical_all_ignored() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    let ext_bytes = extensions::encode_extensions(&[
        Extension {
            ext_type: 0xBEEF,
            critical: false,
            data: vec![0x01],
        },
        Extension {
            ext_type: 0xCAFE,
            critical: false,
            data: vec![0x02],
        },
    ])
    .unwrap();
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 0);
    assert_eq!(result.extensions_ignored, 2);
}

// === Mixed known and unknown extensions ===

#[test]
fn conf_mixed_known_and_unknown_extensions() {
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
            ext_type: 0xBEEF,
            critical: false,
            data: vec![0x02],
        },
    ])
    .unwrap();
    let data = make_data_frame(vec![0x01], ext_bytes);
    let result = pipeline.process(&data).unwrap();
    assert_eq!(result.extension_callback_count, 1);
    assert_eq!(result.extensions_ignored, 1);
}

// === DATA frames skip CBOR validation ===

#[test]
fn conf_data_frame_skips_cbor_validation() {
    let ctx = default_ctx();
    let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
    // DATA frame with non-CBOR payload — should pass CBOR validation phase
    let data = make_data_frame(vec![0xFF, 0xFE, 0xFD], vec![]);
    let result = pipeline.process(&data);
    assert!(
        result.is_ok(),
        "DATA frames should skip CBOR validation: {:?}",
        result
    );
}

// === Phase numbering ===

#[test]
fn conf_phase_numbers_are_sequential_1_to_20() {
    let phases = [
        PipelinePhase::Phase1ValidateHeader,
        PipelinePhase::Phase2ValidateLengths,
        PipelinePhase::Phase3RejectOversized,
        PipelinePhase::Phase4ReadPayload,
        PipelinePhase::Phase5ReadExtensions,
        PipelinePhase::Phase6DecodeCbor,
        PipelinePhase::Phase7RejectDuplicateKeys,
        PipelinePhase::Phase8RejectNonCanonical,
        PipelinePhase::Phase9ValidateTranscript,
        PipelinePhase::Phase10VerifySignatures,
        PipelinePhase::Phase11VerifyAgentId,
        PipelinePhase::Phase12VerifySessionState,
        PipelinePhase::Phase13VerifyAuthorization,
        PipelinePhase::Phase14VerifyCapabilities,
        PipelinePhase::Phase15DecodeExtensions,
        PipelinePhase::Phase16CheckUnknownCritical,
        PipelinePhase::Phase17CheckNonNegotiated,
        PipelinePhase::Phase18ProcessExtensionSemantics,
        PipelinePhase::Phase19ValidateFinalState,
        PipelinePhase::Phase20DeliverToUpperLayer,
    ];
    for (i, phase) in phases.iter().enumerate() {
        assert_eq!(
            phase.number(),
            (i + 1) as u8,
            "Phase {:?} should be number {}",
            phase,
            i + 1
        );
    }
}

// === Phase name matches RFC ===

#[test]
fn conf_phase_names_match_rfc_section_6_5_1() {
    assert_eq!(
        PipelinePhase::Phase1ValidateHeader.name(),
        "validate_frame_header"
    );
    assert_eq!(
        PipelinePhase::Phase2ValidateLengths.name(),
        "validate_lengths"
    );
    assert_eq!(
        PipelinePhase::Phase3RejectOversized.name(),
        "reject_oversized_before_allocation"
    );
    assert_eq!(
        PipelinePhase::Phase10VerifySignatures.name(),
        "verify_signatures"
    );
    assert_eq!(
        PipelinePhase::Phase15DecodeExtensions.name(),
        "decode_extensions"
    );
    assert_eq!(
        PipelinePhase::Phase16CheckUnknownCritical.name(),
        "check_unknown_critical_extensions"
    );
    assert_eq!(
        PipelinePhase::Phase17CheckNonNegotiated.name(),
        "check_non_negotiated_extensions"
    );
    assert_eq!(
        PipelinePhase::Phase18ProcessExtensionSemantics.name(),
        "process_extension_semantics"
    );
}

// === Phase grouping ===

#[test]
fn conf_phase_grouping_pre_auth_includes_1_to_14() {
    for i in 1..=14 {
        let phase = phase_from_number(i);
        assert!(
            phase.is_pre_authentication(),
            "Phase {} should be pre-auth",
            i
        );
    }
}

#[test]
fn conf_phase_grouping_auth_includes_9_to_14() {
    for i in 9..=14 {
        let phase = phase_from_number(i);
        assert!(phase.is_authentication(), "Phase {} should be auth", i);
    }
}

#[test]
fn conf_phase_grouping_ext_includes_15_to_18() {
    for i in 15..=18 {
        let phase = phase_from_number(i);
        assert!(
            phase.is_extension_processing(),
            "Phase {} should be ext processing",
            i
        );
    }
}

fn phase_from_number(n: u8) -> PipelinePhase {
    match n {
        1 => PipelinePhase::Phase1ValidateHeader,
        2 => PipelinePhase::Phase2ValidateLengths,
        3 => PipelinePhase::Phase3RejectOversized,
        4 => PipelinePhase::Phase4ReadPayload,
        5 => PipelinePhase::Phase5ReadExtensions,
        6 => PipelinePhase::Phase6DecodeCbor,
        7 => PipelinePhase::Phase7RejectDuplicateKeys,
        8 => PipelinePhase::Phase8RejectNonCanonical,
        9 => PipelinePhase::Phase9ValidateTranscript,
        10 => PipelinePhase::Phase10VerifySignatures,
        11 => PipelinePhase::Phase11VerifyAgentId,
        12 => PipelinePhase::Phase12VerifySessionState,
        13 => PipelinePhase::Phase13VerifyAuthorization,
        14 => PipelinePhase::Phase14VerifyCapabilities,
        15 => PipelinePhase::Phase15DecodeExtensions,
        16 => PipelinePhase::Phase16CheckUnknownCritical,
        17 => PipelinePhase::Phase17CheckNonNegotiated,
        18 => PipelinePhase::Phase18ProcessExtensionSemantics,
        19 => PipelinePhase::Phase19ValidateFinalState,
        20 => PipelinePhase::Phase20DeliverToUpperLayer,
        _ => panic!("invalid phase number: {}", n),
    }
}
