#![allow(unused_imports)]
#![allow(clippy::all)]

//! Generate pipeline differential test vectors for Rust vs Go comparison.
//!
//! This binary generates a JSON file containing test vectors for the
//! frame processing pipeline (RFC-0002 §6.5). Each vector specifies:
//! - A frame (as hex)
//! - A pipeline context configuration
//! - The expected result (phase, error code, callback count)
//!
//! The Go implementation can then run these same vectors and verify
//! that it produces identical results.

use aafp_conformance::pipeline_order;
use aafp_messaging::extensions::{self, Extension};
use aafp_messaging::framing::{encode_frame, Frame, FrameType};
use aafp_messaging::pipeline::{
    ExtensionCallback, FrameProcessingPipeline, PipelineError, PipelinePhase, TestingContext,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Clone)]
struct PipelineContextConfig {
    signature_verified: bool,
    agent_id_verified: bool,
    session_valid: bool,
    authorized: bool,
    capabilities_sufficient: bool,
    transcript_valid: bool,
    known_types: Vec<u16>,
    negotiated_types: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
struct PipelineTestVector {
    description: String,
    frame_hex: String,
    context: PipelineContextConfig,
    expected_success: bool,
    expected_phase: Option<u8>,
    expected_error_code: Option<u32>,
    expected_fatal: Option<bool>,
    expected_callback_count: usize,
    expected_extensions_ignored: usize,
}

#[derive(Serialize, Deserialize)]
struct PipelineTestVectors {
    vectors: Vec<PipelineTestVector>,
}

fn to_testing_context(cfg: &PipelineContextConfig) -> TestingContext {
    TestingContext {
        signature_verified: cfg.signature_verified,
        agent_id_verified: cfg.agent_id_verified,
        session_valid: cfg.session_valid,
        authorized: cfg.authorized,
        capabilities_sufficient: cfg.capabilities_sufficient,
        transcript_valid: cfg.transcript_valid,
        known_types: cfg.known_types.iter().copied().collect(),
        negotiated_types: cfg.negotiated_types.iter().copied().collect(),
    }
}

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

struct NoopCallback;
impl ExtensionCallback for NoopCallback {
    fn extension_type(&self) -> u16 {
        0x0001
    }
    fn process(&self, _data: &[u8]) -> Result<(), PipelineError> {
        Ok(())
    }
}

fn run_vector(
    description: &str,
    data: &[u8],
    ctx_cfg: &PipelineContextConfig,
) -> PipelineTestVector {
    let ctx = to_testing_context(ctx_cfg);
    let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(NoopCallback)];
    let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);

    let result = pipeline.process(data);

    match result {
        Ok(processed) => PipelineTestVector {
            description: description.to_string(),
            frame_hex: hex::encode(data),
            context: ctx_cfg.clone(),
            expected_success: true,
            expected_phase: None,
            expected_error_code: None,
            expected_fatal: None,
            expected_callback_count: processed.extension_callback_count,
            expected_extensions_ignored: processed.extensions_ignored,
        },
        Err(err) => PipelineTestVector {
            description: description.to_string(),
            frame_hex: hex::encode(data),
            context: ctx_cfg.clone(),
            expected_success: false,
            expected_phase: Some(err.phase.number()),
            expected_error_code: Some(err.error_code),
            expected_fatal: Some(err.fatal),
            expected_callback_count: 0,
            expected_extensions_ignored: 0,
        },
    }
}

fn default_ctx() -> PipelineContextConfig {
    PipelineContextConfig {
        signature_verified: true,
        agent_id_verified: true,
        session_valid: true,
        authorized: true,
        capabilities_sufficient: true,
        transcript_valid: true,
        known_types: vec![],
        negotiated_types: vec![],
    }
}

fn ctx_with_ext(ext_type: u16) -> PipelineContextConfig {
    PipelineContextConfig {
        known_types: vec![ext_type],
        negotiated_types: vec![ext_type],
        ..default_ctx()
    }
}

fn main() {
    let mut vectors = Vec::new();

    // === Success cases ===
    vectors.push(run_vector(
        "valid DATA frame no extensions",
        &make_data_frame(vec![0x01, 0x02], vec![]),
        &default_ctx(),
    ));

    vectors.push(run_vector(
        "valid DATA frame with known extension",
        &make_data_frame(vec![0x01], encode_ext(0x0001, false, vec![0xDE, 0xAD])),
        &ctx_with_ext(0x0001),
    ));

    vectors.push(run_vector(
        "valid DATA frame with unknown non-critical extension",
        &make_data_frame(vec![0x01], encode_ext(0xBEEF, false, vec![0x01])),
        &default_ctx(),
    ));

    vectors.push(run_vector(
        "valid HANDSHAKE frame no extensions",
        &make_handshake_frame(vec![0xA0], vec![]),
        &default_ctx(),
    ));

    // === Phase 1 failures ===
    {
        let mut data = make_data_frame(vec![0x01], vec![]);
        data[0] = 99; // Invalid version
        vectors.push(run_vector("invalid version", &data, &default_ctx()));
    }
    {
        let mut data = make_data_frame(vec![0x01], vec![]);
        data[3] = 0xFF; // Reserved nonzero
        vectors.push(run_vector("reserved field nonzero", &data, &default_ctx()));
    }

    // === Phase 2 failures ===
    {
        let mut data = vec![1u8, 0x01, 0x00, 0x00];
        data.extend_from_slice(&4u64.to_be_bytes());
        data.extend_from_slice(&(2 * 1024 * 1024u64).to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        vectors.push(run_vector("oversized payload", &data, &default_ctx()));
    }
    {
        let mut data = vec![1u8, 0x01, 0x00, 0x00];
        data.extend_from_slice(&4u64.to_be_bytes());
        data.extend_from_slice(&100u64.to_be_bytes());
        data.extend_from_slice(&70000u64.to_be_bytes());
        data.extend_from_slice(&[0u8; 100]);
        vectors.push(run_vector("oversized extension", &data, &default_ctx()));
    }

    // === Phase 6 failures ===
    vectors.push(run_vector(
        "non-canonical CBOR",
        &make_handshake_frame(vec![0x18, 0x05], vec![]),
        &default_ctx(),
    ));
    vectors.push(run_vector(
        "duplicate CBOR keys",
        &make_handshake_frame(vec![0xA2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62], vec![]),
        &default_ctx(),
    ));

    // === Phase 9 failure ===
    vectors.push(run_vector(
        "transcript state invalid",
        &make_handshake_frame(vec![0xA0], vec![]),
        &PipelineContextConfig {
            transcript_valid: false,
            ..default_ctx()
        },
    ));

    // === Phase 10 failure ===
    vectors.push(run_vector(
        "invalid signature",
        &make_data_frame(vec![0x01], vec![]),
        &PipelineContextConfig {
            signature_verified: false,
            ..default_ctx()
        },
    ));

    // === Phase 11 failure ===
    vectors.push(run_vector(
        "invalid agent id",
        &make_data_frame(vec![0x01], vec![]),
        &PipelineContextConfig {
            agent_id_verified: false,
            ..default_ctx()
        },
    ));

    // === Phase 12 failure ===
    vectors.push(run_vector(
        "invalid session state",
        &make_data_frame(vec![0x01], vec![]),
        &PipelineContextConfig {
            session_valid: false,
            ..default_ctx()
        },
    ));

    // === Phase 13 failure ===
    vectors.push(run_vector(
        "unauthorized",
        &make_data_frame(vec![0x01], vec![]),
        &PipelineContextConfig {
            authorized: false,
            ..default_ctx()
        },
    ));

    // === Phase 14 failure ===
    vectors.push(run_vector(
        "insufficient capability",
        &make_data_frame(vec![0x01], vec![]),
        &PipelineContextConfig {
            capabilities_sufficient: false,
            ..default_ctx()
        },
    ));

    // === Phase 15 failure ===
    vectors.push(run_vector(
        "handshake with extensions",
        &make_handshake_frame(vec![0xA0], encode_ext(0x0001, false, vec![0x01])),
        &default_ctx(),
    ));

    // === Phase 16 failure ===
    vectors.push(run_vector(
        "unknown critical extension",
        &make_data_frame(vec![0x01], encode_ext(0xBEEF, true, vec![0x01, 0x02])),
        &default_ctx(),
    ));

    // === Phase 17 failure ===
    vectors.push(run_vector(
        "known but not negotiated extension",
        &make_data_frame(vec![0x01], encode_ext(0x0001, false, vec![0x01])),
        &PipelineContextConfig {
            known_types: vec![0x0001],
            negotiated_types: vec![],
            ..default_ctx()
        },
    ));

    // === Mixed cases ===
    vectors.push(run_vector(
        "mixed known and unknown extensions",
        &make_data_frame(
            vec![0x01],
            extensions::encode_extensions(&[
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
            .unwrap(),
        ),
        &ctx_with_ext(0x0001),
    ));

    // Output as JSON
    let test_vectors = PipelineTestVectors { vectors };
    let json = serde_json::to_string_pretty(&test_vectors).unwrap();
    println!("{}", json);
}
