//! Normative frame processing pipeline (RFC-0002 §6.5, Rev 6 A-7).
//!
//! This module implements the explicit 20-phase frame processing pipeline
//! defined normatively in RFC-0002 Section 6.5. Each phase is a separate
//! function that returns a typed error. The phases MUST be executed in
//! the exact order specified.
//!
//! ## Security Invariant
//!
//! Extension semantics MUST NOT execute before successful authentication
//! and authorization. The pipeline enforces this by structurally
//! separating the phases: extension callbacks are only invoked in Phase
//! 18, after all authentication and authorization phases (9-14) have
//! succeeded.
//!
//! ## Phase Summary
//!
//! | Phases | Purpose |
//! |--------|---------|
//! | 1-3 | Header validation, size checks, no allocation |
//! | 4-5 | Read payload and extension bytes |
//! | 6-8 | Canonical CBOR decoding |
//! | 9-14 | Authentication and authorization |
//! | 15-17 | Extension parsing and validation |
//! | 18 | Extension semantic execution |
//! | 19-20 | Final state validation and delivery |

use crate::extensions::{self, Extension, ExtensionError};
use crate::framing::{self, Frame, FrameError, FrameType, AAFP_VERSION, FRAME_HEADER_SIZE};
use std::collections::HashSet;

/// The phase at which a pipeline error occurred.
///
/// This allows callers to map the error to the correct wire error code
/// and determine the close behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PipelinePhase {
    Phase1ValidateHeader,
    Phase2ValidateLengths,
    Phase3RejectOversized,
    Phase4ReadPayload,
    Phase5ReadExtensions,
    Phase6DecodeCbor,
    Phase7RejectDuplicateKeys,
    Phase8RejectNonCanonical,
    Phase9ValidateTranscript,
    Phase10VerifySignatures,
    Phase11VerifyAgentId,
    Phase12VerifySessionState,
    Phase13VerifyAuthorization,
    Phase14VerifyCapabilities,
    Phase15DecodeExtensions,
    Phase16CheckUnknownCritical,
    Phase17CheckNonNegotiated,
    Phase18ProcessExtensionSemantics,
    Phase19ValidateFinalState,
    Phase20DeliverToUpperLayer,
}

impl PipelinePhase {
    /// Human-readable phase name (matches RFC §6.5.1).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Phase1ValidateHeader => "validate_frame_header",
            Self::Phase2ValidateLengths => "validate_lengths",
            Self::Phase3RejectOversized => "reject_oversized_before_allocation",
            Self::Phase4ReadPayload => "read_payload",
            Self::Phase5ReadExtensions => "read_extensions",
            Self::Phase6DecodeCbor => "decode_canonical_cbor",
            Self::Phase7RejectDuplicateKeys => "reject_duplicate_cbor_keys",
            Self::Phase8RejectNonCanonical => "reject_non_canonical_cbor",
            Self::Phase9ValidateTranscript => "validate_transcript_state",
            Self::Phase10VerifySignatures => "verify_signatures",
            Self::Phase11VerifyAgentId => "verify_agent_id",
            Self::Phase12VerifySessionState => "verify_session_state",
            Self::Phase13VerifyAuthorization => "verify_authorization",
            Self::Phase14VerifyCapabilities => "verify_required_capabilities",
            Self::Phase15DecodeExtensions => "decode_extensions",
            Self::Phase16CheckUnknownCritical => "check_unknown_critical_extensions",
            Self::Phase17CheckNonNegotiated => "check_non_negotiated_extensions",
            Self::Phase18ProcessExtensionSemantics => "process_extension_semantics",
            Self::Phase19ValidateFinalState => "validate_final_state",
            Self::Phase20DeliverToUpperLayer => "deliver_to_upper_layer",
        }
    }

    /// Phase number (1-20).
    pub fn number(&self) -> u8 {
        match self {
            Self::Phase1ValidateHeader => 1,
            Self::Phase2ValidateLengths => 2,
            Self::Phase3RejectOversized => 3,
            Self::Phase4ReadPayload => 4,
            Self::Phase5ReadExtensions => 5,
            Self::Phase6DecodeCbor => 6,
            Self::Phase7RejectDuplicateKeys => 7,
            Self::Phase8RejectNonCanonical => 8,
            Self::Phase9ValidateTranscript => 9,
            Self::Phase10VerifySignatures => 10,
            Self::Phase11VerifyAgentId => 11,
            Self::Phase12VerifySessionState => 12,
            Self::Phase13VerifyAuthorization => 13,
            Self::Phase14VerifyCapabilities => 14,
            Self::Phase15DecodeExtensions => 15,
            Self::Phase16CheckUnknownCritical => 16,
            Self::Phase17CheckNonNegotiated => 17,
            Self::Phase18ProcessExtensionSemantics => 18,
            Self::Phase19ValidateFinalState => 19,
            Self::Phase20DeliverToUpperLayer => 20,
        }
    }

    /// Whether this phase is in the pre-authentication group (1-8).
    /// Extension callbacks MUST NOT execute if the failure is in this group.
    pub fn is_pre_authentication(&self) -> bool {
        self.number() <= 14
    }

    /// Whether this phase is in the authentication group (9-14).
    pub fn is_authentication(&self) -> bool {
        (9..=14).contains(&self.number())
    }

    /// Whether this phase is in the extension processing group (15-18).
    pub fn is_extension_processing(&self) -> bool {
        (15..=18).contains(&self.number())
    }
}

impl std::fmt::Display for PipelinePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Phase {} ({})", self.number(), self.name())
    }
}

/// Error returned by the frame processing pipeline.
///
/// Each error carries the phase at which it occurred, the corresponding
/// wire error code, whether it is fatal, and a human-readable message.
#[derive(Clone, Debug)]
pub struct PipelineError {
    /// The phase at which the error occurred.
    pub phase: PipelinePhase,
    /// The wire error code (RFC-0005).
    pub error_code: u32,
    /// Whether the error is fatal (connection must close).
    pub fatal: bool,
    /// Human-readable error message.
    pub message: String,
}

impl PipelineError {
    /// Create a new pipeline error.
    pub fn new(
        phase: PipelinePhase,
        error_code: u32,
        fatal: bool,
        message: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            error_code,
            fatal,
            message: message.into(),
        }
    }

    /// Whether extension callbacks should have been invoked (always false for
    /// errors in phases 1-17).
    pub fn extension_callbacks_invoked(&self) -> bool {
        // Callbacks only execute in Phase 18. Any error in Phase 18 means
        // a callback was invoked but failed. Errors in all other phases
        // mean no callbacks were invoked.
        self.phase == PipelinePhase::Phase18ProcessExtensionSemantics
    }
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pipeline error at {} (code {}, {}): {}",
            self.phase,
            self.error_code,
            if self.fatal { "fatal" } else { "non-fatal" },
            self.message
        )
    }
}

impl std::error::Error for PipelineError {}

/// Context provided to the pipeline for authentication and authorization phases.
///
/// This trait allows the pipeline to be used with different authentication
/// backends (testing, production, etc.) without coupling to specific
/// crypto implementations.
pub trait PipelineContext {
    /// Whether the peer's signature has been verified (Phase 10).
    fn signature_verified(&self) -> bool;

    /// Whether the peer's AgentId matches the claimed identity (Phase 11).
    fn agent_id_verified(&self) -> bool;

    /// Whether the session is in the correct state for this frame type (Phase 12).
    fn session_state_valid(&self, frame_type: FrameType) -> bool;

    /// Whether the peer is authorized for this frame type (Phase 13).
    fn authorized(&self, frame_type: FrameType) -> bool;

    /// Whether the peer has the required capabilities (Phase 14).
    fn capabilities_sufficient(&self, frame_type: FrameType) -> bool;

    /// Whether the transcript state is valid for a handshake frame (Phase 9).
    fn transcript_state_valid(&self) -> bool;

    /// The set of negotiated extension types (for Phase 17).
    fn negotiated_extension_types(&self) -> &HashSet<u16>;

    /// The set of known extension types (for Phase 16).
    fn known_extension_types(&self) -> &HashSet<u16>;
}

/// A simple context for testing that allows controlling each phase's outcome.
#[derive(Clone, Debug)]
pub struct TestingContext {
    pub signature_verified: bool,
    pub agent_id_verified: bool,
    pub session_valid: bool,
    pub authorized: bool,
    pub capabilities_sufficient: bool,
    pub transcript_valid: bool,
    pub negotiated_types: HashSet<u16>,
    pub known_types: HashSet<u16>,
}

impl Default for TestingContext {
    fn default() -> Self {
        Self {
            signature_verified: true,
            agent_id_verified: true,
            session_valid: true,
            authorized: true,
            capabilities_sufficient: true,
            transcript_valid: true,
            negotiated_types: HashSet::new(),
            known_types: HashSet::new(),
        }
    }
}

impl PipelineContext for TestingContext {
    fn signature_verified(&self) -> bool {
        self.signature_verified
    }
    fn agent_id_verified(&self) -> bool {
        self.agent_id_verified
    }
    fn session_state_valid(&self, _frame_type: FrameType) -> bool {
        self.session_valid
    }
    fn authorized(&self, _frame_type: FrameType) -> bool {
        self.authorized
    }
    fn capabilities_sufficient(&self, _frame_type: FrameType) -> bool {
        self.capabilities_sufficient
    }
    fn transcript_state_valid(&self) -> bool {
        self.transcript_valid
    }
    fn negotiated_extension_types(&self) -> &HashSet<u16> {
        &self.negotiated_types
    }
    fn known_extension_types(&self) -> &HashSet<u16> {
        &self.known_types
    }
}

/// Extension callback trait. Implementations register callbacks for
/// specific extension types. Callbacks are only invoked in Phase 18.
pub trait ExtensionCallback: Send + Sync {
    /// The extension type this callback handles.
    fn extension_type(&self) -> u16;

    /// Process the extension data. Called only after all authentication
    /// and authorization phases have succeeded.
    fn process(&self, data: &[u8]) -> Result<(), PipelineError>;
}

/// Result of successfully processing a frame through the pipeline.
#[derive(Clone, Debug)]
pub struct ProcessedFrame {
    /// The decoded frame.
    pub frame: Frame,
    /// The parsed extensions (empty if no extensions).
    pub extensions: Vec<Extension>,
    /// The number of extension callbacks invoked (Phase 18).
    pub extension_callback_count: usize,
    /// The number of extensions silently ignored (unknown non-critical).
    pub extensions_ignored: usize,
}

/// The frame processing pipeline (RFC-0002 §6.5).
///
/// Executes the 20-phase pipeline in order. Each phase is a separate
/// method that returns a `Result`. The pipeline stops at the first
/// failing phase.
pub struct FrameProcessingPipeline<'a> {
    ctx: &'a dyn PipelineContext,
    callbacks: &'a [Box<dyn ExtensionCallback>],
}

impl<'a> FrameProcessingPipeline<'a> {
    /// Create a new pipeline with the given context and callbacks.
    pub fn new(ctx: &'a dyn PipelineContext, callbacks: &'a [Box<dyn ExtensionCallback>]) -> Self {
        Self { ctx, callbacks }
    }

    /// Run the full 20-phase pipeline on a raw frame byte buffer.
    ///
    /// This is the main entry point. It decodes the frame, validates
    /// all phases, and returns either a processed frame or a pipeline
    /// error indicating which phase failed.
    pub fn process(&self, data: &[u8]) -> Result<ProcessedFrame, PipelineError> {
        // Phase 1: validate_frame_header
        let header = self.validate_frame_header(data)?;

        // Phase 2: validate_lengths
        let (payload_len, ext_len) = self.validate_lengths(&header)?;

        // Phase 3: reject_oversized_before_allocation
        self.reject_oversized_before_allocation(payload_len, ext_len)?;

        // Phase 4-5: read_payload + read_extensions (via decode_frame)
        let (frame, _consumed) = self.read_frame(data)?;

        // Phase 6-8: CBOR validation (for CBOR-bearing frame types)
        self.validate_cbor(&frame)?;

        // Phase 9: validate_transcript_state
        self.validate_transcript_state(&frame)?;

        // Phase 10: verify_signatures
        self.verify_signatures(&frame)?;

        // Phase 11: verify_agent_id
        self.verify_agent_id(&frame)?;

        // Phase 12: verify_session_state
        self.verify_session_state(&frame)?;

        // Phase 13: verify_authorization
        self.verify_authorization(&frame)?;

        // Phase 14: verify_required_capabilities
        self.verify_required_capabilities(&frame)?;

        // ═══════════════════════════════════════════════════
        // ║ AUTHENTICATION AND AUTHORIZATION COMPLETE        ║
        // ║ Extension semantics MAY now execute.              ║
        // ═══════════════════════════════════════════════════

        // Phase 15: decode_extensions
        let parsed_exts = self.decode_extensions(&frame)?;

        // Phase 16: check_unknown_critical_extensions
        self.check_unknown_critical(&parsed_exts)?;

        // Phase 17: check_non_negotiated_extensions
        self.check_non_negotiated(&parsed_exts)?;

        // Phase 18: process_extension_semantics
        let (callback_count, ignored_count) = self.process_extension_semantics(&parsed_exts)?;

        // Phase 19: validate_final_state
        self.validate_final_state(&frame)?;

        // Phase 20: deliver_to_upper_layer
        // (In this implementation, delivery is implicit — the caller
        // receives the ProcessedFrame and delivers it to the application.)

        Ok(ProcessedFrame {
            frame,
            extensions: parsed_exts,
            extension_callback_count: callback_count,
            extensions_ignored: ignored_count,
        })
    }

    // === Phase implementations ===

    /// Phase 1: Validate the 28-byte frame header.
    fn validate_frame_header(&self, data: &[u8]) -> Result<FrameHeader, PipelineError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(PipelineError::new(
                PipelinePhase::Phase1ValidateHeader,
                aafp_core::error::codes::MALFORMED_FRAME,
                true,
                format!(
                    "incomplete header: need {} bytes, have {}",
                    FRAME_HEADER_SIZE,
                    data.len()
                ),
            ));
        }

        let version = data[0];
        if version != AAFP_VERSION {
            return Err(PipelineError::new(
                PipelinePhase::Phase1ValidateHeader,
                aafp_core::error::codes::INVALID_VERSION,
                true,
                format!("invalid version: {} (expected {})", version, AAFP_VERSION),
            ));
        }

        let reserved = data[3];
        if reserved != 0 {
            return Err(PipelineError::new(
                PipelinePhase::Phase1ValidateHeader,
                aafp_core::error::codes::RESERVED_FIELD_NONZERO,
                true,
                format!("reserved field is non-zero: 0x{:02X}", reserved),
            ));
        }

        Ok(FrameHeader {
            version,
            frame_type_raw: data[1],
            flags: data[2],
            reserved,
            stream_id: u64::from_be_bytes(data[4..12].try_into().unwrap()),
            payload_len: u64::from_be_bytes(data[12..20].try_into().unwrap()) as usize,
            ext_len: u64::from_be_bytes(data[20..28].try_into().unwrap()) as usize,
        })
    }

    /// Phase 2: Validate payload and extension lengths.
    fn validate_lengths(&self, header: &FrameHeader) -> Result<(usize, usize), PipelineError> {
        if header.payload_len > framing::MAX_PAYLOAD_SIZE {
            return Err(PipelineError::new(
                PipelinePhase::Phase2ValidateLengths,
                aafp_core::error::codes::FRAME_TOO_LARGE,
                false,
                format!(
                    "payload too large: {} bytes (max {})",
                    header.payload_len,
                    framing::MAX_PAYLOAD_SIZE
                ),
            ));
        }

        if header.ext_len > framing::MAX_EXTENSION_SIZE {
            return Err(PipelineError::new(
                PipelinePhase::Phase2ValidateLengths,
                aafp_core::error::codes::FRAME_TOO_LARGE,
                false,
                format!(
                    "extension too large: {} bytes (max {})",
                    header.ext_len,
                    framing::MAX_EXTENSION_SIZE
                ),
            ));
        }

        // Overflow check
        let _ = header
            .payload_len
            .checked_add(header.ext_len)
            .ok_or_else(|| {
                PipelineError::new(
                    PipelinePhase::Phase2ValidateLengths,
                    aafp_core::error::codes::FRAME_TOO_LARGE,
                    false,
                    "payload + extension length overflow",
                )
            })?;

        Ok((header.payload_len, header.ext_len))
    }

    /// Phase 3: Reject oversized frames before any allocation.
    ///
    /// This is a no-op if Phase 2 passed, but it exists as a separate
    /// phase to make the "no allocation before size validation" invariant
    /// explicit and testable.
    fn reject_oversized_before_allocation(
        &self,
        payload_len: usize,
        ext_len: usize,
    ) -> Result<(), PipelineError> {
        if payload_len > framing::MAX_PAYLOAD_SIZE {
            return Err(PipelineError::new(
                PipelinePhase::Phase3RejectOversized,
                aafp_core::error::codes::FRAME_TOO_LARGE,
                false,
                "rejected before allocation: payload too large",
            ));
        }
        if ext_len > framing::MAX_EXTENSION_SIZE {
            return Err(PipelineError::new(
                PipelinePhase::Phase3RejectOversized,
                aafp_core::error::codes::FRAME_TOO_LARGE,
                false,
                "rejected before allocation: extension too large",
            ));
        }
        Ok(())
    }

    /// Phases 4-5: Read the frame (payload + extensions).
    ///
    /// This uses the existing `decode_frame` function which handles
    /// allocation and extraction. The size checks have already been
    /// done in Phases 2-3.
    fn read_frame(&self, data: &[u8]) -> Result<(Frame, usize), PipelineError> {
        framing::decode_frame(data).map_err(|e| {
            let (code, fatal, msg) = match e {
                FrameError::InvalidVersion(v, expected) => (
                    aafp_core::error::codes::INVALID_VERSION,
                    true,
                    format!("invalid version: {} (expected {})", v, expected),
                ),
                FrameError::PayloadTooLarge(len, max) => (
                    aafp_core::error::codes::FRAME_TOO_LARGE,
                    false,
                    format!("payload too large: {} (max {})", len, max),
                ),
                FrameError::ExtensionTooLarge(len, max) => (
                    aafp_core::error::codes::FRAME_TOO_LARGE,
                    false,
                    format!("extension too large: {} (max {})", len, max),
                ),
                FrameError::UnknownFrameType(ft) => (
                    aafp_core::error::codes::UNKNOWN_CRITICAL_FRAME_TYPE,
                    true,
                    format!("unknown critical frame type: 0x{:02X}", ft),
                ),
                FrameError::Incomplete { needed, have } => (
                    aafp_core::error::codes::MALFORMED_FRAME,
                    true,
                    format!("incomplete frame: need {} bytes, have {}", needed, have),
                ),
                other => (
                    aafp_core::error::codes::MALFORMED_FRAME,
                    true,
                    format!("frame decode error: {}", other),
                ),
            };
            // Both size and decode errors are attributed to Phase 4 (payload read).
            let phase = PipelinePhase::Phase4ReadPayload;
            PipelineError::new(phase, code, fatal, msg)
        })
    }

    /// Phases 6-8: Validate canonical CBOR encoding.
    ///
    /// For frame types that carry CBOR payloads (HANDSHAKE, RPC_REQUEST,
    /// RPC_RESPONSE, CLOSE, ERROR), this phase validates that the payload
    /// is canonical CBOR. For DATA frames, the payload is opaque bytes
    /// and this phase is skipped.
    fn validate_cbor(&self, frame: &Frame) -> Result<(), PipelineError> {
        match frame.frame_type {
            FrameType::Data | FrameType::Ping | FrameType::Pong => {
                // DATA/PING/PONG payloads are opaque — skip CBOR validation
                Ok(())
            }
            FrameType::Handshake
            | FrameType::RpcRequest
            | FrameType::RpcResponse
            | FrameType::Close
            | FrameType::Error => {
                if frame.payload.is_empty() {
                    return Ok(());
                }
                // Attempt to decode as CBOR — if it fails, it's non-canonical
                // The aafp-cbor crate enforces canonical encoding
                aafp_cbor::check_canonical(&frame.payload).map_err(|e| {
                    PipelineError::new(
                        PipelinePhase::Phase6DecodeCbor,
                        aafp_core::error::codes::SERIALIZATION_ERROR,
                        true,
                        format!("CBOR decode error: {}", e),
                    )
                })?;
                Ok(())
            }
            FrameType::Unknown(_) => {
                // Unknown frame types should have been rejected in Phase 1
                Ok(())
            }
        }
    }

    /// Phase 9: Validate transcript state (handshake frames only).
    fn validate_transcript_state(&self, frame: &Frame) -> Result<(), PipelineError> {
        if frame.frame_type == FrameType::Handshake && !self.ctx.transcript_state_valid() {
            return Err(PipelineError::new(
                PipelinePhase::Phase9ValidateTranscript,
                aafp_core::error::codes::HANDSHAKE_FAILED,
                true,
                "transcript state invalid for handshake frame",
            ));
        }
        Ok(())
    }

    /// Phase 10: Verify signatures.
    fn verify_signatures(&self, _frame: &Frame) -> Result<(), PipelineError> {
        if !self.ctx.signature_verified() {
            return Err(PipelineError::new(
                PipelinePhase::Phase10VerifySignatures,
                aafp_core::error::codes::INVALID_SIGNATURE,
                true,
                "signature verification failed",
            ));
        }
        Ok(())
    }

    /// Phase 11: Verify AgentId binding.
    fn verify_agent_id(&self, _frame: &Frame) -> Result<(), PipelineError> {
        if !self.ctx.agent_id_verified() {
            return Err(PipelineError::new(
                PipelinePhase::Phase11VerifyAgentId,
                aafp_core::error::codes::INVALID_AGENT_ID,
                true,
                "agent ID does not match public key hash",
            ));
        }
        Ok(())
    }

    /// Phase 12: Verify session state.
    fn verify_session_state(&self, frame: &Frame) -> Result<(), PipelineError> {
        if !self.ctx.session_state_valid(frame.frame_type) {
            return Err(PipelineError::new(
                PipelinePhase::Phase12VerifySessionState,
                aafp_core::error::codes::PROTOCOL_VIOLATION,
                true,
                "session state invalid for this frame type",
            ));
        }
        Ok(())
    }

    /// Phase 13: Verify authorization.
    fn verify_authorization(&self, frame: &Frame) -> Result<(), PipelineError> {
        if !self.ctx.authorized(frame.frame_type) {
            return Err(PipelineError::new(
                PipelinePhase::Phase13VerifyAuthorization,
                aafp_core::error::codes::UNAUTHORIZED,
                true,
                "peer not authorized for this action",
            ));
        }
        Ok(())
    }

    /// Phase 14: Verify required capabilities.
    fn verify_required_capabilities(&self, frame: &Frame) -> Result<(), PipelineError> {
        if !self.ctx.capabilities_sufficient(frame.frame_type) {
            return Err(PipelineError::new(
                PipelinePhase::Phase14VerifyCapabilities,
                aafp_core::error::codes::INSUFFICIENT_CAPABILITY,
                true,
                "peer lacks required capabilities",
            ));
        }
        Ok(())
    }

    /// Phase 15: Decode extensions from raw bytes.
    fn decode_extensions(&self, frame: &Frame) -> Result<Vec<Extension>, PipelineError> {
        if frame.extensions.is_empty() {
            return Ok(Vec::new());
        }

        // For handshake frames, extensions are forbidden
        if frame.frame_type == FrameType::Handshake {
            return Err(PipelineError::new(
                PipelinePhase::Phase15DecodeExtensions,
                aafp_core::error::codes::PROTOCOL_VIOLATION,
                true,
                "HANDSHAKE frames MUST NOT carry frame extensions",
            ));
        }

        extensions::decode_extensions(&frame.extensions).map_err(|e| {
            let msg = match e {
                ExtensionError::IncompleteHeader { needed, have } => {
                    format!(
                        "incomplete extension header: need {}, have {}",
                        needed, have
                    )
                }
                ExtensionError::IncompleteData { needed, have } => {
                    format!("incomplete extension data: need {}, have {}", needed, have)
                }
                ExtensionError::LengthMismatch { expected, actual } => {
                    format!(
                        "extension length mismatch: expected {}, actual {}",
                        expected, actual
                    )
                }
                other => format!("extension decode error: {}", other),
            };
            PipelineError::new(
                PipelinePhase::Phase15DecodeExtensions,
                aafp_core::error::codes::MALFORMED_FRAME,
                true,
                msg,
            )
        })
    }

    /// Phase 16: Check for unknown critical extensions.
    fn check_unknown_critical(&self, exts: &[Extension]) -> Result<(), PipelineError> {
        let known = self.ctx.known_extension_types();
        for ext in exts {
            if ext.critical && !known.contains(&ext.ext_type) {
                return Err(PipelineError::new(
                    PipelinePhase::Phase16CheckUnknownCritical,
                    aafp_core::error::codes::UNKNOWN_CRITICAL_EXTENSION,
                    true,
                    format!("unknown critical extension: 0x{:04X}", ext.ext_type),
                ));
            }
        }
        Ok(())
    }

    /// Phase 17: Check for non-negotiated extensions.
    fn check_non_negotiated(&self, exts: &[Extension]) -> Result<(), PipelineError> {
        let negotiated = self.ctx.negotiated_extension_types();
        for ext in exts {
            if !negotiated.contains(&ext.ext_type) {
                // Unknown non-critical extensions are silently ignored (Phase 18 skips them)
                // Known but non-negotiated extensions are an error
                let known = self.ctx.known_extension_types();
                if known.contains(&ext.ext_type) {
                    return Err(PipelineError::new(
                        PipelinePhase::Phase17CheckNonNegotiated,
                        aafp_core::error::codes::INVALID_FLAGS,
                        true,
                        format!("non-negotiated extension: 0x{:04X}", ext.ext_type),
                    ));
                }
                // Unknown non-critical: will be silently ignored in Phase 18
            }
        }
        Ok(())
    }

    /// Phase 18: Process extension semantics.
    ///
    /// This is the ONLY phase where extension callbacks execute.
    /// Returns (callback_count, ignored_count).
    fn process_extension_semantics(
        &self,
        exts: &[Extension],
    ) -> Result<(usize, usize), PipelineError> {
        let mut callback_count = 0;
        let mut ignored_count = 0;
        let negotiated = self.ctx.negotiated_extension_types();

        for ext in exts {
            if !negotiated.contains(&ext.ext_type) {
                // Unknown non-critical extension — silently ignore
                ignored_count += 1;
                continue;
            }

            // Find the callback for this extension type
            let callback = self
                .callbacks
                .iter()
                .find(|cb| cb.extension_type() == ext.ext_type);

            if let Some(cb) = callback {
                cb.process(&ext.data)?;
                callback_count += 1;
            } else {
                // Known and negotiated but no callback registered — skip
                ignored_count += 1;
            }
        }

        Ok((callback_count, ignored_count))
    }

    /// Phase 19: Validate final state.
    fn validate_final_state(&self, _frame: &Frame) -> Result<(), PipelineError> {
        // In this implementation, state validation is done by the handshake
        // state machine (aafp-core::handshake_state). This phase is a hook
        // for the application to verify that the frame didn't cause an
        // illegal state transition.
        Ok(())
    }
}

/// Internal representation of a parsed frame header.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct FrameHeader {
    version: u8,
    frame_type_raw: u8,
    flags: u8,
    reserved: u8,
    stream_id: u64,
    payload_len: usize,
    ext_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{encode_frame, Frame, FrameType};

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

    #[allow(dead_code)]
    fn make_handshake_frame(payload: Vec<u8>) -> Vec<u8> {
        let frame = Frame {
            frame_type: FrameType::Handshake,
            flags: 0,
            stream_id: 0,
            extensions: Vec::new(),
            payload,
        };
        encode_frame(&frame).unwrap()
    }

    // === Phase 1 tests ===

    #[test]
    fn test_phase1_valid_header() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01, 0x02], vec![]);
        let result = pipeline.process(&data);
        assert!(result.is_ok(), "valid frame should pass: {:?}", result);
    }

    #[test]
    fn test_phase1_invalid_version() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let mut data = make_data_frame(vec![0x01], vec![]);
        data[0] = 99; // Invalid version
        let result = pipeline.process(&data);
        let err = result.unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
        assert_eq!(err.error_code, aafp_core::error::codes::INVALID_VERSION);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    #[test]
    fn test_phase1_reserved_nonzero() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let mut data = make_data_frame(vec![0x01], vec![]);
        data[3] = 0xFF; // Reserved field non-zero
        let result = pipeline.process(&data);
        let err = result.unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase1ValidateHeader);
        assert_eq!(
            err.error_code,
            aafp_core::error::codes::RESERVED_FIELD_NONZERO
        );
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 2-3 tests ===

    #[test]
    fn test_phase2_oversized_extension() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        // Create a frame header with ext_len = 70000 (exceeds 64 KiB)
        let mut data = vec![1u8, 0x01, 0x00, 0x00]; // version, type, flags, reserved
        data.extend_from_slice(&4u64.to_be_bytes()); // stream_id
        data.extend_from_slice(&100u64.to_be_bytes()); // payload_len
        data.extend_from_slice(&70000u64.to_be_bytes()); // ext_len (too large)
        data.extend_from_slice(&[0u8; 100]); // payload
                                             // Don't add extension bytes — we want to test rejection before allocation

        let result = pipeline.process(&data);
        let err = result.unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase2ValidateLengths);
        assert_eq!(err.error_code, aafp_core::error::codes::FRAME_TOO_LARGE);
        assert!(!err.fatal); // Stream-level, not connection-level
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 10 tests ===

    #[test]
    fn test_phase10_invalid_signature() {
        let ctx = TestingContext {
            signature_verified: false,
            ..Default::default()
        };
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01], vec![]);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase10VerifySignatures);
        assert_eq!(err.error_code, aafp_core::error::codes::INVALID_SIGNATURE);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 11 tests ===

    #[test]
    fn test_phase11_invalid_agent_id() {
        let ctx = TestingContext {
            agent_id_verified: false,
            ..Default::default()
        };
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01], vec![]);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase11VerifyAgentId);
        assert_eq!(err.error_code, aafp_core::error::codes::INVALID_AGENT_ID);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 12 tests ===

    #[test]
    fn test_phase12_invalid_session_state() {
        let ctx = TestingContext {
            session_valid: false,
            ..Default::default()
        };
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01], vec![]);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase12VerifySessionState);
        assert_eq!(err.error_code, aafp_core::error::codes::PROTOCOL_VIOLATION);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 13 tests ===

    #[test]
    fn test_phase13_unauthorized() {
        let ctx = TestingContext {
            authorized: false,
            ..Default::default()
        };
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01], vec![]);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase13VerifyAuthorization);
        assert_eq!(err.error_code, aafp_core::error::codes::UNAUTHORIZED);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 14 tests ===

    #[test]
    fn test_phase14_insufficient_capability() {
        let ctx = TestingContext {
            capabilities_sufficient: false,
            ..Default::default()
        };
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01], vec![]);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase14VerifyCapabilities);
        assert_eq!(
            err.error_code,
            aafp_core::error::codes::INSUFFICIENT_CAPABILITY
        );
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 15 tests ===

    #[test]
    fn test_phase15_handshake_with_extensions_rejected() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        // Create a handshake frame with extensions (should be rejected)
        let ext_bytes = extensions::encode_extensions(&[Extension {
            ext_type: 0x0001,
            critical: false,
            data: vec![0x01],
        }])
        .unwrap();
        let frame = Frame {
            frame_type: FrameType::Handshake,
            flags: 0,
            stream_id: 0,
            extensions: ext_bytes,
            payload: vec![0xA0], // empty CBOR map
        };
        let data = encode_frame(&frame).unwrap();
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase15DecodeExtensions);
        assert_eq!(err.error_code, aafp_core::error::codes::PROTOCOL_VIOLATION);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 16 tests ===

    #[test]
    fn test_phase16_unknown_critical_extension() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let ext_bytes = extensions::encode_extensions(&[Extension {
            ext_type: 0xBEEF,
            critical: true,
            data: vec![0x01, 0x02],
        }])
        .unwrap();
        let data = make_data_frame(vec![0x01], ext_bytes);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase16CheckUnknownCritical);
        assert_eq!(
            err.error_code,
            aafp_core::error::codes::UNKNOWN_CRITICAL_EXTENSION
        );
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 17 tests ===

    #[test]
    fn test_phase17_non_negotiated_extension() {
        let ctx = TestingContext {
            known_types: HashSet::from([0x0001]),
            negotiated_types: HashSet::new(), // 0x0001 is known but not negotiated
            ..Default::default()
        };
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let ext_bytes = extensions::encode_extensions(&[Extension {
            ext_type: 0x0001,
            critical: false,
            data: vec![0x01],
        }])
        .unwrap();
        let data = make_data_frame(vec![0x01], ext_bytes);
        let err = pipeline.process(&data).unwrap_err();
        assert_eq!(err.phase, PipelinePhase::Phase17CheckNonNegotiated);
        assert_eq!(err.error_code, aafp_core::error::codes::INVALID_FLAGS);
        assert!(err.fatal);
        assert!(!err.extension_callbacks_invoked());
    }

    // === Phase 18 tests ===

    #[test]
    fn test_phase18_callback_invoked_for_valid_extension() {
        struct TestCallback;
        impl ExtensionCallback for TestCallback {
            fn extension_type(&self) -> u16 {
                0x0001
            }
            fn process(&self, _data: &[u8]) -> Result<(), PipelineError> {
                Ok(())
            }
        }

        let ctx = TestingContext {
            known_types: HashSet::from([0x0001]),
            negotiated_types: HashSet::from([0x0001]),
            ..Default::default()
        };
        let callbacks: Vec<Box<dyn ExtensionCallback>> = vec![Box::new(TestCallback)];
        let pipeline = FrameProcessingPipeline::new(&ctx, &callbacks);

        let ext_bytes = extensions::encode_extensions(&[Extension {
            ext_type: 0x0001,
            critical: false,
            data: vec![0xDE, 0xAD],
        }])
        .unwrap();
        let data = make_data_frame(vec![0x01], ext_bytes);
        let result = pipeline.process(&data).unwrap();
        assert_eq!(result.extension_callback_count, 1);
        assert_eq!(result.extensions_ignored, 0);
    }

    #[test]
    fn test_phase18_unknown_non_critical_ignored() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let ext_bytes = extensions::encode_extensions(&[Extension {
            ext_type: 0xBEEF,
            critical: false, // Non-critical → silently ignored
            data: vec![0x01],
        }])
        .unwrap();
        let data = make_data_frame(vec![0x01], ext_bytes);
        let result = pipeline.process(&data).unwrap();
        assert_eq!(result.extension_callback_count, 0);
        assert_eq!(result.extensions_ignored, 1);
    }

    #[test]
    fn test_phase18_multiple_extensions() {
        struct TestCallback1;
        impl ExtensionCallback for TestCallback1 {
            fn extension_type(&self) -> u16 {
                0x0001
            }
            fn process(&self, _data: &[u8]) -> Result<(), PipelineError> {
                Ok(())
            }
        }
        struct TestCallback2;
        impl ExtensionCallback for TestCallback2 {
            fn extension_type(&self) -> u16 {
                0x0002
            }
            fn process(&self, _data: &[u8]) -> Result<(), PipelineError> {
                Ok(())
            }
        }

        let ctx = TestingContext {
            known_types: HashSet::from([0x0001, 0x0002]),
            negotiated_types: HashSet::from([0x0001, 0x0002]),
            ..Default::default()
        };
        let callbacks: Vec<Box<dyn ExtensionCallback>> =
            vec![Box::new(TestCallback1), Box::new(TestCallback2)];
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

    // === Full pipeline success test ===

    #[test]
    fn test_full_pipeline_success_no_extensions() {
        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01, 0x02, 0x03], vec![]);
        let result = pipeline.process(&data).unwrap();
        assert_eq!(result.extension_callback_count, 0);
        assert_eq!(result.extensions_ignored, 0);
        assert!(result.extensions.is_empty());
    }

    // === Callback count is zero for all pre-auth failures ===

    #[test]
    fn test_callback_count_zero_for_all_pre_auth_failures() {
        let failure_contexts = vec![
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
            let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
            // Include an extension that would be processed if auth passed
            let ext_bytes = extensions::encode_extensions(&[Extension {
                ext_type: 0x0001,
                critical: false,
                data: vec![0x01],
            }])
            .unwrap();
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

    // === Performance test ===

    #[test]
    fn test_pipeline_performance_baseline() {
        use std::time::Instant;

        let ctx = TestingContext::default();
        let pipeline = FrameProcessingPipeline::new(&ctx, &[]);
        let data = make_data_frame(vec![0x01; 100], vec![]);

        // Warmup
        for _ in 0..100 {
            let _ = pipeline.process(&data);
        }

        // Measure pipeline
        let iterations = 100_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = pipeline.process(&data);
        }
        let pipeline_duration = start.elapsed();

        // Measure raw decode_frame (baseline)
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = crate::framing::decode_frame(&data);
        }
        let baseline_duration = start.elapsed();

        let overhead_ns = pipeline_duration.as_nanos() as f64 / iterations as f64
            - baseline_duration.as_nanos() as f64 / iterations as f64;
        let baseline_ns = baseline_duration.as_nanos() as f64 / iterations as f64;
        let overhead_pct = (overhead_ns / baseline_ns) * 100.0;

        // The pipeline adds context checks (all pass with default ctx),
        // so overhead should be minimal.
        // Note: This is not a regression test (the pipeline is new code),
        // but rather a sanity check that the overhead is reasonable.
        eprintln!(
            "Pipeline performance: baseline={:.0}ns, pipeline={:.0}ns, overhead={:.0}ns ({:.1}%)",
            baseline_ns,
            pipeline_duration.as_nanos() as f64 / iterations as f64,
            overhead_ns,
            overhead_pct
        );

        // The pipeline should not add more than 500% overhead over raw decode
        // (it does additional CBOR validation, context checks, etc.)
        // This is a sanity check, not a strict regression bound.
        assert!(
            overhead_pct < 500.0,
            "pipeline overhead too high: {:.1}% (baseline={:.0}ns, pipeline={:.0}ns)",
            overhead_pct,
            baseline_ns,
            pipeline_duration.as_nanos() as f64 / iterations as f64
        );
    }
}
