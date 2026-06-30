//! Conformance tests for RFC-0005: Error Model.
//!
//! Covers:
//! - §2: Error code format and categories
//! - §3: Error code registry (all codes)
//! - §4: Error frame wire format
//! - §4.4: Fatal error rules

use aafp_core::error::{codes, is_always_fatal, ErrorCategory, ProtocolError};

/// R5-001: Error codes MUST be categorized by thousands digit.
#[test]
fn test_r5_001_category_from_thousands_digit() {
    assert_eq!(ErrorCategory::from_code(0), ErrorCategory::Success);
    assert_eq!(ErrorCategory::from_code(1001), ErrorCategory::Transport);
    assert_eq!(
        ErrorCategory::from_code(2001),
        ErrorCategory::Authentication
    );
    assert_eq!(ErrorCategory::from_code(3001), ErrorCategory::Authorization);
    assert_eq!(ErrorCategory::from_code(4001), ErrorCategory::Discovery);
    assert_eq!(ErrorCategory::from_code(5001), ErrorCategory::Messaging);
    assert_eq!(ErrorCategory::from_code(6001), ErrorCategory::Capability);
    assert_eq!(ErrorCategory::from_code(8001), ErrorCategory::Protocol);
    assert_eq!(ErrorCategory::from_code(9001), ErrorCategory::Application);
}

/// R5-002: Success codes MUST be 0000-0999.
#[test]
fn test_r5_002_success_codes() {
    assert_eq!(codes::OK, 0);
    assert_eq!(codes::PARTIAL, 1);
    assert_eq!(codes::NOT_FOUND, 2);
}

/// R5-003: Transport error codes MUST be 1000-1999.
#[test]
fn test_r5_003_transport_codes() {
    assert_eq!(codes::CONNECTION_RESET, 1001);
    assert_eq!(codes::CONNECTION_TIMEOUT, 1002);
    assert_eq!(codes::STREAM_CLOSED, 1003);
    assert_eq!(codes::STREAM_RESET, 1004);
    assert_eq!(codes::FLOW_CONTROL_ERROR, 1005);
    assert_eq!(codes::TRANSPORT_UNREACHABLE, 1006);
    assert_eq!(codes::TRANSPORT_REFUSED, 1007);
}

/// R5-004: Authentication error codes MUST be 2000-2999.
#[test]
fn test_r5_004_auth_codes() {
    assert_eq!(codes::INVALID_SIGNATURE, 2001);
    assert_eq!(codes::IDENTITY_EXPIRED, 2002);
    assert_eq!(codes::UNKNOWN_AGENT, 2003);
    assert_eq!(codes::VERSION_MISMATCH, 2004);
    assert_eq!(codes::UNSUPPORTED_EXTENSIONS, 2005);
    assert_eq!(codes::HANDSHAKE_FAILED, 2006);
    assert_eq!(codes::INVALID_AGENT_ID, 2007);
    assert_eq!(codes::NONCE_REUSE, 2008);
    assert_eq!(codes::RECEIVER_MAC_INVALID, 2009);
    assert_eq!(codes::UNSUPPORTED_ALGORITHM, 2010);
}

/// R5-005: Authorization error codes MUST be 3000-3999.
#[test]
fn test_r5_005_authz_codes() {
    assert_eq!(codes::UNAUTHORIZED, 3001);
    assert_eq!(codes::INSUFFICIENT_CAPABILITY, 3002);
    assert_eq!(codes::DELEGATION_CHAIN_INVALID, 3003);
    assert_eq!(codes::TOKEN_EXPIRED, 3004);
    assert_eq!(codes::TOKEN_REVOKED, 3005);
    assert_eq!(codes::DELEGATION_DEPTH_EXCEEDED, 3006);
}

/// R5-006: Discovery error codes MUST be 4000-4999.
#[test]
fn test_r5_006_discovery_codes() {
    assert_eq!(codes::DHT_ERROR, 4001);
    assert_eq!(codes::BOOTSTRAP_FAILED, 4002);
    assert_eq!(codes::RECORD_INVALID, 4003);
    assert_eq!(codes::RECORD_EXPIRED, 4004);
    assert_eq!(codes::CAPABILITY_NOT_FOUND, 4005);
    assert_eq!(codes::ANNOUNCEMENT_REJECTED, 4006);
}

/// R5-007: Messaging error codes MUST be 5000-5999.
#[test]
fn test_r5_007_messaging_codes() {
    assert_eq!(codes::MALFORMED_FRAME, 5001);
    assert_eq!(codes::UNKNOWN_METHOD, 5002);
    assert_eq!(codes::SERIALIZATION_ERROR, 5003);
    assert_eq!(codes::METHOD_PARAMS_INVALID, 5004);
    assert_eq!(codes::MESSAGE_TOO_LARGE, 5005);
    assert_eq!(codes::STREAM_NOT_FOUND, 5006);
}

/// R5-008: Capability error codes MUST be 6000-6999.
#[test]
fn test_r5_008_capability_codes() {
    assert_eq!(codes::NEGOTIATION_FAILED, 6001);
    assert_eq!(codes::INCOMPATIBLE, 6002);
    assert_eq!(codes::UNSUPPORTED_CAPABILITY, 6003);
    assert_eq!(codes::CAPABILITY_OVERLOADED, 6004);
}

/// R5-009: Protocol error codes MUST be 8000-8999.
#[test]
fn test_r5_009_protocol_codes() {
    assert_eq!(codes::FRAME_TOO_LARGE, 8001);
    assert_eq!(codes::UNEXPECTED_COMPRESSION, 8002);
    assert_eq!(codes::HANDSHAKE_ON_WRONG_STREAM, 8003);
    assert_eq!(codes::UNKNOWN_CRITICAL_FRAME_TYPE, 8004);
    assert_eq!(codes::UNKNOWN_CRITICAL_EXTENSION, 8005);
    assert_eq!(codes::INVALID_VERSION, 8006);
    assert_eq!(codes::INVALID_FLAGS, 8007);
    assert_eq!(codes::RESERVED_FIELD_NONZERO, 8008);
    assert_eq!(codes::PROTOCOL_VIOLATION, 8009);
}

/// R5-020: All 2xxx authentication errors MUST be always fatal.
#[test]
fn test_r5_020_auth_errors_always_fatal() {
    for code in [
        codes::INVALID_SIGNATURE,
        codes::IDENTITY_EXPIRED,
        codes::UNKNOWN_AGENT,
        codes::VERSION_MISMATCH,
        codes::UNSUPPORTED_EXTENSIONS,
        codes::HANDSHAKE_FAILED,
        codes::INVALID_AGENT_ID,
        codes::NONCE_REUSE,
        codes::RECEIVER_MAC_INVALID,
        codes::UNSUPPORTED_ALGORITHM,
    ] {
        assert!(is_always_fatal(code), "code {code} must be always fatal");
    }
}

/// R5-021: UNKNOWN_CRITICAL_FRAME_TYPE MUST be always fatal.
#[test]
fn test_r5_021_unknown_critical_frame_fatal() {
    assert!(is_always_fatal(codes::UNKNOWN_CRITICAL_FRAME_TYPE));
}

/// R5-022: UNKNOWN_CRITICAL_EXTENSION MUST be always fatal.
#[test]
fn test_r5_022_unknown_critical_ext_fatal() {
    assert!(is_always_fatal(codes::UNKNOWN_CRITICAL_EXTENSION));
}

/// R5-023: INVALID_VERSION MUST be always fatal.
#[test]
fn test_r5_023_invalid_version_fatal() {
    assert!(is_always_fatal(codes::INVALID_VERSION));
}

/// R5-024: PROTOCOL_VIOLATION MUST be always fatal.
#[test]
fn test_r5_024_protocol_violation_fatal() {
    assert!(is_always_fatal(codes::PROTOCOL_VIOLATION));
}

/// R5-025: Non-fatal codes MUST NOT be always fatal.
#[test]
fn test_r5_025_non_fatal_codes() {
    assert!(!is_always_fatal(codes::OK));
    assert!(!is_always_fatal(codes::CONNECTION_RESET));
    assert!(!is_always_fatal(codes::STREAM_CLOSED));
    assert!(!is_always_fatal(codes::FRAME_TOO_LARGE));
    assert!(!is_always_fatal(codes::MALFORMED_FRAME));
}

/// R5-030: ProtocolError MUST set fatal=true for always-fatal codes.
#[test]
fn test_r5_030_protocol_error_auto_fatal() {
    let pe = ProtocolError::new(codes::INVALID_SIGNATURE, "bad sig");
    assert!(pe.is_fatal());
}

/// R5-031: ProtocolError MUST allow non-fatal for non-always-fatal codes.
#[test]
fn test_r5_031_protocol_error_non_fatal() {
    let pe = ProtocolError::new(codes::STREAM_CLOSED, "closed");
    assert!(!pe.is_fatal());
}

/// R5-032: ProtocolError with_fatal(false) MUST NOT override always-fatal.
#[test]
fn test_r5_032_cannot_override_always_fatal() {
    let pe = ProtocolError::new(codes::INVALID_SIGNATURE, "bad sig").with_fatal(false);
    assert!(pe.is_fatal(), "always-fatal cannot be overridden");
}

/// R5-033: ProtocolError data field MUST be truncated to 4096 bytes.
#[test]
fn test_r5_033_data_truncated_to_4096() {
    let pe = ProtocolError::new(codes::PROTOCOL_VIOLATION, "big").with_data(vec![0u8; 5000]);
    assert_eq!(pe.data.as_ref().unwrap().len(), 4096);
}

/// R5-034: ProtocolError MUST have code, message, data, fatal fields.
#[test]
fn test_r5_034_protocol_error_fields() {
    let pe = ProtocolError::new(codes::MALFORMED_FRAME, "bad frame")
        .with_data(vec![1, 2, 3])
        .with_fatal(true);
    assert_eq!(pe.code, codes::MALFORMED_FRAME);
    assert_eq!(pe.message, "bad frame");
    assert_eq!(pe.data, Some(vec![1, 2, 3]));
    assert!(pe.fatal);
}
