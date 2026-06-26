//! AAFP protocol error codes (RFC-0005).
//!
//! This module defines all wire-protocol error codes, the ProtocolError
//! type, and rules for fatal/non-fatal errors.
//!
//! ## Error Categories (RFC-0005 §2)
//!
//! | Category | Range | Description |
//! |----------|-------|-------------|
//! | 0xxx | 0000-0999 | Success / Information |
//! | 1xxx | 1000-1999 | Transport errors |
//! | 2xxx | 2000-2999 | Authentication errors (always fatal) |
//! | 3xxx | 3000-3999 | Authorization errors |
//! | 4xxx | 4000-4999 | Discovery errors |
//! | 5xxx | 5000-5999 | Messaging errors |
//! | 6xxx | 6000-6999 | Capability errors |
//! | 7xxx | 7000-7999 | Resource errors (reserved) |
//! | 8xxx | 8000-8999 | Protocol errors |
//! | 9xxx | 9000-9999 | Application errors (reserved) |

use thiserror::Error;

/// Error category (thousands digit of error code).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum ErrorCategory {
    Success = 0,
    Transport = 1000,
    Authentication = 2000,
    Authorization = 3000,
    Discovery = 4000,
    Messaging = 5000,
    Capability = 6000,
    Resource = 7000,
    Protocol = 8000,
    Application = 9000,
}

impl ErrorCategory {
    /// Determine category from an error code.
    pub fn from_code(code: u32) -> Self {
        match code / 1000 {
            0 => Self::Success,
            1 => Self::Transport,
            2 => Self::Authentication,
            3 => Self::Authorization,
            4 => Self::Discovery,
            5 => Self::Messaging,
            6 => Self::Capability,
            7 => Self::Resource,
            8 => Self::Protocol,
            9 => Self::Application,
            _ => Self::Protocol, // Unknown → treat as protocol error (RFC-0005 §5.1)
        }
    }
}

/// AAFP protocol error codes (RFC-0005 §3).
///
/// Once assigned, error code meanings MUST NOT change (RFC-0005 §2.1).
#[allow(non_camel_case_types)]
pub mod codes {
    // Success / Information (0xxx)
    pub const OK: u32 = 0;
    pub const PARTIAL: u32 = 1;
    pub const NOT_FOUND: u32 = 2;

    // Transport Errors (1xxx)
    pub const CONNECTION_RESET: u32 = 1001;
    pub const CONNECTION_TIMEOUT: u32 = 1002;
    pub const STREAM_CLOSED: u32 = 1003;
    pub const STREAM_RESET: u32 = 1004;
    pub const FLOW_CONTROL_ERROR: u32 = 1005;
    pub const TRANSPORT_UNREACHABLE: u32 = 1006;
    pub const TRANSPORT_REFUSED: u32 = 1007;

    // Authentication Errors (2xxx) — ALWAYS fatal (RFC-0005 §4.4)
    pub const INVALID_SIGNATURE: u32 = 2001;
    pub const IDENTITY_EXPIRED: u32 = 2002;
    pub const UNKNOWN_AGENT: u32 = 2003;
    pub const VERSION_MISMATCH: u32 = 2004;
    pub const UNSUPPORTED_EXTENSIONS: u32 = 2005;
    pub const HANDSHAKE_FAILED: u32 = 2006;
    pub const INVALID_AGENT_ID: u32 = 2007;
    pub const NONCE_REUSE: u32 = 2008;
    pub const RECEIVER_MAC_INVALID: u32 = 2009;
    pub const UNSUPPORTED_ALGORITHM: u32 = 2010;

    // Authorization Errors (3xxx)
    pub const UNAUTHORIZED: u32 = 3001;
    pub const INSUFFICIENT_CAPABILITY: u32 = 3002;
    pub const DELEGATION_CHAIN_INVALID: u32 = 3003;
    pub const TOKEN_EXPIRED: u32 = 3004;
    pub const TOKEN_REVOKED: u32 = 3005;
    pub const DELEGATION_DEPTH_EXCEEDED: u32 = 3006;

    // Discovery Errors (4xxx)
    pub const DHT_ERROR: u32 = 4001;
    pub const BOOTSTRAP_FAILED: u32 = 4002;
    pub const RECORD_INVALID: u32 = 4003;
    pub const RECORD_EXPIRED: u32 = 4004;
    pub const CAPABILITY_NOT_FOUND: u32 = 4005;
    pub const ANNOUNCEMENT_REJECTED: u32 = 4006;

    // Messaging Errors (5xxx)
    pub const MALFORMED_FRAME: u32 = 5001;
    pub const UNKNOWN_METHOD: u32 = 5002;
    pub const SERIALIZATION_ERROR: u32 = 5003;
    pub const METHOD_PARAMS_INVALID: u32 = 5004;
    pub const MESSAGE_TOO_LARGE: u32 = 5005;
    pub const STREAM_NOT_FOUND: u32 = 5006;

    // Capability Errors (6xxx)
    pub const NEGOTIATION_FAILED: u32 = 6001;
    pub const INCOMPATIBLE: u32 = 6002;
    pub const UNSUPPORTED_CAPABILITY: u32 = 6003;
    pub const CAPABILITY_OVERLOADED: u32 = 6004;

    // Protocol Errors (8xxx)
    pub const FRAME_TOO_LARGE: u32 = 8001;
    pub const UNEXPECTED_COMPRESSION: u32 = 8002;
    pub const HANDSHAKE_ON_WRONG_STREAM: u32 = 8003;
    pub const UNKNOWN_CRITICAL_FRAME_TYPE: u32 = 8004;
    pub const UNKNOWN_CRITICAL_EXTENSION: u32 = 8005;
    pub const INVALID_VERSION: u32 = 8006;
    pub const INVALID_FLAGS: u32 = 8007;
    pub const RESERVED_FIELD_NONZERO: u32 = 8008;
    pub const PROTOCOL_VIOLATION: u32 = 8009;
}

/// Check if an error code is always fatal (RFC-0005 §4.4).
///
/// The following are ALWAYS fatal regardless of the fatal flag:
/// - All 2xxx Authentication errors
/// - 8004 UNKNOWN_CRITICAL_FRAME_TYPE
/// - 8005 UNKNOWN_CRITICAL_EXTENSION
/// - 8006 INVALID_VERSION
/// - 8009 PROTOCOL_VIOLATION
pub fn is_always_fatal(code: u32) -> bool {
    let cat = ErrorCategory::from_code(code);
    match cat {
        ErrorCategory::Authentication => true,
        ErrorCategory::Protocol => {
            matches!(
                code,
                codes::UNKNOWN_CRITICAL_FRAME_TYPE
                    | codes::UNKNOWN_CRITICAL_EXTENSION
                    | codes::INVALID_VERSION
                    | codes::PROTOCOL_VIOLATION
            )
        }
        _ => false,
    }
}

/// Protocol error for wire transmission (RFC-0005 §4.1).
///
/// ErrorMessage CBOR structure (integer keys):
/// ```cbor
/// ErrorMessage = {
///     1: uint,            // code
///     2: tstr,            // message
///     3: bstr / null,     // data
///     4: bool,            // fatal
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    pub code: u32,
    pub message: String,
    pub data: Option<Vec<u8>>,
    pub fatal: bool,
}

impl ProtocolError {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        let fatal = is_always_fatal(code);
        Self {
            code,
            message: message.into(),
            data: None,
            fatal,
        }
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        // RFC-0005 §9.3: data field MUST NOT exceed 4096 bytes
        if data.len() > 4096 {
            self.data = Some(data[..4096].to_vec());
        } else {
            self.data = Some(data);
        }
        self
    }

    pub fn with_fatal(mut self, fatal: bool) -> Self {
        // RFC-0005 §4.4: always-fatal codes are fatal regardless
        self.fatal = fatal || is_always_fatal(self.code);
        self
    }

    pub fn category(&self) -> ErrorCategory {
        ErrorCategory::from_code(self.code)
    }

    pub fn is_fatal(&self) -> bool {
        self.fatal
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

/// Internal error type for the AAFP core layer.
#[derive(Debug, Error)]
pub enum Error {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("dial error: {0}")]
    Dial(String),
    #[error("listen error: {0}")]
    Listen(String),
    #[error("not connected to peer")]
    NotConnected,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convert an internal error to a ProtocolError (RFC-0005 §8.3).
impl From<Error> for ProtocolError {
    fn from(err: Error) -> Self {
        match err {
            Error::Protocol(pe) => pe,
            Error::Io(_) => ProtocolError::new(codes::PROTOCOL_VIOLATION, "I/O error"),
            Error::ConnectionClosed => {
                ProtocolError::new(codes::CONNECTION_RESET, "connection closed")
            }
            Error::NotConnected => {
                ProtocolError::new(codes::TRANSPORT_UNREACHABLE, "not connected")
            }
            Error::Transport(s) | Error::Connection(s) | Error::Dial(s) | Error::Listen(s) => {
                ProtocolError::new(codes::CONNECTION_RESET, s)
            }
            Error::Stream(s) => ProtocolError::new(codes::STREAM_CLOSED, s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_from_code() {
        assert_eq!(ErrorCategory::from_code(0), ErrorCategory::Success);
        assert_eq!(ErrorCategory::from_code(1001), ErrorCategory::Transport);
        assert_eq!(ErrorCategory::from_code(2001), ErrorCategory::Authentication);
        assert_eq!(ErrorCategory::from_code(3001), ErrorCategory::Authorization);
        assert_eq!(ErrorCategory::from_code(4001), ErrorCategory::Discovery);
        assert_eq!(ErrorCategory::from_code(5001), ErrorCategory::Messaging);
        assert_eq!(ErrorCategory::from_code(6001), ErrorCategory::Capability);
        assert_eq!(ErrorCategory::from_code(8001), ErrorCategory::Protocol);
        assert_eq!(ErrorCategory::from_code(9001), ErrorCategory::Application);
    }

    #[test]
    fn test_auth_errors_always_fatal() {
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
            assert!(is_always_fatal(code), "code {code} should be always fatal");
        }
    }

    #[test]
    fn test_protocol_errors_always_fatal() {
        for code in [
            codes::UNKNOWN_CRITICAL_FRAME_TYPE,
            codes::UNKNOWN_CRITICAL_EXTENSION,
            codes::INVALID_VERSION,
            codes::PROTOCOL_VIOLATION,
        ] {
            assert!(is_always_fatal(code), "code {code} should be always fatal");
        }
    }

    #[test]
    fn test_non_fatal_codes() {
        assert!(!is_always_fatal(codes::FRAME_TOO_LARGE));
        assert!(!is_always_fatal(codes::STREAM_CLOSED));
        assert!(!is_always_fatal(codes::OK));
    }

    #[test]
    fn test_protocol_error_construction() {
        let pe = ProtocolError::new(codes::INVALID_SIGNATURE, "bad sig");
        assert_eq!(pe.code, codes::INVALID_SIGNATURE);
        assert!(pe.is_fatal()); // Auth errors are always fatal
        assert!(pe.data.is_none());
    }

    #[test]
    fn test_protocol_error_with_data() {
        let pe = ProtocolError::new(codes::PROTOCOL_VIOLATION, "bad frame")
            .with_data(vec![1, 2, 3]);
        assert_eq!(pe.data, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_data_truncated_to_4096() {
        let pe = ProtocolError::new(codes::PROTOCOL_VIOLATION, "big data")
            .with_data(vec![0u8; 5000]);
        assert_eq!(pe.data.as_ref().unwrap().len(), 4096);
    }

    #[test]
    fn test_with_fatal_override() {
        // Non-fatal code can be made fatal
        let pe = ProtocolError::new(codes::FRAME_TOO_LARGE, "too big").with_fatal(true);
        assert!(pe.is_fatal());

        // Always-fatal code cannot be made non-fatal
        let pe = ProtocolError::new(codes::INVALID_SIGNATURE, "bad sig").with_fatal(false);
        assert!(pe.is_fatal());
    }
}
