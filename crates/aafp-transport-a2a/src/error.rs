//! A2A error types and JSON-RPC error mapping.
//!
//! See RFC 0008 §"Error Mapping" for the full error code table.

use thiserror::Error;

/// A2A protocol error types (mapped to JSON-RPC error codes).
#[derive(Debug, Error)]
pub enum A2aError {
    #[error("Task not found: {task_id}")]
    TaskNotFound { task_id: String },

    #[error("Task not cancelable: {task_id}")]
    TaskNotCancelable { task_id: String },

    #[error("Push notifications not supported")]
    PushNotificationNotSupported,

    #[error("Unsupported operation: {operation}")]
    UnsupportedOperation { operation: String },

    #[error("Content type not supported: {content_type}")]
    ContentTypeNotSupported { content_type: String },

    #[error("Invalid agent response")]
    InvalidAgentResponse,

    #[error("Extended agent card not configured")]
    ExtendedAgentCardNotConfigured,

    #[error("Extension support required: {extension}")]
    ExtensionSupportRequired { extension: String },

    #[error("Version not supported: {version}")]
    VersionNotSupported { version: String },

    // JSON-RPC standard errors
    #[error("Parse error")]
    ParseError,

    #[error("Invalid request")]
    InvalidRequest,

    #[error("Method not found: {method}")]
    MethodNotFound { method: String },

    #[error("Invalid params")]
    InvalidParams,

    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl A2aError {
    /// Map to JSON-RPC 2.0 error code per RFC 0008 §"Error Mapping".
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            A2aError::TaskNotFound { .. } => -32001,
            A2aError::TaskNotCancelable { .. } => -32002,
            A2aError::PushNotificationNotSupported => -32003,
            A2aError::UnsupportedOperation { .. } => -32004,
            A2aError::ContentTypeNotSupported { .. } => -32005,
            A2aError::InvalidAgentResponse => -32006,
            A2aError::ExtendedAgentCardNotConfigured => -32007,
            A2aError::ExtensionSupportRequired { .. } => -32008,
            A2aError::VersionNotSupported { .. } => -32009,
            A2aError::ParseError => -32700,
            A2aError::InvalidRequest => -32600,
            A2aError::MethodNotFound { .. } => -32601,
            A2aError::InvalidParams => -32602,
            A2aError::Internal { .. } => -32603,
        }
    }

    /// Convert to a JSON-RPC error response object.
    pub fn to_jsonrpc_error(&self, id: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": self.jsonrpc_code(),
                "message": self.to_string(),
            }
        })
    }
}

/// Error type for the AAFP A2A transport.
#[derive(Debug, Error)]
pub enum AafpA2aError {
    #[error("AAFP SDK error: {0}")]
    Sdk(#[from] aafp_sdk::SdkError),

    #[error("AAFP frame error: {0}")]
    Framing(String),

    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("QUIC I/O error: {0}")]
    Io(#[from] aafp_core::Error),

    #[error("Transport is closed")]
    Closed,

    #[error("Session state error: {0}")]
    Session(String),

    #[error("A2A protocol error: {0}")]
    A2a(#[from] A2aError),
}

impl From<aafp_messaging::FrameError> for AafpA2aError {
    fn from(e: aafp_messaging::FrameError) -> Self {
        AafpA2aError::Framing(e.to_string())
    }
}
