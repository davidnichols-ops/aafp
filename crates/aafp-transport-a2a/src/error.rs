//! A2A error types and JSON-RPC error mapping.
//!
//! See RFC 0008 §"Error Mapping" for the full error code table.

use thiserror::Error;

/// A2A protocol error types (mapped to JSON-RPC error codes).
#[derive(Debug, Error)]
pub enum A2aError {
    /// The requested task does not exist.
    #[error("Task not found: {task_id}")]
    TaskNotFound {
        /// The ID of the task that was not found.
        task_id: String,
    },

    /// The task cannot be canceled in its current state.
    #[error("Task not cancelable: {task_id}")]
    TaskNotCancelable {
        /// The ID of the task that cannot be canceled.
        task_id: String,
    },

    /// The server does not support push notifications.
    #[error("Push notifications not supported")]
    PushNotificationNotSupported,

    /// The requested operation is not supported by the agent.
    #[error("Unsupported operation: {operation}")]
    UnsupportedOperation {
        /// The name of the unsupported operation.
        operation: String,
    },

    /// The requested content type is not supported.
    #[error("Content type not supported: {content_type}")]
    ContentTypeNotSupported {
        /// The unsupported content type identifier.
        content_type: String,
    },

    /// The agent returned an invalid response.
    #[error("Invalid agent response")]
    InvalidAgentResponse,

    /// The extended agent card is not configured on this server.
    #[error("Extended agent card not configured")]
    ExtendedAgentCardNotConfigured,

    /// A required extension is not supported by the receiver.
    #[error("Extension support required: {extension}")]
    ExtensionSupportRequired {
        /// The URI of the required extension.
        extension: String,
    },

    /// The requested protocol version is not supported.
    #[error("Version not supported: {version}")]
    VersionNotSupported {
        /// The unsupported version string.
        version: String,
    },

    // JSON-RPC standard errors
    /// JSON-RPC parse error (invalid JSON).
    #[error("Parse error")]
    ParseError,

    /// JSON-RPC invalid request error.
    #[error("Invalid request")]
    InvalidRequest,

    /// The requested JSON-RPC method does not exist.
    #[error("Method not found: {method}")]
    MethodNotFound {
        /// The name of the unknown method.
        method: String,
    },

    /// JSON-RPC invalid params error.
    #[error("Invalid params")]
    InvalidParams,

    /// JSON-RPC internal server error.
    #[error("Internal error: {message}")]
    Internal {
        /// A human-readable description of the internal error.
        message: String,
    },
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
    /// An error from the underlying AAFP SDK.
    #[error("AAFP SDK error: {0}")]
    Sdk(#[from] aafp_sdk::SdkError),

    /// An error in AAFP frame encoding or decoding.
    #[error("AAFP frame error: {0}")]
    Framing(String),

    /// A JSON serialization or deserialization error.
    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A QUIC I/O error from the underlying transport.
    #[error("QUIC I/O error: {0}")]
    Io(#[from] aafp_core::Error),

    /// The transport has been closed and can no longer be used.
    #[error("Transport is closed")]
    Closed,

    /// A session state error (e.g. invalid state transition).
    #[error("Session state error: {0}")]
    Session(String),

    /// An A2A protocol-level error.
    #[error("A2A protocol error: {0}")]
    A2a(#[from] A2aError),
}

impl From<aafp_messaging::FrameError> for AafpA2aError {
    fn from(e: aafp_messaging::FrameError) -> Self {
        AafpA2aError::Framing(e.to_string())
    }
}
