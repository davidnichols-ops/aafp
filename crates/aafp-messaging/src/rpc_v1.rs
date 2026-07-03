//! AAFP v1 RPC messaging (RFC-0002 §4.3-4.4).
//!
//! RPC structures use canonical CBOR with integer keys:
//!
//! ```cbor
//! RpcRequest = {
//!     1: uint,       // id: Correlation ID
//!     2: tstr,       // method: Method name
//!     3: any,        // params: Method parameters (null if none)
//! }
//!
//! RpcResponse = {
//!     1: uint,                    // id: Matches request ID
//!     2: any / null,              // result: Result data (null if error)
//!     3: { 1: uint, 2: tstr, 3: bstr / null } / null,  // error
//! }
//! ```

use aafp_cbor::{int_map, Value};

/// RPC request (RFC-0002 §4.3).
///
/// Per A-1 (Rev 6): `params` (key 3) MUST be exactly one canonical CBOR
/// item. It MUST be present. It MUST NOT be null, bytes-containing-CBOR,
/// JSON, or text. If a method has no parameters, use an empty map `{}`.
#[derive(Clone, Debug)]
pub struct RpcRequest {
    /// Correlation ID matching this request to its response.
    pub id: u64,
    /// The method name to invoke on the server.
    pub method: String,
    /// Method parameters as a canonical CBOR value.
    pub params: Value,
}

impl RpcRequest {
    /// Create a new RPC request with the given ID and method, defaulting to empty params.
    pub fn new(id: u64, method: impl Into<String>) -> Self {
        Self {
            id,
            method: method.into(),
            params: Value::IntMap(vec![]), // empty map = no params
        }
    }

    /// Set the params CBOR value on this request.
    pub fn with_params(mut self, params: Value) -> Self {
        self.params = params;
        self
    }

    /// Encode to canonical CBOR with integer keys.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.id)),
            (2, Value::TextString(self.method.clone())),
            (3, self.params.clone()),
        ])
    }

    /// Decode from a CBOR Value.
    ///
    /// Per A-1 (Rev 6): params (key 3) MUST be present and MUST be a
    /// canonical CBOR item. Null and missing are rejected.
    pub fn from_cbor(val: &Value) -> Result<Self, RpcError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let id = match get(1) {
            Some(Value::Unsigned(n)) => *n,
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "id",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("id")),
        };

        let method = match get(2) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "method",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("method")),
        };

        // A-1 (Rev 6): params MUST be present, MUST NOT be null
        let params = match get(3) {
            Some(Value::Null) => {
                return Err(RpcError::InvalidField {
                    field: "params",
                    message: "null is not valid; use an empty map for no params (A-1)".to_string(),
                })
            }
            Some(v) => v.clone(),
            None => return Err(RpcError::MissingField("params")),
        };

        Ok(Self { id, method, params })
    }

    /// Encode to bytes (for use as frame payload).
    pub fn encode(&self) -> Result<Vec<u8>, RpcError> {
        let cbor = self.to_cbor();
        aafp_cbor::encode(&cbor).map_err(RpcError::Cbor)
    }

    /// Decode from bytes (frame payload).
    pub fn decode(data: &[u8]) -> Result<Self, RpcError> {
        let (val, _) = aafp_cbor::decode(data).map_err(RpcError::Cbor)?;
        Self::from_cbor(&val)
    }
}

/// RPC error object (RFC-0002 §4.4, RFC-0005 §6).
/// Note: 2xxx and 8xxx errors MUST be sent as ERROR frames, not RPC errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcErrorObject {
    /// The error code (RFC-0005 §6).
    pub code: u32,
    /// Human-readable error message.
    pub message: String,
    /// Optional opaque error data.
    pub data: Option<Vec<u8>>,
}

impl RpcErrorObject {
    /// Create a new RPC error object with the given code and message.
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attach opaque error data to this error object.
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Encode the error object to a canonical CBOR value with integer keys.
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (1i64, Value::Unsigned(self.code as u64)),
            (2, Value::TextString(self.message.clone())),
        ];
        // A-2 (Rev 6): Omit data when absent (NOT null)
        if let Some(data) = &self.data {
            entries.push((3, Value::ByteString(data.clone())));
        }
        int_map(entries)
    }

    /// Decode an error object from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, RpcError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let code = match get(1) {
            Some(Value::Unsigned(n)) => *n as u32,
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "error.code",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("error.code")),
        };

        let message = match get(2) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "error.message",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("error.message")),
        };

        // A-2 (Rev 6): data must be omitted when absent, not null
        let data = match get(3) {
            Some(Value::ByteString(b)) => Some(b.clone()),
            None => None,
            Some(Value::Null) => {
                return Err(RpcError::InvalidField {
                    field: "error.data",
                    message: "null is not valid; field must be omitted when absent (A-2)"
                        .to_string(),
                })
            }
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "error.data",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
        };

        Ok(Self {
            code,
            message,
            data,
        })
    }
}

/// RPC response (RFC-0002 §4.4).
#[derive(Clone, Debug)]
pub struct RpcResponse {
    /// Correlation ID matching the original request.
    pub id: u64,
    /// The successful result value, if the call succeeded.
    pub result: Option<Value>,
    /// An error object, if the call failed.
    pub error: Option<RpcErrorObject>,
}

impl RpcResponse {
    /// Create a successful response with the given result value.
    pub fn success(id: u64, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response with the given error object.
    pub fn error(id: u64, error: RpcErrorObject) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Whether this response represents a successful call (no error).
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }

    /// Encode to canonical CBOR with integer keys.
    ///
    /// Per A-2 (Rev 6): optional fields (result, error) MUST be omitted
    /// when absent, NOT encoded as null. A success response omits key 3
    /// (error); an error response omits key 2 (result).
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![(1, Value::Unsigned(self.id))];
        // A-2: Omit result when absent (error response)
        if let Some(result) = &self.result {
            entries.push((2, result.clone()));
        }
        // A-2: Omit error when absent (success response)
        if let Some(error) = &self.error {
            entries.push((3, error.to_cbor()));
        }
        int_map(entries)
    }

    /// Decode from a CBOR Value.
    ///
    /// Per A-2 (Rev 6): result and error are omitted when absent, not null.
    pub fn from_cbor(val: &Value) -> Result<Self, RpcError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let id = match get(1) {
            Some(Value::Unsigned(n)) => *n,
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "id",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("id")),
        };

        // A-2: null is not valid; field must be omitted when absent
        let result = match get(2) {
            None => None,
            Some(Value::Null) => {
                return Err(RpcError::InvalidField {
                    field: "result",
                    message: "null is not valid; field must be omitted when absent (A-2)"
                        .to_string(),
                })
            }
            Some(other) => Some(other.clone()),
        };

        let error = match get(3) {
            None => None,
            Some(Value::Null) => {
                return Err(RpcError::InvalidField {
                    field: "error",
                    message: "null is not valid; field must be omitted when absent (A-2)"
                        .to_string(),
                })
            }
            Some(e_val) => Some(RpcErrorObject::from_cbor(e_val)?),
        };

        Ok(Self { id, result, error })
    }

    /// Encode to bytes (for use as frame payload).
    pub fn encode(&self) -> Result<Vec<u8>, RpcError> {
        let cbor = self.to_cbor();
        aafp_cbor::encode(&cbor).map_err(RpcError::Cbor)
    }

    /// Decode from bytes (frame payload).
    pub fn decode(data: &[u8]) -> Result<Self, RpcError> {
        let (val, _) = aafp_cbor::decode(data).map_err(RpcError::Cbor)?;
        Self::from_cbor(&val)
    }
}

/// Close message (RFC-0002 §4.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseMessage {
    /// The close code (RFC-0002 §6.6).
    pub code: u32,
    /// Human-readable close message.
    pub message: String,
}

impl CloseMessage {
    /// Create a new close message with the given code and message.
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Encode the close message to a canonical CBOR value with integer keys.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.code as u64)),
            (2, Value::TextString(self.message.clone())),
        ])
    }

    /// Decode a close message from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, RpcError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let code = match get(1) {
            Some(Value::Unsigned(n)) => *n as u32,
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "code",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("code")),
        };

        let message = match get(2) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "message",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("message")),
        };

        Ok(Self { code, message })
    }

    /// Encode the close message to CBOR bytes for use as a frame payload.
    pub fn encode(&self) -> Result<Vec<u8>, RpcError> {
        aafp_cbor::encode(&self.to_cbor()).map_err(RpcError::Cbor)
    }

    /// Decode a close message from CBOR bytes (frame payload).
    pub fn decode(data: &[u8]) -> Result<Self, RpcError> {
        let (val, _) = aafp_cbor::decode(data).map_err(RpcError::Cbor)?;
        Self::from_cbor(&val)
    }
}

/// Error message (RFC-0002 §4.6, RFC-0005 §4.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorMessage {
    /// The error code (RFC-0005 §4.1).
    pub code: u32,
    /// Human-readable error message.
    pub message: String,
    /// Optional opaque error data.
    pub data: Option<Vec<u8>>,
    /// Whether the error is fatal (connection must close).
    pub fatal: bool,
}

impl ErrorMessage {
    /// Create a new error message with the given code, message, and fatality.
    pub fn new(code: u32, message: impl Into<String>, fatal: bool) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
            fatal,
        }
    }

    /// Attach opaque error data to this error message.
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Encode the error message to a canonical CBOR value with integer keys.
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (1i64, Value::Unsigned(self.code as u64)),
            (2, Value::TextString(self.message.clone())),
        ];
        // A-2 (Rev 6): Omit data when absent (NOT null)
        if let Some(data) = &self.data {
            entries.push((3, Value::ByteString(data.clone())));
        }
        entries.push((4, Value::Bool(self.fatal)));
        int_map(entries)
    }

    /// Decode an error message from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, RpcError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let code = match get(1) {
            Some(Value::Unsigned(n)) => *n as u32,
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "code",
                    message: format!("expected uint, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("code")),
        };

        let message = match get(2) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "message",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(RpcError::MissingField("message")),
        };

        // A-2 (Rev 6): data must be omitted when absent, not null
        let data = match get(3) {
            Some(Value::ByteString(b)) => Some(b.clone()),
            None => None,
            Some(Value::Null) => {
                return Err(RpcError::InvalidField {
                    field: "data",
                    message: "null is not valid; field must be omitted when absent (A-2)"
                        .to_string(),
                })
            }
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "data",
                    message: format!("expected bstr, got {:?}", other),
                })
            }
        };

        let fatal = match get(4) {
            Some(Value::Bool(b)) => *b,
            Some(other) => {
                return Err(RpcError::InvalidField {
                    field: "fatal",
                    message: format!("expected bool, got {:?}", other),
                })
            }
            None => false,
        };

        Ok(Self {
            code,
            message,
            data,
            fatal,
        })
    }

    /// Encode the error message to CBOR bytes for use as a frame payload.
    pub fn encode(&self) -> Result<Vec<u8>, RpcError> {
        aafp_cbor::encode(&self.to_cbor()).map_err(RpcError::Cbor)
    }

    /// Decode an error message from CBOR bytes (frame payload).
    pub fn decode(data: &[u8]) -> Result<Self, RpcError> {
        let (val, _) = aafp_cbor::decode(data).map_err(RpcError::Cbor)?;
        Self::from_cbor(&val)
    }
}

/// RPC errors.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// A required CBOR field is missing from the message.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A CBOR field has an invalid type or value.
    #[error("invalid field '{field}': {message}")]
    InvalidField {
        /// The name of the invalid field.
        field: &'static str,
        /// A description of why the field is invalid.
        message: String,
    },
    /// A CBOR encoding or decoding error occurred.
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_request_roundtrip() {
        let req = RpcRequest::new(42, "aafp.discovery.lookup")
            .with_params(Value::TextString("inference".to_string()));

        let encoded = req.encode().unwrap();
        let decoded = RpcRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.method, "aafp.discovery.lookup");
        assert_eq!(decoded.params, Value::TextString("inference".to_string()));
    }

    #[test]
    fn test_rpc_request_empty_params() {
        // A-1 (Rev 6): params defaults to empty map, not null
        let req = RpcRequest::new(1, "aafp.ping");
        let encoded = req.encode().unwrap();
        let decoded = RpcRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.params, Value::IntMap(vec![]));
    }

    #[test]
    fn test_rpc_response_success() {
        let resp = RpcResponse::success(42, Value::Unsigned(100));
        assert!(resp.is_success());

        let encoded = resp.encode().unwrap();
        let decoded = RpcResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.id, 42);
        assert!(decoded.is_success());
        assert_eq!(decoded.result, Some(Value::Unsigned(100)));
        assert!(decoded.error.is_none());
    }

    #[test]
    fn test_rpc_response_error() {
        let err = RpcErrorObject::new(4005, "capability not found");
        let resp = RpcResponse::error(42, err);
        assert!(!resp.is_success());

        let encoded = resp.encode().unwrap();
        let decoded = RpcResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.id, 42);
        assert!(!decoded.is_success());
        assert!(decoded.result.is_none());
        assert!(decoded.error.is_some());
        assert_eq!(decoded.error.unwrap().code, 4005);
    }

    #[test]
    fn test_rpc_error_object_with_data() {
        let err = RpcErrorObject::new(5001, "malformed frame").with_data(vec![0xDE, 0xAD]);
        let cbor = err.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let err2 = RpcErrorObject::from_cbor(&decoded).unwrap();

        assert_eq!(err2.code, 5001);
        assert_eq!(err2.message, "malformed frame");
        assert_eq!(err2.data, Some(vec![0xDE, 0xAD]));
    }

    #[test]
    fn test_close_message_roundtrip() {
        let msg = CloseMessage::new(0, "goodbye");
        let encoded = msg.encode().unwrap();
        let decoded = CloseMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_error_message_roundtrip() {
        let msg = ErrorMessage::new(2001, "invalid signature", true).with_data(vec![0x01, 0x02]);
        let encoded = msg.encode().unwrap();
        let decoded = ErrorMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.code, 2001);
        assert_eq!(decoded.message, "invalid signature");
        assert_eq!(decoded.fatal, true);
        assert_eq!(decoded.data, Some(vec![0x01, 0x02]));
    }

    #[test]
    fn test_error_message_no_data() {
        let msg = ErrorMessage::new(8001, "frame too large", false);
        let encoded = msg.encode().unwrap();
        let decoded = ErrorMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.code, 8001);
        assert_eq!(decoded.fatal, false);
        assert_eq!(decoded.data, None);
    }

    #[test]
    fn test_rpc_request_uses_integer_keys() {
        let req = RpcRequest::new(1, "test");
        let cbor = req.to_cbor();
        // Keys should be 1, 2, 3 (integers, not strings)
        assert!(aafp_cbor::int_map_get(&cbor, 1).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 2).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 3).is_some());
    }

    #[test]
    fn test_rpc_response_uses_integer_keys() {
        // A-2 (Rev 6): success response has keys 1 (id) and 2 (result),
        // but NOT key 3 (error) since error is omitted when absent.
        let resp = RpcResponse::success(1, Value::IntMap(vec![]));
        let cbor = resp.to_cbor();
        assert!(aafp_cbor::int_map_get(&cbor, 1).is_some());
        assert!(aafp_cbor::int_map_get(&cbor, 2).is_some());
        assert!(
            aafp_cbor::int_map_get(&cbor, 3).is_none(),
            "error key must be omitted in success response (A-2)"
        );

        // Error response: has keys 1 (id) and 3 (error), but NOT key 2 (result)
        let err_resp = RpcResponse::error(2, RpcErrorObject::new(4005, "not found"));
        let err_cbor = err_resp.to_cbor();
        assert!(aafp_cbor::int_map_get(&err_cbor, 1).is_some());
        assert!(
            aafp_cbor::int_map_get(&err_cbor, 2).is_none(),
            "result key must be omitted in error response (A-2)"
        );
        assert!(aafp_cbor::int_map_get(&err_cbor, 3).is_some());
    }
}
