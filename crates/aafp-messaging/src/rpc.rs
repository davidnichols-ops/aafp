//! RPC: request/response pattern with correlation IDs.
//!
//! Wire format (CBOR):
//! ```text
//! RpcRequest:  { id: u64, method: String, params: Vec<u8> }
//! RpcResponse: { id: u64, result: Option<Vec<u8>>, error: Option<String> }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{oneshot, Mutex};

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("rpc error: {0}")]
    Remote(String),
    #[error("timeout waiting for response")]
    Timeout,
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// An RPC request.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RpcRequest {
    pub id: u64,
    pub method: String,
    pub params: Vec<u8>,
}

/// An RPC response.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RpcResponse {
    pub id: u64,
    pub result: Option<Vec<u8>>,
    pub error: Option<String>,
}

impl RpcResponse {
    pub fn success(id: u64, result: Vec<u8>) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: u64, error: String) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// RPC server: registers handlers for methods.
pub struct RpcServer {
    handlers: HashMap<String, Box<dyn Fn(Vec<u8>) -> Result<Vec<u8>, String> + Send + Sync>>,
}

impl RpcServer {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a method.
    pub fn register<F>(&mut self, method: &str, handler: F)
    where
        F: Fn(Vec<u8>) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    {
        self.handlers.insert(method.to_string(), Box::new(handler));
    }

    /// Handle an incoming request.
    pub fn handle(&self, request: &RpcRequest) -> RpcResponse {
        match self.handlers.get(&request.method) {
            Some(handler) => match handler(request.params.clone()) {
                Ok(result) => RpcResponse::success(request.id, result),
                Err(e) => RpcResponse::error(request.id, e),
            },
            None => RpcResponse::error(
                request.id,
                RpcError::MethodNotFound(request.method.clone()).to_string(),
            ),
        }
    }

    /// List registered methods.
    pub fn methods(&self) -> Vec<&str> {
        self.handlers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for RpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// RPC client: sends requests and waits for responses.
pub struct RpcClient {
    next_id: u64,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<RpcResponse>>>>,
}

impl RpcClient {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new request and a channel to receive the response.
    pub async fn create_request(&mut self, method: &str, params: Vec<u8>) -> (RpcRequest, oneshot::Receiver<RpcResponse>) {
        let id = self.next_id;
        self.next_id += 1;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        (
            RpcRequest {
                id,
                method: method.to_string(),
                params,
            },
            rx,
        )
    }

    /// Handle an incoming response (dispatch to the waiting request).
    pub async fn handle_response(&self, response: RpcResponse) {
        if let Some(sender) = self.pending.lock().await.remove(&response.id) {
            let _ = sender.send(response);
        }
    }

    /// Get the number of pending requests.
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }
}

impl Default for RpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize an RPC request to CBOR bytes.
pub fn serialize_request(req: &RpcRequest) -> Result<Vec<u8>, RpcError> {
    let mut buf = Vec::new();
    ciborium::into_writer(req, &mut buf)
        .map_err(|e| RpcError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// Deserialize an RPC request from CBOR bytes.
pub fn deserialize_request(data: &[u8]) -> Result<RpcRequest, RpcError> {
    ciborium::from_reader(data).map_err(|e| RpcError::Serialization(e.to_string()))
}

/// Serialize an RPC response to CBOR bytes.
pub fn serialize_response(res: &RpcResponse) -> Result<Vec<u8>, RpcError> {
    let mut buf = Vec::new();
    ciborium::into_writer(res, &mut buf)
        .map_err(|e| RpcError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// Deserialize an RPC response from CBOR bytes.
pub fn deserialize_response(data: &[u8]) -> Result<RpcResponse, RpcError> {
    ciborium::from_reader(data).map_err(|e| RpcError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;
    use std::time::Duration;

    #[test]
    fn server_handles_request() {
        let mut server = RpcServer::new();
        server.register("echo", |params| Ok(params));
        let req = RpcRequest {
            id: 1,
            method: "echo".into(),
            params: b"hello".to_vec(),
        };
        let resp = server.handle(&req);
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), b"hello");
    }

    #[test]
    fn server_method_not_found() {
        let server = RpcServer::new();
        let req = RpcRequest {
            id: 1,
            method: "unknown".into(),
            params: vec![],
        };
        let resp = server.handle(&req);
        assert!(resp.error.is_some());
    }

    #[test]
    fn serialization_roundtrip() {
        let req = RpcRequest {
            id: 42,
            method: "test".into(),
            params: b"params".to_vec(),
        };
        let bytes = serialize_request(&req).unwrap();
        let decoded = deserialize_request(&bytes).unwrap();
        assert_eq!(decoded.id, req.id);
        assert_eq!(decoded.method, req.method);
        assert_eq!(decoded.params, req.params);
    }

    #[test]
    fn response_serialization() {
        let resp = RpcResponse::success(1, b"result".to_vec());
        let bytes = serialize_response(&resp).unwrap();
        let decoded = deserialize_response(&bytes).unwrap();
        assert_eq!(decoded.id, 1);
        assert_eq!(decoded.result, Some(b"result".to_vec()));
    }

    #[tokio::test]
    async fn client_request_response() {
        let mut client = RpcClient::new();
        let (req, rx) = client.create_request("echo", b"hello".to_vec()).await;
        assert_eq!(req.id, 1);

        // Simulate a response.
        let resp = RpcResponse::success(req.id, b"hello".to_vec());
        client.handle_response(resp).await;

        let result = timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();
        assert_eq!(result.result, Some(b"hello".to_vec()));
    }
}
