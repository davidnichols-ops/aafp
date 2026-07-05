//! High-level AAFP API — no protocol knowledge required.
//!
//! # Quick Start
//!
//! ## Serve an agent
//! ```no_run
//! use aafp_sdk::simple::{Agent, Request, Response};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! Agent::serve()
//!     .capability("echo")
//!     .handler(|req: Request| async move { Ok(Response::text(req.body())) })
//!     .start()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Call an agent
//! ```no_run
//! use aafp_sdk::simple::{Agent, Request};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let agent = Agent::connect().connect().await?;
//! let result = agent.discover("echo")
//!     .call(Request::text("hello"))
//!     .await?;
//! println!("{}", result.body());
//! # Ok(())
//! # }
//! ```

use crate::{establish_session, Agent as SdkAgent, AgentBuilder, SdkError};
use aafp_cbor::Value;
use aafp_core::TestingAuthProvider;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::AgentKeypair;
use aafp_messaging::rpc_v1::{RpcErrorObject, RpcRequest, RpcResponse};
use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

// ─── Request / Response ───────────────────────────────────────

/// A simple request from a caller to an agent.
#[derive(Debug, Clone)]
pub struct Request {
    text: String,
    data: Option<Vec<u8>>,
}

impl Request {
    /// Create a text request.
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            data: None,
        }
    }

    /// Create a binary data request.
    pub fn data(data: Vec<u8>) -> Self {
        Self {
            text: String::new(),
            data: Some(data),
        }
    }

    /// Get the text body of the request.
    pub fn body(&self) -> &str {
        &self.text
    }

    /// Get the binary payload, if any.
    pub fn payload(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }
}

/// A simple response from an agent to a caller.
#[derive(Debug, Clone)]
pub struct Response {
    text: String,
    data: Option<Vec<u8>>,
}

impl Response {
    /// Create a text response.
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            data: None,
        }
    }

    /// Create a binary data response.
    pub fn data(data: Vec<u8>) -> Self {
        Self {
            text: String::new(),
            data: Some(data),
        }
    }

    /// Get the text body of the response.
    pub fn body(&self) -> &str {
        &self.text
    }

    /// Get the binary payload, if any.
    pub fn payload(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }
}

// ─── Handler trait ────────────────────────────────────────────

/// Type alias for async handler functions.
pub type HandlerFn = Arc<
    dyn Fn(Request) -> Pin<Box<dyn Future<Output = Result<Response, String>> + Send>> + Send + Sync,
>;

// ─── ServeBuilder ─────────────────────────────────────────────

/// Builder for serving an agent. Hides all protocol complexity.
pub struct ServeBuilder {
    capabilities: Vec<String>,
    handler: Option<HandlerFn>,
    bind_addr: Option<SocketAddr>,
    keypair: Option<AgentKeypair>,
}

impl ServeBuilder {
    /// Add a capability this agent provides.
    pub fn capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Set the request handler.
    pub fn handler<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response, String>> + Send + 'static,
    {
        self.handler = Some(Arc::new(move |req| Box::pin(f(req))));
        self
    }

    /// Set the bind address (default: random port).
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Set the agent's keypair (default: auto-generated).
    pub fn with_keypair(mut self, kp: AgentKeypair) -> Self {
        self.keypair = Some(kp);
        self
    }

    /// Build and start the agent. Blocks until the agent is serving.
    pub async fn start(self) -> Result<ServingAgent, SdkError> {
        let mut builder = AgentBuilder::new().with_capabilities(self.capabilities.clone());

        if let Some(kp) = self.keypair {
            builder = builder.with_keypair(kp);
        }
        if let Some(addr) = self.bind_addr {
            builder = builder.bind(addr);
        }

        let agent = Arc::new(builder.build().await?);
        let addr = agent.multiaddr()?;
        let agent_id = *agent.id();

        let handler = self.handler;
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();

        let agent_clone = agent.clone();
        tokio::spawn(async move {
            loop {
                if !running_clone.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }

                let conn = match agent_clone.transport.accept().await {
                    Ok(conn) => conn,
                    Err(_) => continue,
                };

                let handler = handler.clone();
                let keypair = agent_clone.keypair.clone();

                tokio::spawn(async move {
                    let auth = Arc::new(TestingAuthProvider);
                    let (_session, conn, _peer_info) =
                        match establish_session(conn, &keypair, auth, false, None).await {
                            Ok(result) => result,
                            Err(_) => return,
                        };

                    // If no handler, just keep the connection open
                    let handler = match handler {
                        Some(h) => h,
                        None => return,
                    };

                    // Accept bi-streams and handle requests
                    loop {
                        let (mut send, mut recv) = match conn.accept_bi().await {
                            Ok(pair) => pair,
                            Err(_) => break,
                        };

                        let handler = handler.clone();

                        tokio::spawn(async move {
                            // Read request frame
                            let mut header = [0u8; FRAME_HEADER_SIZE];
                            if recv.read_exact(&mut header).await.is_err() {
                                return;
                            }

                            let payload_len =
                                u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
                            let ext_len =
                                u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
                            let body_len = payload_len + ext_len;

                            let mut body = vec![0u8; body_len];
                            if body_len > 0 && recv.read_exact(&mut body).await.is_err() {
                                return;
                            }

                            let mut full_frame = header.to_vec();
                            full_frame.extend_from_slice(&body);
                            let (frame, _) = match decode_frame(&full_frame) {
                                Ok(result) => result,
                                Err(_) => return,
                            };

                            // Decode RPC request
                            let rpc_req = match RpcRequest::decode(&frame.payload) {
                                Ok(req) => req,
                                Err(_) => return,
                            };

                            // Convert to simple Request
                            let request = match &rpc_req.params {
                                Value::TextString(s) => Request::text(s.clone()),
                                Value::ByteString(b) => Request::data(b.clone()),
                                _ => Request::text(String::new()),
                            };

                            // Call handler
                            let rpc_resp = match handler(request).await {
                                Ok(response) => {
                                    let result = if !response.body().is_empty() {
                                        Value::TextString(response.body().to_string())
                                    } else if let Some(data) = response.payload() {
                                        Value::ByteString(data.to_vec())
                                    } else {
                                        Value::TextString(String::new())
                                    };
                                    RpcResponse::success(rpc_req.id, result)
                                }
                                Err(msg) => {
                                    RpcResponse::error(rpc_req.id, RpcErrorObject::new(5000, msg))
                                }
                            };

                            // Encode and send response
                            let resp_bytes = match rpc_resp.encode() {
                                Ok(bytes) => bytes,
                                Err(_) => return,
                            };
                            let resp_frame = Frame::data(0, resp_bytes);
                            let resp_frame_bytes = match encode_frame(&resp_frame) {
                                Ok(bytes) => bytes,
                                Err(_) => return,
                            };
                            let _ = send.write_all(&resp_frame_bytes).await;
                            send.finish();
                        });
                    }
                });
            }
        });

        Ok(ServingAgent {
            agent,
            addr,
            agent_id,
            running,
        })
    }
}

/// A running agent that is serving requests.
pub struct ServingAgent {
    agent: Arc<SdkAgent>,
    addr: String,
    agent_id: aafp_identity::AgentId,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl ServingAgent {
    /// Get the agent's ID.
    pub fn id(&self) -> &aafp_identity::AgentId {
        &self.agent_id
    }

    /// Get the agent's multiaddr (e.g., "/ip4/127.0.0.1/udp/12345/quic-v1").
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Get the agent's record (for DHT registration).
    pub fn record(&self) -> &AgentRecord {
        &self.agent.record
    }

    /// Stop the serving agent.
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

// ─── ConnectBuilder ───────────────────────────────────────────

/// Builder for connecting to the AAFP network and calling agents.
pub struct ConnectBuilder {
    keypair: Option<AgentKeypair>,
    seeds: Vec<String>,
}

impl ConnectBuilder {
    /// Set the agent's keypair (default: auto-generated).
    pub fn with_keypair(mut self, kp: AgentKeypair) -> Self {
        self.keypair = Some(kp);
        self
    }

    /// Set seed nodes for bootstrap.
    pub fn with_seeds(mut self, seeds: Vec<String>) -> Self {
        self.seeds = seeds;
        self
    }

    /// Build the agent and connect to the network.
    pub async fn connect(self) -> Result<ConnectedAgent, SdkError> {
        let mut builder = AgentBuilder::new();
        if let Some(kp) = self.keypair {
            builder = builder.with_keypair(kp);
        }
        if !self.seeds.is_empty() {
            builder = builder.with_seeds(self.seeds);
        }
        let agent = builder.build().await?;
        Ok(ConnectedAgent { agent })
    }
}

/// A connected agent that can discover and call other agents.
pub struct ConnectedAgent {
    agent: SdkAgent,
}

impl ConnectedAgent {
    /// Discover agents by capability.
    pub fn discover(&self, capability: &str) -> DiscoveryBuilder<'_> {
        DiscoveryBuilder {
            agent: &self.agent,
            capability: capability.to_string(),
        }
    }

    /// Register a server's record in the local DHT (for discovery).
    pub fn register(&mut self, record: &AgentRecord) -> Result<(), SdkError> {
        self.agent
            .dht
            .put(record.clone())
            .map_err(|e| SdkError::Discovery(e.to_string()))
    }

    /// Get the agent's ID.
    pub fn id(&self) -> &aafp_identity::AgentId {
        self.agent.id()
    }
}

/// Builder for discovering and calling an agent.
pub struct DiscoveryBuilder<'a> {
    agent: &'a SdkAgent,
    capability: String,
}

impl<'a> DiscoveryBuilder<'a> {
    /// Discover an agent with the given capability and call it with a request.
    pub async fn call(&self, request: Request) -> Result<Response, SdkError> {
        // 1. Find agents with this capability
        let candidates = self.agent.find_by_capability(&self.capability);
        if candidates.is_empty() {
            return Err(SdkError::Discovery(format!(
                "no agents found for capability '{}'",
                self.capability
            )));
        }

        // 2. Get the first candidate's endpoint
        let peer = &candidates[0];
        let addr = peer
            .endpoints
            .first()
            .ok_or_else(|| SdkError::Discovery("agent has no endpoints".into()))?
            .clone();

        // 3. Dial and handshake
        let conn = self.agent.transport.dial(&addr).await?;
        let auth = Arc::new(TestingAuthProvider);
        let (_session, conn, _peer_info) =
            establish_session(conn, &self.agent.keypair, auth, true, None).await?;

        // 4. Encode request as RPC
        let params = if !request.body().is_empty() {
            Value::TextString(request.body().to_string())
        } else if let Some(data) = request.payload() {
            Value::ByteString(data.to_vec())
        } else {
            Value::TextString(String::new())
        };
        let rpc_req = RpcRequest::new(1, "call").with_params(params);
        let rpc_bytes = rpc_req
            .encode()
            .map_err(|e| SdkError::Messaging(e.to_string()))?;

        // 5. Send request frame
        let (mut send, mut recv) = conn.open_bi().await?;
        let frame = Frame::data(0, rpc_bytes);
        let frame_bytes = encode_frame(&frame)?;
        send.write_all(&frame_bytes).await?;
        send.finish();

        // 6. Read response frame
        let mut header = [0u8; FRAME_HEADER_SIZE];
        recv.read_exact(&mut header).await?;
        let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
        let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
        let body_len = payload_len + ext_len;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            recv.read_exact(&mut body).await?;
        }
        let mut full_frame = header.to_vec();
        full_frame.extend_from_slice(&body);
        let (resp_frame, _) = decode_frame(&full_frame)?;

        // 7. Decode RPC response
        let rpc_resp = RpcResponse::decode(&resp_frame.payload)
            .map_err(|e| SdkError::Messaging(e.to_string()))?;

        if !rpc_resp.is_success() {
            let msg = rpc_resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "unknown error".to_string());
            return Err(SdkError::Messaging(msg));
        }

        // 8. Convert to simple Response
        let response = match &rpc_resp.result {
            Some(Value::TextString(s)) => Response::text(s.clone()),
            Some(Value::ByteString(b)) => Response::data(b.clone()),
            _ => Response::text(String::new()),
        };

        Ok(response)
    }
}

// ─── Top-level Agent (entry point) ────────────────────────────

/// Top-level entry point for the simple API.
pub struct Agent;

impl Agent {
    /// Start serving an agent. Returns a ServeBuilder.
    pub fn serve() -> ServeBuilder {
        ServeBuilder {
            capabilities: vec![],
            handler: None,
            bind_addr: None,
            keypair: None,
        }
    }

    /// Connect to the AAFP network. Returns a ConnectBuilder.
    pub fn connect() -> ConnectBuilder {
        ConnectBuilder {
            keypair: None,
            seeds: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_text() {
        let req = Request::text("hello");
        assert_eq!(req.body(), "hello");
        assert_eq!(req.payload(), None);
    }

    #[test]
    fn test_request_data() {
        let req = Request::data(vec![1, 2, 3]);
        assert_eq!(req.payload(), Some(&[1u8, 2, 3][..]));
        assert_eq!(req.body(), "");
    }

    #[test]
    fn test_response_text() {
        let resp = Response::text("world");
        assert_eq!(resp.body(), "world");
        assert_eq!(resp.payload(), None);
    }

    #[test]
    fn test_response_data() {
        let resp = Response::data(vec![4, 5, 6]);
        assert_eq!(resp.payload(), Some(&[4u8, 5, 6][..]));
        assert_eq!(resp.body(), "");
    }

    #[tokio::test]
    async fn test_serve_builder_defaults() {
        let builder = Agent::serve();
        assert!(builder.capabilities.is_empty());
        assert!(builder.handler.is_none());
        assert!(builder.bind_addr.is_none());
        assert!(builder.keypair.is_none());
    }

    #[tokio::test]
    async fn test_connect_builder_defaults() {
        let builder = Agent::connect();
        assert!(builder.keypair.is_none());
        assert!(builder.seeds.is_empty());
    }

    #[tokio::test]
    async fn test_serve_builder_with_capabilities() {
        let builder = Agent::serve().capability("echo").capability("translate");
        assert_eq!(builder.capabilities, vec!["echo", "translate"]);
    }

    #[tokio::test]
    async fn test_connected_agent_id() {
        let agent = Agent::connect().connect().await.unwrap();
        let _id = agent.id();
    }
}
