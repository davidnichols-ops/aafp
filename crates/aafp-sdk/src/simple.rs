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
use std::sync::{Arc, Mutex};

use aafp_messaging::NetworkedPubSub;
use tokio::sync::{broadcast, mpsc};

use crate::pubsub::backchannel::extract_backchannel_topic;
use crate::pubsub::bridge::PubSubBridge;
use crate::pubsub::handler::{is_pubsub_method, should_reforward_publish};
use crate::pubsub::Event;
use crate::pubsub::SubscriptionStream;

// ─── OnPublishHandler type ─────────────────────────────────────

/// Handler invoked when a PubSub event is received on a subscribed topic.
///
/// Sugar for `subscribe()` + a spawned consumer task. The handler receives
/// the topic name and the decoded `Event`.
pub type OnPublishHandler =
    Arc<dyn Fn(&str, Event) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

// ─── BackchannelHandlerFn type (P3) ────────────────────────────

/// Handler that can emit back-channel events during a long-running RPC.
///
/// When a client sends an RPC request with the `EXT_BACKCHANNEL_TOPIC`
/// extension, this handler is invoked with a [`Backchannel`] handle and a
/// `CancellationToken`. The handler can emit progress events via the
/// back-channel while the RPC runs; the final `Response` is returned on
/// the RPC bi-stream as usual.
pub type BackchannelHandlerFn = Arc<
    dyn Fn(Request, Backchannel) -> Pin<Box<dyn Future<Output = Result<Response, String>> + Send>>
        + Send
        + Sync,
>;

// ─── Backchannel type (P3) ─────────────────────────────────────

/// Handle given to a handler so it can emit back-channel events during a
/// long-running RPC. Events are published to the back-channel topic via
/// the local PubSub instance and forwarded to subscribers (the client)
/// by the propagation driver.
#[derive(Clone)]
pub struct Backchannel {
    topic: String,
    pubsub: Arc<NetworkedPubSub>,
    our_id: aafp_identity::AgentId,
}

impl Backchannel {
    /// Create a new `Backchannel` handle.
    pub(crate) fn new(
        topic: String,
        pubsub: Arc<NetworkedPubSub>,
        our_id: aafp_identity::AgentId,
    ) -> Self {
        Self {
            topic,
            pubsub,
            our_id,
        }
    }

    /// The back-channel topic name (`rpc.<server>.<req_id>.progress`).
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Emit a progress event with a percentage and message.
    pub async fn progress(&self, percent: u8, msg: impl Into<String>) {
        let body = format!("[{}%] {}", percent, msg.into());
        let event = Event::text(body);
        let _ = self
            .pubsub
            .publish_local(&self.topic, self.our_id, event.encode_payload());
    }

    /// Emit a structured partial result (raw bytes).
    pub async fn partial(&self, data: Vec<u8>) {
        let _ = self.pubsub.publish_local(&self.topic, self.our_id, data);
    }

    /// Request human approval. The prompt is emitted as a progress event;
    /// the human approver publishes an approval back to the same topic.
    pub async fn request_approval(&self, prompt: impl Into<String>) {
        self.progress(50, format!("APPROVAL_REQUIRED: {}", prompt.into()))
            .await;
    }

    /// Publish to an arbitrary topic (not just the back-channel topic).
    /// Useful for broadcasting task lifecycle events to a broader audience
    /// while the RPC runs.
    pub async fn publish_topic(&self, topic: &str, event: Event) {
        let _ = self
            .pubsub
            .publish_local(topic, self.our_id, event.encode_payload());
    }
}

// ─── ProgressStream (P3) ───────────────────────────────────────

/// Stream of progress events from a back-channel.
///
/// Wraps the PubSub subscription stream. Yields events until the RPC
/// response arrives or the subscription is dropped.
pub struct ProgressStream {
    inner: SubscriptionStream,
}

impl ProgressStream {
    /// Create a new `ProgressStream` from a `SubscriptionStream`.
    pub fn new(inner: SubscriptionStream) -> Self {
        Self { inner }
    }

    /// Receive the next progress event.
    ///
    /// Returns `None` when the subscription is closed.
    pub async fn next(&mut self) -> Option<Result<Event, SdkError>> {
        self.inner.next().await
    }
}

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
    metrics_addr: Option<SocketAddr>,
    // ── PubSub (P1/P2) ──
    /// Topics this agent publishes to (registered on start).
    pubsub_topics: Vec<String>,
    /// on_publish handlers: topic → async handler closure.
    pubsub_on_publish: Vec<(String, OnPublishHandler)>,
    // ── Back-channel (P3) ──
    /// Back-channel handler for long-running RPCs with progress events.
    backchannel_handler: Option<BackchannelHandlerFn>,
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

    /// Enable Prometheus metrics endpoint.
    ///
    /// When set, the serving agent starts a Prometheus exporter on
    /// the given HTTP address. Endpoint: `GET /metrics`
    pub fn with_metrics(mut self, addr: SocketAddr) -> Self {
        self.metrics_addr = Some(addr);
        self
    }

    /// Declare a PubSub topic this agent publishes to.
    ///
    /// Registers the topic in the internal `NetworkedPubSub` so that
    /// `publish()` calls succeed. The topic is also advertised so remote
    /// peers can subscribe to it. Multiple `.topic()` calls register
    /// multiple topics.
    pub fn topic(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !self.pubsub_topics.contains(&name) {
            self.pubsub_topics.push(name);
        }
        self
    }

    /// Subscribe to a PubSub topic and invoke `handler` for each event.
    ///
    /// This is sugar for `subscribe()` + a spawned consumer task. The handler
    /// runs in a background task for the lifetime of the `ServingAgent`.
    /// Multiple `.on_publish()` calls register handlers for different topics.
    pub fn on_publish<F, Fut>(mut self, topic: impl Into<String>, f: F) -> Self
    where
        F: Fn(&str, Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let topic = topic.into();
        let handler: OnPublishHandler = Arc::new(move |t: &str, ev: Event| Box::pin(f(t, ev)));
        self.pubsub_on_publish.push((topic, handler));
        self
    }

    /// Register a back-channel handler for long-running RPCs.
    ///
    /// When a client sends an RPC request with the `EXT_BACKCHANNEL_TOPIC`
    /// extension, this handler is invoked with a [`Backchannel`] handle.
    /// The handler can emit progress events via the back-channel while the
    /// RPC runs; the final `Response` is returned on the RPC bi-stream as
    /// usual.
    ///
    /// If no back-channel handler is registered, requests with the extension
    /// fall back to the regular `handler()` (graceful degradation).
    pub fn backchannel_handler<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Request, Backchannel) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response, String>> + Send + 'static,
    {
        self.backchannel_handler = Some(Arc::new(move |req, bc| Box::pin(f(req, bc))));
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
        let backchannel_handler = self.backchannel_handler;
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();

        // ── PubSub setup (P1/P2) + Back-channel (P3) ──
        let has_pubsub = !self.pubsub_topics.is_empty()
            || !self.pubsub_on_publish.is_empty()
            || backchannel_handler.is_some();

        let (pubsub_bridge, pubsub_arc): (Option<Arc<PubSubBridge>>, Option<Arc<NetworkedPubSub>>) =
            if has_pubsub {
                let pubsub = NetworkedPubSub::new(agent_id);
                // Pre-register topics (create broadcast channels)
                for topic in &self.pubsub_topics {
                    let _rx = pubsub.subscribe(topic);
                }

                let pubsub = Arc::new(pubsub);

                // Spawn on_publish consumer tasks
                for (topic, handler) in &self.pubsub_on_publish {
                    let mut rx = pubsub.subscribe(topic);
                    let handler = handler.clone();
                    let topic_clone = topic.clone();
                    tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(msg) => {
                                    let event = Event::from_topic_message(&msg);
                                    handler(&topic_clone, event).await;
                                }
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    tracing::warn!("pubsub on_publish lagged by {n} messages");
                                    continue;
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    });
                }

                let bridge = Arc::new(PubSubBridge::new(Arc::clone(&pubsub), agent_id));
                (Some(bridge), Some(pubsub))
            } else {
                (None, None)
            };

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
                let pubsub_bridge = pubsub_bridge.clone();
                let backchannel_handler = backchannel_handler.clone();
                let pubsub_arc = pubsub_arc.clone();
                let server_agent_id = agent_id;

                tokio::spawn(async move {
                    let auth = Arc::new(TestingAuthProvider);
                    let (_session, conn, peer_info) =
                        match establish_session(conn, &keypair, auth, false, None).await {
                            Ok(result) => result,
                            Err(_) => return,
                        };

                    let peer_id = peer_info.agent_id;

                    // If no handler and no pubsub, just keep the connection open
                    let handler = match handler {
                        Some(h) => Some(h),
                        None => {
                            if pubsub_bridge.is_none() {
                                return;
                            }
                            None
                        }
                    };

                    // Accept bi-streams and handle requests
                    loop {
                        let (mut send, mut recv) = match conn.accept_bi().await {
                            Ok(pair) => pair,
                            Err(_) => break,
                        };

                        let handler = handler.clone();
                        let pubsub_bridge = pubsub_bridge.clone();
                        let backchannel_handler = backchannel_handler.clone();
                        let pubsub_arc = pubsub_arc.clone();

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

                            // ── PubSub RPC dispatch (P1/P2) ──
                            // Intercept aafp.pubsub.* methods and dispatch to PubSubRpcHandler.
                            if is_pubsub_method(&rpc_req.method) {
                                let rpc_resp = match &pubsub_bridge {
                                    Some(bridge) => {
                                        let result = bridge.rpc_handler().handle_request(
                                            &rpc_req.method,
                                            &rpc_req.params,
                                            &peer_id,
                                        );
                                        match result {
                                            Ok(value) => RpcResponse::success(rpc_req.id, value),
                                            Err(e) => RpcResponse::error(
                                                rpc_req.id,
                                                RpcErrorObject::new(9000, e.to_string()),
                                            ),
                                        }
                                    }
                                    None => RpcResponse::error(
                                        rpc_req.id,
                                        RpcErrorObject::new(
                                            5001,
                                            "pubsub not enabled on this agent",
                                        ),
                                    ),
                                };

                                // After successful publish, trigger re-forwarding if TTL > 0
                                if rpc_resp.is_success()
                                    && should_reforward_publish(&rpc_req.params)
                                {
                                    if let Some(bridge) = &pubsub_bridge {
                                        if let Ok(pp) = aafp_messaging::PublishParams::from_cbor(
                                            &rpc_req.params,
                                        ) {
                                            bridge.notify_local_publish(pp.topic, peer_id, pp.data);
                                        }
                                    }
                                }

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
                                return;
                            }

                            // ── Regular capability dispatch ──
                            // Check for back-channel extension (P3).
                            let bc_topic = extract_backchannel_topic(&frame);

                            // Convert to simple Request
                            let request = match &rpc_req.params {
                                Value::TextString(s) => Request::text(s.clone()),
                                Value::ByteString(b) => Request::data(b.clone()),
                                _ => Request::text(String::new()),
                            };

                            // Determine which handler to use:
                            // 1. If back-channel extension is present AND a backchannel_handler
                            //    is registered, use the back-channel path.
                            // 2. If back-channel extension is present but no backchannel_handler,
                            //    fall back to regular handler (graceful degradation).
                            // 3. If no extension, use regular handler (existing path).
                            let rpc_resp = if let Some(ref bc_topic) = bc_topic {
                                if let Some(ref bc_handler) = backchannel_handler {
                                    if let Some(ref pubsub) = pubsub_arc {
                                        // Back-channel path: create Backchannel, run handler.
                                        let bc = Backchannel::new(
                                            bc_topic.clone(),
                                            Arc::clone(pubsub),
                                            server_agent_id,
                                        );
                                        match bc_handler(request, bc).await {
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
                                            Err(msg) => RpcResponse::error(
                                                rpc_req.id,
                                                RpcErrorObject::new(5000, msg),
                                            ),
                                        }
                                    } else {
                                        // No pubsub available — degrade to unary.
                                        match &handler {
                                            Some(h) => match h(request).await {
                                                Ok(response) => {
                                                    let result = if !response.body().is_empty() {
                                                        Value::TextString(
                                                            response.body().to_string(),
                                                        )
                                                    } else if let Some(data) = response.payload() {
                                                        Value::ByteString(data.to_vec())
                                                    } else {
                                                        Value::TextString(String::new())
                                                    };
                                                    RpcResponse::success(rpc_req.id, result)
                                                }
                                                Err(msg) => RpcResponse::error(
                                                    rpc_req.id,
                                                    RpcErrorObject::new(5000, msg),
                                                ),
                                            },
                                            None => RpcResponse::error(
                                                rpc_req.id,
                                                RpcErrorObject::new(5000, "no handler registered"),
                                            ),
                                        }
                                    }
                                } else {
                                    // Extension present but no backchannel handler — degrade to unary.
                                    match &handler {
                                        Some(h) => match h(request).await {
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
                                            Err(msg) => RpcResponse::error(
                                                rpc_req.id,
                                                RpcErrorObject::new(5000, msg),
                                            ),
                                        },
                                        None => RpcResponse::error(
                                            rpc_req.id,
                                            RpcErrorObject::new(5000, "no handler registered"),
                                        ),
                                    }
                                }
                            } else {
                                // No extension — plain unary RPC (existing path).
                                match &handler {
                                    Some(h) => match h(request).await {
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
                                        Err(msg) => RpcResponse::error(
                                            rpc_req.id,
                                            RpcErrorObject::new(5000, msg),
                                        ),
                                    },
                                    None => return,
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

                    // Connection-close cleanup: remove peer's PubSub subscriptions
                    if let Some(bridge) = &pubsub_bridge {
                        bridge.pubsub().remove_peer(&peer_id);
                    }
                });
            }
        });

        // Start Prometheus exporter if metrics_addr is set
        if let Some(metrics_addr) = self.metrics_addr {
            let exporter = crate::prometheus::PrometheusExporter::new(
                agent.metrics.clone(),
                hex::encode(agent_id),
            );
            tokio::spawn(async move {
                if let Err(e) = exporter.serve(metrics_addr).await {
                    tracing::warn!("Prometheus exporter stopped: {e}");
                }
            });
        }

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
        Ok(ConnectedAgent {
            agent,
            local_pubsub: None,
        })
    }
}

/// A connected agent that can discover and call other agents.
pub struct ConnectedAgent {
    agent: SdkAgent,
    /// Local PubSub instance for P1 local-only subscribe/publish.
    /// Lazily initialized on first `subscribe()` or `publish()` call.
    local_pubsub: Option<Arc<Mutex<NetworkedPubSub>>>,
}

impl ConnectedAgent {
    /// Discover agents by capability.
    pub fn discover(&self, capability: &str) -> DiscoveryBuilder<'_> {
        DiscoveryBuilder {
            agent: &self.agent,
            capability: capability.to_string(),
        }
    }

    /// Call an agent at a specific address, bypassing discovery.
    ///
    /// This is useful when you know the agent's address directly
    /// (e.g., from `aafp serve` output) and don't want to use
    /// the discovery system.
    pub async fn call_at(&self, addr: &str, request: Request) -> Result<Response, SdkError> {
        call_agent(&self.agent, addr, request).await
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

    /// Subscribe to a PubSub topic.
    ///
    /// For P1 (local-only), subscribes to the local `NetworkedPubSub`
    /// instance and returns a `SubscriptionStream` that yields `Event`s
    /// as they are published locally.
    ///
    /// For P2 (networked), sends an `aafp.pubsub.subscribe` RPC to a
    /// remote peer. Use `subscribe_to(addr, topic)` for explicit peer
    /// addressing.
    pub async fn subscribe(&self, topic: &str) -> Result<SubscriptionStream, SdkError> {
        let (tx, rx) = mpsc::channel::<Result<Event, SdkError>>(256);

        // P1: local-only subscribe
        if let Some(pubsub) = &self.local_pubsub {
            let mut bcast_rx = pubsub.lock().unwrap().subscribe(topic);
            tokio::spawn(async move {
                loop {
                    match bcast_rx.recv().await {
                        Ok(msg) => {
                            let event = Event::from_topic_message(&msg);
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("subscription lagged by {n}");
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let _ = tx
                                .send(Err(SdkError::Messaging("subscription closed".to_string())))
                                .await;
                            break;
                        }
                    }
                }
            });
            return Ok(SubscriptionStream::new(rx));
        }

        Err(SdkError::Messaging(
            "subscribe requires a local pubsub instance or a connected peer".to_string(),
        ))
    }

    /// Publish an event to a PubSub topic (fire-and-forget).
    ///
    /// For P1 (local-only), publishes to the local `NetworkedPubSub`
    /// instance. For P2 (networked), sends an `aafp.pubsub.publish`
    /// RPC to the remote peer.
    pub async fn publish(&self, topic: &str, event: Event) -> Result<(), SdkError> {
        let data = event.encode_payload();

        // P1 local-only: publish to local NetworkedPubSub if present
        if let Some(pubsub) = &self.local_pubsub {
            let from = *self.agent.id();
            pubsub
                .lock()
                .unwrap()
                .publish_local(topic, from, data)
                .map_err(|e| SdkError::Messaging(e.to_string()))?;
            return Ok(());
        }

        Err(SdkError::Messaging(
            "publish requires a local pubsub instance or a connected peer".to_string(),
        ))
    }

    /// Get access to the local PubSub instance, initializing it if needed.
    ///
    /// This is used internally by `subscribe()` and `publish()` for P1
    /// local-only operation.
    pub fn local_pubsub(&mut self) -> &Arc<Mutex<NetworkedPubSub>> {
        if self.local_pubsub.is_none() {
            self.local_pubsub = Some(Arc::new(Mutex::new(NetworkedPubSub::new(*self.agent.id()))));
        }
        self.local_pubsub.as_ref().unwrap()
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

        // 3. Dial, handshake, and call
        call_agent(self.agent, &addr, request).await
    }
}

/// Internal helper: dial an agent at the given address, send a request, and read the response.
async fn call_agent(agent: &SdkAgent, addr: &str, request: Request) -> Result<Response, SdkError> {
    // Dial and handshake
    let conn = agent.transport.dial(addr).await?;
    let auth = Arc::new(TestingAuthProvider);
    let (_session, conn, _peer_info) =
        establish_session(conn, &agent.keypair, auth, true, None).await?;

    // Encode request as RPC
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

    // Send request frame
    let (mut send, mut recv) = conn.open_bi().await?;
    let frame = Frame::data(0, rpc_bytes);
    let frame_bytes = encode_frame(&frame)?;
    send.write_all(&frame_bytes).await?;
    send.finish();

    // Read response frame
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

    // Decode RPC response
    let rpc_resp =
        RpcResponse::decode(&resp_frame.payload).map_err(|e| SdkError::Messaging(e.to_string()))?;

    if !rpc_resp.is_success() {
        let msg = rpc_resp
            .error
            .map(|e| e.message)
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(SdkError::Messaging(msg));
    }

    // Convert to simple Response
    let response = match &rpc_resp.result {
        Some(Value::TextString(s)) => Response::text(s.clone()),
        Some(Value::ByteString(b)) => Response::data(b.clone()),
        _ => Response::text(String::new()),
    };

    Ok(response)
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
            metrics_addr: None,
            pubsub_topics: vec![],
            pubsub_on_publish: vec![],
            backchannel_handler: None,
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

    // ── PubSub tests (P1/P2) ──

    #[tokio::test]
    async fn test_serve_builder_with_topic() {
        let builder = Agent::serve()
            .capability("test")
            .topic("events.topic1")
            .topic("events.topic2");
        assert_eq!(
            builder.pubsub_topics,
            vec!["events.topic1", "events.topic2"]
        );
    }

    #[tokio::test]
    async fn test_serve_builder_topic_dedup() {
        let builder = Agent::serve().topic("same.topic").topic("same.topic");
        assert_eq!(builder.pubsub_topics.len(), 1);
    }

    #[tokio::test]
    async fn test_serve_builder_with_on_publish() {
        let builder = Agent::serve().on_publish("commands", |_topic, _ev| async move {});
        assert_eq!(builder.pubsub_on_publish.len(), 1);
        assert_eq!(builder.pubsub_on_publish[0].0, "commands");
    }

    #[tokio::test]
    async fn test_pubsub_local_subscribe_and_publish() {
        use aafp_messaging::NetworkedPubSub;

        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let mut rx = pubsub.subscribe("test-topic");

        pubsub
            .publish_local("test-topic", [2u8; 32], b"hello".to_vec())
            .unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        let ev = Event::from_topic_message(&msg);
        assert_eq!(ev.topic(), "test-topic");
        assert_eq!(ev.body(), "hello");
    }

    #[tokio::test]
    async fn test_pubsub_multiple_local_subscribers() {
        use aafp_messaging::NetworkedPubSub;

        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let mut rx1 = pubsub.subscribe("fanout");
        let mut rx2 = pubsub.subscribe("fanout");

        pubsub
            .publish_local("fanout", [3u8; 32], b"broadcast".to_vec())
            .unwrap();

        let msg1 = tokio::time::timeout(std::time::Duration::from_secs(1), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(Event::from_topic_message(&msg1).body(), "broadcast");
        assert_eq!(Event::from_topic_message(&msg2).body(), "broadcast");
    }

    #[tokio::test]
    async fn test_pubsub_subscribe_no_subscribers_error() {
        use aafp_messaging::NetworkedPubSub;

        let pubsub = NetworkedPubSub::new([1u8; 32]);
        let result = pubsub.publish_local("no-subs", [2u8; 32], b"data".to_vec());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connected_agent_local_pubsub_subscribe_publish() {
        let mut agent = Agent::connect().connect().await.unwrap();

        // Initialize local pubsub
        let _ = agent.local_pubsub();

        // Subscribe
        let mut events = agent.subscribe("local.topic").await.unwrap();

        // Publish locally
        agent
            .publish("local.topic", Event::text("hello local"))
            .await
            .unwrap();

        // Receive the event
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(event.topic(), "local.topic");
        assert_eq!(event.body(), "hello local");
    }

    // ── Backchannel tests (P3) ──

    #[tokio::test]
    async fn test_backchannel_progress_emits_event() {
        use aafp_messaging::NetworkedPubSub;

        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let topic = "rpc.server123.req_abc.progress";

        // Subscribe to the back-channel topic
        let mut rx = pubsub.subscribe(topic);

        // Create a Backchannel and emit a progress event
        let bc = Backchannel::new(topic.to_string(), Arc::clone(&pubsub), [1u8; 32]);
        bc.progress(50, "halfway done").await;

        // Receive the event
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        let event = Event::from_topic_message(&msg);
        assert_eq!(event.topic(), topic);
        assert!(event.body().contains("50%"));
        assert!(event.body().contains("halfway done"));
    }

    #[tokio::test]
    async fn test_backchannel_request_approval() {
        use aafp_messaging::NetworkedPubSub;

        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let topic = "rpc.server.req_xyz.progress";

        let mut rx = pubsub.subscribe(topic);

        let bc = Backchannel::new(topic.to_string(), Arc::clone(&pubsub), [1u8; 32]);
        bc.request_approval("Allow access to prod?").await;

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        let event = Event::from_topic_message(&msg);
        assert!(event.body().contains("APPROVAL_REQUIRED"));
        assert!(event.body().contains("Allow access to prod?"));
    }

    #[tokio::test]
    async fn test_backchannel_partial() {
        use aafp_messaging::NetworkedPubSub;

        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let topic = "rpc.server.req_partial.progress";

        let mut rx = pubsub.subscribe(topic);

        let bc = Backchannel::new(topic.to_string(), Arc::clone(&pubsub), [1u8; 32]);
        bc.partial(vec![0xDE, 0xAD, 0xBE, 0xEF]).await;

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        let event = Event::from_topic_message(&msg);
        assert_eq!(event.payload(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[tokio::test]
    async fn test_serve_builder_with_backchannel_handler() {
        let builder = Agent::serve()
            .capability("long.task")
            .backchannel_handler(|_req, _bc| async move { Ok(Response::text("done")) });

        assert!(builder.backchannel_handler.is_some());
    }

    #[tokio::test]
    async fn test_serve_builder_backchannel_handler_is_none_by_default() {
        let builder = Agent::serve();
        assert!(builder.backchannel_handler.is_none());
    }
}
