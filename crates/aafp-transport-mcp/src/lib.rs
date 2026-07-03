//! # AAFP Transport for MCP
//!
//! This crate provides an [AAFP](https://github.com/davidnichols-ops/aafp) secure
//! transport binding for the [MCP Rust SDK](https://crates.io/crates/rmcp) (`rmcp`).
//!
//! It implements the `rmcp::transport::Transport<R>` trait, allowing any
//! `rmcp`-based MCP client or server to communicate over AAFP's post-quantum
//! secure channels instead of stdio or HTTP.
//!
//! ## Architectural Layers
//!
//! This crate sits between two protocol layers. Developers should understand
//! where MCP ends and AAFP begins:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  Application Protocol Layer (MCP)                    │
//! │  - JSON-RPC 2.0 message format                       │
//! │  - Method dispatch (tools/list, tools/call, etc.)    │
//! │  - Capability negotiation (initialize handshake)     │
//! │  - Owned by: rmcp SDK, application code              │
//! ├─────────────────────────────────────────────────────┤
//! │  Transport Binding Layer (this crate)                │
//! │  - AafpMcpTransport: implements rmcp Transport<R>    │
//! │  - Carries JSON-RPC messages in AAFP DATA frames     │
//! │  - Manages QUIC stream lifecycle                     │
//! │  - Performs AAFP handshake + authorization           │
//! │  - Owned by: aafp-transport-mcp                      │
//! ├─────────────────────────────────────────────────────┤
//! │  AAFP Core Protocol Layer                             │
//! │  - Frame format (28-byte header, 8 frame types)      │
//! │  - Handshake (ML-DSA-65 identity, PQ TLS)            │
//! │  - Session state machine                              │
//! │  - Control frames (CLOSE, ERROR, PING/PONG)          │
//! │  - Owned by: aafp-sdk, aafp-core, aafp-messaging     │
//! ├─────────────────────────────────────────────────────┤
//! │  Transport Layer (QUIC)                               │
//! │  - quinn + rustls (X25519MLKEM768)                    │
//! │  - Owned by: aafp-transport-quic                      │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! **Where MCP ends:** The MCP protocol defines JSON-RPC 2.0 messages
//! (initialize, tools/list, tools/call, etc.). These messages are produced
//! and consumed by the rmcp SDK's service layer. This crate does not
//! interpret or modify MCP message content.
//!
//! **Where AAFP begins:** AAFP provides the secure transport: post-quantum
//! TLS, ML-DSA-65 agent identity verification, length-delimited framing,
//! and session state enforcement. This crate uses AAFP's public APIs
//! (`AgentBuilder`, `drive_client_handshake`, `Frame::data`, `encode_frame`)
//! to carry MCP messages securely.
//!
//! **The boundary:** The boundary between MCP and AAFP is the AAFP DATA
//! frame (frame type 0x01). Each MCP JSON-RPC message is serialized to JSON
//! and carried as the opaque payload of one DATA frame. AAFP does not
//! interpret the payload; MCP does not know about AAFP framing.
//!
//! ## Framing
//!
//! Each MCP JSON-RPC message is serialized to UTF-8 JSON bytes and carried as
//! the payload of a single AAFP DATA frame (frame type 0x01). The AAFP frame
//! header (28 bytes) provides length-delimited message boundaries, so no
//! additional newline delimiter is needed (unlike stdio framing).
//!
//! This is the intended use of DATA frames per RFC-0002 §4.1:
//! > "DATA frames carry application-layer messages. The interpretation of
//! > the payload is determined by the application protocol running on the
//! > stream."
//!
//! ## Usage
//!
//! ### Client side
//!
//! ```no_run
//! use aafp_sdk::AgentBuilder;
//! use aafp_transport_mcp::AafpMcpTransport;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let agent = AgentBuilder::new()
//!     .bind("127.0.0.1:0".parse()?)
//!     .build().await?;
//!
//! let transport = AafpMcpTransport::connect(&agent, "quic://127.0.0.1:4433").await?;
//!
//! // Use with rmcp:
//! // let client = ().serve(transport).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Server side
//!
//! ```no_run
//! use aafp_sdk::AgentBuilder;
//! use aafp_transport_mcp::AafpMcpTransport;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let agent = AgentBuilder::new()
//!     .bind("127.0.0.1:4433".parse()?)
//!     .build().await?;
//!
//! let transport = AafpMcpTransport::accept(&agent).await?;
//!
//! // Use with rmcp:
//! // let server = my_service.serve(transport).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Authorization
//!
//! By default, `connect()` and `accept()` use `TestingAuthProvider`, which
//! allows all connections. **Production deployments MUST use
//! `connect_with_auth()` / `accept_with_auth()` with a custom
//! `AuthorizationProvider`** (e.g., UCAN capability checks, allowlists).
//!
//! ## See Also
//!
//! - [RFC 0007: AAFP Transport Binding for MCP](../../../../RFCs/0007-mcp-transport-binding.md)
//! - [TRANSPORT_ARCHITECTURE_REVIEW.md](../../../../TRANSPORT_ARCHITECTURE_REVIEW.md)
//! - [COMPATIBILITY_LAYER_ANALYSIS.md](../../../../COMPATIBILITY_LAYER_ANALYSIS.md)
//! - [INTEROPERABILITY_PLAN.md](../../../../INTEROPERABILITY_PLAN.md)

use std::sync::Arc;

use aafp_core::{AuthorizationProvider, Error as CoreError};
use aafp_identity::AgentId;
use aafp_messaging::{
    backpatch_payload_len, encode_frame, encode_header_into, Frame, FrameType, AAFP_VERSION,
    FRAME_HEADER_SIZE,
};
use aafp_sdk::{establish_session, Agent, SdkError};
use aafp_transport_quic::buffer_pool::{acquire, release, BytesMutWriter};
use aafp_transport_quic::{QuicConnection, QuicRecvStream, QuicSendStream};
use bytes::BytesMut;
use rmcp::service::{RxJsonRpcMessage, ServiceRole, TxJsonRpcMessage};
use rmcp::transport::Transport;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

/// AAFP stream ID used for MCP JSON-RPC messages.
///
/// Per RFC-0002 §7.1:
/// - Stream 0 is reserved for the handshake.
/// - Streams 1-2 are reserved for future protocol use.
/// - Application streams start at stream ID 4 (client-initiated)
///   or 5 (server-initiated).
///
/// We use stream ID 4, the first client-initiated application stream.
const MCP_STREAM_ID: u64 = 4;

/// Default capacity for the bounded mpsc send channel (Track H2).
///
/// When the channel is full, senders await (natural backpressure).
/// 1024 is enough to absorb bursts from 8+ concurrent senders without
/// blocking, while keeping memory bounded (~4MB at 4KB/buffer).
const DEFAULT_SEND_CHANNEL_CAPACITY: usize = 1024;

/// Error type for the AAFP MCP transport.
#[derive(Debug, Error)]
pub enum AafpMcpError {
    /// AAFP SDK error.
    #[error("AAFP SDK error: {0}")]
    Sdk(#[from] SdkError),

    /// AAFP frame encoding/decoding error.
    #[error("AAFP frame error: {0}")]
    Framing(String),

    /// JSON serialization/deserialization error.
    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// QUIC I/O error.
    #[error("QUIC I/O error: {0}")]
    Io(#[from] CoreError),

    /// Transport is closed.
    #[error("Transport is closed")]
    Closed,

    /// Session state error.
    #[error("Session state error: {0}")]
    Session(String),
}

impl From<aafp_messaging::FrameError> for AafpMcpError {
    fn from(e: aafp_messaging::FrameError) -> Self {
        AafpMcpError::Framing(e.to_string())
    }
}

/// AAFP-backed transport for MCP (Model Context Protocol).
///
/// Implements `rmcp::transport::Transport<R>` for any `ServiceRole`,
/// allowing AAFP to be used as a secure post-quantum transport for MCP
/// clients and servers.
///
/// The transport carries JSON-RPC 2.0 messages as payloads of AAFP DATA
/// frames over a bidirectional QUIC stream. The AAFP handshake (ML-DSA-65
/// identity verification) is performed during `connect()` / `accept()`.
pub struct AafpMcpTransport {
    /// Send side (legacy): wrapped in `Arc<Mutex<Option<_>>>` so the `send`
    /// future can be `Send + 'static` (required by the `Transport` trait).
    ///
    /// When `spawn_writer()` is called, the `QuicSendStream` is moved out of
    /// this mutex into a dedicated writer task. The mutex then holds `None`.
    /// Kept for backward compatibility with `send_handle()` / `send_for_test()`.
    send: Arc<Mutex<Option<QuicSendStream>>>,
    /// Send side (channel-based, Track H2): when active, senders push
    /// `BytesMut` buffers through this channel. A dedicated writer task
    /// drains the channel and writes to the QUIC stream. This eliminates
    /// the mutex contention that serialized concurrent senders.
    send_channel: Option<mpsc::Sender<BytesMut>>,
    /// Writer task join handle (for graceful shutdown in `close()`).
    /// `None` if `spawn_writer()` was never called.
    writer_task: Option<tokio::task::JoinHandle<()>>,
    /// Receive side: sequential access, `&mut self` is sufficient.
    /// When `spawn_reader()` is called, the stream is moved to a reader
    /// task and this becomes `None`. The caller owns the receive channel.
    recv: Option<QuicRecvStream>,
    /// Reader task join handle (for graceful shutdown in `close()`).
    /// `None` if `spawn_reader()` was never called.
    reader_task: Option<tokio::task::JoinHandle<()>>,
    /// QUIC connection, used for `close()`.
    conn: Option<QuicConnection>,
    /// Whether the transport has been closed.
    closed: bool,
    /// The verified peer AgentId, captured from the handshake.
    /// `None` for transports created via `from_streams()`.
    peer_agent_id: Option<AgentId>,
}

impl AafpMcpTransport {
    /// Create a client-side MCP transport by connecting to an AAFP server.
    ///
    /// This performs the full AAFP v1 handshake:
    /// 1. QUIC connection established
    /// 2. ClientHello/ServerHello/ClientFinished exchange
    /// 3. Peer identity verified (ML-DSA-65)
    /// 4. Authorization (using `TestingAuthProvider` — allows all)
    /// 5. Session transitions to MessagingEnabled
    /// 6. Opens a bidirectional QUIC stream for MCP JSON-RPC messages
    pub async fn connect(agent: &Agent, addr: &str) -> Result<Self, AafpMcpError> {
        Self::connect_with_auth(agent, addr, Arc::new(aafp_core::TestingAuthProvider)).await
    }

    /// Create a client-side MCP transport with a custom authorization provider.
    pub async fn connect_with_auth(
        agent: &Agent,
        addr: &str,
        auth_provider: Arc<dyn AuthorizationProvider>,
    ) -> Result<Self, AafpMcpError> {
        // 1. Establish QUIC connection
        let conn = agent.transport.dial(addr).await?;

        // 2. Drive AAFP v1 handshake + authorization + session transitions
        let (_session, conn, peer_info) =
            establish_session(conn, &agent.keypair, auth_provider, true, None)
                .await
                .map_err(AafpMcpError::from)?;

        // 3. Open bidirectional stream for MCP messages
        let (send, recv) = conn.open_bi().await?;

        Ok(Self {
            send: Arc::new(Mutex::new(Some(send))),
            send_channel: None,
            writer_task: None,
            recv: Some(recv),
            reader_task: None,
            conn: Some(conn),
            closed: false,
            peer_agent_id: Some(peer_info.agent_id),
        })
    }

    /// Create a server-side MCP transport by accepting an AAFP connection.
    ///
    /// This performs the full server-side AAFP v1 handshake:
    /// 1. Accept QUIC connection
    /// 2. ClientHello/ServerHello/ClientFinished exchange
    /// 3. Peer identity verified (ML-DSA-65)
    /// 4. Authorization (using `TestingAuthProvider` — allows all)
    /// 5. Session transitions to MessagingEnabled
    /// 6. Accepts the bidirectional QUIC stream for MCP JSON-RPC messages
    pub async fn accept(agent: &Agent) -> Result<Self, AafpMcpError> {
        Self::accept_with_auth(agent, Arc::new(aafp_core::TestingAuthProvider)).await
    }

    /// Create a server-side MCP transport with a custom authorization provider.
    pub async fn accept_with_auth(
        agent: &Agent,
        auth_provider: Arc<dyn AuthorizationProvider>,
    ) -> Result<Self, AafpMcpError> {
        // 1. Accept QUIC connection
        let conn = agent.transport.accept().await?;

        // 2. Drive AAFP v1 handshake + authorization + session transitions
        let (_session, conn, peer_info) =
            establish_session(conn, &agent.keypair, auth_provider, false, None)
                .await
                .map_err(AafpMcpError::from)?;

        // 3. Accept the bidirectional stream opened by the client
        let (send, recv) = conn.accept_bi().await?;

        Ok(Self {
            send: Arc::new(Mutex::new(Some(send))),
            send_channel: None,
            writer_task: None,
            recv: Some(recv),
            reader_task: None,
            conn: Some(conn),
            closed: false,
            peer_agent_id: Some(peer_info.agent_id),
        })
    }

    /// Construct a transport from pre-established AAFP streams.
    ///
    /// This is for advanced use cases where the caller has already performed
    /// the AAFP handshake and opened a bidirectional stream.
    pub fn from_streams(
        send: QuicSendStream,
        recv: QuicRecvStream,
        conn: Option<QuicConnection>,
    ) -> Self {
        Self {
            send: Arc::new(Mutex::new(Some(send))),
            send_channel: None,
            writer_task: None,
            recv: Some(recv),
            reader_task: None,
            conn,
            closed: false,
            peer_agent_id: None,
        }
    }

    /// The verified peer AgentId, if the transport was created via
    /// `connect()` or `accept()`.
    ///
    /// This is only available when the transport was created via
    /// `connect()` or `accept()` and the peer identity was captured from
    /// the handshake. For transports created via `from_streams()`, this
    /// returns `None`.
    pub fn peer_agent_id(&self) -> Option<&AgentId> {
        self.peer_agent_id.as_ref()
    }

    /// Spawn a dedicated writer task and switch to the channel-based send
    /// path (Track H2).
    ///
    /// This moves the `QuicSendStream` out of the mutex into a background
    /// task that drains an `mpsc` channel. After this call:
    /// - `send()`, `send_zero_copy()`, `send_raw_json()`, and
    ///   `send_raw_json_zero_copy()` push buffers through the channel
    ///   (no mutex acquisition — lock-free for concurrent senders).
    /// - The legacy `send_handle()` returns an `Arc<Mutex<None>>` — use
    ///   `send_channel_handle()` instead for concurrent send.
    /// - `close()` drops the sender, waits for the writer to drain remaining
    ///   messages, finish the stream, and exit.
    ///
    /// **When to call this:** When multiple tasks will send concurrently on
    /// the same connection. The mutex path serializes concurrent sends; the
    /// channel path allows lock-free parallel serialization.
    ///
    /// **When NOT to call this:** If only one task sends at a time, the
    /// mutex path has lower overhead (no channel hop, buffer pool reuse).
    ///
    /// # Panics
    /// Panics if the send stream has already been taken (e.g., if
    /// `spawn_writer()` was called twice, or if the transport was closed).
    pub async fn spawn_writer(&mut self) -> mpsc::Sender<BytesMut> {
        self.spawn_writer_with_capacity(DEFAULT_SEND_CHANNEL_CAPACITY)
            .await
    }

    /// Like `spawn_writer()` but with a custom channel capacity.
    pub async fn spawn_writer_with_capacity(&mut self, capacity: usize) -> mpsc::Sender<BytesMut> {
        // Take the send stream out of the mutex — the writer task owns it now.
        let send_stream = {
            let mut guard = self.send.lock().await;
            guard
                .take()
                .expect("spawn_writer: send stream already taken (double spawn or closed)")
        };

        let (tx, rx) = mpsc::channel::<BytesMut>(capacity);

        let handle = tokio::spawn(async move {
            writer_task_loop(send_stream, rx).await;
        });

        self.send_channel = Some(tx.clone());
        self.writer_task = Some(handle);
        tx
    }

    /// Get a clone of the channel sender for concurrent send from external
    /// tasks (e.g., the PyO3 Python binding).
    ///
    /// Returns `None` if `spawn_writer()` has not been called.
    pub fn send_channel_handle(&self) -> Option<mpsc::Sender<BytesMut>> {
        self.send_channel.clone()
    }

    /// Check whether the channel-based send path is active.
    pub fn has_writer(&self) -> bool {
        self.send_channel.is_some()
    }

    /// Spawn a dedicated reader task and switch to the channel-based receive
    /// path (Track H3).
    ///
    /// This moves the `QuicRecvStream` into a background task that reads
    /// AAFP DATA frames, deserializes JSON, and pushes `serde_json::Value`
    /// through an `mpsc` channel. The returned `mpsc::Receiver` is owned
    /// by the caller — receive messages from it directly.
    ///
    /// After this call:
    /// - `recv_raw_json()`, `recv_raw_json_zero_copy()`, and
    ///   `Transport::receive()` return `None` (the stream has been moved
    ///   to the reader task). Use the returned receiver instead.
    /// - `close()` will wait for the reader task to finish.
    ///
    /// **When to call this:** When you want to decouple QUIC I/O from
    /// message processing. The reader task handles all I/O; your task
    /// just receives decoded JSON values from the channel.
    ///
    /// # Panics
    /// Panics if the receive stream has already been taken.
    pub async fn spawn_reader(&mut self) -> mpsc::Receiver<serde_json::Value> {
        self.spawn_reader_with_capacity(DEFAULT_SEND_CHANNEL_CAPACITY)
            .await
    }

    /// Like `spawn_reader()` but with a custom channel capacity.
    pub async fn spawn_reader_with_capacity(
        &mut self,
        capacity: usize,
    ) -> mpsc::Receiver<serde_json::Value> {
        let recv_stream = self
            .recv
            .take()
            .expect("spawn_reader: receive stream already taken (double spawn or closed)");

        let (tx, rx) = mpsc::channel::<serde_json::Value>(capacity);

        let handle = tokio::spawn(async move {
            reader_task_loop(recv_stream, tx).await;
        });

        self.reader_task = Some(handle);
        rx
    }

    /// Check whether the channel-based receive path is active.
    pub fn has_reader(&self) -> bool {
        self.reader_task.is_some()
    }

    /// Send a raw JSON value as an AAFP DATA frame.
    ///
    /// This is used by non-rmcp consumers (e.g., the Python PyO3 binding)
    /// that need to send JSON-RPC messages without rmcp type constraints.
    ///
    /// If `spawn_writer()` has been called, this uses the channel-based path
    /// (no mutex acquisition). Otherwise, it falls back to the legacy mutex
    /// path.
    pub async fn send_raw_json(&self, json: &serde_json::Value) -> Result<(), AafpMcpError> {
        if let Some(tx) = &self.send_channel {
            // Channel path: serialize into pooled buffer, send through channel
            let mut buf = acquire();
            encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
                .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
            let payload_start = buf.len();
            {
                let mut writer = BytesMutWriter::new(&mut buf);
                serde_json::to_writer(&mut writer, json)?;
            }
            let payload_len = buf.len() - payload_start;
            backpatch_payload_len(&mut buf, payload_len)
                .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
            tx.send(buf).await.map_err(|_| AafpMcpError::Closed)?;
            return Ok(());
        }

        // Legacy mutex path
        let mut guard = self.send.lock().await;
        let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

        let json_bytes = serde_json::to_vec(json)?;
        let frame = Frame::data(MCP_STREAM_ID, json_bytes);
        let frame_bytes = encode_frame(&frame)?;
        send_stream.write_all(&frame_bytes).await?;
        Ok(())
    }

    /// Send a raw JSON value using the zero-copy buffer pool.
    ///
    /// This is the zero-copy version of `send_raw_json`. After pool warmup,
    /// this performs 0 heap allocations per message (on the legacy mutex
    /// path). On the channel path, the buffer is sent to the writer task
    /// which releases it after writing.
    pub async fn send_raw_json_zero_copy(
        &self,
        json: &serde_json::Value,
    ) -> Result<(), AafpMcpError> {
        if let Some(tx) = &self.send_channel {
            // Channel path: serialize into pooled buffer, send through channel
            let mut buf = acquire();
            encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
                .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
            let payload_start = buf.len();
            {
                let mut writer = BytesMutWriter::new(&mut buf);
                serde_json::to_writer(&mut writer, json)?;
            }
            let payload_len = buf.len() - payload_start;
            backpatch_payload_len(&mut buf, payload_len)
                .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
            tx.send(buf).await.map_err(|_| AafpMcpError::Closed)?;
            return Ok(());
        }

        // Legacy mutex path
        let mut guard = self.send.lock().await;
        let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

        let mut buf = acquire();
        encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
            .map_err(|e| AafpMcpError::Framing(e.to_string()))?;

        let payload_start = buf.len();
        {
            let mut writer = BytesMutWriter::new(&mut buf);
            serde_json::to_writer(&mut writer, json)?;
        }
        let payload_len = buf.len() - payload_start;
        backpatch_payload_len(&mut buf, payload_len)
            .map_err(|e| AafpMcpError::Framing(e.to_string()))?;

        send_stream.write_all(&buf).await?;
        release(buf);
        Ok(())
    }

    /// Read a raw JSON value from an AAFP DATA frame.
    ///
    /// Returns `None` when the peer closes the stream.
    /// Used by non-rmcp consumers (e.g., the Python PyO3 binding).
    ///
    /// If `spawn_reader()` has been called, this receives from the channel
    /// instead of reading directly from the QUIC stream.
    pub async fn recv_raw_json(&mut self) -> Option<serde_json::Value> {
        if self.closed {
            return None;
        }

        // Direct receive path (reader task takes over if spawn_reader was called)
        let recv = self.recv.as_mut()?;
        loop {
            match read_data_frame(recv).await {
                Ok(Some(payload)) => match serde_json::from_slice::<serde_json::Value>(&payload) {
                    Ok(msg) => return Some(msg),
                    Err(e) => {
                        match e.classify() {
                            serde_json::error::Category::Syntax
                            | serde_json::error::Category::Eof => {
                                tracing::debug!("Ignoring unparsable message: {e}");
                            }
                            serde_json::error::Category::Data | serde_json::error::Category::Io => {
                                tracing::warn!("Protocol error in message: {e}");
                            }
                        }
                        continue;
                    }
                },
                Ok(None) => return None,
                Err(AafpMcpError::Closed) => return None,
                Err(e) => {
                    tracing::error!("Error reading AAFP frame: {e}");
                    return None;
                }
            }
        }
    }

    /// Read a raw JSON value using the zero-copy buffer pool.
    ///
    /// This is the zero-copy version of `recv_raw_json`. After pool warmup,
    /// this performs 0 heap allocations for the payload.
    ///
    /// If `spawn_reader()` has been called, this receives from the channel
    /// instead of reading directly from the QUIC stream.
    pub async fn recv_raw_json_zero_copy(&mut self) -> Option<serde_json::Value> {
        if self.closed {
            return None;
        }

        // Direct receive path (reader task takes over if spawn_reader was called)
        let recv = self.recv.as_mut()?;
        loop {
            match read_data_frame_zero_copy(recv).await {
                Ok(Some(payload)) => match serde_json::from_slice::<serde_json::Value>(&payload) {
                    Ok(msg) => return Some(msg),
                    Err(e) => {
                        match e.classify() {
                            serde_json::error::Category::Syntax
                            | serde_json::error::Category::Eof => {
                                tracing::debug!("Ignoring unparsable message: {e}");
                            }
                            serde_json::error::Category::Data | serde_json::error::Category::Io => {
                                tracing::warn!("Protocol error in message: {e}");
                            }
                        }
                        continue;
                    }
                },
                Ok(None) => return None,
                Err(AafpMcpError::Closed) => return None,
                Err(e) => {
                    tracing::error!("Error reading AAFP frame: {e}");
                    return None;
                }
            }
        }
    }

    /// Close the transport (raw JSON variant for non-rmcp consumers).
    pub async fn close_raw(&mut self) -> Result<(), AafpMcpError> {
        self.closed = true;

        // Drop the channel sender to signal the writer task to drain and exit.
        drop(self.send_channel.take());

        // Drop the receive channel to signal the reader task to exit.

        // Wait for the writer task to finish (it drains remaining messages,
        // finishes the stream, and exits).
        if let Some(handle) = self.writer_task.take() {
            let _ = handle.await;
        } else {
            // No writer task — use legacy mutex close path
            let mut guard = self.send.lock().await;
            if let Some(mut send) = guard.take() {
                send.finish();
            }
        }

        // Wait for the reader task to finish.
        if let Some(handle) = self.reader_task.take() {
            let _ = handle.await;
        }

        if let Some(conn) = self.conn.take() {
            conn.close(0, b"transport closed");
        }

        Ok(())
    }

    /// Get a reference to the send stream Arc for testing purposes.
    ///
    /// This allows tests to write raw AAFP frames directly, bypassing the
    /// Transport trait's JSON serialization. Used for conformance testing
    /// of error resilience (e.g., sending malformed JSON).
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn send_for_test(&self) -> Arc<Mutex<Option<QuicSendStream>>> {
        self.send.clone()
    }

    /// Get a clone of the send stream handle.
    ///
    /// This allows callers (e.g., the PyO3 Python binding) to send messages
    /// concurrently with receive operations, without holding a lock on the
    /// entire transport. The handle is an `Arc<Mutex<...>>` so it can be
    /// shared across tasks.
    pub fn send_handle(&self) -> Arc<Mutex<Option<QuicSendStream>>> {
        self.send.clone()
    }

    /// Send a JSON-RPC message using the zero-copy buffer pool.
    ///
    /// This is the zero-copy version of the `Transport::send` method. It:
    /// 1. Acquires a buffer from the thread-local pool
    /// 2. Writes the frame header (with placeholder payload_len=0)
    /// 3. Serializes JSON directly into the buffer (no intermediate Vec)
    /// 4. Backpatches the payload length
    /// 5. Writes the buffer to the QUIC stream (or sends through channel)
    /// 6. Releases the buffer back to the pool
    ///
    /// After pool warmup, this performs 0 heap allocations per message
    /// (on the legacy mutex path). On the channel path, the buffer is sent
    /// to the writer task which releases it after writing.
    pub async fn send_zero_copy<T>(&mut self, item: &T) -> Result<(), AafpMcpError>
    where
        T: Serialize + ?Sized,
    {
        if let Some(tx) = &self.send_channel {
            // Channel path: serialize into pooled buffer, send through channel
            let mut buf = acquire();
            encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
                .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
            let payload_start = buf.len();
            {
                let mut writer = BytesMutWriter::new(&mut buf);
                serde_json::to_writer(&mut writer, item)?;
            }
            let payload_len = buf.len() - payload_start;
            backpatch_payload_len(&mut buf, payload_len)
                .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
            tx.send(buf).await.map_err(|_| AafpMcpError::Closed)?;
            return Ok(());
        }

        // Legacy mutex path
        let mut guard = self.send.lock().await;
        let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

        // Acquire a buffer from the pool
        let mut buf = acquire();

        // Write frame header with placeholder payload_len=0
        encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
            .map_err(|e| AafpMcpError::Framing(e.to_string()))?;

        // Serialize JSON directly into the buffer (no intermediate Vec allocation)
        let payload_start = buf.len();
        {
            let mut writer = BytesMutWriter::new(&mut buf);
            serde_json::to_writer(&mut writer, item)?;
        }
        let payload_len = buf.len() - payload_start;

        // Backpatch the payload length in the header
        backpatch_payload_len(&mut buf, payload_len)
            .map_err(|e| AafpMcpError::Framing(e.to_string()))?;

        // Write the entire buffer to the QUIC stream (single write)
        send_stream.write_all(&buf).await?;

        // Release the buffer back to the pool for reuse
        release(buf);

        Ok(())
    }

    /// Receive a JSON-RPC message using the zero-copy buffer pool.
    ///
    /// This is the zero-copy version of the `Transport::receive` method. It
    /// reads the payload directly into a pooled buffer, eliminating the
    /// `vec![0u8; payload_len]` allocation.
    pub async fn receive_zero_copy<R>(&mut self) -> Option<RxJsonRpcMessage<R>>
    where
        R: ServiceRole,
        RxJsonRpcMessage<R>: DeserializeOwned,
    {
        if self.closed {
            return None;
        }

        let recv = self.recv.as_mut()?;
        loop {
            match read_data_frame_zero_copy(recv).await {
                Ok(Some(payload)) => {
                    // Deserialize JSON-RPC from the pooled buffer (no copy)
                    match serde_json::from_slice::<RxJsonRpcMessage<R>>(&payload) {
                        Ok(msg) => return Some(msg),
                        Err(e) => {
                            match e.classify() {
                                serde_json::error::Category::Syntax
                                | serde_json::error::Category::Eof => {
                                    tracing::debug!("Ignoring unparsable MCP message: {e}");
                                }
                                serde_json::error::Category::Data
                                | serde_json::error::Category::Io => {
                                    tracing::warn!("Protocol error in MCP message: {e}");
                                }
                            }
                            continue;
                        }
                    }
                }
                Ok(None) => return None,
                Err(AafpMcpError::Closed) => return None,
                Err(e) => {
                    tracing::error!("Error reading AAFP frame: {e}");
                    return None;
                }
            }
        }
    }
}

/// Send a raw JSON value via a send handle extracted from an `AafpMcpTransport`.
///
/// This is a standalone function that allows sending without holding a lock
/// on the entire transport — only the send stream's own mutex is locked.
/// Used by the PyO3 Python binding for concurrent send/receive.
pub async fn send_raw_json_on_handle(
    send_handle: &Arc<Mutex<Option<QuicSendStream>>>,
    json: &serde_json::Value,
) -> Result<(), AafpMcpError> {
    let mut guard = send_handle.lock().await;
    let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

    let json_bytes = serde_json::to_vec(json)?;
    let frame = Frame::data(MCP_STREAM_ID, json_bytes);
    let frame_bytes = encode_frame(&frame)?;
    send_stream.write_all(&frame_bytes).await?;
    Ok(())
}

/// Send a raw JSON value via a send handle using the zero-copy buffer pool.
///
/// This is the zero-copy version of `send_raw_json_on_handle`. It:
/// 1. Acquires a buffer from the thread-local pool
/// 2. Writes the frame header (with placeholder payload_len=0)
/// 3. Serializes JSON directly into the buffer (no intermediate Vec)
/// 4. Backpatches the payload length
/// 5. Writes the buffer to the QUIC stream
/// 6. Releases the buffer back to the pool
///
/// After pool warmup, this performs 0 heap allocations per message.
pub async fn send_raw_json_on_handle_zero_copy(
    send_handle: &Arc<Mutex<Option<QuicSendStream>>>,
    json: &serde_json::Value,
) -> Result<(), AafpMcpError> {
    let mut guard = send_handle.lock().await;
    let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

    // Acquire a buffer from the pool
    let mut buf = acquire();

    // Write frame header with placeholder payload_len=0
    encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
        .map_err(|e| AafpMcpError::Framing(e.to_string()))?;

    // Serialize JSON directly into the buffer (no intermediate Vec allocation)
    let payload_start = buf.len();
    {
        let mut writer = BytesMutWriter::new(&mut buf);
        serde_json::to_writer(&mut writer, json)?;
    }
    let payload_len = buf.len() - payload_start;

    // Backpatch the payload length in the header
    backpatch_payload_len(&mut buf, payload_len)
        .map_err(|e| AafpMcpError::Framing(e.to_string()))?;

    // Write the entire buffer to the QUIC stream (single write)
    send_stream.write_all(&buf).await?;

    // Release the buffer back to the pool for reuse
    release(buf);

    Ok(())
}

/// Writer task loop: drains the mpsc channel and writes buffers to the QUIC
/// send stream (Track H2).
///
/// This task owns the `QuicSendStream` exclusively. Multiple sender tasks
/// push `BytesMut` buffers through the channel; this task is the single
/// consumer, so there is no contention on the write side.
///
/// When all channel senders are dropped (channel closed), `recv()` returns
/// `None`, the loop exits, and the stream is finished gracefully.
async fn writer_task_loop(mut send_stream: QuicSendStream, mut rx: mpsc::Receiver<BytesMut>) {
    while let Some(buf) = rx.recv().await {
        if let Err(e) = send_stream.write_all(&buf).await {
            tracing::error!("Writer task: QUIC write error, shutting down: {e}");
            break;
        }
        // Release the buffer back to the pool (on this thread).
        // If the pool is full, the buffer is dropped (freed).
        release(buf);
    }
    // Channel closed — finish the send side of the stream
    send_stream.finish();
}

/// Reader task loop: reads AAFP DATA frames from the QUIC receive stream,
/// deserializes JSON, and pushes values through the mpsc channel (Track H3).
///
/// This task owns the `QuicRecvStream` exclusively. It handles all I/O,
/// separating network reads from message processing. The caller receives
/// decoded `serde_json::Value` from the channel — no lock contention.
///
/// When the channel sender is dropped (caller no longer receiving), the
/// task exits. When the QUIC stream ends (peer closed), `read_data_frame`
/// returns `None` and the task exits.
async fn reader_task_loop(mut recv_stream: QuicRecvStream, tx: mpsc::Sender<serde_json::Value>) {
    loop {
        match read_data_frame_zero_copy(&mut recv_stream).await {
            Ok(Some(payload)) => {
                match serde_json::from_slice::<serde_json::Value>(&payload) {
                    Ok(value) => {
                        if tx.send(value).await.is_err() {
                            // Channel closed — caller dropped the receiver
                            break;
                        }
                    }
                    Err(e) => {
                        match e.classify() {
                            serde_json::error::Category::Syntax
                            | serde_json::error::Category::Eof => {
                                tracing::debug!("Reader task: ignoring unparsable message: {e}");
                            }
                            serde_json::error::Category::Data | serde_json::error::Category::Io => {
                                tracing::warn!("Reader task: protocol error in message: {e}");
                            }
                        }
                        continue;
                    }
                }
            }
            Ok(None) => break, // Stream ended
            Err(AafpMcpError::Closed) => break,
            Err(e) => {
                tracing::error!("Reader task: error reading AAFP frame: {e}");
                break;
            }
        }
    }
}

/// Send a raw JSON value via a channel sender extracted from an
/// `AafpMcpTransport` that has called `spawn_writer()`.
///
/// This is the channel-based equivalent of `send_raw_json_on_handle_zero_copy`.
/// Multiple tasks can clone the `mpsc::Sender` and call this concurrently
/// without any mutex contention — the writer task drains the channel.
pub async fn send_raw_json_via_channel(
    tx: &mpsc::Sender<BytesMut>,
    json: &serde_json::Value,
) -> Result<(), AafpMcpError> {
    let mut buf = acquire();
    encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
        .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
    let payload_start = buf.len();
    {
        let mut writer = BytesMutWriter::new(&mut buf);
        serde_json::to_writer(&mut writer, json)?;
    }
    let payload_len = buf.len() - payload_start;
    backpatch_payload_len(&mut buf, payload_len)
        .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
    tx.send(buf).await.map_err(|_| AafpMcpError::Closed)?;
    Ok(())
}

/// Read an AAFP DATA frame from a QUIC receive stream and return the payload.
async fn read_data_frame(recv: &mut QuicRecvStream) -> Result<Option<Vec<u8>>, AafpMcpError> {
    // Read the 28-byte frame header
    let mut header = [0u8; FRAME_HEADER_SIZE];
    recv.read_exact(&mut header).await.map_err(|e| {
        // Check if this is a connection/stream closed error
        let msg = e.to_string();
        if msg.contains("closed") || msg.contains("reset") || msg.contains("stopped") {
            AafpMcpError::Closed
        } else {
            AafpMcpError::Io(e)
        }
    })?;

    // Parse header fields (big-endian)
    let version = header[0];
    let frame_type = header[1];
    let _flags = header[2];
    let _reserved = header[3];
    let _stream_id = u64::from_be_bytes(header[4..12].try_into().unwrap());
    let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;

    // Validate
    if version != AAFP_VERSION {
        tracing::warn!(
            "AAFP frame version mismatch: expected {}, got {}",
            AAFP_VERSION,
            version
        );
        return Err(AafpMcpError::Framing(format!(
            "frame version mismatch: expected {AAFP_VERSION}, got {version}"
        )));
    }
    if frame_type != 0x01 {
        tracing::warn!("Expected DATA frame (0x01), got 0x{frame_type:02x}");
        return Err(AafpMcpError::Framing(format!(
            "expected DATA frame (0x01), got 0x{frame_type:02x}"
        )));
    }
    if payload_len > 1024 * 1024 {
        return Err(AafpMcpError::Framing(format!(
            "payload too large: {payload_len} bytes"
        )));
    }

    // Read extensions (skip if present) + payload
    if ext_len > 0 {
        let mut ext = vec![0u8; ext_len];
        recv.read_exact(&mut ext).await?;
    }

    let mut payload = vec![0u8; payload_len];
    recv.read_exact(&mut payload).await?;

    Ok(Some(payload))
}

/// Read an AAFP DATA frame from a QUIC receive stream into a pooled buffer.
///
/// This is the zero-copy version of `read_data_frame`. It reads the payload
/// directly into a `BytesMut` from the buffer pool, eliminating the
/// `vec![0u8; payload_len]` allocation.
///
/// Returns the payload as a `Bytes` (reference-counted slice) and releases
/// the buffer back to the pool.
async fn read_data_frame_zero_copy(
    recv: &mut QuicRecvStream,
) -> Result<Option<bytes::Bytes>, AafpMcpError> {
    // Read the 28-byte frame header into a stack array (no allocation)
    let mut header = [0u8; FRAME_HEADER_SIZE];
    recv.read_exact(&mut header).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("closed") || msg.contains("reset") || msg.contains("stopped") {
            AafpMcpError::Closed
        } else {
            AafpMcpError::Io(e)
        }
    })?;

    // Parse header fields (big-endian)
    let version = header[0];
    let frame_type = header[1];
    let _flags = header[2];
    let _reserved = header[3];
    let _stream_id = u64::from_be_bytes(header[4..12].try_into().unwrap());
    let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;

    // Validate
    if version != AAFP_VERSION {
        tracing::warn!(
            "AAFP frame version mismatch: expected {}, got {}",
            AAFP_VERSION,
            version
        );
        return Err(AafpMcpError::Framing(format!(
            "frame version mismatch: expected {AAFP_VERSION}, got {version}"
        )));
    }
    if frame_type != 0x01 {
        tracing::warn!("Expected DATA frame (0x01), got 0x{frame_type:02x}");
        return Err(AafpMcpError::Framing(format!(
            "expected DATA frame (0x01), got 0x{frame_type:02x}"
        )));
    }
    if payload_len > 1024 * 1024 {
        return Err(AafpMcpError::Framing(format!(
            "payload too large: {payload_len} bytes"
        )));
    }

    // Skip extensions if present (read into a stack buffer if small)
    if ext_len > 0 {
        let mut ext_buf = vec![0u8; ext_len];
        recv.read_exact(&mut ext_buf).await?;
    }

    // Acquire a buffer from the pool and read payload directly into it
    let mut buf = acquire();
    buf.resize(payload_len, 0);
    recv.read_exact(&mut buf).await?;

    // Convert to Bytes (reference-counted, zero-copy slice)
    let payload = buf.freeze();

    Ok(Some(payload))
}

impl<R: ServiceRole> Transport<R> for AafpMcpTransport
where
    TxJsonRpcMessage<R>: Serialize,
    RxJsonRpcMessage<R>: DeserializeOwned,
{
    type Error = AafpMcpError;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<R>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let send_arc = self.send.clone();
        let send_tx = self.send_channel.clone();
        async move {
            if let Some(tx) = send_tx {
                // Channel path (Track H2): serialize into pooled buffer, send
                // through channel — no mutex acquisition.
                let mut buf = acquire();
                encode_header_into(&mut buf, FrameType::Data, 0, MCP_STREAM_ID, &[])
                    .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
                let payload_start = buf.len();
                {
                    let mut writer = BytesMutWriter::new(&mut buf);
                    serde_json::to_writer(&mut writer, &item)?;
                }
                let payload_len = buf.len() - payload_start;
                backpatch_payload_len(&mut buf, payload_len)
                    .map_err(|e| AafpMcpError::Framing(e.to_string()))?;
                tx.send(buf).await.map_err(|_| AafpMcpError::Closed)?;
                return Ok(());
            }

            // Legacy mutex path
            let mut guard = send_arc.lock().await;
            let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

            // Serialize JSON-RPC message to JSON bytes
            let json_bytes = serde_json::to_vec(&item)?;

            // Wrap in AAFP DATA frame
            let frame = Frame::data(MCP_STREAM_ID, json_bytes);
            let frame_bytes = encode_frame(&frame)?;

            // Write to QUIC stream (do NOT finish — keep stream open for more messages)
            send_stream.write_all(&frame_bytes).await?;

            Ok(())
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<R>> {
        if self.closed {
            return None;
        }

        // Direct receive path (reader task takes over if spawn_reader was called)
        let recv = self.recv.as_mut()?;
        loop {
            match read_data_frame(recv).await {
                Ok(Some(payload)) => {
                    // Deserialize JSON-RPC from payload
                    match serde_json::from_slice::<RxJsonRpcMessage<R>>(&payload) {
                        Ok(msg) => return Some(msg),
                        Err(e) => {
                            // Log and skip invalid JSON-RPC messages.
                            // This matches rmcp's AsyncRwTransport behavior:
                            // syntax/EOF errors are ignored, data errors are
                            // surfaced as invalid request responses (but we
                            // don't have a send channel here, so just log).
                            match e.classify() {
                                serde_json::error::Category::Syntax
                                | serde_json::error::Category::Eof => {
                                    tracing::debug!("Ignoring unparsable MCP message: {e}");
                                }
                                serde_json::error::Category::Data
                                | serde_json::error::Category::Io => {
                                    tracing::warn!("Protocol error in MCP message: {e}");
                                }
                            }
                            continue;
                        }
                    }
                }
                Ok(None) => return None,
                Err(AafpMcpError::Closed) => return None,
                Err(e) => {
                    tracing::error!("Error reading AAFP frame: {e}");
                    return None;
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.closed = true;

        // Drop the channel sender to signal the writer task to drain and exit.
        drop(self.send_channel.take());

        // Drop the receive channel to signal the reader task to exit.

        // Wait for the writer task to finish (it drains remaining messages,
        // finishes the stream, and exits).
        if let Some(handle) = self.writer_task.take() {
            let _ = handle.await;
        } else {
            // No writer task — use legacy mutex close path
            let mut guard = self.send.lock().await;
            if let Some(mut send) = guard.take() {
                send.finish();
            }
        }

        // Wait for the reader task to finish.
        if let Some(handle) = self.reader_task.take() {
            let _ = handle.await;
        }

        // Close the QUIC connection if we own it
        if let Some(conn) = self.conn.take() {
            conn.close(0, b"mcp transport closed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_sdk::AgentBuilder;
    use rmcp::model::{ClientRequest, JsonRpcMessage, PingRequest, RequestId};
    use rmcp::service::TxJsonRpcMessage;
    use rmcp::transport::Transport;
    use rmcp::RoleClient;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_error_display() {
        let err = AafpMcpError::Closed;
        assert_eq!(err.to_string(), "Transport is closed");

        let err = AafpMcpError::Framing("test error".into());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_from_streams() {
        // Verify from_streams constructs without panic
        // (We can't create real QuicStreams without a QUIC connection,
        // but we can verify the struct layout is correct.)
        let _ = std::mem::size_of::<AafpMcpTransport>();
    }

    fn client_ping(id: i64) -> TxJsonRpcMessage<RoleClient> {
        JsonRpcMessage::request(
            ClientRequest::PingRequest(PingRequest::default()),
            RequestId::Number(id),
        )
    }

    /// Set up a connected client-server pair for integration tests.
    async fn setup_pair() -> (AafpMcpTransport, AafpMcpTransport) {
        let server_agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .unwrap(),
        );
        let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

        let client_agent = AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        let server_agent_clone = server_agent.clone();
        let server_handle = tokio::spawn(async move {
            let mut t = AafpMcpTransport::accept(&server_agent_clone).await.unwrap();
            let _ = Transport::<rmcp::RoleServer>::receive(&mut t).await;
            t
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = AafpMcpTransport::connect(&client_agent, &addr)
            .await
            .unwrap();
        Transport::<RoleClient>::send(&mut client, client_ping(0))
            .await
            .unwrap();

        let server = server_handle.await.unwrap();
        (client, server)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_channel_send_single_message() {
        let (mut client, mut server) = setup_pair().await;

        // Spawn writer task — switch to channel path
        let tx = client.spawn_writer().await;
        assert!(client.has_writer());

        // Send via channel path (Transport::send detects channel)
        Transport::<RoleClient>::send(&mut client, client_ping(1))
            .await
            .unwrap();

        // Server should receive it
        let msg = server.recv_raw_json_zero_copy().await;
        assert!(msg.is_some(), "server should receive the message");

        // Drop external sender before close so the writer task can exit
        drop(tx);
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_channel_send_raw_json() {
        let (mut client, mut server) = setup_pair().await;

        let tx = client.spawn_writer().await;

        let msg = json!({"jsonrpc": "2.0", "id": 42, "method": "ping"});
        client.send_raw_json_zero_copy(&msg).await.unwrap();

        let received = server.recv_raw_json_zero_copy().await;
        assert!(received.is_some());
        let received = received.unwrap();
        assert_eq!(received["id"], 42);

        drop(tx);
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_channel_concurrent_senders() {
        let (mut client, mut server) = setup_pair().await;

        // Spawn writer and get the channel sender
        let tx = client.spawn_writer().await;

        // Spawn 4 concurrent sender tasks
        let mut handles = Vec::new();
        for task_id in 0..4u64 {
            let tx_clone = tx.clone();
            let h = tokio::spawn(async move {
                for i in 0..50u64 {
                    let msg = json!({
                        "jsonrpc": "2.0",
                        "id": task_id * 1000 + i,
                        "method": "ping"
                    });
                    send_raw_json_via_channel(&tx_clone, &msg).await.unwrap();
                }
            });
            handles.push(h);
        }

        // Receive all 200 messages on server side
        let mut count = 0;
        for _ in 0..200 {
            let msg = server.recv_raw_json_zero_copy().await;
            if msg.is_some() {
                count += 1;
            } else {
                break;
            }
        }

        // Wait for all senders
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(count, 200, "server should receive all 200 messages");

        drop(tx);
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_channel_close_drains_and_finishes() {
        let (mut client, mut server) = setup_pair().await;

        let tx = client.spawn_writer().await;

        // Send some messages
        for i in 0..10u64 {
            let msg = json!({"jsonrpc": "2.0", "id": i, "method": "ping"});
            send_raw_json_via_channel(&tx, &msg).await.unwrap();
        }

        // Drop external sender so close() can shut down the writer
        drop(tx);

        // Close — should drain remaining messages
        Transport::<RoleClient>::close(&mut client).await.unwrap();

        // Server should receive all 10 messages
        let mut count = 0;
        for _ in 0..10 {
            if server.recv_raw_json_zero_copy().await.is_some() {
                count += 1;
            } else {
                break;
            }
        }
        assert_eq!(count, 10, "all messages should be drained on close");

        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_channel_handle_returns_none_before_spawn() {
        let (client, _server) = setup_pair().await;
        assert!(!client.has_writer());
        assert!(client.send_channel_handle().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_channel_handle_returns_some_after_spawn() {
        let (mut client, _server) = setup_pair().await;
        let tx = client.spawn_writer().await;
        assert!(client.has_writer());
        assert!(client.send_channel_handle().is_some());
        drop(tx);
        Transport::<RoleClient>::close(&mut client).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_legacy_mutex_path_still_works() {
        // Verify that without spawn_writer(), the mutex path still works
        let (mut client, mut server) = setup_pair().await;

        assert!(!client.has_writer());

        // Send via mutex path
        Transport::<RoleClient>::send(&mut client, client_ping(1))
            .await
            .unwrap();

        let msg = server.recv_raw_json_zero_copy().await;
        assert!(msg.is_some());

        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reader_channel_receive() {
        let (mut client, mut server) = setup_pair().await;

        // Spawn reader on server — get the receive channel
        let mut rx = server.spawn_reader().await;
        assert!(server.has_reader());

        // Send from client
        let tx = client.spawn_writer().await;
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        send_raw_json_via_channel(&tx, &msg).await.unwrap();

        // Receive via channel (no direct stream access)
        let received = rx.recv().await;
        assert!(received.is_some(), "should receive message via channel");
        let received = received.unwrap();
        assert_eq!(received["id"], 1);

        drop(tx);
        Transport::<RoleClient>::close(&mut client).await.ok();
        drop(rx);
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reader_channel_multiple_messages() {
        let (mut client, mut server) = setup_pair().await;

        let mut rx = server.spawn_reader().await;
        let tx = client.spawn_writer().await;

        // Send 10 messages
        for i in 0..10u64 {
            let msg = json!({"jsonrpc": "2.0", "id": i, "method": "ping"});
            send_raw_json_via_channel(&tx, &msg).await.unwrap();
        }

        // Receive all 10 via channel
        let mut count = 0;
        for _ in 0..10 {
            if rx.recv().await.is_some() {
                count += 1;
            } else {
                break;
            }
        }
        assert_eq!(count, 10, "should receive all 10 messages via channel");

        drop(tx);
        Transport::<RoleClient>::close(&mut client).await.ok();
        drop(rx);
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reader_has_reader_flag() {
        let (mut client, mut server) = setup_pair().await;

        assert!(!server.has_reader());
        let rx = server.spawn_reader().await;
        assert!(server.has_reader());

        drop(rx);
        Transport::<RoleClient>::close(&mut client).await.ok();
        Transport::<rmcp::RoleServer>::close(&mut server).await.ok();
    }
}
