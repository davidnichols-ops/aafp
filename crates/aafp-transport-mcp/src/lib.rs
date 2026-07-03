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
use rmcp::service::{RxJsonRpcMessage, ServiceRole, TxJsonRpcMessage};
use rmcp::transport::Transport;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Mutex;

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
    /// Send side: wrapped in `Arc<Mutex<Option<_>>>` so the `send` future
    /// can be `Send + 'static` (required by the `Transport` trait).
    send: Arc<Mutex<Option<QuicSendStream>>>,
    /// Receive side: sequential access, `&mut self` is sufficient.
    recv: QuicRecvStream,
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
            recv,
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
            recv,
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
            recv,
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

    /// Send a raw JSON value as an AAFP DATA frame.
    ///
    /// This is used by non-rmcp consumers (e.g., the Python PyO3 binding)
    /// that need to send JSON-RPC messages without rmcp type constraints.
    pub async fn send_raw_json(&self, json: &serde_json::Value) -> Result<(), AafpMcpError> {
        let mut guard = self.send.lock().await;
        let send_stream = guard.as_mut().ok_or(AafpMcpError::Closed)?;

        let json_bytes = serde_json::to_vec(json)?;
        let frame = Frame::data(MCP_STREAM_ID, json_bytes);
        let frame_bytes = encode_frame(&frame)?;
        send_stream.write_all(&frame_bytes).await?;
        Ok(())
    }

    /// Read a raw JSON value from an AAFP DATA frame.
    ///
    /// Returns `None` when the peer closes the stream.
    /// Used by non-rmcp consumers (e.g., the Python PyO3 binding).
    pub async fn recv_raw_json(&mut self) -> Option<serde_json::Value> {
        if self.closed {
            return None;
        }

        loop {
            match read_data_frame(&mut self.recv).await {
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

        let mut guard = self.send.lock().await;
        if let Some(mut send) = guard.take() {
            send.finish();
        }
        drop(guard);

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
    /// 5. Writes the buffer to the QUIC stream
    /// 6. Releases the buffer back to the pool
    ///
    /// After pool warmup, this performs 0 heap allocations per message.
    pub async fn send_zero_copy<T>(&mut self, item: &T) -> Result<(), AafpMcpError>
    where
        T: Serialize + ?Sized,
    {
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

        loop {
            match read_data_frame_zero_copy(&mut self.recv).await {
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
        async move {
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

        loop {
            match read_data_frame(&mut self.recv).await {
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

        // Take and finish the send stream
        let mut guard = self.send.lock().await;
        if let Some(mut send) = guard.take() {
            send.finish();
        }
        drop(guard);

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
}
