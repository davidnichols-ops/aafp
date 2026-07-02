//! # AAFP Transport for A2A
//!
//! AAFP secure transport binding for the A2A (Agent2Agent) Protocol.
//! Carries A2A JSON-RPC 2.0 messages as payloads of AAFP DATA frames
//! over post-quantum QUIC transport.
//!
//! See RFC 0008 for the full specification.
//!
//! ## Architectural Layers
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  Application Protocol Layer (A2A)                    │
//! │  - JSON-RPC 2.0 message format                       │
//! │  - Method dispatch (SendMessage, GetTask, etc.)      │
//! │  - Task state machine, streaming events              │
//! │  - Owned by: application code, A2aServerHandler      │
//! ├─────────────────────────────────────────────────────┤
//! │  Transport Binding Layer (this crate)                │
//! │  - AafpA2aTransport: carries JSON-RPC in DATA frames │
//! │  - A2aClient: high-level client API                  │
//! │  - A2aServerHandler: server-side dispatch trait      │
//! │  - Manages QUIC stream lifecycle                     │
//! │  - Performs AAFP handshake + authorization           │
//! ├─────────────────────────────────────────────────────┤
//! │  AAFP Core Protocol Layer                             │
//! │  - Frame format (28-byte header, 8 frame types)      │
//! │  - Handshake (ML-DSA-65 identity, PQ TLS)            │
//! │  - Session state machine                              │
//! │  - Owned by: aafp-sdk, aafp-core, aafp-messaging     │
//! ├─────────────────────────────────────────────────────┤
//! │  Transport Layer (QUIC)                               │
//! │  - quinn + rustls (X25519MLKEM768)                    │
//! │  - Owned by: aafp-transport-quic                      │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Framing
//!
//! Each A2A JSON-RPC message is serialized to UTF-8 JSON bytes and carried as
//! the payload of a single AAFP DATA frame (frame type 0x01). The AAFP frame
//! header (28 bytes) provides length-delimited message boundaries.
//!
//! ## Authorization
//!
//! By default, `connect()` and `accept()` use `TestingAuthProvider`, which
//! allows all connections. **Production deployments MUST use
//! `connect_with_auth()` / `accept_with_auth()` with a custom
//! `AuthorizationProvider`.**

use std::sync::Arc;

use aafp_core::AuthorizationProvider;
use aafp_identity::AgentId;
use aafp_messaging::{encode_frame, Frame, AAFP_VERSION, FRAME_HEADER_SIZE};
use aafp_sdk::{establish_session, Agent};
use aafp_transport_quic::{QuicConnection, QuicRecvStream, QuicSendStream};
use tokio::sync::Mutex;

mod client;
mod error;
mod server;
mod types;

pub use client::A2aClient;
pub use error::{A2aError, AafpA2aError};
pub use server::{dispatch_request, A2aServerHandler, TaskUpdateEvent};
pub use types::*;

/// AAFP stream ID used for A2A JSON-RPC messages.
///
/// Per RFC-0002 §7.1, application streams start at stream ID 4
/// (client-initiated). We use stream ID 4, same as MCP.
const A2A_STREAM_ID: u64 = 4;

/// AAFP-backed transport for A2A (Agent2Agent) Protocol.
///
/// Carries A2A JSON-RPC 2.0 messages as payloads of AAFP DATA frames
/// over a bidirectional QUIC stream. The AAFP handshake (ML-DSA-65
/// identity verification) is performed during `connect()` / `accept()`.
pub struct AafpA2aTransport {
    /// Send side: wrapped in `Arc<Mutex<Option<_>>>` for shared access.
    send: Arc<Mutex<Option<QuicSendStream>>>,
    /// Receive side: sequential access.
    recv: QuicRecvStream,
    /// QUIC connection, used for `close()`.
    conn: Option<QuicConnection>,
    /// Whether the transport has been closed.
    closed: bool,
    /// The verified peer AgentId, captured from the handshake.
    peer_agent_id: Option<AgentId>,
}

impl AafpA2aTransport {
    /// Create a client-side A2A transport by connecting to an AAFP server.
    ///
    /// Performs the full AAFP v1 handshake:
    /// 1. QUIC connection established
    /// 2. ClientHello/ServerHello/ClientFinished exchange
    /// 3. Peer identity verified (ML-DSA-65)
    /// 4. Authorization (using `TestingAuthProvider` — allows all)
    /// 5. Session transitions to MessagingEnabled
    /// 6. Opens a bidirectional QUIC stream for A2A JSON-RPC messages
    pub async fn connect(agent: &Agent, addr: &str) -> Result<Self, AafpA2aError> {
        Self::connect_with_auth(agent, addr, Arc::new(aafp_core::TestingAuthProvider)).await
    }

    /// Create a client-side A2A transport with a custom authorization provider.
    pub async fn connect_with_auth(
        agent: &Agent,
        addr: &str,
        auth_provider: Arc<dyn AuthorizationProvider>,
    ) -> Result<Self, AafpA2aError> {
        // 1. Establish QUIC connection
        let conn = agent.transport.dial(addr).await?;

        // 2. Drive AAFP v1 handshake + authorization + session transitions
        let (_session, conn, peer_info) =
            establish_session(conn, &agent.keypair, auth_provider, true, None)
                .await
                .map_err(AafpA2aError::from)?;

        // 3. Open bidirectional stream for A2A messages
        let (send, recv) = conn.open_bi().await?;

        Ok(Self {
            send: Arc::new(Mutex::new(Some(send))),
            recv,
            conn: Some(conn),
            closed: false,
            peer_agent_id: Some(peer_info.agent_id),
        })
    }

    /// Create a server-side A2A transport by accepting an AAFP connection.
    ///
    /// Performs the full server-side AAFP v1 handshake:
    /// 1. Accept QUIC connection
    /// 2. ClientHello/ServerHello/ClientFinished exchange
    /// 3. Peer identity verified (ML-DSA-65)
    /// 4. Authorization (using `TestingAuthProvider` — allows all)
    /// 5. Session transitions to MessagingEnabled
    /// 6. Accepts the bidirectional QUIC stream for A2A JSON-RPC messages
    pub async fn accept(agent: &Agent) -> Result<Self, AafpA2aError> {
        Self::accept_with_auth(agent, Arc::new(aafp_core::TestingAuthProvider)).await
    }

    /// Create a server-side A2A transport with a custom authorization provider.
    pub async fn accept_with_auth(
        agent: &Agent,
        auth_provider: Arc<dyn AuthorizationProvider>,
    ) -> Result<Self, AafpA2aError> {
        // 1. Accept QUIC connection
        let conn = agent.transport.accept().await?;

        // 2. Drive AAFP v1 handshake + authorization + session transitions
        let (_session, conn, peer_info) =
            establish_session(conn, &agent.keypair, auth_provider, false, None)
                .await
                .map_err(AafpA2aError::from)?;

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
    pub fn peer_agent_id(&self) -> Option<&AgentId> {
        self.peer_agent_id.as_ref()
    }

    /// Send a JSON-RPC message as an AAFP DATA frame.
    pub async fn send_jsonrpc(&self, json: &serde_json::Value) -> Result<(), AafpA2aError> {
        let mut guard = self.send.lock().await;
        let send_stream = guard.as_mut().ok_or(AafpA2aError::Closed)?;

        let json_bytes = serde_json::to_vec(json)?;
        let frame = Frame::data(A2A_STREAM_ID, json_bytes);
        let frame_bytes = encode_frame(&frame)?;
        send_stream.write_all(&frame_bytes).await?;
        Ok(())
    }

    /// Read a JSON-RPC message from an AAFP DATA frame.
    /// Returns `None` when the peer closes the stream.
    pub async fn recv_jsonrpc(&mut self) -> Option<serde_json::Value> {
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
                                tracing::debug!("Ignoring unparsable A2A message: {e}");
                            }
                            serde_json::error::Category::Data | serde_json::error::Category::Io => {
                                tracing::warn!("Protocol error in A2A message: {e}");
                            }
                        }
                        continue;
                    }
                },
                Ok(None) => return None,
                Err(AafpA2aError::Closed) => return None,
                Err(e) => {
                    tracing::error!("Error reading AAFP frame: {e}");
                    return None;
                }
            }
        }
    }

    /// Close the transport.
    pub async fn close(&mut self) -> Result<(), AafpA2aError> {
        self.closed = true;

        let mut guard = self.send.lock().await;
        if let Some(mut send) = guard.take() {
            send.finish();
        }
        drop(guard);

        if let Some(conn) = self.conn.take() {
            conn.close(0, b"a2a transport closed");
        }

        Ok(())
    }

    /// Get a reference to the send stream Arc for testing purposes.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn send_for_test(&self) -> Arc<Mutex<Option<QuicSendStream>>> {
        self.send.clone()
    }
}

/// Read an AAFP DATA frame from a QUIC receive stream and return the payload.
async fn read_data_frame(recv: &mut QuicRecvStream) -> Result<Option<Vec<u8>>, AafpA2aError> {
    let mut header = [0u8; FRAME_HEADER_SIZE];
    recv.read_exact(&mut header).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("closed") || msg.contains("reset") || msg.contains("stopped") {
            AafpA2aError::Closed
        } else {
            AafpA2aError::Io(e)
        }
    })?;

    let version = header[0];
    let frame_type = header[1];
    let _flags = header[2];
    let _reserved = header[3];
    let _stream_id = u64::from_be_bytes(header[4..12].try_into().unwrap());
    let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;

    if version != AAFP_VERSION {
        tracing::warn!(
            "AAFP frame version mismatch: expected {}, got {}",
            AAFP_VERSION,
            version
        );
        return Err(AafpA2aError::Framing(format!(
            "frame version mismatch: expected {AAFP_VERSION}, got {version}"
        )));
    }
    if frame_type != 0x01 {
        tracing::warn!("Expected DATA frame (0x01), got 0x{frame_type:02x}");
        return Err(AafpA2aError::Framing(format!(
            "expected DATA frame (0x01), got 0x{frame_type:02x}"
        )));
    }
    if payload_len > 1024 * 1024 {
        return Err(AafpA2aError::Framing(format!(
            "payload too large: {payload_len} bytes"
        )));
    }

    if ext_len > 0 {
        let mut ext = vec![0u8; ext_len];
        recv.read_exact(&mut ext).await?;
    }

    let mut payload = vec![0u8; payload_len];
    recv.read_exact(&mut payload).await?;

    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AafpA2aError::Closed;
        assert_eq!(err.to_string(), "Transport is closed");

        let err = AafpA2aError::Framing("test error".into());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_a2a_error_codes() {
        assert_eq!(
            A2aError::TaskNotFound {
                task_id: "t1".into()
            }
            .jsonrpc_code(),
            -32001
        );
        assert_eq!(
            A2aError::TaskNotCancelable {
                task_id: "t1".into()
            }
            .jsonrpc_code(),
            -32002
        );
        assert_eq!(
            A2aError::PushNotificationNotSupported.jsonrpc_code(),
            -32003
        );
        assert_eq!(
            A2aError::UnsupportedOperation {
                operation: "x".into()
            }
            .jsonrpc_code(),
            -32004
        );
        assert_eq!(
            A2aError::ContentTypeNotSupported {
                content_type: "x".into()
            }
            .jsonrpc_code(),
            -32005
        );
        assert_eq!(A2aError::InvalidAgentResponse.jsonrpc_code(), -32006);
        assert_eq!(
            A2aError::ExtendedAgentCardNotConfigured.jsonrpc_code(),
            -32007
        );
        assert_eq!(
            A2aError::ExtensionSupportRequired {
                extension: "x".into()
            }
            .jsonrpc_code(),
            -32008
        );
        assert_eq!(
            A2aError::VersionNotSupported {
                version: "x".into()
            }
            .jsonrpc_code(),
            -32009
        );
        assert_eq!(A2aError::ParseError.jsonrpc_code(), -32700);
        assert_eq!(A2aError::InvalidRequest.jsonrpc_code(), -32600);
        assert_eq!(
            A2aError::MethodNotFound { method: "x".into() }.jsonrpc_code(),
            -32601
        );
        assert_eq!(A2aError::InvalidParams.jsonrpc_code(), -32602);
        assert_eq!(
            A2aError::Internal {
                message: "x".into()
            }
            .jsonrpc_code(),
            -32603
        );
    }

    #[test]
    fn test_jsonrpc_error_response() {
        let err = A2aError::TaskNotFound {
            task_id: "t1".into(),
        };
        let resp = err.to_jsonrpc_error(serde_json::json!(1));
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["error"]["code"], -32001);
        assert!(resp["error"]["message"].as_str().unwrap().contains("t1"));
    }
}
