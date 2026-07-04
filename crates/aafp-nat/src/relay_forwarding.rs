//! Relay data forwarding: bidirectional QUIC stream forwarding (RFC 0010 §4.2).
//!
//! This module implements the actual data forwarding that makes relayed
//! connections work. The relay acts as a byte-pipe between caller and target:
//!
//! ```text
//! Caller A ←→ [QUIC stream] ←→ Relay ←→ [QUIC stream] ←→ Target B
//! ```
//!
//! ## Wire Format (data streams)
//!
//! After a `connect` RPC succeeds and returns a `connection_id`, the caller
//! opens a new bidirectional QUIC stream on the same connection and writes:
//!
//! ```text
//! [1 byte: 0xFF (magic)] [8 bytes: connection_id (big-endian)]
//! ```
//!
//! The relay reads this header, looks up the pending target stream, and
//! starts forwarding bytes bidirectionally. All subsequent bytes on the
//! stream are raw application data — the relay copies them verbatim.
//!
//! On the target side, the relay opens a bi-stream and writes:
//!
//! ```text
//! [1 byte: 0xFE (magic)] [8 bytes: connection_id (big-endian)]
//! ```
//!
//! The target reads this header to identify the incoming relayed connection,
//! then reads/writes application data on the stream.

use crate::relay_v1::{
    ConnectResult, RelayV1Error, RelayV1Service, ReserveResult, METHOD_CONNECT, METHOD_RESERVE,
};
use aafp_cbor::{decode, encode, int_map_get, Value};
use aafp_identity::AgentId;
use aafp_messaging::{RpcErrorObject, RpcRequest, RpcResponse};
use aafp_transport_quic::{QuicConnection, QuicRecvStream, QuicSendStream, QuicTransport};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

/// Magic byte for caller→relay data stream header (RFC 0010 §4.2).
pub const DATA_STREAM_MAGIC: u8 = 0xFF;

/// Magic byte for relay→target incoming connection header (RFC 0010 §4.2).
pub const INCOMING_STREAM_MAGIC: u8 = 0xFE;

/// Size of the data stream header: 1 byte magic + 8 bytes connection_id.
pub const DATA_STREAM_HEADER_LEN: usize = 9;

/// Pending target stream: the relay has opened a bi-stream to the target
/// and is waiting for the caller to open a data stream.
struct PendingConnection {
    /// Send stream to the target.
    target_send: QuicSendStream,
    /// Recv stream from the target.
    target_recv: QuicRecvStream,
}

/// Relay server: accepts QUIC connections, handles RPC, and forwards data
/// between callers and targets (RFC 0010 §4).
pub struct RelayV1Server {
    /// QUIC transport for accepting connections.
    transport: QuicTransport,
    /// Relay service for reservation/connection management.
    service: Arc<Mutex<RelayV1Service>>,
    /// Map: agent_id → QUIC connection (for targets that have reserved).
    agent_connections: Arc<Mutex<HashMap<AgentId, QuicConnection>>>,
    /// Map: connection_id → pending target stream.
    pending_connections: Arc<Mutex<HashMap<u64, PendingConnection>>>,
}

impl RelayV1Server {
    /// Create a new relay server.
    pub fn new(transport: QuicTransport, service: Arc<Mutex<RelayV1Service>>) -> Self {
        Self {
            transport,
            service,
            agent_connections: Arc::new(Mutex::new(HashMap::new())),
            pending_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create with a fresh service and default config.
    pub fn with_defaults(transport: QuicTransport) -> Self {
        Self::new(
            transport,
            Arc::new(Mutex::new(RelayV1Service::with_defaults())),
        )
    }

    /// Get the relay's listen address.
    pub fn local_addr(&self) -> Result<String, RelayV1Error> {
        self.transport
            .local_addr()
            .map(|a| format!("quic://{}", a))
            .map_err(|e| {
                RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                    offset: 0,
                    message: e.to_string(),
                })
            })
    }

    /// Get a reference to the relay service.
    pub fn service(&self) -> &Arc<Mutex<RelayV1Service>> {
        &self.service
    }

    /// Run the relay server: accept connections and handle them.
    ///
    /// Each accepted connection gets a dedicated task that:
    /// 1. Accepts bi-streams on the connection
    /// 2. The first bi-stream is the control stream (RPC)
    /// 3. Subsequent bi-streams are data streams (with connection_id header)
    pub async fn run(self) {
        info!(
            "Relay server started on {}",
            self.local_addr().unwrap_or_default()
        );
        loop {
            match self.transport.accept().await {
                Ok(conn) => {
                    let agent_connections = self.agent_connections.clone();
                    let pending_connections = self.pending_connections.clone();
                    let service = self.service.clone();
                    tokio::spawn(async move {
                        handle_relay_connection(
                            conn,
                            service,
                            agent_connections,
                            pending_connections,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    error!("Relay accept error: {}", e);
                    break;
                }
            }
        }
    }

    /// Get the number of active agent connections.
    pub fn agent_connection_count(&self) -> usize {
        self.agent_connections.lock().unwrap().len()
    }

    /// Get the number of pending data connections.
    pub fn pending_connection_count(&self) -> usize {
        self.pending_connections.lock().unwrap().len()
    }
}

/// Handle a single relay connection: accept bi-streams and dispatch.
async fn handle_relay_connection(
    conn: QuicConnection,
    service: Arc<Mutex<RelayV1Service>>,
    agent_connections: Arc<Mutex<HashMap<AgentId, QuicConnection>>>,
    pending_connections: Arc<Mutex<HashMap<u64, PendingConnection>>>,
) {
    let remote = conn.remote_address();
    debug!("Relay: new connection from {}", remote);

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let stream_id = send.id();
                let service = service.clone();
                let agent_connections = agent_connections.clone();
                let pending_connections = pending_connections.clone();
                let conn_clone = conn.clone();
                tokio::spawn(async move {
                    handle_bi_stream(
                        send,
                        recv,
                        stream_id,
                        service,
                        agent_connections,
                        pending_connections,
                        conn_clone,
                    )
                    .await;
                });
            }
            Err(e) => {
                debug!("Relay: connection from {} closed: {}", remote, e);
                break;
            }
        }
    }
}

/// Handle a single bi-stream on a relay connection.
///
/// The first bi-stream from a connection is treated as the control stream
/// (RPC). Subsequent bi-streams are data streams (with connection_id header).
async fn handle_bi_stream(
    mut send: QuicSendStream,
    mut recv: QuicRecvStream,
    stream_id: u64,
    service: Arc<Mutex<RelayV1Service>>,
    agent_connections: Arc<Mutex<HashMap<AgentId, QuicConnection>>>,
    pending_connections: Arc<Mutex<HashMap<u64, PendingConnection>>>,
    conn: QuicConnection,
) {
    // Read the first byte to determine if this is a control or data stream.
    let mut header_buf = [0u8; 1];
    let n = match recv.read(&mut header_buf).await {
        Ok(Some(n)) => n,
        _ => return,
    };
    if n == 0 {
        return;
    }

    if header_buf[0] == DATA_STREAM_MAGIC {
        // Data stream: read connection_id and start forwarding
        handle_data_stream(send, recv, pending_connections).await;
    } else {
        // Control stream: treat the first byte as part of the RPC request.
        // Read the rest of the request.
        handle_control_stream(
            &mut send,
            &mut recv,
            header_buf[0],
            service,
            agent_connections,
            pending_connections,
            conn,
        )
        .await;
    }
    let _ = stream_id;
}

/// Handle a control stream (RPC request/response).
async fn handle_control_stream(
    send: &mut QuicSendStream,
    recv: &mut QuicRecvStream,
    first_byte: u8,
    service: Arc<Mutex<RelayV1Service>>,
    agent_connections: Arc<Mutex<HashMap<AgentId, QuicConnection>>>,
    pending_connections: Arc<Mutex<HashMap<u64, PendingConnection>>>,
    conn: QuicConnection,
) {
    // Read the rest of the RPC request
    let mut buf = vec![0u8; 4096];
    buf[0] = first_byte;
    let mut total = 1;
    while total < buf.len() {
        match recv.read(&mut buf[total..]).await {
            Ok(Some(n)) => {
                total += n;
                // Try to decode — if it succeeds, we have the full request
                if let Ok((_, remaining)) = decode(&buf[..total]) {
                    if remaining == 0 {
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => return,
        }
    }

    // Decode RPC request
    let request = match RpcRequest::decode(&buf[..total]) {
        Ok(req) => req,
        Err(e) => {
            warn!("Relay: failed to decode RPC request: {}", e);
            return;
        }
    };

    // Get caller_id — for now, we use a placeholder (in production, this
    // would come from the authenticated QUIC connection's identity).
    // The caller_id is extracted from the QUIC connection's TLS identity.
    // For testing, we pass it in the RPC params as an extra field.
    // In production, the relay would extract it from the TLS cert.
    let caller_id = extract_caller_id(&request, &conn);

    // Handle the RPC — split into sync (service lock) and async (stream ops)
    // to avoid holding std::sync::MutexGuard across .await points.
    enum RpcOutcome {
        Reserve(ReserveResult),
        ConnectNeedsTarget(u64, AgentId), // connection_id, target
        Error(RelayV1Error),
        ParamError(String),
    }

    // Parse params BEFORE locking the service
    let outcome = match request.method.as_str() {
        METHOD_RESERVE => match crate::relay_v1::ReserveParams::from_cbor(&request.params) {
            Ok(p) => {
                let result = service.lock().unwrap().handle_reserve(&caller_id, &p);
                match result {
                    Ok(r) => {
                        agent_connections
                            .lock()
                            .unwrap()
                            .insert(caller_id, conn.clone());
                        RpcOutcome::Reserve(r)
                    }
                    Err(e) => RpcOutcome::Error(e),
                }
            }
            Err(e) => RpcOutcome::ParamError(e.to_string()),
        },
        METHOD_CONNECT => match crate::relay_v1::ConnectParams::from_cbor(&request.params) {
            Ok(p) => {
                let result = service.lock().unwrap().handle_connect(&caller_id, &p);
                match result {
                    Ok(r) => RpcOutcome::ConnectNeedsTarget(r.connection_id, p.target),
                    Err(e) => RpcOutcome::Error(e),
                }
            }
            Err(e) => RpcOutcome::ParamError(e.to_string()),
        },
        _ => {
            let _ = send_error_response(
                send,
                request.id,
                &format!("unknown method: {}", request.method),
            )
            .await;
            return;
        }
    };

    // Process the outcome (async operations happen here, lock-free)
    let result: Result<Value, String> = match outcome {
        RpcOutcome::Reserve(result) => Ok(result.to_cbor()),
        RpcOutcome::Error(e) => Err(e.to_string()),
        RpcOutcome::ParamError(msg) => Err(msg),
        RpcOutcome::ConnectNeedsTarget(connection_id, target) => {
            // Look up the target's QUIC connection (no service lock needed)
            let target_conn = agent_connections.lock().unwrap().get(&target).cloned();
            match target_conn {
                Some(target_quic_conn) => {
                    // Open a bi-stream to the target (async)
                    match target_quic_conn.open_bi().await {
                        Ok((mut target_send, target_recv)) => {
                            // Send incoming connection header to target
                            let mut header = vec![INCOMING_STREAM_MAGIC];
                            header.extend_from_slice(&connection_id.to_be_bytes());
                            if target_send.write_all(&header).await.is_err() {
                                let _ = send_error_response(
                                    send,
                                    request.id,
                                    "failed to send target header",
                                )
                                .await;
                                return;
                            }
                            // Store pending connection
                            pending_connections.lock().unwrap().insert(
                                connection_id,
                                PendingConnection {
                                    target_send,
                                    target_recv,
                                },
                            );
                            Ok(ConnectResult::new(connection_id).to_cbor()) as Result<Value, String>
                        }
                        Err(e) => {
                            let _ = send_error_response(
                                send,
                                request.id,
                                &format!("failed to open target stream: {}", e),
                            )
                            .await;
                            return;
                        }
                    }
                }
                None => {
                    let _ =
                        send_error_response(send, request.id, "target has no active connection")
                            .await;
                    return;
                }
            }
        }
    };

    // Send response
    match result {
        Ok(result_val) => {
            let response = RpcResponse {
                id: request.id,
                result: Some(result_val),
                error: None,
            };
            let encoded = match response.encode() {
                Ok(data) => data,
                Err(e) => {
                    error!("Relay: failed to encode response: {}", e);
                    return;
                }
            };
            let _ = send.write_all(&encoded).await;
            send.finish();
        }
        Err(msg) => {
            let _ = send_error_response(send, request.id, &msg).await;
        }
    }
}

/// Handle a data stream: read connection_id header and start forwarding.
async fn handle_data_stream(
    send: QuicSendStream,
    mut recv: QuicRecvStream,
    pending_connections: Arc<Mutex<HashMap<u64, PendingConnection>>>,
) {
    // The magic byte (0xFF) was already read in handle_bi_stream.
    // Read the remaining 8 bytes of the connection_id (big-endian).
    let mut id_buf = [0u8; 8];
    if recv.read_exact(&mut id_buf).await.is_err() {
        warn!("Relay: failed to read connection_id from data stream");
        return;
    }
    let connection_id = u64::from_be_bytes(id_buf);

    // Look up the pending target stream
    let pending = pending_connections.lock().unwrap().remove(&connection_id);
    let pending = match pending {
        Some(p) => p,
        None => {
            warn!("Relay: no pending connection for id {}", connection_id);
            return;
        }
    };

    debug!(
        "Relay: starting data forwarding for connection {}",
        connection_id
    );

    // Forward data bidirectionally
    forward_data(recv, send, pending.target_send, pending.target_recv).await;
}

/// Forward data bidirectionally between caller and target (RFC 0010 §4.2).
///
/// Spawns two tasks:
/// - caller_recv → target_send
/// - target_recv → caller_send
///
/// Returns when either direction closes.
pub async fn forward_data(
    caller_recv: QuicRecvStream,
    caller_send: QuicSendStream,
    target_send: QuicSendStream,
    target_recv: QuicRecvStream,
) {
    let (mut caller_recv, mut caller_send, mut target_send, mut target_recv) =
        (caller_recv, caller_send, target_send, target_recv);

    // Task 1: caller → target
    let task1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match caller_recv.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => {
                    if target_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        target_send.finish();
    });

    // Task 2: target → caller
    let task2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match target_recv.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => {
                    if caller_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        caller_send.finish();
    });

    // Wait for both directions to close
    let _ = task1.await;
    let _ = task2.await;
    debug!("Relay: data forwarding complete");
}

/// Send an error RPC response.
async fn send_error_response(send: &mut QuicSendStream, id: u64, message: &str) -> Result<(), ()> {
    let response = RpcResponse {
        id,
        result: None,
        error: Some(RpcErrorObject::new(1, message)),
    };
    let encoded = response.encode().map_err(|_| ())?;
    send.write_all(&encoded).await.map_err(|_| ())?;
    send.finish();
    Ok(())
}

/// Extract caller_id from an RPC request.
///
/// In production, this would come from the authenticated QUIC connection's
/// TLS identity. For now, we extract it from the RPC params (field 99:
/// caller_id) if present, or use a default.
fn extract_caller_id(request: &RpcRequest, _conn: &QuicConnection) -> AgentId {
    // Check if the params contain a caller_id field (key 99)
    if let Some(Value::ByteString(b)) = int_map_get(&request.params, 99) {
        if b.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            return arr;
        }
    }
    // Fallback: use a default agent ID (for testing without auth)
    [0u8; 32]
}

// Helper: encode a reserve request with caller_id
pub fn encode_reserve_request_with_caller(
    correlation_id: u64,
    duration_secs: u64,
    caller_id: AgentId,
) -> Result<Vec<u8>, RelayV1Error> {
    let mut params = aafp_cbor::int_map(vec![(1, Value::Unsigned(duration_secs))]);
    if let Value::IntMap(ref mut entries) = params {
        entries.push((99, Value::ByteString(caller_id.to_vec())));
    }
    let request = RpcRequest {
        id: correlation_id,
        method: METHOD_RESERVE.to_string(),
        params,
    };
    encode(&request.to_cbor()).map_err(RelayV1Error::Cbor)
}

/// Encode a connect request with caller_id.
pub fn encode_connect_request_with_caller(
    correlation_id: u64,
    target: AgentId,
    caller_id: AgentId,
) -> Result<Vec<u8>, RelayV1Error> {
    let mut params = aafp_cbor::int_map(vec![(1, Value::ByteString(target.to_vec()))]);
    if let Value::IntMap(ref mut entries) = params {
        entries.push((99, Value::ByteString(caller_id.to_vec())));
    }
    let request = RpcRequest {
        id: correlation_id,
        method: METHOD_CONNECT.to_string(),
        params,
    };
    encode(&request.to_cbor()).map_err(RelayV1Error::Cbor)
}

/// Target-side handler: connects to relay, reserves, and accepts incoming
/// relayed connections (RFC 0010 §4).
pub struct RelayV1TargetHandler {
    /// Connection to the relay.
    relay_conn: QuicConnection,
    /// The target's AgentId.
    agent_id: AgentId,
    /// Reservation ID (set after reserve).
    reservation_id: Option<u64>,
}

impl RelayV1TargetHandler {
    /// Create a new target handler with an existing relay connection.
    pub fn new(relay_conn: QuicConnection, agent_id: AgentId) -> Self {
        Self {
            relay_conn,
            agent_id,
            reservation_id: None,
        }
    }

    /// Reserve on the relay and start accepting incoming relayed connections.
    ///
    /// Returns the reservation result. The caller should then call
    /// `accept_incoming()` to accept relayed connections.
    pub async fn reserve(
        &mut self,
        relay_addr: &str,
        duration_secs: u64,
    ) -> Result<ReserveResult, RelayV1Error> {
        // Open a control stream
        let (mut send, mut recv) = self.relay_conn.open_bi().await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;

        // Send reserve request
        let request = encode_reserve_request_with_caller(1, duration_secs, self.agent_id)?;
        send.write_all(&request).await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;
        send.finish();

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| {
                RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                    offset: 0,
                    message: e.to_string(),
                })
            })?
            .ok_or(RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: "connection closed".into(),
            }))?;

        let result = crate::relay_v1::RelayV1Client::decode_reserve_response(&buf[..n])?;
        self.reservation_id = Some(result.reservation_id);
        let _ = relay_addr;
        Ok(result)
    }

    /// Accept an incoming relayed connection.
    ///
    /// Returns the connection_id and the bi-stream (send, recv) for the
    /// incoming connection. The caller can then read/write data on this stream.
    pub async fn accept_incoming(
        &self,
    ) -> Result<(u64, QuicSendStream, QuicRecvStream), RelayV1Error> {
        let (send, mut recv) = self.relay_conn.accept_bi().await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;

        // Read the incoming connection header: [0xFE + 8 bytes connection_id]
        let mut header = [0u8; DATA_STREAM_HEADER_LEN];
        recv.read_exact(&mut header).await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;

        if header[0] != INCOMING_STREAM_MAGIC {
            return Err(RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: "invalid incoming stream header".into(),
            }));
        }

        let connection_id = u64::from_be_bytes([
            header[1], header[2], header[3], header[4], header[5], header[6], header[7], header[8],
        ]);

        Ok((connection_id, send, recv))
    }

    /// Get the reservation ID.
    pub fn reservation_id(&self) -> Option<u64> {
        self.reservation_id
    }

    /// Get a reference to the relay connection.
    pub fn relay_connection(&self) -> &QuicConnection {
        &self.relay_conn
    }
}

/// Caller-side helper: connect to a target through a relay.
///
/// This is a convenience function that:
/// 1. Sends a connect RPC to the relay
/// 2. Opens a data bi-stream with the connection_id header
/// 3. Returns the data stream for the caller to read/write
pub struct RelayV1CallerHelper;

impl RelayV1CallerHelper {
    /// Connect to a target through the relay.
    ///
    /// `relay_conn` is an existing QUIC connection to the relay.
    /// Returns (connection_id, send_stream, recv_stream) for data exchange.
    pub async fn connect(
        relay_conn: &QuicConnection,
        target: AgentId,
        caller_id: AgentId,
    ) -> Result<(u64, QuicSendStream, QuicRecvStream), RelayV1Error> {
        // Step 1: Send connect RPC on a control stream
        let (mut ctrl_send, mut ctrl_recv) = relay_conn.open_bi().await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;

        let request = encode_connect_request_with_caller(1, target, caller_id)?;
        ctrl_send.write_all(&request).await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;
        ctrl_send.finish();

        // Read connect response
        let mut buf = vec![0u8; 4096];
        let n = ctrl_recv
            .read(&mut buf)
            .await
            .map_err(|e| {
                RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                    offset: 0,
                    message: e.to_string(),
                })
            })?
            .ok_or(RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: "connection closed".into(),
            }))?;

        let connect_result = crate::relay_v1::RelayV1Client::decode_connect_response(&buf[..n])?;
        let connection_id = connect_result.connection_id;

        // Step 2: Open a data bi-stream with the connection_id header
        let (mut data_send, data_recv) = relay_conn.open_bi().await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;

        // Write header: [0xFF + connection_id]
        let mut header = vec![DATA_STREAM_MAGIC];
        header.extend_from_slice(&connection_id.to_be_bytes());
        data_send.write_all(&header).await.map_err(|e| {
            RelayV1Error::Cbor(aafp_cbor::CborError::Invalid {
                offset: 0,
                message: e.to_string(),
            })
        })?;

        Ok((connection_id, data_send, data_recv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_transport_quic::{QuicConfig, QuicTransport};

    fn make_agent_id(byte: u8) -> AgentId {
        [byte; 32]
    }

    #[test]
    fn test_wire_format_constants() {
        assert_eq!(DATA_STREAM_MAGIC, 0xFF);
        assert_eq!(INCOMING_STREAM_MAGIC, 0xFE);
        assert_eq!(DATA_STREAM_HEADER_LEN, 9);
    }

    #[test]
    fn test_encode_reserve_with_caller() {
        let caller = make_agent_id(1);
        let encoded = encode_reserve_request_with_caller(1, 3600, caller).unwrap();
        assert!(!encoded.is_empty());

        let request = RpcRequest::decode(&encoded).unwrap();
        assert_eq!(request.id, 1);
        assert_eq!(request.method, METHOD_RESERVE);
    }

    #[test]
    fn test_encode_connect_with_caller() {
        let target = make_agent_id(2);
        let caller = make_agent_id(1);
        let encoded = encode_connect_request_with_caller(1, target, caller).unwrap();
        let request = RpcRequest::decode(&encoded).unwrap();
        assert_eq!(request.id, 1);
        assert_eq!(request.method, METHOD_CONNECT);
    }

    #[tokio::test]
    async fn test_relay_end_to_end_forwarding() {
        // This test creates a relay, a target B, and a caller A,
        // then forwards data through the relay.

        // 1. Start relay
        let relay_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
        let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
        let relay_server = RelayV1Server::with_defaults(relay_transport);

        // Spawn relay accept loop
        tokio::spawn(async move {
            relay_server.run().await;
        });

        // Give relay time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 2. Start target B
        let b_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create B transport");
        let b_id = make_agent_id(2);

        // B connects to relay
        let b_relay_conn = b_transport.dial(&relay_addr).await.expect("B dial relay");
        let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);

        // B reserves on relay
        let reserve_result = b_target
            .reserve(&relay_addr, 3600)
            .await
            .expect("B reserve");
        assert!(reserve_result.reservation_id > 0);

        // Spawn B's accept loop
        let b_accept_handle = tokio::spawn(async move {
            // Accept incoming relayed connection
            let (conn_id, mut b_send, mut b_recv) =
                b_target.accept_incoming().await.expect("B accept incoming");

            // Read message from A
            let mut buf = vec![0u8; 1024];
            let n = b_recv.read(&mut buf).await.unwrap().unwrap();
            let msg = String::from_utf8_lossy(&buf[..n]);
            assert_eq!(msg, "Hello through relay!");

            // Send reply
            b_send.write_all(b"Reply from B!").await.unwrap();
            b_send.finish();

            conn_id
        });

        // 3. Caller A connects to relay
        let a_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create A transport");
        let a_id = make_agent_id(1);

        let a_relay_conn = a_transport.dial(&relay_addr).await.expect("A dial relay");

        // A connects to B through relay
        let (conn_id, mut a_send, mut a_recv) =
            RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
                .await
                .expect("A connect to B");

        assert!(conn_id > 0);

        // A sends message
        a_send.write_all(b"Hello through relay!").await.unwrap();

        // A reads reply
        let mut reply_buf = vec![0u8; 1024];
        let n = a_recv.read(&mut reply_buf).await.unwrap().unwrap();
        let reply = String::from_utf8_lossy(&reply_buf[..n]);
        assert_eq!(reply, "Reply from B!");

        // Wait for B's accept to complete
        let b_conn_id = b_accept_handle.await.unwrap();
        assert_eq!(b_conn_id, conn_id);

        // Close connections
        a_relay_conn.close(0, b"done");
        b_relay_conn.close(0, b"done");
    }

    #[tokio::test]
    async fn test_relay_multiple_messages() {
        // Test multiple back-and-forth messages through the relay.

        // 1. Start relay
        let relay_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
        let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
        let relay_server = RelayV1Server::with_defaults(relay_transport);

        tokio::spawn(async move {
            relay_server.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 2. Target B
        let b_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create B transport");
        let b_id = make_agent_id(2);
        let b_relay_conn = b_transport.dial(&relay_addr).await.expect("B dial relay");
        let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
        b_target.reserve(&relay_addr, 3600).await.unwrap();

        let b_handle = tokio::spawn(async move {
            let (_conn_id, mut b_send, mut b_recv) =
                b_target.accept_incoming().await.expect("B accept");

            // Echo loop: read message, send echo back
            for i in 0..3 {
                let mut buf = vec![0u8; 1024];
                let n = b_recv.read(&mut buf).await.unwrap().unwrap();
                let msg = String::from_utf8_lossy(&buf[..n]);
                let expected = format!("Message {}", i);
                assert_eq!(msg, expected);

                let reply = format!("Echo {}", i);
                b_send.write_all(reply.as_bytes()).await.unwrap();
            }
            b_send.finish();
        });

        // 3. Caller A
        let a_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create A transport");
        let a_id = make_agent_id(1);
        let a_relay_conn = a_transport.dial(&relay_addr).await.expect("A dial relay");

        let (_conn_id, mut a_send, mut a_recv) =
            RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
                .await
                .expect("A connect");

        // Send 3 messages, read 3 echoes
        for i in 0..3 {
            let msg = format!("Message {}", i);
            a_send.write_all(msg.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = a_recv.read(&mut buf).await.unwrap().unwrap();
            let reply = String::from_utf8_lossy(&buf[..n]);
            let expected = format!("Echo {}", i);
            assert_eq!(reply, expected);
        }

        b_handle.await.unwrap();
        a_relay_conn.close(0, b"done");
        b_relay_conn.close(0, b"done");
    }

    #[tokio::test]
    async fn test_relay_connection_close_cleanup() {
        // Test that closing one side cleans up the connection.

        let relay_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create relay transport");
        let relay_addr = format!("quic://{}", relay_transport.local_addr().unwrap());
        let relay_server = RelayV1Server::with_defaults(relay_transport);

        tokio::spawn(async move {
            relay_server.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let b_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create B transport");
        let b_id = make_agent_id(2);
        let b_relay_conn = b_transport.dial(&relay_addr).await.expect("B dial relay");
        let mut b_target = RelayV1TargetHandler::new(b_relay_conn.clone(), b_id);
        b_target.reserve(&relay_addr, 3600).await.unwrap();

        let b_handle = tokio::spawn(async move {
            let (_conn_id, mut b_send, mut b_recv) =
                b_target.accept_incoming().await.expect("B accept");

            // Read one message
            let mut buf = vec![0u8; 1024];
            let _ = b_recv.read(&mut buf).await;

            // Close the send side
            b_send.finish();
        });

        let a_transport =
            QuicTransport::new(QuicConfig::default()).expect("failed to create A transport");
        let a_id = make_agent_id(1);
        let a_relay_conn = a_transport.dial(&relay_addr).await.expect("A dial relay");

        let (_conn_id, mut a_send, mut a_recv) =
            RelayV1CallerHelper::connect(&a_relay_conn, b_id, a_id)
                .await
                .expect("A connect");

        // Send a message then close
        a_send.write_all(b"Hello").await.unwrap();
        a_send.finish();

        // Read should eventually return None or 0 when B closes
        let mut buf = vec![0u8; 1024];
        let _ = a_recv.read(&mut buf).await;

        b_handle.await.unwrap();
        a_relay_conn.close(0, b"done");
        b_relay_conn.close(0, b"done");
    }
}
