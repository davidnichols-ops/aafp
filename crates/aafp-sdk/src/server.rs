//! Agent server: accept incoming connections and handle messages.
//!
//! All incoming connections require a completed AAFP v1 handshake before
//! application messages can be processed. There is no code path where an
//! unauthenticated peer can send application messages.

use crate::{establish_session, Agent, SdkError};
use aafp_core::{AuthorizationProvider, Session, SessionState};
use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// A server-side authenticated peer connection.
pub struct ServerPeerConnection {
    /// The authenticated session for this peer connection.
    pub session: Session,
    /// The underlying QUIC connection to the peer.
    pub conn: aafp_transport_quic::QuicConnection,
}

impl ServerPeerConnection {
    /// Current session state.
    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    /// Verified peer AgentId.
    pub fn peer_agent_id(&self) -> Option<&AgentId> {
        self.session.peer_agent_id()
    }

    /// Whether messaging is active.
    pub fn is_messaging_active(&self) -> bool {
        self.session.state().is_messaging_active()
    }

    /// Check if the peer is authorized for a capability.
    pub fn is_authorized(&self, capability: &str) -> bool {
        self.session.is_authorized(capability)
    }
}

/// Server-side operations for an agent.
pub struct AgentServer {
    /// Whether the server is accepting connections.
    running: Arc<Mutex<bool>>,
    /// Number of connections accepted.
    accepted_count: Arc<Mutex<u64>>,
    /// Active authenticated peer connections.
    connections: Arc<Mutex<HashMap<AgentId, ServerPeerConnection>>>,
    /// Authorization provider (pluggable: UCAN, OIDC, custom, testing).
    auth_provider: Arc<dyn AuthorizationProvider>,
}

impl AgentServer {
    /// Create a new server with the given authorization provider.
    pub fn with_auth_provider(auth_provider: Arc<dyn AuthorizationProvider>) -> Self {
        Self {
            running: Arc::new(Mutex::new(false)),
            accepted_count: Arc::new(Mutex::new(0)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            auth_provider,
        }
    }

    /// Create a new server with a testing auth provider (allows all).
    pub fn new() -> Self {
        Self::with_auth_provider(Arc::new(aafp_core::TestingAuthProvider))
    }

    /// Start accepting connections (runs in background).
    pub async fn start(&self, agent: &Agent) -> Result<(), SdkError> {
        *self.running.lock().await = true;
        info!("Agent server started for {}", hex::encode(agent.id()));
        Ok(())
    }

    /// Stop the server.
    pub async fn stop(&self) {
        *self.running.lock().await = false;
    }

    /// Check if the server is running.
    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }

    /// Get the number of accepted connections.
    pub async fn accepted_count(&self) -> u64 {
        *self.accepted_count.lock().await
    }

    /// Accept one incoming connection, perform the AAFP v1 handshake,
    /// authorize the peer, and store the authenticated connection.
    ///
    /// This performs the full server-side handshake:
    /// 1. Accept QUIC connection
    /// 2. Extract TLS channel binding
    /// 3. Drive server-side handshake (ClientHello → ServerHello → ClientFinished)
    /// 4. Verify peer identity (agent_id == SHA-256(public_key))
    /// 5. Run authorization via the configured provider
    /// 6. Transition session to MessagingEnabled
    /// 7. Store the authenticated connection
    ///
    /// Returns the verified peer AgentId on success.
    pub async fn accept_one(&self, agent: &Agent) -> Result<AgentId, SdkError> {
        let conn = agent.transport.accept().await?;
        *self.accepted_count.lock().await += 1;

        // Drive AAFP v1 handshake + authorization + session transitions
        let (session, conn, peer_info) = establish_session(
            conn,
            &agent.keypair,
            self.auth_provider.clone(),
            false,
            None,
        )
        .await?;

        let peer_id = peer_info.agent_id;

        // Store the authenticated connection
        let server_conn = ServerPeerConnection { session, conn };
        self.connections.lock().await.insert(peer_id, server_conn);

        Ok(peer_id)
    }

    /// Get all authenticated peer IDs.
    pub async fn connected_peers(&self) -> Vec<AgentId> {
        self.connections.lock().await.keys().copied().collect()
    }

    /// Get the number of authenticated connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Get the session state for a peer.
    pub async fn session_state(&self, peer_id: &AgentId) -> Option<SessionState> {
        self.connections
            .lock()
            .await
            .get(peer_id)
            .map(|p| p.session_state())
    }
}

impl Default for AgentServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentBuilder;
    use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
    use aafp_transport_quic::QuicConfig;

    #[tokio::test]
    async fn server_start_stop() {
        let agent = AgentBuilder::new().build().await.unwrap();
        let server = AgentServer::new();
        assert!(!server.is_running().await);
        server.start(&agent).await.unwrap();
        assert!(server.is_running().await);
        server.stop().await;
        assert!(!server.is_running().await);
    }

    #[tokio::test]
    async fn server_accept_and_echo() {
        // Create server agent.
        let server_agent = Arc::new(AgentBuilder::new().build().await.unwrap());
        let server_addr = server_agent.multiaddr().unwrap();

        // Create client transport.
        let client_config = QuicConfig::default();
        let client = aafp_transport_quic::QuicTransport::new(client_config).unwrap();

        // Spawn server to accept one connection and echo.
        // NOTE: This test uses the raw transport (no AAFP handshake) to
        // verify that the QUIC layer still works. The full handshake
        // integration is tested in the handshake_driver tests.
        let server_handle = tokio::spawn(async move {
            let conn = server_agent.transport.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            // Read frame header (28 bytes).
            let mut header = [0u8; FRAME_HEADER_SIZE];
            recv.read_exact(&mut header).await.unwrap();

            // Parse header to determine total frame size.
            let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
            let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
            let body_len = payload_len + ext_len;

            // Read remaining frame data (extensions + payload).
            let mut body = vec![0u8; body_len];
            if body_len > 0 {
                recv.read_exact(&mut body).await.unwrap();
            }

            // Combine header + body and decode.
            let mut full_frame = header.to_vec();
            full_frame.extend_from_slice(&body);
            let (frame, _) = decode_frame(&full_frame).unwrap();

            // Echo back.
            let resp_frame = Frame::data(0, frame.payload.clone());
            let resp_bytes = encode_frame(&resp_frame).unwrap();
            send.write_all(&resp_bytes).await.unwrap();
            send.finish();

            // Keep connection alive so client can read.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        // Client connects and sends a message.
        let conn = client.dial(&server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let msg = b"echo test";
        let msg_frame = Frame::data(0, msg.to_vec());
        let msg_bytes = encode_frame(&msg_frame).unwrap();
        send.write_all(&msg_bytes).await.unwrap();
        send.finish();

        // Read echo response (full frame).
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.unwrap().unwrap_or(0);
        let (resp_frame, _) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(resp_frame.payload, msg);

        server_handle.await.unwrap();
        client.close();
    }
}
