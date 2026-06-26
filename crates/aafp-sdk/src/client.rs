//! Agent client: connect to peers, send messages, perform RPC.

use crate::{Agent, SdkError};
use aafp_crypto::{Aead, AeadAlgorithm};
use aafp_identity::AgentId;
use aafp_messaging::{serialize_frame, Frame};
use aafp_transport_quic::QuicConnection;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A connected peer.
pub struct PeerConnection {
    pub agent_id: AgentId,
    pub conn: QuicConnection,
    pub shared_key: [u8; 32],
}

/// Client-side operations for an agent.
pub struct AgentClient {
    /// Active connections keyed by AgentId.
    connections: Arc<Mutex<HashMap<AgentId, PeerConnection>>>,
}

impl AgentClient {
    /// Create a new client.
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Connect to a peer by multiaddr.
    pub async fn connect(&self, agent: &Agent, addr: &str) -> Result<AgentId, SdkError> {
        let conn = agent.transport.dial(addr).await?;
        let remote_addr = conn.remote_address().to_string();

        // For MVP, we derive a placeholder AgentId from the remote address.
        // In production, the application-layer handshake would exchange
        // AgentRecords and verify the peer's ML-DSA-65 identity.
        let mut hasher = sha2::Sha256::new();
        hasher.update(remote_addr.as_bytes());
        let result = hasher.finalize();
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&result);

        // Derive a shared key (for MVP, from the connection's TLS exporter
        // or a placeholder). In production, this comes from the AAFP handshake.
        let shared_key = [0u8; 32]; // Placeholder — real key from handshake.

        let peer_conn = PeerConnection {
            agent_id: peer_id,
            conn,
            shared_key,
        };

        self.connections.lock().await.insert(peer_id, peer_conn);
        Ok(peer_id)
    }

    /// Send a message to a connected peer.
    pub async fn send(&self, peer_id: &AgentId, data: &[u8]) -> Result<(), SdkError> {
        let mut conns = self.connections.lock().await;
        let peer = conns
            .get_mut(peer_id)
            .ok_or(SdkError::NotConnected)?;

        let (mut send, _recv) = peer.conn.open_bi().await?;
        let frame = serialize_frame(data);
        send.write_all(&frame).await?;
        send.finish();
        Ok(())
    }

    /// Send a message and receive a response (request/response pattern).
    pub async fn send_and_receive(
        &self,
        peer_id: &AgentId,
        data: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        let mut conns = self.connections.lock().await;
        let peer = conns
            .get_mut(peer_id)
            .ok_or(SdkError::NotConnected)?;

        let (mut send, mut recv) = peer.conn.open_bi().await?;
        let frame = serialize_frame(data);
        send.write_all(&frame).await?;
        send.finish();

        // Read response frame.
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await?;
        Ok(payload)
    }

    /// Disconnect from a peer.
    pub async fn disconnect(&self, peer_id: &AgentId) -> Result<(), SdkError> {
        let mut conns = self.connections.lock().await;
        if let Some(peer) = conns.remove(peer_id) {
            peer.conn.close(0, b"disconnect");
        }
        Ok(())
    }

    /// Get the number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Get all connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<AgentId> {
        self.connections.lock().await.keys().copied().collect()
    }

    /// Check if connected to a peer.
    pub async fn is_connected(&self, peer_id: &AgentId) -> bool {
        self.connections.lock().await.contains_key(peer_id)
    }
}

impl Default for AgentClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentBuilder;

    #[tokio::test]
    async fn client_basic() {
        let agent = AgentBuilder::new().build().await.unwrap();
        let client = AgentClient::new();
        assert_eq!(client.connection_count().await, 0);
        assert!(client.connected_peers().await.is_empty());
    }
}
