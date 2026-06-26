//! Agent server: accept incoming connections and handle messages.

use crate::{Agent, SdkError};
use aafp_identity::AgentId;
use aafp_messaging::deserialize_frame;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// Server-side operations for an agent.
pub struct AgentServer {
    /// Whether the server is accepting connections.
    running: Arc<Mutex<bool>>,
    /// Number of connections accepted.
    accepted_count: Arc<Mutex<u64>>,
}

impl AgentServer {
    /// Create a new server.
    pub fn new() -> Self {
        Self {
            running: Arc::new(Mutex::new(false)),
            accepted_count: Arc::new(Mutex::new(0)),
        }
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

    /// Accept one incoming connection and handle it.
    ///
    /// For MVP, this reads a single framed message and echoes it back.
    /// A production version would perform the AAFP handshake and route
    /// messages to the appropriate handler.
    pub async fn accept_one(&self, agent: &Agent) -> Result<(), SdkError> {
        let conn = agent.transport.accept().await?;
        *self.accepted_count.lock().await += 1;

        let (mut send, mut recv) = conn.accept_bi().await?;

        // Read a framed message.
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await?;

        // Echo back.
        let frame = aafp_messaging::serialize_frame(&payload);
        send.write_all(&frame).await?;
        send.finish();

        Ok(())
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
    use aafp_messaging::serialize_frame;
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
        let server_handle = tokio::spawn(async move {
            let conn = server_agent.transport.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            // Read framed message.
            let mut len_buf = [0u8; 4];
            recv.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            recv.read_exact(&mut payload).await.unwrap();

            // Echo back.
            let frame = serialize_frame(&payload);
            send.write_all(&frame).await.unwrap();
            send.finish();

            // Keep connection alive so client can read.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        // Client connects and sends a message.
        let conn = client.dial(&server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let msg = b"echo test";
        send.write_all(&serialize_frame(msg)).await.unwrap();
        send.finish();

        // Read echo response.
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, msg);

        server_handle.await.unwrap();
        client.close();
    }
}
