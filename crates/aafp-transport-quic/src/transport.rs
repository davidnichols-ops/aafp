//! QUIC transport implementation using `quinn`.
//!
//! Provides async connection establishment, bidirectional streams, and
//! post-quantum key exchange (X25519MLKEM768) via rustls + aws-lc-rs.

use crate::config::{generate_self_signed_cert, QuicConfig, TlsIdentity};
use aafp_core::{Error, Multiaddr};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use tracing::info;

/// A QUIC endpoint (server + client combined).
pub struct QuicTransport {
    endpoint: Endpoint,
    config: QuicConfig,
    identity: TlsIdentity,
}

impl QuicTransport {
    /// Create a new QUIC transport with a self-signed certificate.
    pub fn new(config: QuicConfig) -> Result<Self, Error> {
        let identity = generate_self_signed_cert().map_err(|e| Error::Transport(e.to_string()))?;
        let server_config = config
            .build_server_config(&identity)
            .map_err(|e| Error::Transport(e.to_string()))?;

        let endpoint = Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| Error::Transport(e.to_string()))?;

        info!(
            "QUIC endpoint listening on {}",
            endpoint
                .local_addr()
                .map_err(|e| Error::Transport(e.to_string()))?
        );

        Ok(Self {
            endpoint,
            config,
            identity,
        })
    }

    /// Get the local bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Get the local multiaddr.
    pub fn local_multiaddr(&self) -> Result<Multiaddr, Error> {
        let addr = self.local_addr()?;
        Ok(format!("quic://{}", addr))
    }

    /// Dial a remote peer by address.
    pub async fn dial(&self, addr: &str) -> Result<QuicConnection, Error> {
        let socket_addr = parse_multiaddr(addr)?;
        let client_config = self
            .config
            .build_client_config()
            .map_err(|e| Error::Dial(e.to_string()))?;

        let conn = self
            .endpoint
            .connect_with(client_config, socket_addr, "localhost")
            .map_err(|e| Error::Dial(e.to_string()))?
            .await
            .map_err(|e| Error::Dial(e.to_string()))?;

        info!("Connected to {}", socket_addr);
        Ok(QuicConnection::new(conn))
    }

    /// Accept an incoming connection.
    pub async fn accept(&self) -> Result<QuicConnection, Error> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::Listen("endpoint closed".into()))?;

        let conn = incoming
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        info!("Accepted connection from {}", conn.remote_address());
        Ok(QuicConnection::new(conn))
    }

    /// Close the endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }

    /// Wait for all connections on the endpoint to be cleanly shut down.
    ///
    /// Call after `close()` to ensure peers are notified before process
    /// exit. This drains quinn's background tasks, preventing use-after-free
    /// crashes when the tokio runtime is dropped.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// Get the TLS identity (cert + key).
    pub fn identity(&self) -> &TlsIdentity {
        &self.identity
    }
}

/// A QUIC connection wrapping a quinn::Connection.
///
/// `quinn::Connection` is internally `Arc`-based, so cloning a
/// `QuicConnection` is cheap and shares the same underlying connection.
#[derive(Clone)]
pub struct QuicConnection {
    conn: Connection,
}

impl QuicConnection {
    fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// Get the remote address.
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Get the remote multiaddr.
    pub fn remote_multiaddr(&self) -> Multiaddr {
        format!("quic://{}", self.conn.remote_address())
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(QuicSendStream, QuicRecvStream), Error> {
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::Stream(e.to_string()))?;
        Ok((QuicSendStream::new(send), QuicRecvStream::new(recv)))
    }

    /// Open a unidirectional stream.
    pub async fn open_uni(&self) -> Result<QuicSendStream, Error> {
        let send = self
            .conn
            .open_uni()
            .await
            .map_err(|e| Error::Stream(e.to_string()))?;
        Ok(QuicSendStream::new(send))
    }

    /// Accept a bidirectional stream from the peer.
    pub async fn accept_bi(&self) -> Result<(QuicSendStream, QuicRecvStream), Error> {
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| Error::Stream(e.to_string()))?;
        Ok((QuicSendStream::new(send), QuicRecvStream::new(recv)))
    }

    /// Accept a unidirectional stream from the peer.
    pub async fn accept_uni(&self) -> Result<QuicRecvStream, Error> {
        let recv = self
            .conn
            .accept_uni()
            .await
            .map_err(|e| Error::Stream(e.to_string()))?;
        Ok(QuicRecvStream::new(recv))
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code.into(), reason);
    }

    /// Export TLS channel binding material using the TLS exporter (RFC 5705).
    ///
    /// This wraps `quinn::Connection::export_keying_material()` to provide
    /// access to TLS channel binding without exposing the underlying quinn
    /// connection. The binding material is used by the AAFP v1 handshake to
    /// bind the application-layer identity verification to the TLS session,
    /// preventing man-in-the-middle attacks.
    ///
    /// # Arguments
    ///
    /// * `label` - A label string that identifies the intended use of the
    ///   exported keying material (e.g., `TLS_EXPORTER_LABEL`).
    /// * `context` - Optional context string (pass empty `&[]` if not needed).
    ///
    /// # Returns
    ///
    /// A 32-byte binding material derived from the TLS session keys.
    ///
    /// # Errors
    ///
    /// Returns `Error::Transport` if the TLS exporter fails (e.g., if the
    /// handshake has not completed or the connection is closed).
    pub fn export_tls_binding(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], Error> {
        let mut binding = [0u8; 32];
        self.conn
            .export_keying_material(&mut binding, label, context)
            .map_err(|e| Error::Transport(format!("TLS exporter failed: {e:?}")))?;
        Ok(binding)
    }

    /// Get the quinn connection (for advanced use).
    ///
    /// **Deprecated:** This method exposes the underlying `quinn::Connection`,
    /// creating a leaky abstraction. New code should use `export_tls_binding()`
    /// or other typed methods instead. This method is retained for backwards
    /// compatibility but may be removed in a future version.
    #[deprecated(
        since = "0.1.0",
        note = "use `export_tls_binding()` or other typed methods instead"
    )]
    pub fn raw(&self) -> &Connection {
        &self.conn
    }
}

/// A QUIC send stream.
pub struct QuicSendStream {
    inner: SendStream,
}

impl QuicSendStream {
    fn new(stream: SendStream) -> Self {
        Self { inner: stream }
    }

    /// Write data to the stream.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.inner
            .write(data)
            .await
            .map_err(|e| Error::Stream(e.to_string()))
    }

    /// Write all data to the stream.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner
            .write_all(data)
            .await
            .map_err(|e| Error::Stream(e.to_string()))
    }

    /// Finish the stream (send FIN).
    pub fn finish(&mut self) {
        let _ = self.inner.finish();
    }

    /// Reset the stream.
    pub fn reset(&mut self, code: u32) {
        let _ = self.inner.reset(code.into());
    }

    /// Get the stream ID.
    pub fn id(&self) -> u64 {
        self.inner.id().into()
    }
}

/// A QUIC receive stream.
pub struct QuicRecvStream {
    inner: RecvStream,
}

impl QuicRecvStream {
    fn new(stream: RecvStream) -> Self {
        Self { inner: stream }
    }

    /// Read data from the stream.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        self.inner
            .read(buf)
            .await
            .map_err(|e| Error::Stream(e.to_string()))
    }

    /// Read exactly `buf.len()` bytes.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.inner
            .read_exact(buf)
            .await
            .map_err(|e| Error::Stream(e.to_string()))
    }

    /// Stop the stream with a reason code.
    pub fn stop(&mut self, code: u32) {
        let _ = self.inner.stop(code.into());
    }

    /// Get the stream ID.
    pub fn id(&self) -> u64 {
        self.inner.id().into()
    }
}

/// Parse a multiaddr string (e.g., "quic://1.2.3.4:4433") into a SocketAddr.
fn parse_multiaddr(addr: &str) -> Result<SocketAddr, Error> {
    let addr = addr
        .strip_prefix("quic://")
        .ok_or_else(|| Error::Dial(format!("invalid multiaddr: {}", addr)))?;
    addr.parse::<SocketAddr>()
        .map_err(|e| Error::Dial(format!("invalid address: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn parse_multiaddrs() {
        assert!(parse_multiaddr("quic://127.0.0.1:4433").is_ok());
        assert!(parse_multiaddr("quic://[::1]:4433").is_ok());
        assert!(parse_multiaddr("not-a-multiaddr").is_err());
        assert!(parse_multiaddr("quic://not-an-ip").is_err());
    }

    #[tokio::test]
    async fn create_transport() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let transport = QuicTransport::new(config).unwrap();
        let addr = transport.local_addr().unwrap();
        assert!(addr.port() > 0);
        let multiaddr = transport.local_multiaddr().unwrap();
        assert!(multiaddr.starts_with("quic://"));
        transport.close();
    }

    #[tokio::test]
    async fn connect_and_stream() {
        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server = Arc::new(QuicTransport::new(server_config).unwrap());
        let server_addr = server.local_multiaddr().unwrap();

        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let client = QuicTransport::new(client_config).unwrap();

        // Spawn server acceptor (keep server alive via Arc).
        let server_clone = server.clone();
        let server_handle = tokio::spawn(async move {
            let conn = server_clone.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut buf = [0u8; 5];
            recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            send.write_all(b"world").await.unwrap();
            send.finish();
            // Keep the connection alive briefly so the client can read.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        // Client connects and opens a stream.
        let conn = client.dial(&server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hello").await.unwrap();
        send.finish();

        let mut buf = [0u8; 5];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        server_handle.await.unwrap();
        client.close();
        // Keep server alive until after client closes.
        drop(server);
    }
}
