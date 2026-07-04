//! QUIC transport implementation using `quinn`.
//!
//! Provides async connection establishment, bidirectional streams, and
//! post-quantum key exchange (X25519MLKEM768) via rustls + aws-lc-rs.

use crate::config::{generate_self_signed_cert, QuicConfig, TlsIdentity};
use crate::session_cache::SessionCache;
use aafp_core::{Error, Multiaddr};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use tracing::info;

/// A QUIC endpoint (server + client combined).
///
/// When created with [`QuicTransport::new_with_resumption()`], the transport
/// caches a `ClientConfig` with a shared TLS session ticket store. This
/// enables TLS 1.3 session resumption: the first `dial()` to a server
/// performs a full TLS handshake, and subsequent `dial()`s to the same
/// server reuse the cached session ticket (Track I1).
pub struct QuicTransport {
    endpoint: Endpoint,
    config: QuicConfig,
    identity: TlsIdentity,
    /// Cached client config with session resumption (Track I1).
    /// `None` if created with `new()` (no resumption — backward compat).
    client_config: Option<ClientConfig>,
    /// Shared session cache (Track I1). `None` if resumption is not enabled.
    session_cache: Option<SessionCache>,
}

impl QuicTransport {
    /// Create a new QUIC transport with a self-signed certificate.
    ///
    /// This does NOT enable TLS session resumption. Use
    /// [`QuicTransport::new_with_resumption()`] to enable resumption.
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
            client_config: None,
            session_cache: None,
        })
    }

    /// Create a new QUIC transport with TLS session resumption enabled (Track I1).
    ///
    /// The transport caches a `ClientConfig` with a shared `SessionCache`.
    /// All `dial()` calls reuse this config, allowing TLS 1.3 session tickets
    /// to be stored and reused across connections to the same server.
    ///
    /// The server side is also configured to send TLS 1.3 session tickets
    /// (4 tickets per connection) so that clients can resume sessions.
    ///
    /// **When to use this:** When the agent will connect to the same peer
    /// multiple times. The first connection pays the full TLS handshake cost;
    /// subsequent connections can resume the session (skipping the KEX).
    ///
    /// **When NOT to use this:** For one-shot connections where resumption
    /// won't be used. The session cache adds ~200KB memory overhead.
    pub fn new_with_resumption(config: QuicConfig) -> Result<Self, Error> {
        Self::new_with_resumption_cache(config, SessionCache::new())
    }

    /// Create a new QUIC transport with a custom session cache (Track I1).
    ///
    /// Like [`QuicTransport::new_with_resumption()`] but allows specifying
    /// a custom `SessionCache` size.
    pub fn new_with_resumption_cache(
        config: QuicConfig,
        session_cache: SessionCache,
    ) -> Result<Self, Error> {
        let identity = generate_self_signed_cert().map_err(|e| Error::Transport(e.to_string()))?;
        let server_config = config
            .build_server_config(&identity)
            .map_err(|e| Error::Transport(e.to_string()))?;

        let endpoint = Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| Error::Transport(e.to_string()))?;

        // Build and cache the client config with session resumption.
        let client_config = config
            .build_client_config_with_resumption(&session_cache)
            .map_err(|e| Error::Transport(e.to_string()))?;

        info!(
            "QUIC endpoint listening on {} (TLS resumption enabled, cache size {})",
            endpoint
                .local_addr()
                .map_err(|e| Error::Transport(e.to_string()))?,
            session_cache.size()
        );

        Ok(Self {
            endpoint,
            config,
            identity,
            client_config: Some(client_config),
            session_cache: Some(session_cache),
        })
    }

    /// Get the shared session cache, if resumption is enabled.
    ///
    /// Returns `None` if the transport was created with `new()` (no resumption).
    /// The returned `SessionCache` can be inspected or shared with other
    /// transports to share session tickets across endpoints.
    pub fn session_cache(&self) -> Option<&SessionCache> {
        self.session_cache.as_ref()
    }

    /// Check whether TLS session resumption is enabled.
    pub fn has_resumption(&self) -> bool {
        self.client_config.is_some()
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
    ///
    /// If the transport was created with `new_with_resumption()`, the cached
    /// `ClientConfig` (with session resumption) is reused. This allows TLS 1.3
    /// session tickets to be stored and reused across `dial()` calls to the
    /// same server (Track I1).
    ///
    /// If the transport was created with `new()` (no resumption), a fresh
    /// `ClientConfig` is built for each call (backward compatible).
    pub async fn dial(&self, addr: &str) -> Result<QuicConnection, Error> {
        let socket_addr = parse_multiaddr(addr)?;

        // Use cached client config (with resumption) if available, otherwise
        // build a fresh one (backward compatible with new()).
        let client_config = if let Some(cc) = &self.client_config {
            cc.clone()
        } else {
            self.config
                .build_client_config()
                .map_err(|e| Error::Dial(e.to_string()))?
        };

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

    // ----- Track I1: TLS session resumption tests -----

    #[tokio::test]
    async fn create_transport_with_resumption() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let transport = QuicTransport::new_with_resumption(config).unwrap();
        assert!(transport.has_resumption());
        assert!(transport.session_cache().is_some());
        assert_eq!(
            transport.session_cache().unwrap().size(),
            crate::session_cache::DEFAULT_SESSION_CACHE_SIZE
        );
        transport.close();
    }

    #[tokio::test]
    async fn create_transport_without_resumption() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let transport = QuicTransport::new(config).unwrap();
        assert!(!transport.has_resumption());
        assert!(transport.session_cache().is_none());
        transport.close();
    }

    #[tokio::test]
    async fn create_transport_with_custom_cache_size() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let cache = SessionCache::with_size(256);
        let transport = QuicTransport::new_with_resumption_cache(config, cache).unwrap();
        assert_eq!(transport.session_cache().unwrap().size(), 256);
        transport.close();
    }

    /// Verify that two consecutive connections to the same server work
    /// with session resumption enabled. The first connection performs a
    /// full TLS handshake and receives session tickets. The second
    /// connection should be able to resume the session.
    #[tokio::test]
    async fn resumption_two_connections_to_same_server() {
        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server = Arc::new(QuicTransport::new_with_resumption(server_config).unwrap());
        let server_addr = server.local_multiaddr().unwrap();

        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let client = QuicTransport::new_with_resumption(client_config).unwrap();

        // First connection (full handshake)
        let server_clone = server.clone();
        let handle1 = tokio::spawn(async move {
            let conn = server_clone.accept().await.unwrap();
            // Keep alive briefly
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            conn.close(0u32, b"done");
        });

        let conn1 = client.dial(&server_addr).await.unwrap();
        handle1.await.unwrap();

        // Wait for the first connection to fully close so the server can
        // process the session ticket and be ready for the next accept.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Second connection (should reuse session ticket if resumption works)
        let server_clone2 = server.clone();
        let handle2 = tokio::spawn(async move {
            let conn = server_clone2.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            conn.close(0u32, b"done");
        });

        let conn2 = client.dial(&server_addr).await.unwrap();
        handle2.await.unwrap();

        // Both connections succeeded — resumption didn't break anything.
        // (We can't easily verify the ticket was actually reused without
        // inspecting rustls internals, but the connection succeeding with
        // resumption enabled is the key test.)
        drop(conn1);
        drop(conn2);
        client.close();
        drop(server);
    }

    /// Verify that resumption works with bidirectional streams (full
    /// application-level functionality is preserved after resumption).
    #[tokio::test]
    async fn resumption_stream_works_after_reconnect() {
        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server = Arc::new(QuicTransport::new_with_resumption(server_config).unwrap());
        let server_addr = server.local_multiaddr().unwrap();

        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let client = QuicTransport::new_with_resumption(client_config).unwrap();

        // First connection: exchange data
        let server_clone = server.clone();
        let handle1 = tokio::spawn(async move {
            let conn = server_clone.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut buf = [0u8; 5];
            recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            send.write_all(b"world").await.unwrap();
            send.finish();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let conn1 = client.dial(&server_addr).await.unwrap();
        let (mut send, mut recv) = conn1.open_bi().await.unwrap();
        send.write_all(b"hello").await.unwrap();
        send.finish();
        let mut buf = [0u8; 5];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        handle1.await.unwrap();

        // Wait for first connection to settle
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Second connection: exchange data again (with resumption)
        let server_clone2 = server.clone();
        let handle2 = tokio::spawn(async move {
            let conn = server_clone2.accept().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut buf = [0u8; 7];
            recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello2!");
            send.write_all(b"world2!").await.unwrap();
            send.finish();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let conn2 = client.dial(&server_addr).await.unwrap();
        let (mut send, mut recv) = conn2.open_bi().await.unwrap();
        send.write_all(b"hello2!").await.unwrap();
        send.finish();
        let mut buf = [0u8; 7];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world2!");
        handle2.await.unwrap();

        drop(conn1);
        drop(conn2);
        client.close();
        drop(server);
    }
}
