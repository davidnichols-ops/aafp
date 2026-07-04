//! QUIC transport configuration with post-quantum key exchange.
//!
//! Uses `quinn` + `rustls` with the `aws-lc-rs` backend and
//! `prefer-post-quantum` feature, which enables `X25519MLKEM768` hybrid KEX
//! inside the TLS 1.3 handshake.
//!
//! ## Certificate strategy
//! For MVP, each node generates a self-signed Ed25519 certificate for the TLS
//! layer (transport encryption). Agent identity authentication (ML-DSA-65)
//! happens at the application layer via the AAFP handshake, not in TLS.
//! This is because rustls does not yet support ML-DSA-65 in certificate
//! verification. The PQ KEX (X25519MLKEM768) still protects the transport
//! against harvest-now-decrypt-later attacks.

use crate::session_cache::SessionCache;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// ALPN protocol identifier for AAFP v1 (RFC-0002 §2.2, RFC-0006 §2.3).
///
/// Both client and server MUST negotiate this ALPN during the TLS handshake.
/// If ALPN negotiation fails, the connection MUST be closed.
pub const AAFP_ALPN: &[u8] = b"aafp/1";

/// Errors that can occur while building QUIC transport configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A rustls configuration or handshake error.
    #[error("rustls error: {0}")]
    Rustls(String),
    /// An error while generating the self-signed TLS certificate.
    #[error("certificate generation error: {0}")]
    CertGen(String),
    /// A quinn configuration error.
    #[error("quinn error: {0}")]
    Quinn(String),
    /// ALPN negotiation failed because the server did not select `aafp/1`.
    #[error("ALPN negotiation failed: server did not select aafp/1")]
    AlpnFailed,
}

/// A self-signed certificate and private key for QUIC TLS.
pub struct TlsIdentity {
    /// The self-signed DER-encoded certificate used for TLS.
    pub cert: CertificateDer<'static>,
    /// The private key corresponding to the certificate.
    pub key: PrivateKeyDer<'static>,
}

/// Generate a self-signed certificate for QUIC TLS.
pub fn generate_self_signed_cert() -> Result<TlsIdentity, ConfigError> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let key_pair = rcgen::KeyPair::generate().map_err(|e| ConfigError::CertGen(e.to_string()))?;
    let cert_params = rcgen::CertificateParams::new(subject_alt_names)
        .map_err(|e| ConfigError::CertGen(e.to_string()))?;
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| ConfigError::CertGen(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = key_pair.serialize_der();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    Ok(TlsIdentity {
        cert: cert_der,
        key,
    })
}

/// Configuration for the AAFP QUIC transport.
#[derive(Clone)]
pub struct QuicConfig {
    /// Address to bind the QUIC endpoint.
    pub bind_addr: SocketAddr,
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u64,
    /// Keep-alive interval.
    pub keep_alive_interval: Duration,
    /// Enable post-quantum KEX (X25519MLKEM768).
    pub enable_pq: bool,
    /// Congestion controller (Track J1).
    pub congestion: crate::congestion::CongestionController,
    /// Initial RTT estimate (Track J2). Default: 10ms (quinn default: 333ms).
    /// Lower values reduce retransmission timer for LAN/localhost.
    pub initial_rtt: Duration,
    /// Maximum idle timeout (Track J2). Default: 30s.
    pub max_idle_timeout: Duration,
    /// Maximum ACK delay (Track J4). Default: 5ms (quinn default: 25ms).
    /// Lower values make ACKs more frequent, reducing retransmission latency.
    pub max_ack_delay: Duration,
    /// Stream initial max data (Track J3). Default: 1MB (quinn default: 100KB).
    /// Larger window allows the first message to be sent without waiting.
    pub stream_initial_max_data: u64,
    /// Crypto buffer size (Track J2). Default: 8192 bytes.
    /// Tuned for small RPC messages.
    pub crypto_buffer_size: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_concurrent_streams: 100,
            keep_alive_interval: Duration::from_secs(30),
            enable_pq: true,
            congestion: crate::congestion::CongestionController::Cubic,
            initial_rtt: Duration::from_millis(10),
            max_idle_timeout: Duration::from_secs(30),
            max_ack_delay: Duration::from_millis(5),
            stream_initial_max_data: 1024 * 1024, // 1MB
            crypto_buffer_size: 8192,
        }
    }
}

impl QuicConfig {
    /// Low-latency preset for agent-to-agent RPC (Track J1-J4).
    ///
    /// Uses BBR congestion control, 10ms initial RTT, 5ms ACK delay,
    /// 1MB stream window, and 8KB crypto buffer. Optimized for
    /// small-message, low-latency RPC over LAN/localhost.
    pub fn low_latency() -> Self {
        Self {
            congestion: crate::congestion::CongestionController::Bbr,
            initial_rtt: Duration::from_millis(10),
            max_idle_timeout: Duration::from_secs(30),
            max_ack_delay: Duration::from_millis(5),
            stream_initial_max_data: 1024 * 1024, // 1MB
            crypto_buffer_size: 8192,
            ..Default::default()
        }
    }

    /// Bulk transfer preset for file transfer / large payloads (Track J1-J4).
    ///
    /// Uses Cubic congestion control (TCP-friendly), 100ms initial RTT,
    /// 25ms ACK delay, 10MB stream window, and 64KB crypto buffer.
    /// Optimized for high-throughput bulk transfer.
    pub fn bulk_transfer() -> Self {
        Self {
            congestion: crate::congestion::CongestionController::Cubic,
            initial_rtt: Duration::from_millis(100),
            max_idle_timeout: Duration::from_secs(300),
            max_ack_delay: Duration::from_millis(25),
            stream_initial_max_data: 10 * 1024 * 1024, // 10MB
            crypto_buffer_size: 64 * 1024,             // 64KB
            ..Default::default()
        }
    }

    /// Build a tuned `TransportConfig` from this `QuicConfig` (Track J1-J4).
    ///
    /// Applies:
    /// - Congestion controller (J1)
    /// - Initial RTT (J2)
    /// - Max idle timeout (J2)
    /// - Keep-alive interval (J2)
    /// - Stream initial max data (J3)
    /// - Max ACK delay (J4)
    /// - Crypto buffer size (J2)
    /// - Max concurrent streams
    fn build_transport_config(&self) -> TransportConfig {
        let mut transport = TransportConfig::default();

        // J1: Congestion controller
        self.congestion.apply_to_transport_config(&mut transport);

        // J2: Initial RTT (default 333ms → 10ms for LAN/localhost)
        transport.initial_rtt(self.initial_rtt);

        // J2: Max idle timeout
        let idle_timeout = quinn::IdleTimeout::try_from(self.max_idle_timeout)
            .unwrap_or_else(|_| quinn::IdleTimeout::from(VarInt::from_u32(30_000)));
        transport.max_idle_timeout(Some(idle_timeout));

        // J2: Keep-alive interval
        transport.keep_alive_interval(Some(self.keep_alive_interval));

        // J3: Stream receive window (larger window for first message)
        let stream_window = VarInt::from_u64(self.stream_initial_max_data).unwrap_or(VarInt::MAX);
        transport.stream_receive_window(stream_window);

        // J4: Max ACK delay (default 25ms → 5ms for faster feedback)
        // This is set via AckFrequencyConfig, not directly on TransportConfig.
        let mut ack_freq = quinn::AckFrequencyConfig::default();
        ack_freq.max_ack_delay(Some(self.max_ack_delay));
        transport.ack_frequency_config(Some(ack_freq));

        // J2: Crypto buffer size (tuned for small RPC messages)
        transport.crypto_buffer_size(self.crypto_buffer_size as usize);

        // Max concurrent streams
        let max_streams = VarInt::from_u64(self.max_concurrent_streams).unwrap_or(VarInt::MAX);
        transport
            .max_concurrent_uni_streams(max_streams)
            .max_concurrent_bidi_streams(max_streams);

        transport
    }

    /// Build a quinn server config with PQ KEX, self-signed cert, and ALPN.
    ///
    /// The server requires the `aafp/1` ALPN. Connections that do not offer
    /// or select this ALPN are rejected during the TLS handshake (RFC-0002 §2.2).
    pub fn build_server_config(&self, identity: &TlsIdentity) -> Result<ServerConfig, ConfigError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cert_chain = vec![identity.cert.clone()];

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ConfigError::Rustls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, identity.key.clone_key())
            .map_err(|e| ConfigError::Rustls(e.to_string()))?;

        // Require ALPN aafp/1 (RFC-0002 §2.2).
        server_crypto.alpn_protocols = vec![AAFP_ALPN.to_vec()];

        // Send TLS 1.3 session tickets for resumption (Track I1).
        // Default is 2; we send 4 to allow more resumptions per connection.
        // Each ticket is single-use, so more tickets = more resumptions.
        server_crypto.send_tls13_tickets = 4;

        let quic_server_config = QuicServerConfig::try_from(server_crypto)
            .map_err(|e| ConfigError::Quinn(e.to_string()))?;

        let transport_config = self.build_transport_config();

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Build a quinn client config with PQ KEX, no certificate verification
    /// (TOFU — agent identity is verified at the application layer), and ALPN.
    ///
    /// The client advertises the `aafp/1` ALPN. If the server does not select
    /// this ALPN, the TLS handshake fails (RFC-0002 §2.2).
    pub fn build_client_config(&self) -> Result<ClientConfig, ConfigError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

        let root_store = rustls::RootCertStore::empty();
        // For MVP P2P: we skip server cert verification at the TLS layer.
        // Agent identity is authenticated via the AAFP application-layer handshake.
        // This is safe because the PQ KEX still encrypts the transport, and
        // the application-layer handshake binds the TLS session to the agent's
        // ML-DSA-65 identity.

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ConfigError::Rustls(e.to_string()))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Disable certificate verification (TOFU model).
        client_crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));

        // Advertise ALPN aafp/1 (RFC-0002 §2.2).
        client_crypto.alpn_protocols = vec![AAFP_ALPN.to_vec()];

        let quic_client_config = QuicClientConfig::try_from(client_crypto)
            .map_err(|e| ConfigError::Quinn(e.to_string()))?;

        let transport_config = self.build_transport_config();

        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
    }

    /// Build a quinn client config with TLS session resumption enabled (Track I1).
    ///
    /// This is like `build_client_config()` but uses the provided `SessionCache`
    /// to store and retrieve TLS 1.3 session tickets. When the client connects
    /// to a server it has connected to before, the cached ticket is presented,
    /// allowing the server to resume the TLS session without a full key exchange.
    ///
    /// The `SessionCache` should be shared across all `dial()` calls on the
    /// same `QuicTransport` to maximize ticket reuse.
    ///
    /// **Note:** The AAFP application-layer handshake (ML-DSA-65 identity
    /// verification) still runs after TLS resumption. Only the TLS KEX is
    /// skipped — agent identity authentication is not affected.
    ///
    /// **Security:** 0-RTT early data is NOT enabled (replay attack risk).
    /// The client waits for the server's response before sending application
    /// data, same as a full handshake.
    pub fn build_client_config_with_resumption(
        &self,
        session_cache: &SessionCache,
    ) -> Result<ClientConfig, ConfigError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

        let root_store = rustls::RootCertStore::empty();

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ConfigError::Rustls(e.to_string()))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Disable certificate verification (TOFU model).
        client_crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));

        // Advertise ALPN aafp/1 (RFC-0002 §2.2).
        client_crypto.alpn_protocols = vec![AAFP_ALPN.to_vec()];

        // Enable TLS 1.3 session resumption with the shared session cache.
        // This allows the client to reuse session tickets from previous
        // connections to the same server, skipping the full TLS KEX.
        client_crypto.resumption = rustls::client::Resumption::store(session_cache.store());

        // 0-RTT early data is NOT enabled (replay attack risk).
        // The client waits for the server's response before sending app data.
        // (This is the default — explicit for documentation.)

        let quic_client_config = QuicClientConfig::try_from(client_crypto)
            .map_err(|e| ConfigError::Quinn(e.to_string()))?;

        let transport_config = self.build_transport_config();

        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
    }
}

/// A no-op certificate verifier (TOFU — trust on first use).
/// Agent identity is verified at the application layer, not in TLS.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::QuicTransport;

    #[test]
    fn generate_cert() {
        let identity = generate_self_signed_cert().unwrap();
        assert!(!identity.cert.as_ref().is_empty());
        assert!(!identity.key.secret_der().is_empty());
    }

    #[test]
    fn build_configs() {
        let identity = generate_self_signed_cert().unwrap();
        let config = QuicConfig::default();
        let server = config.build_server_config(&identity).unwrap();
        let client = config.build_client_config().unwrap();
        let _ = (server, client);
    }

    #[test]
    fn low_latency_preset_uses_bbr() {
        let config = QuicConfig::low_latency();
        assert_eq!(
            config.congestion,
            crate::congestion::CongestionController::Bbr
        );
        assert_eq!(config.initial_rtt, Duration::from_millis(10));
        assert_eq!(config.max_ack_delay, Duration::from_millis(5));
        assert_eq!(config.stream_initial_max_data, 1024 * 1024);
        assert_eq!(config.crypto_buffer_size, 8192);
    }

    #[test]
    fn bulk_transfer_preset_uses_cubic() {
        let config = QuicConfig::bulk_transfer();
        assert_eq!(
            config.congestion,
            crate::congestion::CongestionController::Cubic
        );
        assert_eq!(config.initial_rtt, Duration::from_millis(100));
        assert_eq!(config.max_ack_delay, Duration::from_millis(25));
        assert_eq!(config.stream_initial_max_data, 10 * 1024 * 1024);
        assert_eq!(config.crypto_buffer_size, 64 * 1024);
    }

    #[test]
    fn default_config_has_tuned_parameters() {
        let config = QuicConfig::default();
        // J2: Initial RTT should be 10ms (not quinn's 333ms default)
        assert_eq!(config.initial_rtt, Duration::from_millis(10));
        // J4: Max ACK delay should be 5ms (not quinn's 25ms default)
        assert_eq!(config.max_ack_delay, Duration::from_millis(5));
        // J3: Stream window should be 1MB (not quinn's 100KB default)
        assert_eq!(config.stream_initial_max_data, 1024 * 1024);
    }

    #[test]
    fn build_transport_config_with_bbr() {
        let config = QuicConfig::low_latency();
        // Should not panic — builds with BBR congestion controller
        let identity = generate_self_signed_cert().unwrap();
        let server = config.build_server_config(&identity).unwrap();
        let client = config.build_client_config().unwrap();
        let _ = (server, client);
    }

    #[test]
    fn alpn_constant_is_aafp_slash_1() {
        assert_eq!(AAFP_ALPN, b"aafp/1");
    }

    #[tokio::test]
    async fn alpn_negotiation_succeeds() {
        // Both server and client offer aafp/1 — connection should succeed.
        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server = std::sync::Arc::new(QuicTransport::new(server_config).unwrap());
        let server_addr = server.local_multiaddr().unwrap();

        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let client = QuicTransport::new(client_config).unwrap();

        let server_clone = server.clone();
        let handle = tokio::spawn(async move {
            let conn = server_clone.accept().await.unwrap();
            // handshake_data is present once TLS completes with ALPN.
            #[allow(deprecated)]
            assert!(conn.raw().handshake_data().is_some());
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // Connection succeeds only if ALPN negotiation succeeds.
        let conn = client.dial(&server_addr).await.unwrap();
        #[allow(deprecated)]
        assert!(conn.raw().handshake_data().is_some());

        handle.await.unwrap();
        client.close();
        drop(server);
    }

    #[tokio::test]
    async fn alpn_mismatch_rejects_connection() {
        // Server offers aafp/1, client offers something else — should fail.
        let identity = generate_self_signed_cert().unwrap();
        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server_quinn_config = server_config.build_server_config(&identity).unwrap();
        let server = std::sync::Arc::new(
            quinn::Endpoint::server(server_quinn_config, server_config.bind_addr).unwrap(),
        );
        let server_addr: std::net::SocketAddr = server.local_addr().unwrap();

        // Build a client config with a WRONG ALPN.
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let root_store = rustls::RootCertStore::empty();
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto
            .dangerous()
            .set_certificate_verifier(std::sync::Arc::new(NoVerifier));
        client_crypto.alpn_protocols = vec![b"wrong/1".to_vec()]; // Wrong ALPN

        let quic_client_config = QuicClientConfig::try_from(client_crypto).unwrap();
        let mut client_quinn_config =
            quinn::ClientConfig::new(std::sync::Arc::new(quic_client_config));
        let transport_config = quinn::TransportConfig::default();
        client_quinn_config.transport_config(std::sync::Arc::new(transport_config));

        let client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connect = client_endpoint
            .connect_with(client_quinn_config, server_addr, "localhost")
            .unwrap();

        // The connection should fail due to ALPN mismatch.
        let result = connect.await;
        assert!(
            result.is_err(),
            "Connection with wrong ALPN must be rejected"
        );

        server.close(0u32.into(), b"done");
    }
}
