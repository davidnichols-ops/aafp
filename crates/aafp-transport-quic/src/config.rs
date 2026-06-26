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

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("rustls error: {0}")]
    Rustls(String),
    #[error("certificate generation error: {0}")]
    CertGen(String),
    #[error("quinn error: {0}")]
    Quinn(String),
}

/// A self-signed certificate and private key for QUIC TLS.
pub struct TlsIdentity {
    pub cert: CertificateDer<'static>,
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

    Ok(TlsIdentity { cert: cert_der, key })
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
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_concurrent_streams: 100,
            keep_alive_interval: Duration::from_secs(30),
            enable_pq: true,
        }
    }
}

impl QuicConfig {
    /// Build a quinn server config with PQ KEX and a self-signed cert.
    pub fn build_server_config(
        &self,
        identity: &TlsIdentity,
    ) -> Result<ServerConfig, ConfigError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cert_chain = vec![identity.cert.clone()];

        let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ConfigError::Rustls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, identity.key.clone_key())
            .map_err(|e| ConfigError::Rustls(e.to_string()))?;

        let quic_server_config =
            QuicServerConfig::try_from(server_crypto).map_err(|e| ConfigError::Quinn(e.to_string()))?;

        let mut transport_config = TransportConfig::default();
        let max_streams = VarInt::from_u64(self.max_concurrent_streams).unwrap_or(VarInt::MAX);
        transport_config
            .max_concurrent_uni_streams(max_streams)
            .max_concurrent_bidi_streams(max_streams)
            .keep_alive_interval(Some(self.keep_alive_interval));

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Build a quinn client config with PQ KEX and no certificate verification
    /// (TOFU — agent identity is verified at the application layer).
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

        let quic_client_config =
            QuicClientConfig::try_from(client_crypto).map_err(|e| ConfigError::Quinn(e.to_string()))?;

        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(self.keep_alive_interval));

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
}
