//! AAFP QUIC transport: post-quantum key exchange over QUIC using `quinn`.
//!
//! ## Post-Quantum KEX
//! The TLS 1.3 handshake uses `X25519MLKEM768` hybrid key exchange via
//! `rustls` with the `aws-lc-rs` backend and `prefer-post-quantum` feature.
//! This protects the transport layer against harvest-now-decrypt-later attacks.
//!
//! ## Identity Authentication
//! Agent identity (ML-DSA-65) is verified at the application layer via the
//! AAFP handshake, not in TLS. The TLS layer uses self-signed certificates
//! with a TOFU (trust-on-first-use) model. The application-layer handshake
//! binds the TLS session to the agent's ML-DSA-65 identity, providing
//! end-to-end authentication.

/// Thread-local buffer pool for zero-copy message handling.
pub mod buffer_pool;
pub mod config;
pub mod transport;

pub use buffer_pool::{
    acquire, acquire_guard, release, BufferGuard, BufferPoolConfig, BytesMutWriter, PoolStats,
};
pub use config::{generate_self_signed_cert, ConfigError, QuicConfig, TlsIdentity, AAFP_ALPN};
pub use transport::{QuicConnection, QuicRecvStream, QuicSendStream, QuicTransport};
