//! Shared transport binding infrastructure.
//!
//! Used by AgentClient, AgentServer, and all transport binding crates
//! (aafp-transport-mcp, aafp-transport-a2a) to avoid duplicating the
//! handshake + authorization + session-transition logic.
//!
//! See TRANSPORT_ARCHITECTURE_REVIEW.md §5.1, §5.3, §6.3.

use std::sync::Arc;

use aafp_core::{AuthorizationProvider, Session};
use aafp_crypto::ReplayCache;
use aafp_identity::AgentKeypair;

use crate::handshake_driver::{drive_client_handshake, drive_server_handshake, PeerInfo};
use crate::SdkError;
use aafp_transport_quic::QuicConnection;

/// Establish an authenticated AAFP session over a QUIC connection.
///
/// This performs:
/// 1. TLS channel binding extraction
/// 2. AAFP v1 handshake (client or server side)
/// 3. Authorization via the provided AuthorizationProvider
/// 4. Session state transitions to MessagingEnabled
///
/// Returns `(Session, QuicConnection, PeerInfo)` on success. The `Session`
/// is in `MessagingEnabled` state — application data can flow immediately.
///
/// # Parameters
/// - `conn`: The QUIC connection (consumed and returned)
/// - `keypair`: The local agent's keypair
/// - `auth_provider`: Authorization provider for peer authorization
/// - `is_client`: `true` for client-side handshake, `false` for server-side
/// - `replay_cache`: Optional replay cache for nonce reuse detection
pub async fn establish_session(
    conn: QuicConnection,
    keypair: &AgentKeypair,
    auth_provider: Arc<dyn AuthorizationProvider>,
    is_client: bool,
    replay_cache: Option<&ReplayCache>,
) -> Result<(Session, QuicConnection, PeerInfo), SdkError> {
    // 1. Extract TLS channel binding from the QUIC connection
    let tls_binding = conn
        .export_tls_binding(aafp_crypto::TLS_EXPORTER_LABEL.as_bytes(), &[])
        .map_err(|e| SdkError::Handshake(e.to_string()))?;

    // 2. Drive the AAFP v1 handshake (verifies identity, signature, version, expiry)
    let (mut session, conn, peer_info) = if is_client {
        drive_client_handshake(conn, keypair, tls_binding, replay_cache).await?
    } else {
        drive_server_handshake(conn, keypair, tls_binding, replay_cache).await?
    };

    // 3. Run authorization via the configured provider
    let auth_ctx = auth_provider
        .authorize(&peer_info.agent_id, &peer_info.public_key)
        .await
        .map_err(|e| SdkError::Handshake(format!("authorization denied: {e}")))?;
    session
        .on_authorization_verified(auth_ctx)
        .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;

    // 4. Transition to Authenticated → MessagingEnabled
    session
        .on_authenticated()
        .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;
    session
        .on_messaging_enabled()
        .map_err(|e| SdkError::Handshake(format!("session state error: {e}")))?;

    Ok((session, conn, peer_info))
}
