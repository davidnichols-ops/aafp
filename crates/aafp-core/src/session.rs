//! Session abstraction: the central state machine for an AAFP connection.
//!
//! Session is intentionally thin. It tracks the lifecycle of a connection
//! through authentication and authorization into messaging, but it does NOT
//! own transport state, crypto state, replay windows, congestion control, or
//! any QUIC/TLS implementation details. Those stay where they belong.
//!
//! ## State machine
//!
//! ```text
//! Connecting
//!     ↓
//! TransportEstablished
//!     ↓
//! IdentityVerified
//!     ↓
//! AuthorizationVerified
//!     ↓
//! Authenticated
//!     ↓
//! MessagingEnabled
//!     ↓
//! Closing
//!     ↓
//! Closed
//! ```
//!
//! Illegal transitions are rejected at runtime. Any non-terminal state may
//! transition to `Closing` (graceful) or `Closed` (abort).

use aafp_identity::AgentId;
use std::time::SystemTime;

/// Session identifier (32 bytes, derived from the handshake transcript).
pub const SESSION_ID_SIZE: usize = 32;
pub type SessionId = [u8; SESSION_ID_SIZE];

/// Features negotiated during the handshake.
#[derive(Clone, Debug, Default)]
pub struct NegotiatedFeatures {
    /// Protocol version agreed upon (currently always 1).
    pub protocol_version: u8,
    /// Extension type IDs that were negotiated and accepted.
    pub extensions: Vec<u16>,
}

/// Opaque handle to the underlying transport connection.
///
/// This trait is intentionally minimal. Session does not own or expose
/// QUIC state, TLS state, congestion control, or any transport implementation
/// details. Implementations provide just enough for Session to track the
/// connection's existence and remote address.
pub trait TransportHandle: Send {
    /// The remote peer's multiaddr (e.g., "quic://1.2.3.4:4433").
    fn remote_addr(&self) -> &str;

    /// Whether the underlying transport connection has been closed.
    fn is_closed(&self) -> bool;
}

/// Authorization context attached to a session after authorization verification.
///
/// The SDK does not know whether authorization is backed by UCAN, OIDC, a
/// custom enterprise provider, or a testing provider. Only the `is_authorized`
/// interface matters.
pub trait AuthorizationContext: Send + Sync {
    /// Check whether the peer is authorized for the given capability.
    fn is_authorized(&self, capability: &str) -> bool;
}

/// Error returned when authorization verification fails.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("authorization token expired")]
    Expired,
    #[error("authorization token revoked")]
    Revoked,
    #[error("insufficient capability: {0}")]
    InsufficientCapability(String),
    #[error("delegation chain invalid: {0}")]
    DelegationChainInvalid(String),
    #[error("authorization provider error: {0}")]
    Provider(String),
}

/// Authorization provider: verifies the peer's authorization after the
/// handshake completes (IdentityVerified state) and produces an
/// AuthorizationContext.
///
/// This trait is intentionally minimal. The SDK does not know whether
/// authorization comes from UCAN, OIDC, a custom enterprise provider, or
/// a testing provider. Only `authorize()` matters.
///
/// Implementations:
/// - `TestingAuthProvider` — allows everything (for tests)
/// - UCAN-based provider (in aafp-identity)
/// - OIDC-based provider (future)
/// - Custom enterprise provider (future)
#[async_trait::async_trait]
pub trait AuthorizationProvider: Send + Sync {
    /// Verify the peer's authorization and produce an AuthorizationContext.
    ///
    /// Called after the handshake completes, when the peer's AgentId and
    /// public key have been cryptographically verified.
    async fn authorize(
        &self,
        peer_agent_id: &AgentId,
        peer_public_key: &[u8],
    ) -> Result<Box<dyn AuthorizationContext>, AuthorizationError>;
}

/// Testing authorization provider that allows all capabilities.
///
/// **WARNING**: Only use in tests. This provider does NOT perform any
/// authorization checks — it allows every capability for every peer.
pub struct TestingAuthProvider;

#[async_trait::async_trait]
impl AuthorizationProvider for TestingAuthProvider {
    async fn authorize(
        &self,
        _peer_agent_id: &AgentId,
        _peer_public_key: &[u8],
    ) -> Result<Box<dyn AuthorizationContext>, AuthorizationError> {
        Ok(Box::new(AllowAllAuthContext))
    }
}

/// Authorization context that allows all capabilities (testing only).
struct AllowAllAuthContext;

impl AuthorizationContext for AllowAllAuthContext {
    fn is_authorized(&self, _capability: &str) -> bool {
        true
    }
}

/// Testing authorization provider that denies all capabilities.
pub struct TestingDenyProvider;

#[async_trait::async_trait]
impl AuthorizationProvider for TestingDenyProvider {
    async fn authorize(
        &self,
        _peer_agent_id: &AgentId,
        _peer_public_key: &[u8],
    ) -> Result<Box<dyn AuthorizationContext>, AuthorizationError> {
        Ok(Box::new(DenyAllAuthContext))
    }
}

/// Authorization context that denies all capabilities (testing only).
struct DenyAllAuthContext;

impl AuthorizationContext for DenyAllAuthContext {
    fn is_authorized(&self, _capability: &str) -> bool {
        false
    }
}

/// Testing authorization provider that allows a specific set of capabilities.
pub struct TestingCapabilityProvider {
    allowed: Vec<String>,
}

impl TestingCapabilityProvider {
    pub fn new(allowed: Vec<String>) -> Self {
        Self { allowed }
    }
}

#[async_trait::async_trait]
impl AuthorizationProvider for TestingCapabilityProvider {
    async fn authorize(
        &self,
        _peer_agent_id: &AgentId,
        _peer_public_key: &[u8],
    ) -> Result<Box<dyn AuthorizationContext>, AuthorizationError> {
        Ok(Box::new(AllowedCapsAuthContext {
            allowed: self.allowed.clone(),
        }))
    }
}

struct AllowedCapsAuthContext {
    allowed: Vec<String>,
}

impl AuthorizationContext for AllowedCapsAuthContext {
    fn is_authorized(&self, capability: &str) -> bool {
        self.allowed.iter().any(|c| c == capability)
    }
}

/// Session lifecycle state.
///
/// States are ordered. Forward transitions follow the defined progression.
/// Any non-terminal state may transition to `Closing` (graceful) or `Closed`
/// (abort). `Closed` is terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SessionState {
    /// QUIC connection being established (dial or accept in progress).
    Connecting,
    /// QUIC connection exists; no AAFP handshake yet.
    TransportEstablished,
    /// AAFP handshake completed; peer AgentId verified cryptographically.
    IdentityVerified,
    /// Authorization tokens verified; peer capabilities checked.
    AuthorizationVerified,
    /// Session is fully authenticated and ready to enable messaging.
    Authenticated,
    /// Application data can flow (AEAD keys applied to streams).
    MessagingEnabled,
    /// Graceful shutdown in progress (CLOSE frame sent or received).
    Closing,
    /// Terminal state. Connection is fully closed.
    Closed,
}

impl SessionState {
    /// Whether this state is terminal (no further transitions possible).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether messaging is active (application data can flow).
    pub fn is_messaging_active(&self) -> bool {
        matches!(self, Self::MessagingEnabled)
    }

    /// Whether the peer's identity has been verified.
    pub fn is_identity_verified(&self) -> bool {
        !matches!(self, Self::Connecting | Self::TransportEstablished)
    }

    /// Whether the session is fully authenticated.
    pub fn is_authenticated(&self) -> bool {
        matches!(
            self,
            Self::Authenticated | Self::MessagingEnabled | Self::Closing
        )
    }

    /// Check whether a transition from `self` to `next` is valid.
    pub fn can_transition_to(&self, next: SessionState) -> bool {
        use SessionState::*;
        match (*self, next) {
            // Forward transitions (defined progression)
            (Connecting, TransportEstablished) => true,
            (TransportEstablished, IdentityVerified) => true,
            (IdentityVerified, AuthorizationVerified) => true,
            (AuthorizationVerified, Authenticated) => true,
            (Authenticated, MessagingEnabled) => true,
            (MessagingEnabled, Closing) => true,
            (Closing, Closed) => true,

            // Graceful shutdown from any active (non-Connecting) state
            (
                TransportEstablished | IdentityVerified | AuthorizationVerified | Authenticated,
                Closing,
            ) => true,

            // Abort from any non-terminal state (except Closing, handled above)
            (
                Connecting
                | TransportEstablished
                | IdentityVerified
                | AuthorizationVerified
                | Authenticated
                | MessagingEnabled,
                Closed,
            ) => true,

            // Everything else is illegal
            _ => false,
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Error returned when an illegal state transition is attempted.
#[derive(Debug, thiserror::Error)]
#[error("illegal session state transition: {from} → {to}")]
pub struct SessionStateError {
    pub from: SessionState,
    pub to: SessionState,
}

/// A thin session object tracking the lifecycle of one AAFP connection.
///
/// Session does NOT own:
/// - congestion control, retransmission, packet loss (QUIC's job)
/// - TLS state (rustls/quinn's job)
/// - replay windows (crypto/handshake layer's job)
/// - crypto implementation details (aafp-crypto's job)
///
/// Session DOES track:
/// - the current lifecycle state (state machine)
/// - the verified peer AgentId (after identity verification)
/// - the session ID (after handshake)
/// - negotiated features (version, extensions)
/// - timestamps (created, last activity)
/// - an opaque transport handle
/// - an authorization context (after authorization verification)
pub struct Session {
    /// Current lifecycle state.
    state: SessionState,
    /// Session ID derived from the handshake transcript.
    /// `None` until `IdentityVerified`.
    session_id: Option<SessionId>,
    /// Cryptographically verified peer AgentId.
    /// `None` until `IdentityVerified`.
    peer_agent_id: Option<AgentId>,
    /// Features negotiated during handshake.
    /// `None` until `TransportEstablished`.
    negotiated_features: Option<NegotiatedFeatures>,
    /// When the session was created (entered `Connecting`).
    created_at: SystemTime,
    /// Last time a frame was sent or received.
    last_activity: SystemTime,
    /// Opaque transport handle.
    /// `None` until `TransportEstablished`.
    transport_handle: Option<Box<dyn TransportHandle>>,
    /// Authorization context.
    /// `None` until `AuthorizationVerified`.
    authorization_context: Option<Box<dyn AuthorizationContext>>,
}

impl Session {
    /// Create a new session in the `Connecting` state.
    pub fn new() -> Self {
        let now = SystemTime::now();
        Self {
            state: SessionState::Connecting,
            session_id: None,
            peer_agent_id: None,
            negotiated_features: None,
            created_at: now,
            last_activity: now,
            transport_handle: None,
            authorization_context: None,
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Session ID, if identity has been verified.
    pub fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    /// Verified peer AgentId, if identity has been verified.
    pub fn peer_agent_id(&self) -> Option<&AgentId> {
        self.peer_agent_id.as_ref()
    }

    /// Negotiated features, if transport is established.
    pub fn negotiated_features(&self) -> Option<&NegotiatedFeatures> {
        self.negotiated_features.as_ref()
    }

    /// When the session was created.
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Last activity timestamp.
    pub fn last_activity(&self) -> SystemTime {
        self.last_activity
    }

    /// Update the last activity timestamp (called on frame send/receive).
    pub fn touch(&mut self) {
        self.last_activity = SystemTime::now();
    }

    /// Transport handle, if transport is established.
    pub fn transport_handle(&self) -> Option<&dyn TransportHandle> {
        self.transport_handle.as_deref()
    }

    /// Authorization context, if authorization has been verified.
    pub fn authorization_context(&self) -> Option<&dyn AuthorizationContext> {
        self.authorization_context.as_deref()
    }

    // --- State transitions ---

    /// Attempt a state transition. Returns an error if the transition is illegal.
    fn transition_to(&mut self, new_state: SessionState) -> Result<(), SessionStateError> {
        if !self.state.can_transition_to(new_state) {
            return Err(SessionStateError {
                from: self.state,
                to: new_state,
            });
        }
        self.state = new_state;
        Ok(())
    }

    /// Transition to `TransportEstablished` with a transport handle and
    /// initially negotiated features (e.g., protocol version from ALPN).
    pub fn on_transport_established(
        &mut self,
        handle: Box<dyn TransportHandle>,
        features: NegotiatedFeatures,
    ) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::TransportEstablished)?;
        self.transport_handle = Some(handle);
        self.negotiated_features = Some(features);
        self.touch();
        Ok(())
    }

    /// Transition to `IdentityVerified` with the verified peer AgentId and
    /// session ID from the completed handshake.
    pub fn on_identity_verified(
        &mut self,
        peer_agent_id: AgentId,
        session_id: SessionId,
    ) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::IdentityVerified)?;
        self.peer_agent_id = Some(peer_agent_id);
        self.session_id = Some(session_id);
        self.touch();
        Ok(())
    }

    /// Transition to `AuthorizationVerified` with an authorization context.
    pub fn on_authorization_verified(
        &mut self,
        auth_ctx: Box<dyn AuthorizationContext>,
    ) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::AuthorizationVerified)?;
        self.authorization_context = Some(auth_ctx);
        self.touch();
        Ok(())
    }

    /// Transition to `Authenticated`.
    pub fn on_authenticated(&mut self) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::Authenticated)?;
        self.touch();
        Ok(())
    }

    /// Transition to `MessagingEnabled`. Application data can now flow.
    pub fn on_messaging_enabled(&mut self) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::MessagingEnabled)?;
        self.touch();
        Ok(())
    }

    /// Transition to `Closing` (graceful shutdown initiated).
    pub fn begin_close(&mut self) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::Closing)?;
        self.touch();
        Ok(())
    }

    /// Transition to `Closed` (terminal). Can be reached from any non-terminal
    /// state, including `Closing`.
    pub fn close(&mut self) -> Result<(), SessionStateError> {
        self.transition_to(SessionState::Closed)?;
        Ok(())
    }

    /// Check whether the peer is authorized for a capability. Returns `false`
    /// if authorization has not been verified or the capability is not granted.
    pub fn is_authorized(&self, capability: &str) -> bool {
        self.authorization_context
            .as_deref()
            .map(|ctx| ctx.is_authorized(capability))
            .unwrap_or(false)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("state", &self.state)
            .field("session_id", &self.session_id)
            .field("peer_agent_id", &self.peer_agent_id)
            .field("negotiated_features", &self.negotiated_features)
            .field("created_at", &self.created_at)
            .field("last_activity", &self.last_activity)
            .field("has_transport", &self.transport_handle.is_some())
            .field("has_authorization", &self.authorization_context.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTransport {
        addr: String,
        closed: bool,
    }

    impl TransportHandle for TestTransport {
        fn remote_addr(&self) -> &str {
            &self.addr
        }
        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    struct TestAuth {
        allowed: Vec<String>,
    }

    impl AuthorizationContext for TestAuth {
        fn is_authorized(&self, capability: &str) -> bool {
            self.allowed.iter().any(|c| c == capability)
        }
    }

    #[test]
    fn test_state_machine_forward_progression() {
        let mut s = Session::new();
        assert_eq!(s.state(), SessionState::Connecting);

        s.on_transport_established(
            Box::new(TestTransport {
                addr: "quic://1.2.3.4:4433".into(),
                closed: false,
            }),
            NegotiatedFeatures {
                protocol_version: 1,
                extensions: vec![],
            },
        )
        .unwrap();
        assert_eq!(s.state(), SessionState::TransportEstablished);
        assert!(s.transport_handle().is_some());
        assert!(s.negotiated_features().is_some());

        let peer_id = [0xAA; 32];
        let sid = [0xBB; 32];
        s.on_identity_verified(peer_id, sid).unwrap();
        assert_eq!(s.state(), SessionState::IdentityVerified);
        assert_eq!(s.peer_agent_id(), Some(&peer_id));
        assert_eq!(s.session_id(), Some(&sid));

        s.on_authorization_verified(Box::new(TestAuth {
            allowed: vec!["aafp.discovery".into()],
        }))
        .unwrap();
        assert_eq!(s.state(), SessionState::AuthorizationVerified);
        assert!(s.is_authorized("aafp.discovery"));
        assert!(!s.is_authorized("aafp.admin"));

        s.on_authenticated().unwrap();
        assert_eq!(s.state(), SessionState::Authenticated);

        s.on_messaging_enabled().unwrap();
        assert_eq!(s.state(), SessionState::MessagingEnabled);
        assert!(s.state().is_messaging_active());

        s.begin_close().unwrap();
        assert_eq!(s.state(), SessionState::Closing);

        s.close().unwrap();
        assert_eq!(s.state(), SessionState::Closed);
        assert!(s.state().is_terminal());
    }

    #[test]
    fn test_illegal_forward_transition_rejected() {
        let mut s = Session::new();
        // Connecting → IdentityVerified is illegal (must go through TransportEstablished first)
        let err = s.on_identity_verified([0xAA; 32], [0xBB; 32]).unwrap_err();
        assert_eq!(err.from, SessionState::Connecting);
        assert_eq!(err.to, SessionState::IdentityVerified);
        assert_eq!(s.state(), SessionState::Connecting); // state unchanged
    }

    #[test]
    fn test_illegal_backward_transition_rejected() {
        let mut s = Session::new();
        s.on_transport_established(
            Box::new(TestTransport {
                addr: "quic://x".into(),
                closed: false,
            }),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        // TransportEstablished → Connecting is illegal
        assert!(s.transition_to(SessionState::Connecting).is_err());
    }

    #[test]
    fn test_abort_from_any_state() {
        for state in [
            SessionState::Connecting,
            SessionState::TransportEstablished,
            SessionState::IdentityVerified,
            SessionState::AuthorizationVerified,
            SessionState::Authenticated,
            SessionState::MessagingEnabled,
            SessionState::Closing,
        ] {
            assert!(
                state.can_transition_to(SessionState::Closed),
                "{state} → Closed should be allowed (abort path)"
            );
        }
    }

    #[test]
    fn test_graceful_close_from_active_states() {
        for state in [
            SessionState::TransportEstablished,
            SessionState::IdentityVerified,
            SessionState::AuthorizationVerified,
            SessionState::Authenticated,
            SessionState::MessagingEnabled,
        ] {
            assert!(
                state.can_transition_to(SessionState::Closing),
                "{state} → Closing should be allowed (graceful shutdown)"
            );
        }
    }

    #[test]
    fn test_cannot_close_from_closed() {
        let closed = SessionState::Closed;
        assert!(!closed.can_transition_to(SessionState::Closing));
        assert!(!closed.can_transition_to(SessionState::Connecting));
        assert!(closed.is_terminal());
    }

    #[test]
    fn test_cannot_skip_states() {
        // Cannot go from Connecting directly to Authenticated
        assert!(!SessionState::Connecting.can_transition_to(SessionState::Authenticated));
        // Cannot go from TransportEstablished directly to Authenticated
        assert!(!SessionState::TransportEstablished.can_transition_to(SessionState::Authenticated));
        // Cannot go from IdentityVerified directly to MessagingEnabled
        assert!(!SessionState::IdentityVerified.can_transition_to(SessionState::MessagingEnabled));
    }

    #[test]
    fn test_touch_updates_activity() {
        let mut s = Session::new();
        let t0 = s.last_activity();
        std::thread::sleep(std::time::Duration::from_millis(2));
        s.touch();
        assert!(s.last_activity() > t0);
    }

    #[test]
    fn test_state_predicates() {
        assert!(SessionState::Connecting.is_terminal() == false);
        assert!(SessionState::Closed.is_terminal());
        assert!(!SessionState::Connecting.is_identity_verified());
        assert!(!SessionState::TransportEstablished.is_identity_verified());
        assert!(SessionState::IdentityVerified.is_identity_verified());
        assert!(SessionState::MessagingEnabled.is_authenticated());
        assert!(!SessionState::Connecting.is_authenticated());
    }

    #[test]
    fn test_is_authorized_before_auth_returns_false() {
        let s = Session::new();
        assert!(!s.is_authorized("anything"));
    }

    // --- AuthorizationProvider tests ---

    #[tokio::test]
    async fn test_testing_auth_provider_allows_all() {
        let provider = TestingAuthProvider;
        let ctx = provider
            .authorize(&[0xAA; 32], &[0xBB; 1952])
            .await
            .unwrap();
        assert!(ctx.is_authorized("anything"));
        assert!(ctx.is_authorized("aafp.admin"));
        assert!(ctx.is_authorized("aafp.discovery"));
    }

    #[tokio::test]
    async fn test_testing_deny_provider_denies_all() {
        let provider = TestingDenyProvider;
        let ctx = provider
            .authorize(&[0xAA; 32], &[0xBB; 1952])
            .await
            .unwrap();
        assert!(!ctx.is_authorized("anything"));
        assert!(!ctx.is_authorized("aafp.admin"));
    }

    #[tokio::test]
    async fn test_testing_capability_provider_allows_specific() {
        let provider =
            TestingCapabilityProvider::new(vec!["aafp.discovery".into(), "aafp.messaging".into()]);
        let ctx = provider
            .authorize(&[0xAA; 32], &[0xBB; 1952])
            .await
            .unwrap();
        assert!(ctx.is_authorized("aafp.discovery"));
        assert!(ctx.is_authorized("aafp.messaging"));
        assert!(!ctx.is_authorized("aafp.admin"));
    }

    #[tokio::test]
    async fn test_session_with_authorization_provider() {
        let provider = TestingCapabilityProvider::new(vec!["aafp.discovery".into()]);
        let mut s = Session::new();

        // Must go through the state machine
        s.on_transport_established(
            Box::new(TestTransport {
                addr: "quic://x".into(),
                closed: false,
            }),
            NegotiatedFeatures::default(),
        )
        .unwrap();
        s.on_identity_verified([0xAA; 32], [0xBB; 32]).unwrap();

        // Authorize
        let ctx = provider
            .authorize(&[0xAA; 32], &[0xCC; 1952])
            .await
            .unwrap();
        s.on_authorization_verified(ctx).unwrap();
        assert_eq!(s.state(), SessionState::AuthorizationVerified);
        assert!(s.is_authorized("aafp.discovery"));
        assert!(!s.is_authorized("aafp.admin"));
    }
}
