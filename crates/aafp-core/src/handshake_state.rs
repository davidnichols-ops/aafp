//! Normative handshake state machine (RFC-0002 §5.10, Rev 6 A-6).
//!
//! This module implements the complete handshake state machine defined
//! normatively in RFC-0002 Section 5.10. It tracks the handshake sub-states
//! for both client and server roles, enforces allowed transitions, rejects
//! forbidden transitions, and handles timeouts, duplicates, and unexpected
//! frames.
//!
//! The handshake state machine is separate from the session-level state
//! machine (`SessionState`) because the handshake has more granular
//! states than the session lifecycle. The mapping between handshake
//! states and session states is defined in RFC-0002 §5.10.11.

use std::fmt;
use std::time::{Duration, Instant};

/// Default handshake timeout (30 seconds).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default graceful close timeout (5 seconds).
pub const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum handshake timeout (10 seconds).
pub const MIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum close timeout (1 second).
pub const MIN_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Client handshake states (RFC-0002 §5.10.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ClientHandshakeState {
    /// No connection initiated. Initial state.
    Idle,
    /// QUIC connection in progress, TLS handshake underway.
    Connecting,
    /// ClientHello sent on stream 0, awaiting ServerHello.
    ChSent,
    /// ServerHello received and cryptographically verified. Session ID derived.
    ShVerified,
    /// ClientFinished sent. Handshake complete. Awaiting authorization.
    CfSent,
    /// Authorization verified. Ready to enable messaging.
    Authorized,
    /// Application data flowing. AEAD applied to streams.
    Messaging,
    /// CLOSE frame sent. Awaiting peer CLOSE or timeout.
    Closing,
    /// Terminal state. QUIC connection fully closed.
    Closed,
}

impl ClientHandshakeState {
    /// Whether this state is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether the handshake is complete (post-ClientFinished).
    pub fn is_handshake_complete(&self) -> bool {
        matches!(
            self,
            Self::CfSent | Self::Authorized | Self::Messaging | Self::Closing
        )
    }

    /// Whether messaging is active.
    pub fn is_messaging_active(&self) -> bool {
        matches!(self, Self::Messaging)
    }

    /// Whether the peer's identity has been verified.
    pub fn is_identity_verified(&self) -> bool {
        matches!(
            self,
            Self::ShVerified | Self::CfSent | Self::Authorized | Self::Messaging | Self::Closing
        )
    }

    /// Check whether a transition from `self` to `next` is valid.
    pub fn can_transition_to(&self, next: ClientHandshakeState) -> bool {
        use ClientHandshakeState::*;
        match (*self, next) {
            // Forward transitions
            (Idle, Connecting) => true,
            (Connecting, ChSent) => true,
            (ChSent, ShVerified) => true,
            (ShVerified, CfSent) => true,
            (CfSent, Authorized) => true,
            (Authorized, Messaging) => true,
            (Messaging, Closing) => true,
            (Closing, Closed) => true,

            // Graceful shutdown from active states
            (Connecting | ChSent | ShVerified | CfSent | Authorized, Closing) => true,

            // Abort from any non-terminal state
            (Idle | Connecting | ChSent | ShVerified | CfSent | Authorized | Messaging, Closed) => {
                true
            }

            // Everything else is illegal
            _ => false,
        }
    }

    /// Allowed frame types in this state (as frame type bytes).
    ///
    /// Per RFC-0002 §5.10.7. ERROR frames are allowed in all non-terminal,
    /// non-idle states because the peer may send an error at any time.
    /// In Closing state, only CLOSE is accepted; all other frames are
    /// silently discarded (use `frame_disposition` to distinguish).
    pub fn allowed_frame_types(&self) -> &'static [u8] {
        use ClientHandshakeState::*;
        match self {
            Idle | Connecting => &[],
            ChSent => &[0x02, 0x06],        // HANDSHAKE, ERROR
            ShVerified | CfSent => &[0x06], // ERROR
            Authorized | Messaging => &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // DATA, RPC_REQ, RPC_RESP, CLOSE, ERROR, PING, PONG
            Closing => &[0x05],                                                    // CLOSE
            Closed => &[],
        }
    }
}

impl fmt::Display for ClientHandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "C_IDLE"),
            Self::Connecting => write!(f, "C_CONNECTING"),
            Self::ChSent => write!(f, "C_CH_SENT"),
            Self::ShVerified => write!(f, "C_SH_VERIFIED"),
            Self::CfSent => write!(f, "C_CF_SENT"),
            Self::Authorized => write!(f, "C_AUTHORIZED"),
            Self::Messaging => write!(f, "C_MESSAGING"),
            Self::Closing => write!(f, "C_CLOSING"),
            Self::Closed => write!(f, "C_CLOSED"),
        }
    }
}

/// Server handshake states (RFC-0002 §5.10.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ServerHandshakeState {
    /// Waiting for incoming QUIC connections. Initial state.
    Listening,
    /// QUIC + TLS established. Awaiting ClientHello on stream 0.
    TransportReady,
    /// ClientHello received and cryptographically verified.
    ChVerified,
    /// ServerHello sent. Awaiting ClientFinished.
    ShSent,
    /// ClientFinished received and verified. Handshake complete.
    CfVerified,
    /// Authorization verified. Ready to enable messaging.
    Authorized,
    /// Application data flowing. AEAD applied to streams.
    Messaging,
    /// CLOSE frame sent. Awaiting peer CLOSE or timeout.
    Closing,
    /// Terminal state. QUIC connection fully closed.
    Closed,
}

impl ServerHandshakeState {
    /// Whether this state is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether the handshake is complete (post-ClientFinished).
    pub fn is_handshake_complete(&self) -> bool {
        matches!(
            self,
            Self::CfVerified | Self::Authorized | Self::Messaging | Self::Closing
        )
    }

    /// Whether messaging is active.
    pub fn is_messaging_active(&self) -> bool {
        matches!(self, Self::Messaging)
    }

    /// Whether the peer's identity has been verified.
    pub fn is_identity_verified(&self) -> bool {
        matches!(
            self,
            Self::ChVerified
                | Self::ShSent
                | Self::CfVerified
                | Self::Authorized
                | Self::Messaging
                | Self::Closing
        )
    }

    /// Check whether a transition from `self` to `next` is valid.
    pub fn can_transition_to(&self, next: ServerHandshakeState) -> bool {
        use ServerHandshakeState::*;
        match (*self, next) {
            // Forward transitions
            (Listening, TransportReady) => true,
            (TransportReady, ChVerified) => true,
            (ChVerified, ShSent) => true,
            (ShSent, CfVerified) => true,
            (CfVerified, Authorized) => true,
            (Authorized, Messaging) => true,
            (Messaging, Closing) => true,
            (Closing, Closed) => true,

            // Graceful shutdown from active states
            (TransportReady | ChVerified | ShSent | CfVerified | Authorized, Closing) => true,

            // Abort from any non-terminal state
            (
                Listening | TransportReady | ChVerified | ShSent | CfVerified | Authorized
                | Messaging,
                Closed,
            ) => true,

            // Everything else is illegal
            _ => false,
        }
    }

    /// Allowed frame types in this state (as frame type bytes).
    ///
    /// Per RFC-0002 §5.10.7. ERROR frames are allowed in all non-terminal,
    /// non-listening states because the peer may send an error at any time.
    /// In Closing state, only CLOSE is accepted; all other frames are
    /// silently discarded (use `frame_disposition` to distinguish).
    pub fn allowed_frame_types(&self) -> &'static [u8] {
        use ServerHandshakeState::*;
        match self {
            Listening => &[],
            TransportReady => &[0x02, 0x06],      // HANDSHAKE, ERROR
            ChVerified | ShSent => &[0x02, 0x06], // HANDSHAKE, ERROR
            CfVerified | Authorized => &[0x06],   // ERROR
            Messaging => &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            Closing => &[0x05], // CLOSE
            Closed => &[],
        }
    }
}

impl fmt::Display for ServerHandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listening => write!(f, "S_LISTENING"),
            Self::TransportReady => write!(f, "S_TRANSPORT_READY"),
            Self::ChVerified => write!(f, "S_CH_VERIFIED"),
            Self::ShSent => write!(f, "S_SH_SENT"),
            Self::CfVerified => write!(f, "S_CF_VERIFIED"),
            Self::Authorized => write!(f, "S_AUTHORIZED"),
            Self::Messaging => write!(f, "S_MESSAGING"),
            Self::Closing => write!(f, "S_CLOSING"),
            Self::Closed => write!(f, "S_CLOSED"),
        }
    }
}

/// The role of the state machine owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HandshakeRole {
    Client,
    Server,
}

/// Disposition of a frame received in a given state (RFC-0002 §5.10.7).
///
/// Distinguishes between frames that should be processed, frames that
/// should cause an ERROR 2008 and connection close, and frames that
/// should be silently discarded (in Closing state).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FrameDisposition {
    /// Frame is allowed in the current state and should be processed.
    Accept,
    /// Frame is not allowed; send ERROR 2008 and close the connection.
    RejectWithError,
    /// Frame is not allowed but should be silently discarded (Closing state).
    /// No error should be sent. The connection continues in the current state.
    DiscardSilently,
}

/// Error returned when an illegal state transition is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeStateError {
    pub role: HandshakeRole,
    pub from_state: String,
    pub to_state: String,
    pub reason: String,
}

impl fmt::Display for HandshakeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal {} handshake transition: {} → {} ({})",
            if self.role == HandshakeRole::Client {
                "client"
            } else {
                "server"
            },
            self.from_state,
            self.to_state,
            self.reason
        )
    }
}

impl std::error::Error for HandshakeStateError {}

/// Error returned when an unexpected frame is received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnexpectedFrameError {
    pub current_state: String,
    pub frame_type: u8,
    pub allowed: Vec<u8>,
}

impl fmt::Display for UnexpectedFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unexpected frame type 0x{:02X} in state {} (allowed: {:?})",
            self.frame_type, self.current_state, self.allowed
        )
    }
}

impl std::error::Error for UnexpectedFrameError {}

/// Error returned when a timeout occurs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeTimeoutError {
    pub state: String,
    pub elapsed: Duration,
    pub limit: Duration,
}

impl fmt::Display for HandshakeTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "handshake timeout in state {} ({}s > {}s limit)",
            self.state,
            self.elapsed.as_secs(),
            self.limit.as_secs()
        )
    }
}

impl std::error::Error for HandshakeTimeoutError {}

/// Error returned when a duplicate handshake message is received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateHandshakeMessageError {
    pub state: String,
    pub message_type: &'static str,
}

impl fmt::Display for DuplicateHandshakeMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "duplicate {} received in state {}",
            self.message_type, self.state
        )
    }
}

impl std::error::Error for DuplicateHandshakeMessageError {}

/// Client handshake state machine.
///
/// Tracks the current state, deadline, and provides transition validation
/// per RFC-0002 §5.10.
pub struct ClientHandshakeMachine {
    state: ClientHandshakeState,
    deadline: Option<Instant>,
    handshake_timeout: Duration,
    close_timeout: Duration,
    /// Whether a ServerHello has already been received (for duplicate detection).
    server_hello_received: bool,
}

impl Default for ClientHandshakeMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHandshakeMachine {
    /// Create a new client state machine in the `Idle` state.
    pub fn new() -> Self {
        Self {
            state: ClientHandshakeState::Idle,
            deadline: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            close_timeout: DEFAULT_CLOSE_TIMEOUT,
            server_hello_received: false,
        }
    }

    /// Set the handshake timeout (must be >= 10 seconds).
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        assert!(
            timeout >= MIN_HANDSHAKE_TIMEOUT,
            "handshake timeout must be >= 10s"
        );
        self.handshake_timeout = timeout;
        self
    }

    /// Set the close timeout (must be >= 1 second).
    pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
        assert!(timeout >= MIN_CLOSE_TIMEOUT, "close timeout must be >= 1s");
        self.close_timeout = timeout;
        self
    }

    /// Current state.
    pub fn state(&self) -> ClientHandshakeState {
        self.state
    }

    /// Configured handshake timeout.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Configured close timeout.
    pub fn close_timeout(&self) -> Duration {
        self.close_timeout
    }

    /// Set the handshake timeout bypassing the minimum check.
    /// This is intended for testing only.
    pub fn set_handshake_timeout_for_test(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Whether the state machine is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Transition to a new state. Returns error if the transition is invalid.
    pub fn transition_to(&mut self, next: ClientHandshakeState) -> Result<(), HandshakeStateError> {
        if !self.state.can_transition_to(next) {
            return Err(HandshakeStateError {
                role: HandshakeRole::Client,
                from_state: self.state.to_string(),
                to_state: next.to_string(),
                reason: "transition not allowed".to_string(),
            });
        }

        // Set deadline when entering a waiting state
        match next {
            ClientHandshakeState::Connecting | ClientHandshakeState::ChSent => {
                self.deadline = Some(Instant::now() + self.handshake_timeout);
            }
            ClientHandshakeState::Closing => {
                self.deadline = Some(Instant::now() + self.close_timeout);
            }
            ClientHandshakeState::Closed => {
                self.deadline = None;
            }
            _ => {}
        }

        // Reset duplicate tracking on state change
        if next == ClientHandshakeState::ChSent {
            self.server_hello_received = false;
        }

        self.state = next;
        Ok(())
    }

    /// Check if the current state has timed out.
    pub fn check_timeout(&self) -> Result<(), HandshakeTimeoutError> {
        if let Some(deadline) = self.deadline {
            if Instant::now() > deadline {
                return Err(HandshakeTimeoutError {
                    state: self.state.to_string(),
                    elapsed: deadline.elapsed(),
                    limit: match self.state {
                        ClientHandshakeState::Closing => self.close_timeout,
                        _ => self.handshake_timeout,
                    },
                });
            }
        }
        Ok(())
    }

    /// Check if a frame type is allowed in the current state.
    pub fn check_frame_type(&self, frame_type: u8) -> Result<(), UnexpectedFrameError> {
        let allowed = self.state.allowed_frame_types();
        if allowed.is_empty() {
            return Err(UnexpectedFrameError {
                current_state: self.state.to_string(),
                frame_type,
                allowed: allowed.to_vec(),
            });
        }
        if !allowed.contains(&frame_type) {
            return Err(UnexpectedFrameError {
                current_state: self.state.to_string(),
                frame_type,
                allowed: allowed.to_vec(),
            });
        }
        Ok(())
    }

    /// Determine the disposition of a frame in the current state (RFC-0002 §5.10.7).
    ///
    /// In Closing state, non-CLOSE frames are silently discarded (not errored).
    /// In all other states, non-allowed frames are rejected with ERROR 2008.
    pub fn frame_disposition(&self, frame_type: u8) -> FrameDisposition {
        // In Closing state, only CLOSE is accepted; everything else is discarded
        if self.state == ClientHandshakeState::Closing {
            if frame_type == 0x05 {
                return FrameDisposition::Accept;
            }
            return FrameDisposition::DiscardSilently;
        }

        // In Closed state, everything is discarded silently (connection is gone)
        if self.state == ClientHandshakeState::Closed {
            return FrameDisposition::DiscardSilently;
        }

        // In other states, use allowed_frame_types
        let allowed = self.state.allowed_frame_types();
        if allowed.contains(&frame_type) {
            FrameDisposition::Accept
        } else {
            FrameDisposition::RejectWithError
        }
    }

    /// Mark that a ServerHello has been received (for duplicate detection).
    /// Returns error if a ServerHello was already received.
    pub fn on_server_hello_received(&mut self) -> Result<(), DuplicateHandshakeMessageError> {
        if self.server_hello_received {
            return Err(DuplicateHandshakeMessageError {
                state: self.state.to_string(),
                message_type: "ServerHello",
            });
        }
        self.server_hello_received = true;
        Ok(())
    }

    /// Abort the connection immediately (transition to Closed).
    pub fn abort(&mut self) -> Result<(), HandshakeStateError> {
        self.transition_to(ClientHandshakeState::Closed)
    }
}

/// Server handshake state machine.
///
/// Tracks the current state, deadline, and provides transition validation
/// per RFC-0002 §5.10.
pub struct ServerHandshakeMachine {
    state: ServerHandshakeState,
    deadline: Option<Instant>,
    handshake_timeout: Duration,
    close_timeout: Duration,
    /// Whether a ClientHello has already been received (for duplicate detection).
    client_hello_received: bool,
    /// Whether a ClientFinished has already been received (for duplicate detection).
    client_finished_received: bool,
}

impl Default for ServerHandshakeMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerHandshakeMachine {
    /// Create a new server state machine in the `Listening` state.
    pub fn new() -> Self {
        Self {
            state: ServerHandshakeState::Listening,
            deadline: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            close_timeout: DEFAULT_CLOSE_TIMEOUT,
            client_hello_received: false,
            client_finished_received: false,
        }
    }

    /// Set the handshake timeout (must be >= 10 seconds).
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        assert!(
            timeout >= MIN_HANDSHAKE_TIMEOUT,
            "handshake timeout must be >= 10s"
        );
        self.handshake_timeout = timeout;
        self
    }

    /// Set the close timeout (must be >= 1 second).
    pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
        assert!(timeout >= MIN_CLOSE_TIMEOUT, "close timeout must be >= 1s");
        self.close_timeout = timeout;
        self
    }

    /// Current state.
    pub fn state(&self) -> ServerHandshakeState {
        self.state
    }

    /// Configured handshake timeout.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Configured close timeout.
    pub fn close_timeout(&self) -> Duration {
        self.close_timeout
    }

    /// Set the handshake timeout bypassing the minimum check.
    /// This is intended for testing only.
    pub fn set_handshake_timeout_for_test(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Whether the state machine is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Transition to a new state. Returns error if the transition is invalid.
    pub fn transition_to(&mut self, next: ServerHandshakeState) -> Result<(), HandshakeStateError> {
        if !self.state.can_transition_to(next) {
            return Err(HandshakeStateError {
                role: HandshakeRole::Server,
                from_state: self.state.to_string(),
                to_state: next.to_string(),
                reason: "transition not allowed".to_string(),
            });
        }

        // Set deadline when entering a waiting state
        match next {
            ServerHandshakeState::TransportReady | ServerHandshakeState::ShSent => {
                self.deadline = Some(Instant::now() + self.handshake_timeout);
            }
            ServerHandshakeState::Closing => {
                self.deadline = Some(Instant::now() + self.close_timeout);
            }
            ServerHandshakeState::Closed => {
                self.deadline = None;
            }
            _ => {}
        }

        // Reset duplicate tracking on state change
        if next == ServerHandshakeState::TransportReady {
            self.client_hello_received = false;
            self.client_finished_received = false;
        }

        self.state = next;
        Ok(())
    }

    /// Check if the current state has timed out.
    pub fn check_timeout(&self) -> Result<(), HandshakeTimeoutError> {
        if let Some(deadline) = self.deadline {
            if Instant::now() > deadline {
                return Err(HandshakeTimeoutError {
                    state: self.state.to_string(),
                    elapsed: deadline.elapsed(),
                    limit: match self.state {
                        ServerHandshakeState::Closing => self.close_timeout,
                        _ => self.handshake_timeout,
                    },
                });
            }
        }
        Ok(())
    }

    /// Check if a frame type is allowed in the current state.
    pub fn check_frame_type(&self, frame_type: u8) -> Result<(), UnexpectedFrameError> {
        let allowed = self.state.allowed_frame_types();
        if allowed.is_empty() {
            return Err(UnexpectedFrameError {
                current_state: self.state.to_string(),
                frame_type,
                allowed: allowed.to_vec(),
            });
        }
        if !allowed.contains(&frame_type) {
            return Err(UnexpectedFrameError {
                current_state: self.state.to_string(),
                frame_type,
                allowed: allowed.to_vec(),
            });
        }
        Ok(())
    }

    /// Determine the disposition of a frame in the current state (RFC-0002 §5.10.7).
    ///
    /// In Closing state, non-CLOSE frames are silently discarded (not errored).
    /// In all other states, non-allowed frames are rejected with ERROR 2008.
    pub fn frame_disposition(&self, frame_type: u8) -> FrameDisposition {
        // In Closing state, only CLOSE is accepted; everything else is discarded
        if self.state == ServerHandshakeState::Closing {
            if frame_type == 0x05 {
                return FrameDisposition::Accept;
            }
            return FrameDisposition::DiscardSilently;
        }

        // In Closed state, everything is discarded silently (connection is gone)
        if self.state == ServerHandshakeState::Closed {
            return FrameDisposition::DiscardSilently;
        }

        // In other states, use allowed_frame_types
        let allowed = self.state.allowed_frame_types();
        if allowed.contains(&frame_type) {
            FrameDisposition::Accept
        } else {
            FrameDisposition::RejectWithError
        }
    }

    /// Mark that a ClientHello has been received (for duplicate detection).
    /// Returns error if a ClientHello was already received.
    pub fn on_client_hello_received(&mut self) -> Result<(), DuplicateHandshakeMessageError> {
        if self.client_hello_received {
            return Err(DuplicateHandshakeMessageError {
                state: self.state.to_string(),
                message_type: "ClientHello",
            });
        }
        self.client_hello_received = true;
        Ok(())
    }

    /// Mark that a ClientFinished has been received (for duplicate detection).
    /// Returns error if a ClientFinished was already received.
    pub fn on_client_finished_received(&mut self) -> Result<(), DuplicateHandshakeMessageError> {
        if self.client_finished_received {
            return Err(DuplicateHandshakeMessageError {
                state: self.state.to_string(),
                message_type: "ClientFinished",
            });
        }
        self.client_finished_received = true;
        Ok(())
    }

    /// Abort the connection immediately (transition to Closed).
    pub fn abort(&mut self) -> Result<(), HandshakeStateError> {
        self.transition_to(ServerHandshakeState::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Client state machine tests ===

    #[test]
    fn test_client_initial_state() {
        let m = ClientHandshakeMachine::new();
        assert_eq!(m.state(), ClientHandshakeState::Idle);
        assert!(!m.is_terminal());
    }

    #[test]
    fn test_client_normal_progression() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.transition_to(ClientHandshakeState::ShVerified).unwrap();
        m.transition_to(ClientHandshakeState::CfSent).unwrap();
        m.transition_to(ClientHandshakeState::Authorized).unwrap();
        m.transition_to(ClientHandshakeState::Messaging).unwrap();
        m.transition_to(ClientHandshakeState::Closing).unwrap();
        m.transition_to(ClientHandshakeState::Closed).unwrap();
        assert!(m.is_terminal());
    }

    #[test]
    fn test_client_illegal_skip_transition() {
        let mut m = ClientHandshakeMachine::new();
        // Cannot skip from Idle to ChSent
        let err = m.transition_to(ClientHandshakeState::ChSent).unwrap_err();
        assert_eq!(err.role, HandshakeRole::Client);
        assert!(err.from_state.contains("C_IDLE"));
        assert!(err.to_state.contains("C_CH_SENT"));
    }

    #[test]
    fn test_client_illegal_backward_transition() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        // Cannot go backward
        let err = m
            .transition_to(ClientHandshakeState::Connecting)
            .unwrap_err();
        assert!(err.from_state.contains("C_CH_SENT"));
    }

    #[test]
    fn test_client_abort_from_any_state() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.abort().unwrap();
        assert_eq!(m.state(), ClientHandshakeState::Closed);
        assert!(m.is_terminal());

        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.abort().unwrap();
        assert_eq!(m.state(), ClientHandshakeState::Closed);

        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.transition_to(ClientHandshakeState::ShVerified).unwrap();
        m.transition_to(ClientHandshakeState::CfSent).unwrap();
        m.abort().unwrap();
        assert_eq!(m.state(), ClientHandshakeState::Closed);
    }

    #[test]
    fn test_client_graceful_close_from_messaging() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.transition_to(ClientHandshakeState::ShVerified).unwrap();
        m.transition_to(ClientHandshakeState::CfSent).unwrap();
        m.transition_to(ClientHandshakeState::Authorized).unwrap();
        m.transition_to(ClientHandshakeState::Messaging).unwrap();
        m.transition_to(ClientHandshakeState::Closing).unwrap();
        assert_eq!(m.state(), ClientHandshakeState::Closing);
    }

    #[test]
    fn test_client_close_from_handshake_state() {
        // Graceful close from any active state is allowed
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::Closing).unwrap();
        assert_eq!(m.state(), ClientHandshakeState::Closing);
    }

    #[test]
    fn test_client_duplicate_server_hello() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.on_server_hello_received().unwrap();
        let err = m.on_server_hello_received().unwrap_err();
        assert_eq!(err.message_type, "ServerHello");
    }

    #[test]
    fn test_client_unexpected_frame_in_ch_sent() {
        let m = ClientHandshakeMachine::new();
        // In Idle state, no frames are allowed
        let err = m.check_frame_type(0x01).unwrap_err();
        assert_eq!(err.frame_type, 0x01);
    }

    #[test]
    fn test_client_allowed_frames_in_messaging() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.transition_to(ClientHandshakeState::ShVerified).unwrap();
        m.transition_to(ClientHandshakeState::CfSent).unwrap();
        m.transition_to(ClientHandshakeState::Authorized).unwrap();
        m.transition_to(ClientHandshakeState::Messaging).unwrap();

        // DATA, RPC_REQUEST, RPC_RESPONSE, CLOSE, ERROR, PING, PONG allowed
        for ft in [0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            m.check_frame_type(ft).unwrap();
        }

        // HANDSHAKE frame not allowed in messaging
        let err = m.check_frame_type(0x02).unwrap_err();
        assert_eq!(err.frame_type, 0x02);
    }

    #[test]
    fn test_client_handshake_frame_only_in_ch_sent() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();

        // HANDSHAKE allowed
        m.check_frame_type(0x02).unwrap();

        // DATA not allowed
        let err = m.check_frame_type(0x01).unwrap_err();
        assert_eq!(err.frame_type, 0x01);
    }

    #[test]
    fn test_client_closing_only_allows_close() {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.transition_to(ClientHandshakeState::ShVerified).unwrap();
        m.transition_to(ClientHandshakeState::CfSent).unwrap();
        m.transition_to(ClientHandshakeState::Authorized).unwrap();
        m.transition_to(ClientHandshakeState::Messaging).unwrap();
        m.transition_to(ClientHandshakeState::Closing).unwrap();

        // CLOSE allowed
        m.check_frame_type(0x05).unwrap();

        // DATA not allowed
        let err = m.check_frame_type(0x01).unwrap_err();
        assert_eq!(err.frame_type, 0x01);
    }

    #[test]
    fn test_client_timeout_validation() {
        let mut m = ClientHandshakeMachine::new();
        // Bypass the builder's minimum-timeout assertion for testing
        m.handshake_timeout = Duration::from_millis(1);
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        let err = m.check_timeout().unwrap_err();
        assert!(err.state.contains("C_CH_SENT"));
    }

    #[test]
    fn test_client_custom_timeouts() {
        let m = ClientHandshakeMachine::new()
            .with_handshake_timeout(Duration::from_secs(60))
            .with_close_timeout(Duration::from_secs(10));
        assert_eq!(m.handshake_timeout, Duration::from_secs(60));
        assert_eq!(m.close_timeout, Duration::from_secs(10));
    }

    #[test]
    #[should_panic(expected = "handshake timeout must be >= 10s")]
    fn test_client_min_handshake_timeout() {
        ClientHandshakeMachine::new().with_handshake_timeout(Duration::from_secs(5));
    }

    #[test]
    #[should_panic(expected = "close timeout must be >= 1s")]
    fn test_client_min_close_timeout() {
        ClientHandshakeMachine::new().with_close_timeout(Duration::from_millis(500));
    }

    // === Server state machine tests ===

    #[test]
    fn test_server_initial_state() {
        let m = ServerHandshakeMachine::new();
        assert_eq!(m.state(), ServerHandshakeState::Listening);
        assert!(!m.is_terminal());
    }

    #[test]
    fn test_server_normal_progression() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.transition_to(ServerHandshakeState::ChVerified).unwrap();
        m.transition_to(ServerHandshakeState::ShSent).unwrap();
        m.transition_to(ServerHandshakeState::CfVerified).unwrap();
        m.transition_to(ServerHandshakeState::Authorized).unwrap();
        m.transition_to(ServerHandshakeState::Messaging).unwrap();
        m.transition_to(ServerHandshakeState::Closing).unwrap();
        m.transition_to(ServerHandshakeState::Closed).unwrap();
        assert!(m.is_terminal());
    }

    #[test]
    fn test_server_illegal_skip_transition() {
        let mut m = ServerHandshakeMachine::new();
        // Cannot skip from Listening to ChVerified
        let err = m
            .transition_to(ServerHandshakeState::ChVerified)
            .unwrap_err();
        assert_eq!(err.role, HandshakeRole::Server);
        assert!(err.from_state.contains("S_LISTENING"));
    }

    #[test]
    fn test_server_abort_from_any_state() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.abort().unwrap();
        assert_eq!(m.state(), ServerHandshakeState::Closed);

        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.transition_to(ServerHandshakeState::ChVerified).unwrap();
        m.transition_to(ServerHandshakeState::ShSent).unwrap();
        m.abort().unwrap();
        assert_eq!(m.state(), ServerHandshakeState::Closed);
    }

    #[test]
    fn test_server_duplicate_client_hello() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.on_client_hello_received().unwrap();
        let err = m.on_client_hello_received().unwrap_err();
        assert_eq!(err.message_type, "ClientHello");
    }

    #[test]
    fn test_server_duplicate_client_finished() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.transition_to(ServerHandshakeState::ChVerified).unwrap();
        m.transition_to(ServerHandshakeState::ShSent).unwrap();
        m.on_client_finished_received().unwrap();
        let err = m.on_client_finished_received().unwrap_err();
        assert_eq!(err.message_type, "ClientFinished");
    }

    #[test]
    fn test_server_handshake_frame_only_in_transport_ready() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();

        // HANDSHAKE allowed
        m.check_frame_type(0x02).unwrap();

        // DATA not allowed
        let err = m.check_frame_type(0x01).unwrap_err();
        assert_eq!(err.frame_type, 0x01);
    }

    #[test]
    fn test_server_messaging_allowed_frames() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.transition_to(ServerHandshakeState::ChVerified).unwrap();
        m.transition_to(ServerHandshakeState::ShSent).unwrap();
        m.transition_to(ServerHandshakeState::CfVerified).unwrap();
        m.transition_to(ServerHandshakeState::Authorized).unwrap();
        m.transition_to(ServerHandshakeState::Messaging).unwrap();

        for ft in [0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            m.check_frame_type(ft).unwrap();
        }

        // HANDSHAKE not allowed in messaging
        let err = m.check_frame_type(0x02).unwrap_err();
        assert_eq!(err.frame_type, 0x02);
    }

    #[test]
    fn test_server_closing_only_allows_close() {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.transition_to(ServerHandshakeState::ChVerified).unwrap();
        m.transition_to(ServerHandshakeState::ShSent).unwrap();
        m.transition_to(ServerHandshakeState::CfVerified).unwrap();
        m.transition_to(ServerHandshakeState::Authorized).unwrap();
        m.transition_to(ServerHandshakeState::Messaging).unwrap();
        m.transition_to(ServerHandshakeState::Closing).unwrap();

        m.check_frame_type(0x05).unwrap();
        let err = m.check_frame_type(0x01).unwrap_err();
        assert_eq!(err.frame_type, 0x01);
    }

    #[test]
    fn test_server_timeout_validation() {
        let mut m = ServerHandshakeMachine::new();
        // Bypass the builder's minimum-timeout assertion for testing
        m.handshake_timeout = Duration::from_millis(1);
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let err = m.check_timeout().unwrap_err();
        assert!(err.state.contains("S_TRANSPORT_READY"));
    }

    // === State display tests ===

    #[test]
    fn test_client_state_display() {
        assert_eq!(ClientHandshakeState::Idle.to_string(), "C_IDLE");
        assert_eq!(ClientHandshakeState::ChSent.to_string(), "C_CH_SENT");
        assert_eq!(ClientHandshakeState::Closed.to_string(), "C_CLOSED");
    }

    #[test]
    fn test_server_state_display() {
        assert_eq!(ServerHandshakeState::Listening.to_string(), "S_LISTENING");
        assert_eq!(
            ServerHandshakeState::TransportReady.to_string(),
            "S_TRANSPORT_READY"
        );
        assert_eq!(ServerHandshakeState::Closed.to_string(), "S_CLOSED");
    }

    // === State property tests ===

    #[test]
    fn test_client_is_identity_verified() {
        assert!(!ClientHandshakeState::Idle.is_identity_verified());
        assert!(!ClientHandshakeState::Connecting.is_identity_verified());
        assert!(!ClientHandshakeState::ChSent.is_identity_verified());
        assert!(ClientHandshakeState::ShVerified.is_identity_verified());
        assert!(ClientHandshakeState::CfSent.is_identity_verified());
        assert!(ClientHandshakeState::Messaging.is_identity_verified());
    }

    #[test]
    fn test_server_is_identity_verified() {
        assert!(!ServerHandshakeState::Listening.is_identity_verified());
        assert!(!ServerHandshakeState::TransportReady.is_identity_verified());
        assert!(ServerHandshakeState::ChVerified.is_identity_verified());
        assert!(ServerHandshakeState::ShSent.is_identity_verified());
        assert!(ServerHandshakeState::Messaging.is_identity_verified());
    }
}
