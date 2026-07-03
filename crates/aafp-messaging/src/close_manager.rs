//! Normative CLOSE frame semantics (RFC-0002 §6.6, Rev 6 A-8).
//!
//! The `CloseManager` is the single authority for all close-related state
//! transitions on a connection. It tracks five states (`Open`,
//! `LocalCloseSent`, `RemoteCloseReceived`, `CloseReceived`, `Closed`),
//! enforces the five normative invariants from §6.6.1, and returns
//! `CloseAction` values that tell the caller what to do (send a CLOSE
//! frame, close the QUIC connection, or do nothing).
//!
//! ## Design
//!
//! The `CloseManager` is **transport-agnostic** and **synchronous**. It
//! does not own timers, QUIC connections, or streams. The caller is
//! responsible for:
//!
//! 1. Calling `on_timeout()` when the close timer fires.
//! 2. Sending CLOSE frames when `CloseAction::SendCloseFrame` is returned.
//! 3. Closing the QUIC connection when `CloseAction::CloseQuic` is returned.
//! 4. Cleaning up outstanding RPCs, streams, and buffers on `CloseQuic`.
//!
//! This separation makes the `CloseManager` trivially testable: every
//! state transition is a pure function of the current state and the
//! incoming event.

use std::time::{Duration, Instant};

/// Default close timeout (RFC-0002 §6.6.5).
pub const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum close timeout (RFC-0002 §6.6.5).
pub const MIN_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum close message length (RFC-0002 §6.6.12).
pub const MAX_CLOSE_MESSAGE_LEN: usize = 256;

/// CloseManager state (RFC-0002 §6.6.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CloseState {
    /// No CLOSE sent or received. Application data flows normally.
    Open,
    /// Local agent has sent a CLOSE frame. Awaiting peer CLOSE or timeout.
    LocalCloseSent,
    /// Remote agent has sent a CLOSE frame. Local agent should respond.
    RemoteCloseReceived,
    /// Both sides have exchanged CLOSE frames. Connection is being torn down.
    CloseReceived,
    /// Terminal. QUIC connection has been closed.
    Closed,
}

impl CloseState {
    /// Whether this state is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether the connection is in any closing state (not Open, not fully Closed).
    pub fn is_closing(&self) -> bool {
        matches!(
            self,
            Self::LocalCloseSent | Self::RemoteCloseReceived | Self::CloseReceived
        )
    }

    /// RFC-0002 §6.6.1 state name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::LocalCloseSent => "LocalCloseSent",
            Self::RemoteCloseReceived => "RemoteCloseReceived",
            Self::CloseReceived => "CloseReceived",
            Self::Closed => "Closed",
        }
    }
}

impl std::fmt::Display for CloseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Action the caller should take after a CloseManager event (RFC-0002 §6.6.10).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloseAction {
    /// Encode and send a CLOSE frame with the given code and message.
    SendCloseFrame {
        /// The close code to include in the CLOSE frame.
        code: u32,
        /// The human-readable close message.
        message: String,
    },
    /// Close the QUIC connection (graceful or forced).
    CloseQuic,
    /// No action needed (e.g., duplicate event, already closed).
    None,
}

/// Error returned by `CloseManager::new` for invalid timeout.
#[derive(Debug, thiserror::Error)]
pub enum CloseManagerError {
    /// The configured close timeout is shorter than the minimum allowed.
    #[error("close timeout must be >= 1s, got {0:?}")]
    TimeoutTooShort(Duration),
}

/// Normative CLOSE frame lifecycle manager (RFC-0002 §6.6).
///
/// Single authority for all close-related state transitions on a
/// connection. Transport-agnostic and synchronous.
#[derive(Clone, Debug)]
pub struct CloseManager {
    state: CloseState,
    /// Close code received from the peer (if any).
    remote_code: Option<u32>,
    /// Close message received from the peer (if any).
    remote_message: Option<String>,
    /// Configured close timeout.
    close_timeout: Duration,
    /// Deadline for the close timer (set when entering LocalCloseSent or
    /// RemoteCloseReceived). The caller checks this and calls
    /// `on_timeout()` when it expires.
    deadline: Option<Instant>,
}

impl CloseManager {
    /// Create a new CloseManager in `Open` state with the default timeout.
    pub fn new() -> Self {
        Self {
            state: CloseState::Open,
            remote_code: None,
            remote_message: None,
            close_timeout: DEFAULT_CLOSE_TIMEOUT,
            deadline: None,
        }
    }

    /// Create a CloseManager with a custom close timeout.
    ///
    /// Returns an error if the timeout is less than 1 second (§6.6.5).
    pub fn with_timeout(close_timeout: Duration) -> Result<Self, CloseManagerError> {
        if close_timeout < MIN_CLOSE_TIMEOUT {
            return Err(CloseManagerError::TimeoutTooShort(close_timeout));
        }
        Ok(Self {
            state: CloseState::Open,
            remote_code: None,
            remote_message: None,
            close_timeout,
            deadline: None,
        })
    }

    // ── Queries ───────────────────────────────────────────────────────

    /// Current state.
    pub fn state(&self) -> CloseState {
        self.state
    }

    /// Whether the connection is fully closed (terminal).
    pub fn is_closed(&self) -> bool {
        self.state == CloseState::Closed
    }

    /// Whether the connection is in any closing state.
    pub fn is_closing(&self) -> bool {
        self.state.is_closing()
    }

    /// Remote close code (if a CLOSE frame was received from the peer).
    pub fn remote_code(&self) -> Option<u32> {
        self.remote_code
    }

    /// Remote close message (if a CLOSE frame was received from the peer).
    pub fn remote_message(&self) -> Option<&str> {
        self.remote_message.as_deref()
    }

    /// Configured close timeout.
    pub fn close_timeout(&self) -> Duration {
        self.close_timeout
    }

    /// Close timer deadline (if a timer is running).
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether the close timer is active.
    pub fn timer_active(&self) -> bool {
        self.deadline.is_some()
    }

    /// Whether a frame of the given type can be sent in the current state
    /// (RFC-0002 §6.6.1 Invariant 3, §6.6.6).
    ///
    /// Frame type constants: 0x01=DATA, 0x02=HANDSHAKE, 0x03=RPC_REQUEST,
    /// 0x04=RPC_RESPONSE, 0x05=CLOSE, 0x06=ERROR, 0x07=PING, 0x08=PONG.
    pub fn can_send(&self, frame_type: u8) -> bool {
        match self.state {
            CloseState::Open => true,
            CloseState::LocalCloseSent => {
                // Invariant 3: no data after CLOSE sent.
                // Only a responding CLOSE is NOT permitted here (we already
                // sent ours). Fatal ERROR is allowed as an emergency signal.
                frame_type == 0x06
            }
            CloseState::RemoteCloseReceived => {
                // We can send a responding CLOSE or a fatal ERROR.
                frame_type == 0x05 || frame_type == 0x06
            }
            CloseState::CloseReceived | CloseState::Closed => false,
        }
    }

    /// Frame disposition for an incoming frame (RFC-0002 §6.6.6).
    ///
    /// Returns `Accept`, `DiscardSilently`. This method never returns
    /// `RejectWithError` — during close, no ERROR frames are sent.
    pub fn frame_disposition(&self, frame_type: u8) -> CloseFrameDisposition {
        match self.state {
            CloseState::Open => CloseFrameDisposition::Accept,
            CloseState::LocalCloseSent => {
                if frame_type == 0x05 {
                    CloseFrameDisposition::Accept
                } else {
                    CloseFrameDisposition::DiscardSilently
                }
            }
            CloseState::RemoteCloseReceived => CloseFrameDisposition::DiscardSilently,
            CloseState::CloseReceived | CloseState::Closed => {
                CloseFrameDisposition::DiscardSilently
            }
        }
    }

    // ── Commands ──────────────────────────────────────────────────────

    /// Initiate a graceful close (RFC-0002 §6.6.2).
    ///
    /// Returns `SendCloseFrame` if this is the first close initiation,
    /// `None` if the close is already in progress (idempotent).
    pub fn initiate_close(&mut self, code: u32, message: impl Into<String>) -> CloseAction {
        match self.state {
            CloseState::Open => {
                self.state = CloseState::LocalCloseSent;
                self.deadline = Some(Instant::now() + self.close_timeout);
                CloseAction::SendCloseFrame {
                    code,
                    message: truncate_message(message.into()),
                }
            }
            // Idempotent: close already in progress or done.
            _ => CloseAction::None,
        }
    }

    /// Process a received CLOSE frame (RFC-0002 §6.6.3).
    ///
    /// Returns the action the caller should take.
    pub fn on_close_received(&mut self, code: u32, message: impl Into<String>) -> CloseAction {
        let msg = truncate_message(message.into());
        match self.state {
            CloseState::Open => {
                // §6.6.3 case 1: first CLOSE from peer.
                self.remote_code = Some(code);
                self.remote_message = Some(msg);
                self.state = CloseState::RemoteCloseReceived;
                self.deadline = Some(Instant::now() + self.close_timeout);
                // Caller SHOULD call respond_close() next.
                CloseAction::None
            }
            CloseState::LocalCloseSent => {
                // §6.6.3 case 2: peer's responding CLOSE (or crossed CLOSE).
                self.remote_code = Some(code);
                self.remote_message = Some(msg);
                self.deadline = None; // stop timer
                self.state = CloseState::CloseReceived;
                // Entry action: close QUIC.
                self.state = CloseState::Closed;
                CloseAction::CloseQuic
            }
            CloseState::RemoteCloseReceived => {
                // §6.6.3 case 3: duplicate CLOSE. Silently discard.
                CloseAction::None
            }
            CloseState::CloseReceived | CloseState::Closed => {
                // §6.6.3 case 4: already closed. No-op.
                CloseAction::None
            }
        }
    }

    /// Send a responding CLOSE frame after receiving the peer's CLOSE
    /// (RFC-0002 §6.6.3 case 1d).
    ///
    /// Only valid in `RemoteCloseReceived` state. Returns `SendCloseFrame`
    /// and transitions to `CloseReceived` → `Closed`.
    pub fn respond_close(&mut self, code: u32, message: impl Into<String>) -> CloseAction {
        match self.state {
            CloseState::RemoteCloseReceived => {
                self.deadline = None; // stop timer
                self.state = CloseState::CloseReceived;
                self.state = CloseState::Closed;
                CloseAction::SendCloseFrame {
                    code,
                    message: truncate_message(message.into()),
                }
            }
            _ => CloseAction::None,
        }
    }

    /// Process a received fatal ERROR frame (RFC-0002 §6.6.8).
    ///
    /// Transitions directly to `Closed`. No responding CLOSE is sent.
    /// In `Closed` state, this is a no-op.
    pub fn on_fatal_error_received(&mut self) -> CloseAction {
        match self.state {
            CloseState::Closed => CloseAction::None,
            _ => {
                self.deadline = None;
                self.state = CloseState::Closed;
                CloseAction::CloseQuic
            }
        }
    }

    /// Process a transport reset / EOF (RFC-0002 §6.6.9).
    ///
    /// Transitions directly to `Closed`. No CLOSE is sent (transport gone).
    /// In `Closed` state, this is a no-op.
    pub fn on_transport_reset(&mut self) -> CloseAction {
        match self.state {
            CloseState::Closed => CloseAction::None,
            _ => {
                self.deadline = None;
                self.state = CloseState::Closed;
                CloseAction::CloseQuic
            }
        }
    }

    /// Process a close timer expiry (RFC-0002 §6.6.5).
    ///
    /// Force-closes the QUIC connection. Only meaningful in
    /// `LocalCloseSent` or `RemoteCloseReceived` states.
    pub fn on_timeout(&mut self) -> CloseAction {
        match self.state {
            CloseState::LocalCloseSent | CloseState::RemoteCloseReceived => {
                self.deadline = None;
                self.state = CloseState::Closed;
                CloseAction::CloseQuic
            }
            _ => CloseAction::None,
        }
    }

    /// Abort the connection immediately (RFC-0002 §5.10.10).
    ///
    /// This is an ungraceful close initiated locally. No CLOSE frame
    /// is sent. Transitions directly to `Closed`. In `Closed` state,
    /// this is a no-op.
    pub fn abort(&mut self) -> CloseAction {
        match self.state {
            CloseState::Closed => CloseAction::None,
            _ => {
                self.deadline = None;
                self.state = CloseState::Closed;
                CloseAction::CloseQuic
            }
        }
    }

    /// Check if the close timer has expired and fire it if so.
    ///
    /// Convenience method for callers that poll. Returns `CloseQuic` if
    /// the timer fired, `None` otherwise.
    pub fn check_timer(&mut self, now: Instant) -> CloseAction {
        if let Some(deadline) = self.deadline {
            if now >= deadline {
                return self.on_timeout();
            }
        }
        CloseAction::None
    }
}

impl Default for CloseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame disposition during close (RFC-0002 §6.6.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CloseFrameDisposition {
    /// Frame is allowed and should be processed.
    Accept,
    /// Frame should be silently discarded (no ERROR sent).
    DiscardSilently,
}

/// Truncate a close message to MAX_CLOSE_MESSAGE_LEN bytes (UTF-8 safe).
///
/// RFC-0002 §6.6.12: implementations MAY truncate messages longer than
/// 256 bytes. This truncates at a UTF-8 char boundary to avoid producing
/// invalid UTF-8.
fn truncate_message(s: String) -> String {
    if s.len() <= MAX_CLOSE_MESSAGE_LEN {
        return s;
    }
    // Find the largest char boundary <= MAX_CLOSE_MESSAGE_LEN.
    let mut end = MAX_CLOSE_MESSAGE_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic state transitions ───────────────────────────────────────

    #[test]
    fn test_new_manager_starts_open() {
        let cm = CloseManager::new();
        assert_eq!(cm.state(), CloseState::Open);
        assert!(!cm.is_closed());
        assert!(!cm.is_closing());
        assert!(!cm.timer_active());
        assert_eq!(cm.close_timeout(), DEFAULT_CLOSE_TIMEOUT);
    }

    #[test]
    fn test_with_custom_timeout() {
        let cm = CloseManager::with_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(cm.close_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_with_timeout_below_minimum_fails() {
        let err = CloseManager::with_timeout(Duration::from_millis(500)).unwrap_err();
        assert!(err.to_string().contains("1s"));
    }

    #[test]
    fn test_with_timeout_exactly_minimum() {
        let cm = CloseManager::with_timeout(MIN_CLOSE_TIMEOUT).unwrap();
        assert_eq!(cm.close_timeout(), MIN_CLOSE_TIMEOUT);
    }

    // ── initiate_close ────────────────────────────────────────────────

    #[test]
    fn test_initiate_close_from_open() {
        let mut cm = CloseManager::new();
        let action = cm.initiate_close(0, "goodbye");
        assert_eq!(
            action,
            CloseAction::SendCloseFrame {
                code: 0,
                message: "goodbye".to_string()
            }
        );
        assert_eq!(cm.state(), CloseState::LocalCloseSent);
        assert!(cm.timer_active());
        assert!(cm.is_closing());
    }

    #[test]
    fn test_initiate_close_idempotent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "first");
        let action = cm.initiate_close(0, "second");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::LocalCloseSent);
    }

    #[test]
    fn test_initiate_close_after_remote_close_is_noop() {
        let mut cm = CloseManager::new();
        cm.on_close_received(0, "peer");
        let action = cm.initiate_close(0, "local");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
    }

    // ── on_close_received ─────────────────────────────────────────────

    #[test]
    fn test_on_close_received_from_open() {
        let mut cm = CloseManager::new();
        let action = cm.on_close_received(1000, "going away");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
        assert_eq!(cm.remote_code(), Some(1000));
        assert_eq!(cm.remote_message(), Some("going away"));
        assert!(cm.timer_active());
    }

    #[test]
    fn test_on_close_received_from_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let action = cm.on_close_received(0, "ack");
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
        assert_eq!(cm.remote_code(), Some(0));
        assert_eq!(cm.remote_message(), Some("ack"));
    }

    #[test]
    fn test_on_close_received_duplicate_in_remote_close() {
        let mut cm = CloseManager::new();
        cm.on_close_received(0, "first");
        let action = cm.on_close_received(0, "second");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
        // First message is preserved.
        assert_eq!(cm.remote_message(), Some("first"));
    }

    #[test]
    fn test_on_close_received_in_closed_is_noop() {
        let mut cm = CloseManager::new();
        cm.abort();
        let action = cm.on_close_received(0, "late");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    // ── respond_close ─────────────────────────────────────────────────

    #[test]
    fn test_respond_close_from_remote_close_received() {
        let mut cm = CloseManager::new();
        cm.on_close_received(0, "peer");
        let action = cm.respond_close(0, "ack");
        assert_eq!(
            action,
            CloseAction::SendCloseFrame {
                code: 0,
                message: "ack".to_string()
            }
        );
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
    }

    #[test]
    fn test_respond_close_from_open_is_noop() {
        let mut cm = CloseManager::new();
        let action = cm.respond_close(0, "ack");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::Open);
    }

    #[test]
    fn test_respond_close_from_local_close_sent_is_noop() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let action = cm.respond_close(0, "ack");
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::LocalCloseSent);
    }

    // ── Crossed close ─────────────────────────────────────────────────

    #[test]
    fn test_crossed_close() {
        // Both sides send CLOSE simultaneously.
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "local");
        // Peer's CLOSE arrives while we're in LocalCloseSent.
        let action = cm.on_close_received(0, "peer");
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
    }

    // ── on_fatal_error_received ───────────────────────────────────────

    #[test]
    fn test_on_fatal_error_from_open() {
        let mut cm = CloseManager::new();
        let action = cm.on_fatal_error_received();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_on_fatal_error_from_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let action = cm.on_fatal_error_received();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
    }

    // ── on_transport_reset ────────────────────────────────────────────

    #[test]
    fn test_on_transport_reset_from_open() {
        let mut cm = CloseManager::new();
        let action = cm.on_transport_reset();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_on_transport_reset_from_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let action = cm.on_transport_reset();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
    }

    // ── on_timeout ────────────────────────────────────────────────────

    #[test]
    fn test_on_timeout_from_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let action = cm.on_timeout();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
    }

    #[test]
    fn test_on_timeout_from_remote_close_received() {
        let mut cm = CloseManager::new();
        cm.on_close_received(0, "peer");
        let action = cm.on_timeout();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_on_timeout_from_open_is_noop() {
        let mut cm = CloseManager::new();
        let action = cm.on_timeout();
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::Open);
    }

    #[test]
    fn test_on_timeout_from_closed_is_noop() {
        let mut cm = CloseManager::new();
        cm.abort();
        let action = cm.on_timeout();
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    // ── check_timer ───────────────────────────────────────────────────

    #[test]
    fn test_check_timer_not_expired() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let now = cm.deadline().unwrap() - Duration::from_millis(100);
        let action = cm.check_timer(now);
        assert_eq!(action, CloseAction::None);
        assert_eq!(cm.state(), CloseState::LocalCloseSent);
    }

    #[test]
    fn test_check_timer_expired() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let now = cm.deadline().unwrap() + Duration::from_millis(1);
        let action = cm.check_timer(now);
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    // ── abort ─────────────────────────────────────────────────────────

    #[test]
    fn test_abort_from_open() {
        let mut cm = CloseManager::new();
        let action = cm.abort();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_abort_from_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        let action = cm.abort();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
        assert!(!cm.timer_active());
    }

    // ── can_send ──────────────────────────────────────────────────────

    #[test]
    fn test_can_send_in_open() {
        let cm = CloseManager::new();
        for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            assert!(
                cm.can_send(ft),
                "should be able to send 0x{:02X} in Open",
                ft
            );
        }
    }

    #[test]
    fn test_can_send_in_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        // No data frames after CLOSE sent (Invariant 3).
        for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08] {
            assert!(
                !cm.can_send(ft),
                "should NOT be able to send 0x{:02X} in LocalCloseSent",
                ft
            );
        }
        // Fatal ERROR is allowed as emergency signal.
        assert!(
            cm.can_send(0x06),
            "fatal ERROR should be sendable in LocalCloseSent"
        );
    }

    #[test]
    fn test_can_send_in_remote_close_received() {
        let mut cm = CloseManager::new();
        cm.on_close_received(0, "peer");
        // Only responding CLOSE and fatal ERROR.
        assert!(
            cm.can_send(0x05),
            "CLOSE should be sendable in RemoteCloseReceived"
        );
        assert!(
            cm.can_send(0x06),
            "ERROR should be sendable in RemoteCloseReceived"
        );
        for ft in [0x01, 0x02, 0x03, 0x04, 0x07, 0x08] {
            assert!(
                !cm.can_send(ft),
                "should NOT be able to send 0x{:02X} in RemoteCloseReceived",
                ft
            );
        }
    }

    #[test]
    fn test_can_send_in_closed() {
        let mut cm = CloseManager::new();
        cm.abort();
        for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            assert!(!cm.can_send(ft), "should NOT send 0x{:02X} in Closed", ft);
        }
    }

    // ── frame_disposition ─────────────────────────────────────────────

    #[test]
    fn test_frame_disposition_in_open() {
        let cm = CloseManager::new();
        for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            assert_eq!(
                cm.frame_disposition(ft),
                CloseFrameDisposition::Accept,
                "0x{:02X} should be Accept in Open",
                ft
            );
        }
    }

    #[test]
    fn test_frame_disposition_in_local_close_sent() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        assert_eq!(cm.frame_disposition(0x05), CloseFrameDisposition::Accept);
        for ft in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08] {
            assert_eq!(
                cm.frame_disposition(ft),
                CloseFrameDisposition::DiscardSilently,
                "0x{:02X} should be DiscardSilently in LocalCloseSent",
                ft
            );
        }
    }

    #[test]
    fn test_frame_disposition_in_remote_close_received() {
        let mut cm = CloseManager::new();
        cm.on_close_received(0, "peer");
        // All frames discarded (including duplicate CLOSE).
        for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            assert_eq!(
                cm.frame_disposition(ft),
                CloseFrameDisposition::DiscardSilently,
                "0x{:02X} should be DiscardSilently in RemoteCloseReceived",
                ft
            );
        }
    }

    #[test]
    fn test_frame_disposition_in_closed() {
        let mut cm = CloseManager::new();
        cm.abort();
        for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            assert_eq!(
                cm.frame_disposition(ft),
                CloseFrameDisposition::DiscardSilently,
                "0x{:02X} should be DiscardSilently in Closed",
                ft
            );
        }
    }

    // ── Message truncation ────────────────────────────────────────────

    #[test]
    fn test_truncate_message_short() {
        assert_eq!(truncate_message("hello".to_string()), "hello");
    }

    #[test]
    fn test_truncate_message_exact_limit() {
        let s = "x".repeat(MAX_CLOSE_MESSAGE_LEN);
        assert_eq!(truncate_message(s.clone()), s);
    }

    #[test]
    fn test_truncate_message_over_limit() {
        let s = "x".repeat(MAX_CLOSE_MESSAGE_LEN + 100);
        let truncated = truncate_message(s);
        assert!(truncated.len() <= MAX_CLOSE_MESSAGE_LEN);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn test_truncate_message_utf8_safe() {
        // Each 'é' is 2 bytes. 130 'é' = 260 bytes > 256.
        let s = "é".repeat(130);
        let truncated = truncate_message(s);
        assert!(truncated.len() <= MAX_CLOSE_MESSAGE_LEN);
        // Must be valid UTF-8 (String guarantees this, but verify no panic).
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    // ── Full lifecycle scenarios ──────────────────────────────────────

    #[test]
    fn test_full_graceful_close_lifecycle() {
        let mut cm = CloseManager::new();
        // 1. Initiate close
        let a1 = cm.initiate_close(0, "goodbye");
        assert!(matches!(a1, CloseAction::SendCloseFrame { .. }));
        assert_eq!(cm.state(), CloseState::LocalCloseSent);
        // 2. Peer responds with CLOSE
        let a2 = cm.on_close_received(0, "ack");
        assert_eq!(a2, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_full_remote_initiated_close_lifecycle() {
        let mut cm = CloseManager::new();
        // 1. Peer sends CLOSE
        let a1 = cm.on_close_received(0, "peer goodbye");
        assert_eq!(a1, CloseAction::None);
        assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
        // 2. We respond
        let a2 = cm.respond_close(0, "ack");
        assert!(matches!(a2, CloseAction::SendCloseFrame { .. }));
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_full_timeout_lifecycle() {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "bye");
        // Peer never responds.
        let action = cm.on_timeout();
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    #[test]
    fn test_closed_state_is_truly_terminal() {
        let mut cm = CloseManager::new();
        cm.abort();
        // All events are no-ops.
        assert_eq!(cm.initiate_close(0, "x"), CloseAction::None);
        assert_eq!(cm.on_close_received(0, "x"), CloseAction::None);
        assert_eq!(cm.respond_close(0, "x"), CloseAction::None);
        assert_eq!(cm.on_fatal_error_received(), CloseAction::None);
        assert_eq!(cm.on_transport_reset(), CloseAction::None);
        assert_eq!(cm.on_timeout(), CloseAction::None);
        assert_eq!(cm.state(), CloseState::Closed);
    }

    // ── State string representation ───────────────────────────────────

    #[test]
    fn test_state_display() {
        assert_eq!(CloseState::Open.to_string(), "Open");
        assert_eq!(CloseState::LocalCloseSent.to_string(), "LocalCloseSent");
        assert_eq!(
            CloseState::RemoteCloseReceived.to_string(),
            "RemoteCloseReceived"
        );
        assert_eq!(CloseState::CloseReceived.to_string(), "CloseReceived");
        assert_eq!(CloseState::Closed.to_string(), "Closed");
    }

    #[test]
    fn test_state_is_terminal() {
        assert!(!CloseState::Open.is_terminal());
        assert!(!CloseState::LocalCloseSent.is_terminal());
        assert!(!CloseState::RemoteCloseReceived.is_terminal());
        assert!(!CloseState::CloseReceived.is_terminal());
        assert!(CloseState::Closed.is_terminal());
    }

    #[test]
    fn test_state_is_closing() {
        assert!(!CloseState::Open.is_closing());
        assert!(CloseState::LocalCloseSent.is_closing());
        assert!(CloseState::RemoteCloseReceived.is_closing());
        assert!(CloseState::CloseReceived.is_closing());
        assert!(!CloseState::Closed.is_closing());
    }
}
