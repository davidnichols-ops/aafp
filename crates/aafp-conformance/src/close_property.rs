//! Property-based tests for CLOSE frame semantics (RFC-0002 §6.6, A-8).
//!
//! These tests run 100,000+ randomized shutdown sequences to verify
//! that the CloseManager upholds its invariants under all possible
//! event orderings.

#![allow(unused_imports)]
use aafp_messaging::{CloseAction, CloseFrameDisposition, CloseManager, CloseState};
use std::time::{Duration, Instant};

/// Simple deterministic PRNG (xorshift64) for reproducible property tests.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        self.next_u64() % max
    }
}

/// Random event to apply to a CloseManager.
#[derive(Clone, Copy, Debug)]
enum CloseEvent {
    InitiateClose,
    OnCloseReceived,
    RespondClose,
    OnTimeout,
    OnFatalError,
    OnTransportReset,
    Abort,
    CheckTimer,
}

impl CloseEvent {
    fn random(rng: &mut Rng) -> Self {
        match rng.next_range(8) {
            0 => CloseEvent::InitiateClose,
            1 => CloseEvent::OnCloseReceived,
            2 => CloseEvent::RespondClose,
            3 => CloseEvent::OnTimeout,
            4 => CloseEvent::OnFatalError,
            5 => CloseEvent::OnTransportReset,
            6 => CloseEvent::Abort,
            _ => CloseEvent::CheckTimer,
        }
    }

    fn apply(self, cm: &mut CloseManager, rng: &mut Rng) -> CloseAction {
        match self {
            CloseEvent::InitiateClose => cm.initiate_close(rng.next_u32(), "x"),
            CloseEvent::OnCloseReceived => cm.on_close_received(rng.next_u32(), "x"),
            CloseEvent::RespondClose => cm.respond_close(rng.next_u32(), "x"),
            CloseEvent::OnTimeout => cm.on_timeout(),
            CloseEvent::OnFatalError => cm.on_fatal_error_received(),
            CloseEvent::OnTransportReset => cm.on_transport_reset(),
            CloseEvent::Abort => cm.abort(),
            CloseEvent::CheckTimer => {
                let now = if rng.next_bool() {
                    Instant::now() + Duration::from_secs(rng.next_range(10))
                } else {
                    Instant::now() - Duration::from_secs(rng.next_range(10))
                };
                cm.check_timer(now)
            }
        }
    }
}

// ── Property 1: Closed state is terminal ──────────────────────────

#[test]
fn test_prop_closed_is_always_terminal() {
    let mut rng = Rng::new(42);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        // Apply random events until Closed.
        for _ in 0..20 {
            let event = CloseEvent::random(&mut rng);
            event.apply(&mut cm, &mut rng);
            if cm.is_closed() {
                // Once closed, all further events must keep it closed.
                for _ in 0..10 {
                    let event = CloseEvent::random(&mut rng);
                    event.apply(&mut cm, &mut rng);
                    assert!(cm.is_closed(), "state leaked from Closed: {}", cm.state());
                }
                break;
            }
        }
    }
}

// ── Property 2: At most one SendCloseFrame from initiate_close ────

#[test]
fn test_prop_initiate_close_sends_at_most_one() {
    let mut rng = Rng::new(123);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        let mut send_count = 0;
        for _ in 0..20 {
            let action = cm.initiate_close(rng.next_u32(), "x");
            if matches!(action, CloseAction::SendCloseFrame { .. }) {
                send_count += 1;
            }
        }
        assert!(
            send_count <= 1,
            "initiate_close sent {} CLOSE frames (max 1 allowed)",
            send_count
        );
    }
}

// ── Property 3: At most one SendCloseFrame from respond_close ─────

#[test]
fn test_prop_respond_close_sends_at_most_one() {
    let mut rng = Rng::new(456);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        // First, receive a CLOSE to enter RemoteCloseReceived.
        cm.on_close_received(0, "peer");
        let mut send_count = 0;
        for _ in 0..20 {
            let action = cm.respond_close(rng.next_u32(), "x");
            if matches!(action, CloseAction::SendCloseFrame { .. }) {
                send_count += 1;
            }
        }
        assert!(
            send_count <= 1,
            "respond_close sent {} CLOSE frames (max 1 allowed)",
            send_count
        );
    }
}

// ── Property 4: can_send is false for data frames after close sent ─

#[test]
fn test_prop_no_data_after_close_sent() {
    let mut rng = Rng::new(789);
    let data_frame_types = [0x01u8, 0x03, 0x04, 0x07, 0x08];
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        // Apply random events.
        for _ in 0..10 {
            CloseEvent::random(&mut rng).apply(&mut cm, &mut rng);
        }
        // If we're in LocalCloseSent, no data frames should be sendable.
        if cm.state() == CloseState::LocalCloseSent {
            for &ft in &data_frame_types {
                assert!(
                    !cm.can_send(ft),
                    "can_send(0x{:02X}) returned true in LocalCloseSent",
                    ft
                );
            }
        }
    }
}

// ── Property 5: Frame disposition never returns RejectWithError ───

#[test]
fn test_prop_disposition_never_reject_with_error() {
    // The CloseManager's frame_disposition only returns Accept or
    // DiscardSilently, never RejectWithError.
    let mut rng = Rng::new(321);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        for _ in 0..10 {
            CloseEvent::random(&mut rng).apply(&mut cm, &mut rng);
        }
        for ft in 0u8..=255 {
            let d = cm.frame_disposition(ft);
            assert!(
                d == CloseFrameDisposition::Accept || d == CloseFrameDisposition::DiscardSilently,
                "disposition for 0x{:02X} in state {} is invalid: {:?}",
                ft,
                cm.state(),
                d
            );
        }
    }
}

// ── Property 6: Timer is only active in LocalCloseSent or RemoteCloseReceived ─

#[test]
fn test_prop_timer_only_active_in_closing_states() {
    let mut rng = Rng::new(654);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        for _ in 0..10 {
            CloseEvent::random(&mut rng).apply(&mut cm, &mut rng);
        }
        if cm.timer_active() {
            assert!(
                cm.state() == CloseState::LocalCloseSent
                    || cm.state() == CloseState::RemoteCloseReceived,
                "timer active in state {} (should only be in LocalCloseSent or RemoteCloseReceived)",
                cm.state()
            );
        }
    }
}

// ── Property 7: State machine has exactly 5 states ────────────────

#[test]
fn test_prop_only_five_states_reachable() {
    let mut rng = Rng::new(987);
    let valid_states = [
        CloseState::Open,
        CloseState::LocalCloseSent,
        CloseState::RemoteCloseReceived,
        CloseState::CloseReceived,
        CloseState::Closed,
    ];
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        for _ in 0..10 {
            CloseEvent::random(&mut rng).apply(&mut cm, &mut rng);
        }
        let state = cm.state();
        assert!(valid_states.contains(&state), "invalid state: {:?}", state);
    }
}

// ── Property 8: Once closed, no action returns CloseQuic ──────────

#[test]
fn test_prop_no_closequic_after_closed() {
    let mut rng = Rng::new(111);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        // Force closed.
        cm.abort();
        // Apply random events — none should return CloseQuic.
        for _ in 0..10 {
            let action = CloseEvent::random(&mut rng).apply(&mut cm, &mut rng);
            assert!(
                !matches!(action, CloseAction::CloseQuic),
                "CloseQuic returned after already Closed"
            );
        }
    }
}

// ── Property 9: Message always truncated to <= 256 bytes ──────────

#[test]
fn test_prop_message_always_truncated() {
    let mut rng = Rng::new(222);
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        let len = rng.next_range(1000) as usize;
        let msg = "x".repeat(len);
        let action = cm.initiate_close(0, &msg);
        if let CloseAction::SendCloseFrame { message, .. } = action {
            assert!(
                message.len() <= aafp_messaging::MAX_CLOSE_MESSAGE_LEN,
                "message len {} > {}",
                message.len(),
                aafp_messaging::MAX_CLOSE_MESSAGE_LEN
            );
        }
    }
}

// ── Property 10: Crossed close always results in Closed ───────────

#[test]
fn test_prop_crossed_close_always_closed() {
    for _ in 0..100_000 {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, "local");
        let action = cm.on_close_received(0, "peer");
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }
}
