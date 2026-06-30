//! Conformance tests for normative CLOSE frame semantics (RFC-0002 §6.6, A-8).
//!
//! These tests verify that the CloseManager implements every normative
//! requirement from §6.6. Each test is tagged with its source section.
//!
//! ## Test Categories
//!
//! - **State machine transitions**: §6.6.1 transition table
//! - **Invariants**: §6.6.1 invariants 1-5
//! - **Close initiation**: §6.6.2
//! - **Close reception**: §6.6.3
//! - **Crossed close**: §6.6.4
//! - **Close timeout**: §6.6.5
//! - **Frame disposition**: §6.6.6
//! - **Fatal ERROR vs CLOSE**: §6.6.8
//! - **Transport reset**: §6.6.9
//! - **Security**: §6.6.12

#![allow(unused_imports)]
use aafp_messaging::{
    CloseAction, CloseFrameDisposition, CloseManager, CloseState, DEFAULT_CLOSE_TIMEOUT,
    MAX_CLOSE_MESSAGE_LEN, MIN_CLOSE_TIMEOUT,
};
use std::time::{Duration, Instant};

// ── §6.6.1 State Machine Transition Table ─────────────────────────

#[test]
fn test_r2_300_open_to_local_close_sent_on_initiate() {
    // §6.6.1: Open + initiate_close → LocalCloseSent, start timer
    let mut cm = CloseManager::new();
    let action = cm.initiate_close(0, "goodbye");
    assert!(matches!(action, CloseAction::SendCloseFrame { .. }));
    assert_eq!(cm.state(), CloseState::LocalCloseSent);
    assert!(
        cm.timer_active(),
        "timer must be started on entering LocalCloseSent"
    );
}

#[test]
fn test_r2_301_open_to_remote_close_received_on_receive() {
    // §6.6.1: Open + CLOSE received → RemoteCloseReceived, start timer
    let mut cm = CloseManager::new();
    let action = cm.on_close_received(0, "peer");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
    assert!(
        cm.timer_active(),
        "timer must be started on entering RemoteCloseReceived"
    );
}

#[test]
fn test_r2_302_local_close_sent_to_closed_on_peer_close() {
    // §6.6.1: LocalCloseSent + CLOSE received → CloseReceived → Closed
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let action = cm.on_close_received(0, "ack");
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
    assert!(!cm.timer_active(), "timer must be stopped");
}

#[test]
fn test_r2_303_local_close_sent_to_closed_on_timeout() {
    // §6.6.1: LocalCloseSent + timeout → Closed
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let action = cm.on_timeout();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_304_local_close_sent_discard_non_close() {
    // §6.6.1: LocalCloseSent + non-CLOSE frame → discard, remain
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    for ft in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08] {
        assert_eq!(
            cm.frame_disposition(ft),
            CloseFrameDisposition::DiscardSilently,
            "0x{:02X} should be DiscardSilently",
            ft
        );
    }
    assert_eq!(cm.state(), CloseState::LocalCloseSent);
}

#[test]
fn test_r2_305_remote_close_received_to_closed_on_respond() {
    // §6.6.1: RemoteCloseReceived + respond_close → CloseReceived → Closed
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    let action = cm.respond_close(0, "ack");
    assert!(matches!(action, CloseAction::SendCloseFrame { .. }));
    assert_eq!(cm.state(), CloseState::Closed);
    assert!(!cm.timer_active());
}

#[test]
fn test_r2_306_remote_close_received_to_closed_on_timeout() {
    // §6.6.1: RemoteCloseReceived + timeout → Closed
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    let action = cm.on_timeout();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_307_remote_close_received_discard_duplicate_close() {
    // §6.6.1: RemoteCloseReceived + second CLOSE → discard, remain
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "first");
    let action = cm.on_close_received(0, "second");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
}

#[test]
fn test_r2_308_closed_is_terminal() {
    // §6.6.1: Closed + any event → no-op
    let mut cm = CloseManager::new();
    cm.abort();
    assert_eq!(cm.initiate_close(0, "x"), CloseAction::None);
    assert_eq!(cm.on_close_received(0, "x"), CloseAction::None);
    assert_eq!(cm.respond_close(0, "x"), CloseAction::None);
    assert_eq!(cm.on_timeout(), CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── §6.6.1 Invariants ─────────────────────────────────────────────

#[test]
fn test_r2_310_invariant1_at_most_one_outbound_close() {
    // Invariant 1: initiate_close in LocalCloseSent/CloseReceived/Closed is no-op
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "first");
    assert_eq!(cm.initiate_close(0, "second"), CloseAction::None);
    assert_eq!(cm.state(), CloseState::LocalCloseSent);
}

#[test]
fn test_r2_311_invariant2_at_most_one_responding_close() {
    // Invariant 2: respond_close sends exactly one CLOSE
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    let a1 = cm.respond_close(0, "ack");
    assert!(matches!(a1, CloseAction::SendCloseFrame { .. }));
    // After Closed, respond_close is no-op.
    let a2 = cm.respond_close(0, "again");
    assert_eq!(a2, CloseAction::None);
}

#[test]
fn test_r2_312_invariant3_no_data_after_close_sent() {
    // Invariant 3: can_send returns false for data frames in LocalCloseSent
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(!cm.can_send(0x01), "DATA must not be sendable");
    assert!(!cm.can_send(0x03), "RPC_REQUEST must not be sendable");
    assert!(!cm.can_send(0x04), "RPC_RESPONSE must not be sendable");
    assert!(!cm.can_send(0x07), "PING must not be sendable");
    assert!(!cm.can_send(0x08), "PONG must not be sendable");
}

#[test]
fn test_r2_313_invariant4_terminal_irreversible() {
    // Invariant 4: Closed is irreversible
    let mut cm = CloseManager::new();
    cm.abort();
    // No event can move out of Closed.
    cm.initiate_close(0, "x");
    cm.on_close_received(0, "x");
    cm.on_fatal_error_received();
    cm.on_transport_reset();
    cm.on_timeout();
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_314_invariant5_timer_discipline() {
    // Invariant 5: timer starts on LocalCloseSent/RemoteCloseReceived,
    // stops on peer CLOSE / respond_close / timeout
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(
        cm.timer_active(),
        "timer should be active in LocalCloseSent"
    );
    cm.on_close_received(0, "ack");
    assert!(
        !cm.timer_active(),
        "timer should be stopped after peer CLOSE"
    );

    let mut cm2 = CloseManager::new();
    cm2.on_close_received(0, "peer");
    assert!(
        cm2.timer_active(),
        "timer should be active in RemoteCloseReceived"
    );
    cm2.respond_close(0, "ack");
    assert!(
        !cm2.timer_active(),
        "timer should be stopped after respond_close"
    );
}

// ── §6.6.2 Close Initiation ───────────────────────────────────────

#[test]
fn test_r2_320_initiate_close_with_code_zero() {
    let mut cm = CloseManager::new();
    let action = cm.initiate_close(0, "normal shutdown");
    match action {
        CloseAction::SendCloseFrame { code, message } => {
            assert_eq!(code, 0);
            assert_eq!(message, "normal shutdown");
        }
        _ => panic!("expected SendCloseFrame"),
    }
}

#[test]
fn test_r2_321_initiate_close_with_nonzero_code() {
    let mut cm = CloseManager::new();
    let action = cm.initiate_close(1000, "going away");
    match action {
        CloseAction::SendCloseFrame { code, message } => {
            assert_eq!(code, 1000);
            assert_eq!(message, "going away");
        }
        _ => panic!("expected SendCloseFrame"),
    }
}

#[test]
fn test_r2_322_initiate_close_truncates_long_message() {
    let mut cm = CloseManager::new();
    let long_msg = "x".repeat(MAX_CLOSE_MESSAGE_LEN + 100);
    let action = cm.initiate_close(0, long_msg);
    match action {
        CloseAction::SendCloseFrame { code, message } => {
            assert!(message.len() <= MAX_CLOSE_MESSAGE_LEN);
        }
        _ => panic!("expected SendCloseFrame"),
    }
}

// ── §6.6.3 Close Reception ────────────────────────────────────────

#[test]
fn test_r2_330_receive_close_from_open_records_remote() {
    let mut cm = CloseManager::new();
    cm.on_close_received(42, "peer reason");
    assert_eq!(cm.remote_code(), Some(42));
    assert_eq!(cm.remote_message(), Some("peer reason"));
    assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
}

#[test]
fn test_r2_331_receive_close_from_local_close_sent_is_crossed() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "local");
    cm.on_close_received(0, "peer");
    assert_eq!(cm.remote_code(), Some(0));
    assert_eq!(cm.remote_message(), Some("peer"));
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_332_receive_close_duplicate_preserves_first() {
    let mut cm = CloseManager::new();
    cm.on_close_received(1, "first");
    cm.on_close_received(2, "second");
    assert_eq!(cm.remote_code(), Some(1), "first code should be preserved");
    assert_eq!(
        cm.remote_message(),
        Some("first"),
        "first message should be preserved"
    );
}

// ── §6.6.4 Crossed Close ──────────────────────────────────────────

#[test]
fn test_r2_340_crossed_close_graceful() {
    // Both sides send CLOSE simultaneously.
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "local");
    let action = cm.on_close_received(0, "peer");
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
    // No error generated (graceful).
}

// ── §6.6.5 Close Timeout ──────────────────────────────────────────

#[test]
fn test_r2_350_default_timeout_is_5s() {
    let cm = CloseManager::new();
    assert_eq!(cm.close_timeout(), Duration::from_secs(5));
}

#[test]
fn test_r2_351_min_timeout_is_1s() {
    let cm = CloseManager::with_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(cm.close_timeout(), Duration::from_secs(1));
}

#[test]
fn test_r2_352_timeout_below_minimum_rejected() {
    assert!(CloseManager::with_timeout(Duration::from_millis(999)).is_err());
}

#[test]
fn test_r2_353_timeout_in_local_close_sent_forces_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let action = cm.on_timeout();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_354_timeout_in_remote_close_received_forces_close() {
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    let action = cm.on_timeout();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── §6.6.6 Frame Disposition ──────────────────────────────────────

#[test]
fn test_r2_360_disposition_open_accepts_all() {
    let cm = CloseManager::new();
    for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
        assert_eq!(cm.frame_disposition(ft), CloseFrameDisposition::Accept);
    }
}

#[test]
fn test_r2_361_disposition_local_close_sent_accepts_only_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert_eq!(cm.frame_disposition(0x05), CloseFrameDisposition::Accept);
    for ft in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08] {
        assert_eq!(
            cm.frame_disposition(ft),
            CloseFrameDisposition::DiscardSilently
        );
    }
}

#[test]
fn test_r2_362_disposition_never_returns_reject_with_error() {
    // §6.6.6: No ERROR is sent for frames received during close.
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    for ft in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
        let d = cm.frame_disposition(ft);
        assert!(
            d == CloseFrameDisposition::Accept || d == CloseFrameDisposition::DiscardSilently,
            "disposition must not be RejectWithError during close"
        );
    }
}

// ── §6.6.8 Fatal ERROR vs CLOSE ───────────────────────────────────

#[test]
fn test_r2_370_fatal_error_bypasses_graceful_path() {
    let mut cm = CloseManager::new();
    let action = cm.on_fatal_error_received();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
    // No CLOSE was sent (no SendCloseFrame action).
}

#[test]
fn test_r2_371_fatal_error_during_local_close_sent() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let action = cm.on_fatal_error_received();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
    assert!(!cm.timer_active());
}

// ── §6.6.9 Transport Reset ────────────────────────────────────────

#[test]
fn test_r2_380_transport_reset_from_open() {
    let mut cm = CloseManager::new();
    let action = cm.on_transport_reset();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_381_transport_reset_from_local_close_sent() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let action = cm.on_transport_reset();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_382_transport_reset_from_remote_close_received() {
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    let action = cm.on_transport_reset();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── §6.6.12 Security Considerations ───────────────────────────────

#[test]
fn test_r2_390_no_close_amplification() {
    // §6.6.12.3: A single received CLOSE results in at most one sent CLOSE.
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    let a1 = cm.respond_close(0, "ack");
    assert!(matches!(a1, CloseAction::SendCloseFrame { .. }));
    // Any further respond_close is no-op.
    let a2 = cm.respond_close(0, "again");
    assert_eq!(a2, CloseAction::None);
}

#[test]
fn test_r2_391_duplicate_close_no_amplification() {
    // Multiple CLOSE frames received → at most one CLOSE sent in response.
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "first");
    cm.on_close_received(0, "second");
    cm.on_close_received(0, "third");
    let action = cm.respond_close(0, "ack");
    assert!(matches!(action, CloseAction::SendCloseFrame { .. }));
    // Only one CLOSE is sent.
}

#[test]
fn test_r2_392_message_truncation_utf8_safe() {
    // §6.6.12.2: truncated message must be valid UTF-8.
    let mut cm = CloseManager::new();
    let long_msg = "é".repeat(130); // 260 bytes > 256
    let action = cm.initiate_close(0, long_msg);
    if let CloseAction::SendCloseFrame { message, .. } = action {
        assert!(message.len() <= MAX_CLOSE_MESSAGE_LEN);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    } else {
        panic!("expected SendCloseFrame");
    }
}

#[test]
fn test_r2_393_close_timer_bounds_closing_duration() {
    // §6.6.12.4: close timeout bounds the time in closing state.
    let mut cm = CloseManager::with_timeout(Duration::from_secs(2)).unwrap();
    cm.initiate_close(0, "bye");
    assert_eq!(cm.close_timeout(), Duration::from_secs(2));
    // Timer fires after 2s.
    let action = cm.on_timeout();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── Full lifecycle scenarios ──────────────────────────────────────

#[test]
fn test_r2_395_full_client_initiated_graceful_close() {
    let mut cm = CloseManager::new();
    // 1. Client initiates close
    let a1 = cm.initiate_close(0, "goodbye");
    assert!(matches!(a1, CloseAction::SendCloseFrame { .. }));
    // 2. Server responds with CLOSE
    let a2 = cm.on_close_received(0, "ack");
    assert_eq!(a2, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_396_full_server_initiated_graceful_close() {
    let mut cm = CloseManager::new();
    // 1. Server sends CLOSE
    let a1 = cm.on_close_received(0, "server goodbye");
    assert_eq!(a1, CloseAction::None);
    // 2. Client responds
    let a2 = cm.respond_close(0, "client ack");
    assert!(matches!(a2, CloseAction::SendCloseFrame { .. }));
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_397_full_crossed_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "local");
    let action = cm.on_close_received(0, "peer");
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_398_full_timeout_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let action = cm.on_timeout();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_r2_399_full_abort_close() {
    let mut cm = CloseManager::new();
    let action = cm.abort();
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}
