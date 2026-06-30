//! Adversarial tests for CLOSE frame semantics (RFC-0002 §6.6, A-8).
//!
//! These tests verify that the CloseManager is robust against:
//! - CLOSE frame flooding (many CLOSE frames in sequence)
//! - Truncated/oversized close messages
//! - Out-of-order events (timeout after close, fatal error after close)
//! - Late CLOSE frames (arriving after Closed state)
//! - Rapid initiate/abort cycles
//! - State corruption attempts

#![allow(unused_imports)]
use aafp_messaging::{
    CloseAction, CloseFrameDisposition, CloseManager, CloseState, MAX_CLOSE_MESSAGE_LEN,
};
use std::time::{Duration, Instant};

// ── CLOSE frame flooding ──────────────────────────────────────────

#[test]
fn test_adv_close_flood_1000_close_frames() {
    // Adversary sends 1000 CLOSE frames. Only the first is processed;
    // the rest are silently discarded. No amplification.
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "first");
    for i in 1..1000 {
        let action = cm.on_close_received(i, format!("flood-{}", i));
        assert_eq!(
            action,
            CloseAction::None,
            "flood CLOSE #{} should be no-op",
            i
        );
    }
    assert_eq!(cm.state(), CloseState::RemoteCloseReceived);
    // First code is preserved.
    assert_eq!(cm.remote_code(), Some(0));
}

#[test]
fn test_adv_close_flood_after_local_close() {
    // We send CLOSE, then peer floods us with 1000 CLOSE frames.
    // Only the first peer CLOSE transitions us to Closed; rest are no-ops.
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    cm.on_close_received(0, "peer first");
    assert_eq!(cm.state(), CloseState::Closed);
    for i in 1..1000 {
        let action = cm.on_close_received(i, format!("flood-{}", i));
        assert_eq!(action, CloseAction::None);
    }
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_close_flood_mixed_frame_types() {
    // Adversary sends a mix of frame types during close. All non-CLOSE
    // frames are silently discarded.
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    let frame_types = [0x01u8, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08];
    for i in 0..1000 {
        let ft = frame_types[i % frame_types.len()];
        let disp = cm.frame_disposition(ft);
        assert_eq!(disp, CloseFrameDisposition::DiscardSilently);
    }
    assert_eq!(cm.state(), CloseState::LocalCloseSent);
}

// ── Truncated / oversized messages ────────────────────────────────

#[test]
fn test_adv_oversized_message_truncated() {
    let mut cm = CloseManager::new();
    let huge = "A".repeat(100_000);
    let action = cm.initiate_close(0, huge);
    if let CloseAction::SendCloseFrame { message, .. } = action {
        assert!(message.len() <= MAX_CLOSE_MESSAGE_LEN);
    } else {
        panic!("expected SendCloseFrame");
    }
}

#[test]
fn test_adv_oversized_remote_message_truncated() {
    let mut cm = CloseManager::new();
    let huge = "B".repeat(100_000);
    cm.on_close_received(0, &huge);
    let msg = cm.remote_message().unwrap();
    assert!(msg.len() <= MAX_CLOSE_MESSAGE_LEN);
}

#[test]
fn test_adv_empty_message_accepted() {
    let mut cm = CloseManager::new();
    let action = cm.initiate_close(0, "");
    if let CloseAction::SendCloseFrame { message, .. } = action {
        assert_eq!(message, "");
    } else {
        panic!("expected SendCloseFrame");
    }
}

#[test]
fn test_adv_empty_remote_message_accepted() {
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "");
    assert_eq!(cm.remote_message(), Some(""));
}

#[test]
fn test_adv_multibyte_utf8_message_truncated_safely() {
    let mut cm = CloseManager::new();
    // 4-byte UTF-8 characters (emoji). 65 * 4 = 260 > 256.
    let msg = "🎉".repeat(65);
    let action = cm.initiate_close(0, &msg);
    if let CloseAction::SendCloseFrame { message, .. } = action {
        assert!(message.len() <= MAX_CLOSE_MESSAGE_LEN);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    } else {
        panic!("expected SendCloseFrame");
    }
}

// ── Out-of-order events ───────────────────────────────────────────

#[test]
fn test_adv_timeout_after_closed() {
    // Timeout fires after we're already Closed (race condition).
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    cm.on_close_received(0, "peer"); // → Closed
    let action = cm.on_timeout(); // Late timeout
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_fatal_error_after_closed() {
    let mut cm = CloseManager::new();
    cm.abort();
    let action = cm.on_fatal_error_received();
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_transport_reset_after_closed() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    cm.on_close_received(0, "peer"); // → Closed
    let action = cm.on_transport_reset();
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_initiate_after_abort() {
    let mut cm = CloseManager::new();
    cm.abort();
    let action = cm.initiate_close(0, "late");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_respond_close_after_timeout() {
    // Timeout fires in RemoteCloseReceived, then caller tries respond_close.
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    cm.on_timeout(); // → Closed
    let action = cm.respond_close(0, "late");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── Late CLOSE frames ─────────────────────────────────────────────

#[test]
fn test_adv_late_close_after_abort() {
    let mut cm = CloseManager::new();
    cm.abort();
    let action = cm.on_close_received(0, "late");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_late_close_after_timeout() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    cm.on_timeout(); // → Closed
    let action = cm.on_close_received(0, "late");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_late_close_after_fatal_error() {
    let mut cm = CloseManager::new();
    cm.on_fatal_error_received(); // → Closed
    let action = cm.on_close_received(0, "late");
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── Rapid cycles ──────────────────────────────────────────────────

#[test]
fn test_adv_rapid_initiate_abort_cycles() {
    // Rapidly create and abort 1000 CloseManagers.
    for i in 0..1000 {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, format!("cycle-{}", i));
        cm.abort();
        assert_eq!(cm.state(), CloseState::Closed);
    }
}

#[test]
fn test_adv_rapid_initiate_peer_close_cycles() {
    for i in 0..1000 {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, format!("cycle-{}", i));
        let action = cm.on_close_received(0, "peer");
        assert_eq!(action, CloseAction::CloseQuic);
        assert_eq!(cm.state(), CloseState::Closed);
    }
}

// ── State corruption attempts ─────────────────────────────────────

#[test]
fn test_adv_no_state_corruption_from_flood() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    // Flood with all possible frame types.
    for ft in 0u8..=255 {
        let _ = cm.frame_disposition(ft);
    }
    // State should be unchanged.
    assert_eq!(cm.state(), CloseState::LocalCloseSent);
    assert!(cm.timer_active());
}

#[test]
fn test_adv_no_state_corruption_from_random_events() {
    let mut cm = CloseManager::new();
    for i in 0..10000u64 {
        let _ = match i % 6 {
            0 => cm.initiate_close(i as u32, "x"),
            1 => cm.on_close_received(i as u32, "x"),
            2 => cm.on_timeout(),
            3 => cm.on_fatal_error_received(),
            4 => cm.on_transport_reset(),
            _ => cm.abort(),
        };
        if cm.is_closed() {
            // Once closed, all further events are no-ops.
            break;
        }
    }
    // No panic = no state corruption.
}

// ── Timer manipulation ────────────────────────────────────────────

#[test]
fn test_adv_check_timer_with_past_time() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    // Check with a time in the past — should not fire.
    let past = Instant::now() - Duration::from_secs(60);
    let action = cm.check_timer(past);
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::LocalCloseSent);
}

#[test]
fn test_adv_check_timer_with_future_time() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    // Check with a time far in the future — should fire.
    let future = Instant::now() + Duration::from_secs(60);
    let action = cm.check_timer(future);
    assert_eq!(action, CloseAction::CloseQuic);
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_adv_check_timer_no_timer_running() {
    let mut cm = CloseManager::new();
    let action = cm.check_timer(Instant::now());
    assert_eq!(action, CloseAction::None);
    assert_eq!(cm.state(), CloseState::Open);
}

// ── Extreme close codes ───────────────────────────────────────────

#[test]
fn test_adv_max_close_code() {
    let mut cm = CloseManager::new();
    let action = cm.initiate_close(u32::MAX, "max code");
    if let CloseAction::SendCloseFrame { code, .. } = action {
        assert_eq!(code, u32::MAX);
    } else {
        panic!("expected SendCloseFrame");
    }
}

#[test]
fn test_adv_zero_close_code() {
    let mut cm = CloseManager::new();
    let action = cm.initiate_close(0, "zero code");
    if let CloseAction::SendCloseFrame { code, .. } = action {
        assert_eq!(code, 0);
    } else {
        panic!("expected SendCloseFrame");
    }
}

#[test]
fn test_adv_remote_max_close_code() {
    let mut cm = CloseManager::new();
    cm.on_close_received(u32::MAX, "max");
    assert_eq!(cm.remote_code(), Some(u32::MAX));
}

// ── Concurrent close race simulation ──────────────────────────────

#[test]
fn test_adv_simulated_race_initiate_vs_receive() {
    // Simulate a race: both sides initiate close at the "same time".
    // The CloseManager should handle this gracefully regardless of order.
    let mut cm1 = CloseManager::new();
    // Scenario A: initiate first, then receive
    cm1.initiate_close(0, "local");
    let a = cm1.on_close_received(0, "peer");
    assert_eq!(a, CloseAction::CloseQuic);

    let mut cm2 = CloseManager::new();
    // Scenario B: receive first, then initiate (should be no-op)
    cm2.on_close_received(0, "peer");
    let a = cm2.initiate_close(0, "local");
    assert_eq!(a, CloseAction::None);
    // Then respond
    let a = cm2.respond_close(0, "ack");
    assert!(matches!(a, CloseAction::SendCloseFrame { .. }));

    // Both end up Closed.
    assert_eq!(cm1.state(), CloseState::Closed);
    assert_eq!(cm2.state(), CloseState::Closed);
}
