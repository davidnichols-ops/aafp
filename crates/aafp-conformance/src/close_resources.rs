//! Resource verification tests for CloseManager (RFC-0002 §6.6.7, A-8).
//!
//! These tests verify that:
//! - The close timer is properly started, stopped, and never leaks.
//! - The CloseManager's internal state (remote_code, remote_message) is
//!   correctly tracked and cleaned up.
//! - No resources are held after transition to Closed.
//! - The CloseManager is reusable (a new one can be created after old one
//!   is dropped).

#![allow(unused_imports)]
use aafp_messaging::{CloseAction, CloseManager, CloseState};
use std::time::{Duration, Instant};

// ── Timer resource verification ───────────────────────────────────

#[test]
fn test_resource_timer_started_on_initiate() {
    let mut cm = CloseManager::new();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
    cm.initiate_close(0, "bye");
    assert!(cm.timer_active());
    assert!(cm.deadline().is_some());
}

#[test]
fn test_resource_timer_started_on_remote_close() {
    let mut cm = CloseManager::new();
    assert!(!cm.timer_active());
    cm.on_close_received(0, "peer");
    assert!(cm.timer_active());
    assert!(cm.deadline().is_some());
}

#[test]
fn test_resource_timer_stopped_on_peer_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(cm.timer_active());
    cm.on_close_received(0, "ack");
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_timer_stopped_on_respond() {
    let mut cm = CloseManager::new();
    cm.on_close_received(0, "peer");
    assert!(cm.timer_active());
    cm.respond_close(0, "ack");
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_timer_stopped_on_timeout() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(cm.timer_active());
    cm.on_timeout();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_timer_stopped_on_abort() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(cm.timer_active());
    cm.abort();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_timer_stopped_on_fatal_error() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(cm.timer_active());
    cm.on_fatal_error_received();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_timer_stopped_on_transport_reset() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    assert!(cm.timer_active());
    cm.on_transport_reset();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_no_timer_in_open_state() {
    let cm = CloseManager::new();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

#[test]
fn test_resource_no_timer_in_closed_state() {
    let mut cm = CloseManager::new();
    cm.abort();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
}

// ── Remote state tracking ─────────────────────────────────────────

#[test]
fn test_resource_remote_code_recorded() {
    let mut cm = CloseManager::new();
    assert_eq!(cm.remote_code(), None);
    cm.on_close_received(42, "answer");
    assert_eq!(cm.remote_code(), Some(42));
}

#[test]
fn test_resource_remote_message_recorded() {
    let mut cm = CloseManager::new();
    assert_eq!(cm.remote_message(), None);
    cm.on_close_received(0, "goodbye");
    assert_eq!(cm.remote_message(), Some("goodbye"));
}

#[test]
fn test_resource_remote_state_not_cleared_on_duplicate() {
    let mut cm = CloseManager::new();
    cm.on_close_received(1, "first");
    cm.on_close_received(2, "second");
    // First values are preserved.
    assert_eq!(cm.remote_code(), Some(1));
    assert_eq!(cm.remote_message(), Some("first"));
}

#[test]
fn test_resource_remote_state_recorded_in_crossed_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "local");
    cm.on_close_received(99, "peer");
    assert_eq!(cm.remote_code(), Some(99));
    assert_eq!(cm.remote_message(), Some("peer"));
}

// ── No resource leak after close ──────────────────────────────────

#[test]
fn test_resource_no_leak_after_graceful_close() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    cm.on_close_received(0, "ack");
    // All resources should be released.
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_resource_no_leak_after_timeout() {
    let mut cm = CloseManager::new();
    cm.initiate_close(0, "bye");
    cm.on_timeout();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_resource_no_leak_after_abort() {
    let mut cm = CloseManager::new();
    cm.abort();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_resource_no_leak_after_fatal_error() {
    let mut cm = CloseManager::new();
    cm.on_fatal_error_received();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
    assert_eq!(cm.state(), CloseState::Closed);
}

#[test]
fn test_resource_no_leak_after_transport_reset() {
    let mut cm = CloseManager::new();
    cm.on_transport_reset();
    assert!(!cm.timer_active());
    assert!(cm.deadline().is_none());
    assert_eq!(cm.state(), CloseState::Closed);
}

// ── CloseManager is reusable (drop and recreate) ──────────────────

#[test]
fn test_resource_drop_and_recreate() {
    for i in 0..1000 {
        let mut cm = CloseManager::new();
        cm.initiate_close(0, format!("cycle-{}", i));
        cm.on_close_received(0, "ack");
        // cm is dropped at end of iteration.
    }
    // No panic, no resource exhaustion.
}

// ── Timer deadline is in the future ───────────────────────────────

#[test]
fn test_resource_deadline_in_future_on_initiate() {
    let mut cm = CloseManager::new();
    let before = Instant::now();
    cm.initiate_close(0, "bye");
    let deadline = cm.deadline().unwrap();
    assert!(deadline > before, "deadline should be in the future");
    assert!(
        deadline <= before + Duration::from_secs(6),
        "deadline should be ~5s from now"
    );
}

#[test]
fn test_resource_deadline_in_future_on_remote_close() {
    let mut cm = CloseManager::new();
    let before = Instant::now();
    cm.on_close_received(0, "peer");
    let deadline = cm.deadline().unwrap();
    assert!(deadline > before, "deadline should be in the future");
    assert!(
        deadline <= before + Duration::from_secs(6),
        "deadline should be ~5s from now"
    );
}

// ── Custom timeout affects deadline ───────────────────────────────

#[test]
fn test_resource_custom_timeout_affects_deadline() {
    let mut cm = CloseManager::with_timeout(Duration::from_secs(10)).unwrap();
    let before = Instant::now();
    cm.initiate_close(0, "bye");
    let deadline = cm.deadline().unwrap();
    assert!(
        deadline > before + Duration::from_secs(9),
        "deadline should be ~10s from now"
    );
    assert!(
        deadline <= before + Duration::from_secs(11),
        "deadline should be ~10s from now"
    );
}

// ── State queries are consistent ──────────────────────────────────

#[test]
fn test_resource_state_queries_consistent() {
    let mut cm = CloseManager::new();
    assert!(!cm.is_closed());
    assert!(!cm.is_closing());

    cm.initiate_close(0, "bye");
    assert!(!cm.is_closed());
    assert!(cm.is_closing());

    cm.on_close_received(0, "ack");
    assert!(cm.is_closed());
    assert!(!cm.is_closing()); // Closed is not "closing"
}

// ── CloseTimeout configuration is preserved ───────────────────────

#[test]
fn test_resource_timeout_preserved_through_lifecycle() {
    let mut cm = CloseManager::with_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(cm.close_timeout(), Duration::from_secs(3));
    cm.initiate_close(0, "bye");
    assert_eq!(cm.close_timeout(), Duration::from_secs(3));
    cm.on_close_received(0, "ack");
    assert_eq!(cm.close_timeout(), Duration::from_secs(3));
}
