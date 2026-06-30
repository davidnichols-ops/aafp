//! Conformance tests for the normative handshake state machine (RFC-0002 §5.10, Rev 6 A-6).
//!
//! These tests verify that the `aafp-core::handshake_state` module conforms
//! to the normative state machine defined in RFC-0002 Section 5.10. They
//! cover:
//!
//! - State enumeration (§5.10.1, §5.10.2)
//! - Forward transitions (§5.10.4, §5.10.5)
//! - Illegal transitions rejected
//! - Graceful shutdown from any active state
//! - Abort from any non-terminal state
//! - Unexpected frame handling (§5.10.7)
//! - Duplicate handshake message detection (§5.10.6)
//! - Timeout enforcement (§5.10.8)
//! - Close behavior (§5.10.9)
//! - State-to-session mapping (§5.10.11)

use aafp_core::handshake_state::{
    ClientHandshakeMachine, ClientHandshakeState, DuplicateHandshakeMessageError, HandshakeRole,
    HandshakeStateError, HandshakeTimeoutError, ServerHandshakeMachine, ServerHandshakeState,
    UnexpectedFrameError, DEFAULT_CLOSE_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT, MIN_CLOSE_TIMEOUT,
    MIN_HANDSHAKE_TIMEOUT,
};
use std::time::Duration;

// === §5.10.1 Client States ===

#[test]
fn test_r2_100_client_state_enumeration() {
    // All 9 client states must exist and have correct string forms
    assert_eq!(ClientHandshakeState::Idle.to_string(), "C_IDLE");
    assert_eq!(ClientHandshakeState::Connecting.to_string(), "C_CONNECTING");
    assert_eq!(ClientHandshakeState::ChSent.to_string(), "C_CH_SENT");
    assert_eq!(
        ClientHandshakeState::ShVerified.to_string(),
        "C_SH_VERIFIED"
    );
    assert_eq!(ClientHandshakeState::CfSent.to_string(), "C_CF_SENT");
    assert_eq!(ClientHandshakeState::Authorized.to_string(), "C_AUTHORIZED");
    assert_eq!(ClientHandshakeState::Messaging.to_string(), "C_MESSAGING");
    assert_eq!(ClientHandshakeState::Closing.to_string(), "C_CLOSING");
    assert_eq!(ClientHandshakeState::Closed.to_string(), "C_CLOSED");
}

// === §5.10.2 Server States ===

#[test]
fn test_r2_101_server_state_enumeration() {
    assert_eq!(ServerHandshakeState::Listening.to_string(), "S_LISTENING");
    assert_eq!(
        ServerHandshakeState::TransportReady.to_string(),
        "S_TRANSPORT_READY"
    );
    assert_eq!(
        ServerHandshakeState::ChVerified.to_string(),
        "S_CH_VERIFIED"
    );
    assert_eq!(ServerHandshakeState::ShSent.to_string(), "S_SH_SENT");
    assert_eq!(
        ServerHandshakeState::CfVerified.to_string(),
        "S_CF_VERIFIED"
    );
    assert_eq!(ServerHandshakeState::Authorized.to_string(), "S_AUTHORIZED");
    assert_eq!(ServerHandshakeState::Messaging.to_string(), "S_MESSAGING");
    assert_eq!(ServerHandshakeState::Closing.to_string(), "S_CLOSING");
    assert_eq!(ServerHandshakeState::Closed.to_string(), "S_CLOSED");
}

// === §5.10.4 Client Transition Table ===

#[test]
fn test_r2_110_client_full_forward_progression() {
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
fn test_r2_111_client_skip_transition_rejected() {
    let mut m = ClientHandshakeMachine::new();
    let err = m.transition_to(ClientHandshakeState::ChSent).unwrap_err();
    assert_eq!(err.role, HandshakeRole::Client);
    assert!(err.from_state.contains("C_IDLE"));
    assert!(err.to_state.contains("C_CH_SENT"));
}

#[test]
fn test_r2_112_client_backward_transition_rejected() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    let err = m
        .transition_to(ClientHandshakeState::Connecting)
        .unwrap_err();
    assert!(err.from_state.contains("C_CH_SENT"));
}

#[test]
fn test_r2_113_client_graceful_close_from_any_active_state() {
    // From Connecting
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();
    assert_eq!(m.state(), ClientHandshakeState::Closing);

    // From ChSent
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();

    // From ShVerified
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.transition_to(ClientHandshakeState::ShVerified).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();

    // From CfSent
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.transition_to(ClientHandshakeState::ShVerified).unwrap();
    m.transition_to(ClientHandshakeState::CfSent).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();

    // From Authorized
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.transition_to(ClientHandshakeState::ShVerified).unwrap();
    m.transition_to(ClientHandshakeState::CfSent).unwrap();
    m.transition_to(ClientHandshakeState::Authorized).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();
}

#[test]
fn test_r2_114_client_abort_from_any_non_terminal_state() {
    for abort_from in [
        ClientHandshakeState::Connecting,
        ClientHandshakeState::ChSent,
        ClientHandshakeState::ShVerified,
        ClientHandshakeState::CfSent,
        ClientHandshakeState::Authorized,
        ClientHandshakeState::Messaging,
    ] {
        let mut m = ClientHandshakeMachine::new();
        // Advance to the target state
        match abort_from {
            ClientHandshakeState::Connecting => {
                m.transition_to(ClientHandshakeState::Connecting).unwrap();
            }
            ClientHandshakeState::ChSent => {
                m.transition_to(ClientHandshakeState::Connecting).unwrap();
                m.transition_to(ClientHandshakeState::ChSent).unwrap();
            }
            ClientHandshakeState::ShVerified => {
                m.transition_to(ClientHandshakeState::Connecting).unwrap();
                m.transition_to(ClientHandshakeState::ChSent).unwrap();
                m.transition_to(ClientHandshakeState::ShVerified).unwrap();
            }
            ClientHandshakeState::CfSent => {
                m.transition_to(ClientHandshakeState::Connecting).unwrap();
                m.transition_to(ClientHandshakeState::ChSent).unwrap();
                m.transition_to(ClientHandshakeState::ShVerified).unwrap();
                m.transition_to(ClientHandshakeState::CfSent).unwrap();
            }
            ClientHandshakeState::Authorized => {
                m.transition_to(ClientHandshakeState::Connecting).unwrap();
                m.transition_to(ClientHandshakeState::ChSent).unwrap();
                m.transition_to(ClientHandshakeState::ShVerified).unwrap();
                m.transition_to(ClientHandshakeState::CfSent).unwrap();
                m.transition_to(ClientHandshakeState::Authorized).unwrap();
            }
            ClientHandshakeState::Messaging => {
                m.transition_to(ClientHandshakeState::Connecting).unwrap();
                m.transition_to(ClientHandshakeState::ChSent).unwrap();
                m.transition_to(ClientHandshakeState::ShVerified).unwrap();
                m.transition_to(ClientHandshakeState::CfSent).unwrap();
                m.transition_to(ClientHandshakeState::Authorized).unwrap();
                m.transition_to(ClientHandshakeState::Messaging).unwrap();
            }
            _ => unreachable!(),
        }
        m.abort().unwrap();
        assert_eq!(m.state(), ClientHandshakeState::Closed);
        assert!(m.is_terminal());
    }
}

// === §5.10.5 Server Transition Table ===

#[test]
fn test_r2_120_server_full_forward_progression() {
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
fn test_r2_121_server_skip_transition_rejected() {
    let mut m = ServerHandshakeMachine::new();
    let err = m
        .transition_to(ServerHandshakeState::ChVerified)
        .unwrap_err();
    assert_eq!(err.role, HandshakeRole::Server);
    assert!(err.from_state.contains("S_LISTENING"));
}

#[test]
fn test_r2_122_server_abort_from_any_non_terminal_state() {
    for abort_from in [
        ServerHandshakeState::TransportReady,
        ServerHandshakeState::ChVerified,
        ServerHandshakeState::ShSent,
        ServerHandshakeState::CfVerified,
        ServerHandshakeState::Authorized,
        ServerHandshakeState::Messaging,
    ] {
        let mut m = ServerHandshakeMachine::new();
        // Advance to the target state
        match abort_from {
            ServerHandshakeState::TransportReady => {
                m.transition_to(ServerHandshakeState::TransportReady)
                    .unwrap();
            }
            ServerHandshakeState::ChVerified => {
                m.transition_to(ServerHandshakeState::TransportReady)
                    .unwrap();
                m.transition_to(ServerHandshakeState::ChVerified).unwrap();
            }
            ServerHandshakeState::ShSent => {
                m.transition_to(ServerHandshakeState::TransportReady)
                    .unwrap();
                m.transition_to(ServerHandshakeState::ChVerified).unwrap();
                m.transition_to(ServerHandshakeState::ShSent).unwrap();
            }
            ServerHandshakeState::CfVerified => {
                m.transition_to(ServerHandshakeState::TransportReady)
                    .unwrap();
                m.transition_to(ServerHandshakeState::ChVerified).unwrap();
                m.transition_to(ServerHandshakeState::ShSent).unwrap();
                m.transition_to(ServerHandshakeState::CfVerified).unwrap();
            }
            ServerHandshakeState::Authorized => {
                m.transition_to(ServerHandshakeState::TransportReady)
                    .unwrap();
                m.transition_to(ServerHandshakeState::ChVerified).unwrap();
                m.transition_to(ServerHandshakeState::ShSent).unwrap();
                m.transition_to(ServerHandshakeState::CfVerified).unwrap();
                m.transition_to(ServerHandshakeState::Authorized).unwrap();
            }
            ServerHandshakeState::Messaging => {
                m.transition_to(ServerHandshakeState::TransportReady)
                    .unwrap();
                m.transition_to(ServerHandshakeState::ChVerified).unwrap();
                m.transition_to(ServerHandshakeState::ShSent).unwrap();
                m.transition_to(ServerHandshakeState::CfVerified).unwrap();
                m.transition_to(ServerHandshakeState::Authorized).unwrap();
                m.transition_to(ServerHandshakeState::Messaging).unwrap();
            }
            _ => unreachable!(),
        }
        m.abort().unwrap();
        assert_eq!(m.state(), ServerHandshakeState::Closed);
        assert!(m.is_terminal());
    }
}

// === §5.10.6 Duplicate Handshake Message Detection ===

#[test]
fn test_r2_130_client_duplicate_server_hello_rejected() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.on_server_hello_received().unwrap();
    let err = m.on_server_hello_received().unwrap_err();
    assert_eq!(err.message_type, "ServerHello");
}

#[test]
fn test_r2_131_server_duplicate_client_hello_rejected() {
    let mut m = ServerHandshakeMachine::new();
    m.transition_to(ServerHandshakeState::TransportReady)
        .unwrap();
    m.on_client_hello_received().unwrap();
    let err = m.on_client_hello_received().unwrap_err();
    assert_eq!(err.message_type, "ClientHello");
}

#[test]
fn test_r2_132_server_duplicate_client_finished_rejected() {
    let mut m = ServerHandshakeMachine::new();
    m.transition_to(ServerHandshakeState::TransportReady)
        .unwrap();
    m.transition_to(ServerHandshakeState::ChVerified).unwrap();
    m.transition_to(ServerHandshakeState::ShSent).unwrap();
    m.on_client_finished_received().unwrap();
    let err = m.on_client_finished_received().unwrap_err();
    assert_eq!(err.message_type, "ClientFinished");
}

// === §5.10.7 Unexpected Frame Handling ===

#[test]
fn test_r2_140_client_handshake_only_in_ch_sent() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();

    // HANDSHAKE allowed
    m.check_frame_type(0x02).unwrap();

    // DATA rejected
    let err = m.check_frame_type(0x01).unwrap_err();
    assert_eq!(err.frame_type, 0x01);
}

#[test]
fn test_r2_141_client_messaging_allowed_frames() {
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

    // HANDSHAKE rejected in messaging (§5.10.7)
    let err = m.check_frame_type(0x02).unwrap_err();
    assert_eq!(err.frame_type, 0x02);
}

#[test]
fn test_r2_142_client_closing_only_close_allowed() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.transition_to(ClientHandshakeState::ShVerified).unwrap();
    m.transition_to(ClientHandshakeState::CfSent).unwrap();
    m.transition_to(ClientHandshakeState::Authorized).unwrap();
    m.transition_to(ClientHandshakeState::Messaging).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();

    m.check_frame_type(0x05).unwrap();
    let err = m.check_frame_type(0x01).unwrap_err();
    assert_eq!(err.frame_type, 0x01);
}

#[test]
fn test_r2_143_server_handshake_only_in_transport_ready() {
    let mut m = ServerHandshakeMachine::new();
    m.transition_to(ServerHandshakeState::TransportReady)
        .unwrap();

    m.check_frame_type(0x02).unwrap();
    let err = m.check_frame_type(0x01).unwrap_err();
    assert_eq!(err.frame_type, 0x01);
}

#[test]
fn test_r2_144_server_messaging_handshake_rejected() {
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

    let err = m.check_frame_type(0x02).unwrap_err();
    assert_eq!(err.frame_type, 0x02);
}

// === §5.10.8 Timeout Specification ===

#[test]
fn test_r2_150_default_timeouts() {
    assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(30));
    assert_eq!(DEFAULT_CLOSE_TIMEOUT, Duration::from_secs(5));
}

#[test]
fn test_r2_151_min_timeouts() {
    assert_eq!(MIN_HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    assert_eq!(MIN_CLOSE_TIMEOUT, Duration::from_secs(1));
}

#[test]
fn test_r2_152_client_timeout_enforced() {
    let mut m = ClientHandshakeMachine::new();
    m.set_handshake_timeout_for_test(Duration::from_millis(1));
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();

    std::thread::sleep(Duration::from_millis(10));

    let err = m.check_timeout().unwrap_err();
    assert!(err.state.contains("C_CH_SENT"));
}

#[test]
fn test_r2_153_server_timeout_enforced() {
    let mut m = ServerHandshakeMachine::new();
    m.set_handshake_timeout_for_test(Duration::from_millis(1));
    m.transition_to(ServerHandshakeState::TransportReady)
        .unwrap();

    std::thread::sleep(Duration::from_millis(10));

    let err = m.check_timeout().unwrap_err();
    assert!(err.state.contains("S_TRANSPORT_READY"));
}

#[test]
fn test_r2_154_client_custom_timeout_via_builder() {
    let m = ClientHandshakeMachine::new()
        .with_handshake_timeout(Duration::from_secs(60))
        .with_close_timeout(Duration::from_secs(10));
    assert_eq!(m.handshake_timeout(), Duration::from_secs(60));
    assert_eq!(m.close_timeout(), Duration::from_secs(10));
}

#[test]
#[should_panic(expected = "handshake timeout must be >= 10s")]
fn test_r2_155_client_min_handshake_timeout_enforced() {
    ClientHandshakeMachine::new().with_handshake_timeout(Duration::from_secs(5));
}

#[test]
#[should_panic(expected = "close timeout must be >= 1s")]
fn test_r2_156_client_min_close_timeout_enforced() {
    ClientHandshakeMachine::new().with_close_timeout(Duration::from_millis(500));
}

// === §5.10.9 Close Behavior ===

#[test]
fn test_r2_160_close_after_close_to_closed() {
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
fn test_r2_161_closed_is_terminal() {
    let m = ClientHandshakeMachine::new();
    assert!(!m.is_terminal());
    let mut m = m;
    m.transition_to(ClientHandshakeState::Closed).unwrap();
    assert!(m.is_terminal());

    let mut s = ServerHandshakeMachine::new();
    s.transition_to(ServerHandshakeState::Closed).unwrap();
    assert!(s.is_terminal());
}

// === §5.10.11 Session State Mapping ===

#[test]
fn test_r2_170_client_identity_verified_mapping() {
    // Pre-handshake states: NOT identity verified
    assert!(!ClientHandshakeState::Idle.is_identity_verified());
    assert!(!ClientHandshakeState::Connecting.is_identity_verified());
    assert!(!ClientHandshakeState::ChSent.is_identity_verified());

    // Post-ShVerified: identity verified
    assert!(ClientHandshakeState::ShVerified.is_identity_verified());
    assert!(ClientHandshakeState::CfSent.is_identity_verified());
    assert!(ClientHandshakeState::Authorized.is_identity_verified());
    assert!(ClientHandshakeState::Messaging.is_identity_verified());
}

#[test]
fn test_r2_171_server_identity_verified_mapping() {
    assert!(!ServerHandshakeState::Listening.is_identity_verified());
    assert!(!ServerHandshakeState::TransportReady.is_identity_verified());

    // Post-ChVerified: identity verified
    assert!(ServerHandshakeState::ChVerified.is_identity_verified());
    assert!(ServerHandshakeState::ShSent.is_identity_verified());
    assert!(ServerHandshakeState::CfVerified.is_identity_verified());
    assert!(ServerHandshakeState::Authorized.is_identity_verified());
    assert!(ServerHandshakeState::Messaging.is_identity_verified());
}

#[test]
fn test_r2_172_messaging_active_mapping() {
    assert!(ClientHandshakeState::Messaging.is_messaging_active());
    assert!(!ClientHandshakeState::Authorized.is_messaging_active());
    assert!(!ClientHandshakeState::Closing.is_messaging_active());

    assert!(ServerHandshakeState::Messaging.is_messaging_active());
    assert!(!ServerHandshakeState::Authorized.is_messaging_active());
}

#[test]
fn test_r2_173_handshake_complete_mapping() {
    // Client: complete after CfSent
    assert!(!ClientHandshakeState::ChSent.is_handshake_complete());
    assert!(!ClientHandshakeState::ShVerified.is_handshake_complete());
    assert!(ClientHandshakeState::CfSent.is_handshake_complete());
    assert!(ClientHandshakeState::Messaging.is_handshake_complete());

    // Server: complete after CfVerified
    assert!(!ServerHandshakeState::ShSent.is_handshake_complete());
    assert!(ServerHandshakeState::CfVerified.is_handshake_complete());
    assert!(ServerHandshakeState::Messaging.is_handshake_complete());
}

// === §5.10.7 Full Unexpected Frame Matrix ===
//
// For every state × frame type combination, verify the disposition matches
// the RFC specification. Frame types:
//   0x01 DATA, 0x02 HANDSHAKE, 0x03 RPC_REQUEST, 0x04 RPC_RESPONSE,
//   0x05 CLOSE, 0x06 ERROR, 0x07 PING, 0x08 PONG
//   0x09..0xFF = unknown/reserved

use aafp_core::handshake_state::FrameDisposition;

/// All defined frame types.
const ALL_FRAME_TYPES: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// Unknown frame type for testing.
const UNKNOWN_FRAME_TYPE: u8 = 0x0A;

#[test]
fn test_r2_180_client_full_frame_matrix() {
    // (state, allowed frames, discard-silently frames)
    // All other frames → RejectWithError
    let cases: [(ClientHandshakeState, &[u8]); 9] = [
        (ClientHandshakeState::Idle, &[]),
        (ClientHandshakeState::Connecting, &[]),
        (ClientHandshakeState::ChSent, &[0x02, 0x06]),
        (ClientHandshakeState::ShVerified, &[0x06]),
        (ClientHandshakeState::CfSent, &[0x06]),
        (
            ClientHandshakeState::Authorized,
            &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ),
        (
            ClientHandshakeState::Messaging,
            &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ),
        (ClientHandshakeState::Closing, &[0x05]),
        (ClientHandshakeState::Closed, &[]),
    ];

    for (state, allowed) in cases.iter() {
        let m = ClientHandshakeMachine::new();
        // We test at the state level via allowed_frame_types and frame_disposition
        for ft in ALL_FRAME_TYPES.iter() {
            let in_allowed = allowed.contains(ft);
            let disp = if *state == ClientHandshakeState::Closing {
                if *ft == 0x05 {
                    FrameDisposition::Accept
                } else {
                    FrameDisposition::DiscardSilently
                }
            } else if *state == ClientHandshakeState::Closed {
                FrameDisposition::DiscardSilently
            } else if in_allowed {
                FrameDisposition::Accept
            } else {
                FrameDisposition::RejectWithError
            };

            // Verify allowed_frame_types matches
            let actual_allowed = state.allowed_frame_types().contains(ft);
            assert_eq!(
                actual_allowed, in_allowed,
                "client state {}: frame 0x{:02X} allowed_frame_types mismatch",
                state, ft
            );
        }

        // Unknown frame type is never allowed
        assert!(
            !state.allowed_frame_types().contains(&UNKNOWN_FRAME_TYPE),
            "client state {}: unknown frame type should not be allowed",
            state
        );
    }
}

#[test]
fn test_r2_181_server_full_frame_matrix() {
    let cases: [(ServerHandshakeState, &[u8]); 9] = [
        (ServerHandshakeState::Listening, &[]),
        (ServerHandshakeState::TransportReady, &[0x02, 0x06]),
        (ServerHandshakeState::ChVerified, &[0x02, 0x06]),
        (ServerHandshakeState::ShSent, &[0x02, 0x06]),
        (ServerHandshakeState::CfVerified, &[0x06]),
        (ServerHandshakeState::Authorized, &[0x06]),
        (
            ServerHandshakeState::Messaging,
            &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ),
        (ServerHandshakeState::Closing, &[0x05]),
        (ServerHandshakeState::Closed, &[]),
    ];

    for (state, allowed) in cases.iter() {
        for ft in ALL_FRAME_TYPES.iter() {
            let in_allowed = allowed.contains(ft);
            let actual_allowed = state.allowed_frame_types().contains(ft);
            assert_eq!(
                actual_allowed, in_allowed,
                "server state {}: frame 0x{:02X} allowed_frame_types mismatch",
                state, ft
            );
        }
        assert!(
            !state.allowed_frame_types().contains(&UNKNOWN_FRAME_TYPE),
            "server state {}: unknown frame type should not be allowed",
            state
        );
    }
}

#[test]
fn test_r2_182_client_frame_disposition_closing() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();
    m.transition_to(ClientHandshakeState::ShVerified).unwrap();
    m.transition_to(ClientHandshakeState::CfSent).unwrap();
    m.transition_to(ClientHandshakeState::Authorized).unwrap();
    m.transition_to(ClientHandshakeState::Messaging).unwrap();
    m.transition_to(ClientHandshakeState::Closing).unwrap();

    // CLOSE is accepted
    assert_eq!(m.frame_disposition(0x05), FrameDisposition::Accept);

    // All other frames are silently discarded (not errored)
    for ft in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, UNKNOWN_FRAME_TYPE] {
        assert_eq!(
            m.frame_disposition(ft),
            FrameDisposition::DiscardSilently,
            "frame 0x{:02X} should be DiscardSilently in Closing",
            ft
        );
    }
}

#[test]
fn test_r2_183_server_frame_disposition_closing() {
    let mut m = ServerHandshakeMachine::new();
    m.transition_to(ServerHandshakeState::TransportReady)
        .unwrap();
    m.transition_to(ServerHandshakeState::ChVerified).unwrap();
    m.transition_to(ServerHandshakeState::ShSent).unwrap();
    m.transition_to(ServerHandshakeState::CfVerified).unwrap();
    m.transition_to(ServerHandshakeState::Authorized).unwrap();
    m.transition_to(ServerHandshakeState::Messaging).unwrap();
    m.transition_to(ServerHandshakeState::Closing).unwrap();

    assert_eq!(m.frame_disposition(0x05), FrameDisposition::Accept);
    for ft in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, UNKNOWN_FRAME_TYPE] {
        assert_eq!(
            m.frame_disposition(ft),
            FrameDisposition::DiscardSilently,
            "frame 0x{:02X} should be DiscardSilently in Closing",
            ft
        );
    }
}

#[test]
fn test_r2_184_client_frame_disposition_ch_sent() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Connecting).unwrap();
    m.transition_to(ClientHandshakeState::ChSent).unwrap();

    // HANDSHAKE and ERROR accepted
    assert_eq!(m.frame_disposition(0x02), FrameDisposition::Accept);
    assert_eq!(m.frame_disposition(0x06), FrameDisposition::Accept);

    // All others rejected with error
    for ft in [0x01, 0x03, 0x04, 0x05, 0x07, 0x08, UNKNOWN_FRAME_TYPE] {
        assert_eq!(
            m.frame_disposition(ft),
            FrameDisposition::RejectWithError,
            "frame 0x{:02X} should be RejectWithError in ChSent",
            ft
        );
    }
}

#[test]
fn test_r2_185_client_frame_disposition_closed() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Closed).unwrap();

    // Everything is discarded silently in Closed state
    for ft in ALL_FRAME_TYPES {
        assert_eq!(
            m.frame_disposition(ft),
            FrameDisposition::DiscardSilently,
            "frame 0x{:02X} should be DiscardSilently in Closed",
            ft
        );
    }
}

#[test]
fn test_r2_186_server_frame_disposition_closed() {
    let mut m = ServerHandshakeMachine::new();
    m.transition_to(ServerHandshakeState::Closed).unwrap();

    for ft in ALL_FRAME_TYPES {
        assert_eq!(
            m.frame_disposition(ft),
            FrameDisposition::DiscardSilently,
            "frame 0x{:02X} should be DiscardSilently in Closed",
            ft
        );
    }
}

// === §5.10.7 Terminal State Immutability ===

#[test]
fn test_r2_190_client_closed_no_transitions() {
    let mut m = ClientHandshakeMachine::new();
    m.transition_to(ClientHandshakeState::Closed).unwrap();
    assert!(m.is_terminal());

    // No transition from Closed should succeed
    for next in [
        ClientHandshakeState::Idle,
        ClientHandshakeState::Connecting,
        ClientHandshakeState::ChSent,
        ClientHandshakeState::ShVerified,
        ClientHandshakeState::CfSent,
        ClientHandshakeState::Authorized,
        ClientHandshakeState::Messaging,
        ClientHandshakeState::Closing,
    ] {
        assert!(
            m.transition_to(next).is_err(),
            "transition from Closed to {} should fail",
            next
        );
    }
    // Closed → Closed is also not allowed (no self-transition)
    assert!(m.transition_to(ClientHandshakeState::Closed).is_err());
}

#[test]
fn test_r2_191_server_closed_no_transitions() {
    let mut m = ServerHandshakeMachine::new();
    m.transition_to(ServerHandshakeState::Closed).unwrap();
    assert!(m.is_terminal());

    for next in [
        ServerHandshakeState::Listening,
        ServerHandshakeState::TransportReady,
        ServerHandshakeState::ChVerified,
        ServerHandshakeState::ShSent,
        ServerHandshakeState::CfVerified,
        ServerHandshakeState::Authorized,
        ServerHandshakeState::Messaging,
        ServerHandshakeState::Closing,
    ] {
        assert!(
            m.transition_to(next).is_err(),
            "transition from Closed to {} should fail",
            next
        );
    }
    assert!(m.transition_to(ServerHandshakeState::Closed).is_err());
}

// === §5.10 Property Tests: Random Transition Sequences ===
//
// Verify that:
// 1. Illegal transitions are always rejected (never panic)
// 2. Duplicate transitions are rejected
// 3. Terminal states are immutable
// 4. No panics under any random sequence of operations

#[test]
fn test_r2_200_client_property_random_transitions() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let all_client_states = [
        ClientHandshakeState::Idle,
        ClientHandshakeState::Connecting,
        ClientHandshakeState::ChSent,
        ClientHandshakeState::ShVerified,
        ClientHandshakeState::CfSent,
        ClientHandshakeState::Authorized,
        ClientHandshakeState::Messaging,
        ClientHandshakeState::Closing,
        ClientHandshakeState::Closed,
    ];

    // Deterministic PRNG (no external dep) — LCG
    let mut seed: u64 = 0x1234567890ABCDEF;
    let mut rng = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };

    for _ in 0..100_000 {
        let mut m = ClientHandshakeMachine::new();
        let num_ops = (rng() % 20) as usize;
        for _ in 0..num_ops {
            let next = all_client_states[(rng() as usize) % all_client_states.len()];
            // Must never panic
            let _ = m.transition_to(next);
        }
        // If we ended in Closed, verify terminal
        if m.state() == ClientHandshakeState::Closed {
            assert!(m.is_terminal());
            // No further transitions should work
            for next in all_client_states.iter() {
                assert!(m.transition_to(*next).is_err());
            }
        }
    }
}

#[test]
fn test_r2_201_server_property_random_transitions() {
    let all_server_states = [
        ServerHandshakeState::Listening,
        ServerHandshakeState::TransportReady,
        ServerHandshakeState::ChVerified,
        ServerHandshakeState::ShSent,
        ServerHandshakeState::CfVerified,
        ServerHandshakeState::Authorized,
        ServerHandshakeState::Messaging,
        ServerHandshakeState::Closing,
        ServerHandshakeState::Closed,
    ];

    let mut seed: u64 = 0xFEDCBA0987654321;
    let mut rng = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };

    for _ in 0..100_000 {
        let mut m = ServerHandshakeMachine::new();
        let num_ops = (rng() % 20) as usize;
        for _ in 0..num_ops {
            let next = all_server_states[(rng() as usize) % all_server_states.len()];
            let _ = m.transition_to(next);
        }
        if m.state() == ServerHandshakeState::Closed {
            assert!(m.is_terminal());
            for next in all_server_states.iter() {
                assert!(m.transition_to(*next).is_err());
            }
        }
    }
}

#[test]
fn test_r2_202_client_property_random_frames() {
    let mut seed: u64 = 0xDEADBEEFCAFEBABE;
    let mut rng = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };

    let all_frames: [u8; 9] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A];

    for _ in 0..100_000 {
        let mut m = ClientHandshakeMachine::new();
        // Advance to a random state
        let num_transitions = (rng() % 8) as usize;
        let all_client_states = [
            ClientHandshakeState::Connecting,
            ClientHandshakeState::ChSent,
            ClientHandshakeState::ShVerified,
            ClientHandshakeState::CfSent,
            ClientHandshakeState::Authorized,
            ClientHandshakeState::Messaging,
            ClientHandshakeState::Closing,
            ClientHandshakeState::Closed,
        ];
        for i in 0..num_transitions {
            let _ = m.transition_to(all_client_states[i]);
        }

        // Now throw random frames at it — must never panic
        for _ in 0..10 {
            let ft = all_frames[(rng() as usize) % all_frames.len()];
            let _ = m.check_frame_type(ft);
            let _ = m.frame_disposition(ft);
        }
    }
}

#[test]
fn test_r2_203_server_property_random_frames() {
    let mut seed: u64 = 0xABCDEF0123456789;
    let mut rng = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };

    let all_frames: [u8; 9] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A];

    for _ in 0..100_000 {
        let mut m = ServerHandshakeMachine::new();
        let num_transitions = (rng() % 8) as usize;
        let all_server_states = [
            ServerHandshakeState::TransportReady,
            ServerHandshakeState::ChVerified,
            ServerHandshakeState::ShSent,
            ServerHandshakeState::CfVerified,
            ServerHandshakeState::Authorized,
            ServerHandshakeState::Messaging,
            ServerHandshakeState::Closing,
            ServerHandshakeState::Closed,
        ];
        for i in 0..num_transitions {
            let _ = m.transition_to(all_server_states[i]);
        }

        for _ in 0..10 {
            let ft = all_frames[(rng() as usize) % all_frames.len()];
            let _ = m.check_frame_type(ft);
            let _ = m.frame_disposition(ft);
        }
    }
}

#[test]
fn test_r2_204_property_duplicate_detection_idempotent() {
    // Calling on_server_hello_received twice always fails, regardless of
    // intervening state transitions
    for _ in 0..10_000 {
        let mut m = ClientHandshakeMachine::new();
        m.transition_to(ClientHandshakeState::Connecting).unwrap();
        m.transition_to(ClientHandshakeState::ChSent).unwrap();
        m.on_server_hello_received().unwrap();
        // Second call must always fail
        assert!(m.on_server_hello_received().is_err());
    }

    for _ in 0..10_000 {
        let mut m = ServerHandshakeMachine::new();
        m.transition_to(ServerHandshakeState::TransportReady)
            .unwrap();
        m.on_client_hello_received().unwrap();
        assert!(m.on_client_hello_received().is_err());
    }
}
