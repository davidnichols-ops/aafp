//! Differential tests for CloseManager (RFC-0002 §6.6, A-8).
//!
//! These tests read the same JSON trace vectors as the Go implementation
//! and verify that the Rust CloseManager produces identical results.

#![allow(unused_imports)]
use aafp_messaging::{CloseAction, CloseManager, CloseState, MAX_CLOSE_MESSAGE_LEN};
use serde::{Deserialize, Serialize};

/// A single event in a shutdown trace vector.
#[derive(Clone, Debug, Deserialize)]
struct CloseEventVec {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    code: u32,
    #[serde(default)]
    message: String,
}

/// An expected action result.
#[derive(Clone, Debug, Deserialize)]
struct CloseActionVec {
    kind: String,
    #[serde(default)]
    code: u32,
    #[serde(default)]
    message: String,
    #[serde(default)]
    message_truncated: bool,
}

/// A complete shutdown trace vector.
#[derive(Clone, Debug, Deserialize)]
struct CloseTraceVector {
    name: String,
    #[serde(default)]
    description: String,
    events: Vec<CloseEventVec>,
    expected_final_state: String,
    expected_actions: Vec<CloseActionVec>,
}

/// Top-level vector file.
#[derive(Debug, Deserialize)]
struct CloseTraceVectors {
    #[serde(default)]
    description: String,
    vectors: Vec<CloseTraceVector>,
}

fn load_vectors() -> CloseTraceVectors {
    let path = std::path::Path::new("../../../go/closemanager/close_vectors.json");
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read close_vectors.json: {}", e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse close_vectors.json: {}", e))
}

fn apply_event(cm: &mut CloseManager, evt: &CloseEventVec) -> CloseAction {
    match evt.event_type.as_str() {
        "initiate_close" => cm.initiate_close(evt.code, &evt.message),
        "on_close_received" => cm.on_close_received(evt.code, &evt.message),
        "respond_close" => cm.respond_close(evt.code, &evt.message),
        "on_timeout" => cm.on_timeout(),
        "on_fatal_error" => cm.on_fatal_error_received(),
        "on_transport_reset" => cm.on_transport_reset(),
        "abort" => cm.abort(),
        other => panic!("unknown event type: {}", other),
    }
}

fn action_kind_str(a: &CloseAction) -> &str {
    match a {
        CloseAction::None => "none",
        CloseAction::SendCloseFrame { .. } => "send_close_frame",
        CloseAction::CloseQuic => "close_quic",
    }
}

fn state_str(s: CloseState) -> &'static str {
    match s {
        CloseState::Open => "Open",
        CloseState::LocalCloseSent => "LocalCloseSent",
        CloseState::RemoteCloseReceived => "RemoteCloseReceived",
        CloseState::CloseReceived => "CloseReceived",
        CloseState::Closed => "Closed",
    }
}

#[test]
fn test_differential_close_vectors() {
    let vectors = load_vectors();
    assert!(!vectors.vectors.is_empty(), "no vectors loaded");

    for v in &vectors.vectors {
        let mut cm = CloseManager::new();
        let mut actions = Vec::new();

        for evt in &v.events {
            let action = apply_event(&mut cm, evt);
            actions.push(action);
        }

        // Verify final state.
        let got_state = state_str(cm.state());
        assert_eq!(
            got_state, v.expected_final_state,
            "vector {}: final state mismatch",
            v.name
        );

        // Verify number of actions.
        assert_eq!(
            actions.len(),
            v.expected_actions.len(),
            "vector {}: action count mismatch",
            v.name
        );

        for (i, expected) in v.expected_actions.iter().enumerate() {
            let got = &actions[i];
            let got_kind = action_kind_str(got);

            assert_eq!(
                got_kind, expected.kind,
                "vector {}: action[{}] kind mismatch",
                v.name, i
            );

            if expected.kind == "send_close_frame" {
                match got {
                    CloseAction::SendCloseFrame { code, message, .. } => {
                        assert_eq!(
                            *code, expected.code,
                            "vector {}: action[{}] code mismatch",
                            v.name, i
                        );
                        if expected.message_truncated {
                            assert!(
                                message.len() <= MAX_CLOSE_MESSAGE_LEN,
                                "vector {}: action[{}] message not truncated: {}",
                                v.name,
                                i,
                                message.len()
                            );
                        } else {
                            assert_eq!(
                                message, &expected.message,
                                "vector {}: action[{}] message mismatch",
                                v.name, i
                            );
                        }
                    }
                    _ => panic!("expected SendCloseFrame"),
                }
            }
        }
    }
}

#[test]
fn test_differential_vector_count() {
    let vectors = load_vectors();
    assert!(
        vectors.vectors.len() >= 15,
        "expected at least 15 vectors, got {}",
        vectors.vectors.len()
    );
}
