//! MQTT-style hierarchical topic validation and helpers (PubSub P4, §6).
//!
//! Topics are slash-separated (`.` is also accepted as a separator for
//! backwards compatibility with P1-P2 flat topics, but `/` is the canonical
//! separator for hierarchical topics). Wildcards `+` (single-level) and
//! `#` (multi-level, must be last) are permitted in subscription filters
//! but not in publish topics.
//!
//! This module is a pre-build scaffold; function bodies are `todo!()` stubs
//! to be implemented in the P4 build pass.

#![allow(dead_code)]

/// Maximum topic length in bytes (§6.5).
pub const MAX_TOPIC_LENGTH: usize = 256;

/// Maximum topic depth (number of segments) (§6.5).
pub const MAX_TOPIC_DEPTH: usize = 16;

/// Validate a topic name for publishing.
///
/// Returns `Ok(())` if valid, or an error code (RFC-0005 extension):
/// - `9009` (`PUBSUB_INVALID_TOPIC`) — empty, too deep, or contains wildcards.
/// - `9007` (`PUBSUB_TOPIC_TOO_LONG`) — exceeds `MAX_TOPIC_LENGTH`.
///
/// Publish topics must NOT contain `+` or `#` wildcards.
pub fn validate_publish_topic(topic: &str) -> Result<(), u16> {
    todo!("check empty, length, depth, and reject + / # wildcards")
}

/// Validate a subscription filter (allows wildcards).
///
/// Returns `Ok(())` if valid, or an error code (RFC-0005 extension):
/// - `9009` (`PUBSUB_INVALID_TOPIC`) — empty, too deep, or `#` not last.
/// - `9007` (`PUBSUB_TOPIC_TOO_LONG`) — exceeds `MAX_TOPIC_LENGTH`.
///
/// `#` (multi-level wildcard) must be the last segment of the filter.
pub fn validate_filter(filter: &str) -> Result<(), u16> {
    todo!("check empty, length, depth, and # must be last segment")
}

/// Check if a topic uses a reserved prefix correctly.
///
/// Reserved top-level segments: `rpc`, `agents`, `tasks`, `llm`, `tools`.
/// Returns `Ok(())` if valid or unprefixed; `Err(warning_msg)` if a reserved
/// prefix is used incorrectly (non-fatal — log a warning, do not reject).
pub fn check_reserved_prefix(topic: &str) -> Result<(), String> {
    todo!("split topic, match on first segment (rpc/agents) for shape checks")
}

/// Split a topic into segments.
///
/// Accepts both `/` and `.` as separators (normalizes `.` to `/` for
/// hierarchical matching).
pub fn split_topic(topic: &str) -> Vec<&str> {
    todo!("topic.split(|c| c == '/' || c == '.').collect()")
}

/// MQTT-style topic filter matching (P4, §6.3, Appendix B).
///
/// `+` matches exactly one level. `#` matches zero or more remaining levels
/// and must be the last segment of the filter. `.` and `/` are treated as
/// equivalent separators.
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    todo!("segment-by-segment match: # -> true, + -> skip one, exact -> advance")
}
