//! MQTT-style hierarchical topic validation and helpers (PubSub P4, §6).
//!
//! Topics are slash-separated (`.` is also accepted as a separator for
//! backwards compatibility with P1-P2 flat topics, but `/` is the canonical
//! separator for hierarchical topics). Wildcards `+` (single-level) and
//! `#` (multi-level, must be last) are permitted in subscription filters
//! but not in publish topics.

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
    if topic.is_empty() {
        return Err(9009); // PUBSUB_INVALID_TOPIC
    }
    if topic.len() > MAX_TOPIC_LENGTH {
        return Err(9007); // PUBSUB_TOPIC_TOO_LONG
    }
    let segs = split_topic(topic);
    if segs.len() > MAX_TOPIC_DEPTH {
        return Err(9009);
    }
    // Publish topics must not contain wildcards.
    if segs.iter().any(|s| *s == "+" || *s == "#") {
        return Err(9009);
    }
    Ok(())
}

/// Validate a subscription filter (allows wildcards).
///
/// Returns `Ok(())` if valid, or an error code (RFC-0005 extension):
/// - `9009` (`PUBSUB_INVALID_TOPIC`) — empty, too deep, or `#` not last.
/// - `9007` (`PUBSUB_TOPIC_TOO_LONG`) — exceeds `MAX_TOPIC_LENGTH`.
///
/// `#` (multi-level wildcard) must be the last segment of the filter.
pub fn validate_filter(filter: &str) -> Result<(), u16> {
    if filter.is_empty() {
        return Err(9009);
    }
    if filter.len() > MAX_TOPIC_LENGTH {
        return Err(9007);
    }
    let segs = split_topic(filter);
    if segs.len() > MAX_TOPIC_DEPTH {
        return Err(9009);
    }
    // `#` must be the last segment.
    for (i, s) in segs.iter().enumerate() {
        if *s == "#" && i != segs.len() - 1 {
            return Err(9009);
        }
    }
    Ok(())
}

/// Check if a topic uses a reserved prefix correctly.
///
/// Reserved top-level segments: `rpc`, `agents`, `tasks`, `llm`, `tools`.
/// Returns `Ok(())` if valid or unprefixed; `Err(warning_msg)` if a reserved
/// prefix is used incorrectly (non-fatal — log a warning, do not reject).
pub fn check_reserved_prefix(topic: &str) -> Result<(), String> {
    let segs = split_topic(topic);
    match segs.first() {
        Some(&"rpc") if !is_backchannel_topic(topic) => {
            Err(format!(
                "rpc/ prefix should be rpc/<server>/<req_id>/progress, got: {topic}"
            ))
        }
        Some(&"agents") if segs.len() < 2 => {
            Err(format!(
                "agents/ prefix requires an agent id in segment 2, got: {topic}"
            ))
        }
        _ => Ok(()),
    }
}

/// Split a topic into segments.
///
/// Accepts both `/` and `.` as separators (normalizes `.` to `/` for
/// hierarchical matching).
pub fn split_topic(topic: &str) -> Vec<&str> {
    topic.split(['/', '.']).collect()
}

/// MQTT-style topic filter matching (P4, §6.3, Appendix B).
///
/// `+` matches exactly one level. `#` matches zero or more remaining levels
/// and must be the last segment of the filter. `.` and `/` are treated as
/// equivalent separators.
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    let f: Vec<&str> = split_topic(filter);
    let t: Vec<&str> = split_topic(topic);
    let mut fi = 0;
    for seg in &t {
        match f.get(fi) {
            Some(&"#") => return true, // multi-level: rest matches
            Some(&"+") => fi += 1,     // single-level: match any
            Some(s) if *s == *seg => fi += 1, // exact segment match
            _ => return false,
        }
    }
    // All topic segments consumed. Filter matches if fully consumed, or if
    // the only remaining filter segment is `#` (matches zero remaining).
    fi == f.len() || matches!(f.get(fi), Some(&"#"))
}

/// Construct a back-channel topic for an in-flight RPC.
///
/// Format: `rpc.<server_id>.<req_id>.progress`
pub fn backchannel_topic(server_id: &str, req_id: &str) -> String {
    format!("rpc.{server_id}.{req_id}.progress")
}

/// Validate that a topic is a well-formed back-channel topic.
///
/// A well-formed back-channel topic has exactly 4 dot-separated segments
/// where the first is `rpc` and the last is `progress`, with non-empty
/// server id and request id segments.
pub fn is_backchannel_topic(topic: &str) -> bool {
    let segs: Vec<&str> = topic.split('.').collect();
    segs.len() == 4
        && segs[0] == "rpc"
        && segs[3] == "progress"
        && !segs[1].is_empty()
        && !segs[2].is_empty()
}

/// Extract the `(server_id, request_id)` from a back-channel topic.
///
/// Returns `None` if the topic is malformed.
pub fn parse_backchannel_topic(topic: &str) -> Option<(String, String)> {
    let segs: Vec<&str> = topic.split('.').collect();
    if segs.len() == 4 && segs[0] == "rpc" && segs[3] == "progress" {
        Some((segs[1].to_string(), segs[2].to_string()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── topic_matches() ──────────────────────────────────────────

    #[test]
    fn exact_match() {
        assert!(topic_matches("a/b/c", "a/b/c"));
    }

    #[test]
    fn exact_no_match() {
        assert!(!topic_matches("a/b/c", "a/b/d"));
    }

    #[test]
    fn single_wildcard_matches() {
        assert!(topic_matches("a/+/c", "a/b/c"));
        assert!(topic_matches("a/+/c", "a/x/c"));
    }

    #[test]
    fn single_wildcard_no_match_extra_level() {
        assert!(!topic_matches("a/+/c", "a/b/c/d"));
        assert!(!topic_matches("a/+/c", "a/b/x/d"));
    }

    #[test]
    fn single_wildcard_no_match_missing_level() {
        assert!(!topic_matches("a/+/c", "a/c"));
    }

    #[test]
    fn multi_wildcard_matches_rest() {
        assert!(topic_matches("a/#", "a/b/c/d"));
        assert!(topic_matches("a/#", "a/b"));
    }

    #[test]
    fn multi_wildcard_matches_zero_levels() {
        assert!(topic_matches("a/#", "a"));
    }

    #[test]
    fn multi_wildcard_must_be_last() {
        // If `#` appears mid-filter, it matches everything after, so this
        // is treated as: a, #, c — but # returns true immediately.
        // The validator (validate_filter) rejects `#` not-last; topic_matches
        // itself is lenient and treats `#` as "match all remaining".
        assert!(topic_matches("a/#/c", "a/b/c")); // # matches "b"
    }

    #[test]
    fn multi_wildcard_no_match_different_prefix() {
        assert!(!topic_matches("a/#", "b/c"));
    }

    #[test]
    fn dot_separator_treated_as_slash() {
        assert!(topic_matches("a.b.c", "a/b/c"));
        assert!(topic_matches("a/+/c", "a.b.c"));
    }

    #[test]
    fn filter_shorter_than_topic_no_wildcard() {
        assert!(!topic_matches("a/b", "a/b/c"));
    }

    #[test]
    fn filter_longer_than_topic() {
        assert!(!topic_matches("a/b/c/d", "a/b/c"));
    }

    // ── Validation ───────────────────────────────────────────────

    #[test]
    fn validate_publish_topic_rejects_wildcards() {
        assert!(validate_publish_topic("a/+/c").is_err());
        assert!(validate_publish_topic("a/#").is_err());
        assert!(validate_publish_topic("a/b/c").is_ok());
    }

    #[test]
    fn validate_filter_allows_wildcards() {
        assert!(validate_filter("a/+/c").is_ok());
        assert!(validate_filter("a/#").is_ok());
        assert!(validate_filter("a/b/c").is_ok());
    }

    #[test]
    fn validate_filter_rejects_hash_not_last() {
        assert!(validate_filter("a/#/c").is_err());
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(validate_publish_topic("").is_err());
        assert!(validate_filter("").is_err());
    }

    #[test]
    fn validate_rejects_too_long() {
        let long = "a".repeat(MAX_TOPIC_LENGTH + 1);
        assert!(validate_publish_topic(&long).is_err());
        assert!(validate_filter(&long).is_err());
    }

    // ── Backchannel topic helpers ────────────────────────────────

    #[test]
    fn backchannel_topic_format() {
        let topic = backchannel_topic("agent_server123", "req_abc");
        assert_eq!(topic, "rpc.agent_server123.req_abc.progress");
    }

    #[test]
    fn is_backchannel_topic_valid() {
        assert!(is_backchannel_topic("rpc.server.req123.progress"));
    }

    #[test]
    fn is_backchannel_topic_invalid() {
        assert!(!is_backchannel_topic("rpc.server.req123"));
        assert!(!is_backchannel_topic("agents/A/status"));
        assert!(!is_backchannel_topic("rpc.server.req123.progress.extra"));
    }

    #[test]
    fn parse_backchannel_topic_extracts_ids() {
        let (server, req) = parse_backchannel_topic("rpc.agent_X.req_42.progress").unwrap();
        assert_eq!(server, "agent_X");
        assert_eq!(req, "req_42");
    }

    #[test]
    fn parse_backchannel_topic_malformed() {
        assert!(parse_backchannel_topic("agents/A/status").is_none());
        assert!(parse_backchannel_topic("rpc.server").is_none());
    }
}
