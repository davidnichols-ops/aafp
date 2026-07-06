//! Back-channel topic naming and RFC-0006 extension helpers (PubSub P3).
//!
//! Back-channel topics follow the convention:
//! `rpc.<server_agent_id>.<request_id>.progress`
//!
//! The back-channel is a side-channel for progress/lifecycle events during
//! long-running RPCs, delivered via PubSub subscriptions with no wire
//! protocol changes. The only addition is an RFC-0006 extension
//! (`EXT_BACKCHANNEL_TOPIC = 0x0010`) on the RPC_REQUEST frame, which is
//! backward compatible by design (unknown extensions are ignored per
//! RFC-0006 §3 graceful degradation).
//!
//! This module is a pre-build scaffold; function bodies are `todo!()` stubs
//! to be implemented in the P3 build pass.

#![allow(dead_code)]

use aafp_identity::AgentId;
use aafp_messaging::framing::Frame;

/// Extension type `0x0010`: back-channel topic (RFC-0006 registry).
///
/// Payload: CBOR-encoded text string (the back-channel topic name).
/// Carried on `RPC_REQUEST` frames. Servers that do not recognize this
/// extension MUST ignore it (RFC-0006 §3 graceful degradation), causing
/// the RPC to proceed as a plain unary call with no progress events.
pub const EXT_BACKCHANNEL_TOPIC: u16 = 0x0010;

/// Construct a back-channel topic for an in-flight RPC.
///
/// Format: `rpc.<server_id>.<req_id>.progress`
pub fn backchannel_topic(server_id: &AgentId, req_id: &str) -> String {
    todo!("format!(\"rpc.{}.{}.progress\", server_id, req_id)")
}

/// Validate that a topic is a well-formed back-channel topic.
///
/// A well-formed back-channel topic has exactly 4 dot-separated segments
/// where the first is `rpc` and the last is `progress`, with non-empty
/// server id and request id segments.
pub fn is_backchannel_topic(topic: &str) -> bool {
    todo!("split on '.' and check 4 segs: rpc / non-empty / non-empty / progress")
}

/// Extract the `(server_id, request_id)` from a back-channel topic.
///
/// Returns `None` if the topic is malformed.
pub fn parse_backchannel_topic(topic: &str) -> Option<(String, String)> {
    todo!("split on '.' and return (segs[1], segs[2]) when shape matches")
}

/// Extract the back-channel topic from a frame's extension list, if present.
///
/// Decodes the frame's extension section, finds the `EXT_BACKCHANNEL_TOPIC`
/// entry, and decodes its CBOR text payload. Returns `None` if the extension
/// is absent or the payload is not a valid CBOR text string.
pub fn extract_backchannel_topic(frame: &Frame) -> Option<String> {
    todo!("decode frame extensions, find EXT_BACKCHANNEL_TOPIC, decode CBOR text")
}

/// Attach a back-channel topic extension to an RPC request frame.
///
/// Encodes the topic as a CBOR text payload in an `EXT_BACKCHANNEL_TOPIC`
/// extension and appends it to the frame's extension list. If encoding
/// fails, the frame is returned unmodified (degrades to unary RPC).
pub fn frame_with_backchannel(frame: Frame, bc_topic: &str) -> Frame {
    todo!("encode_backchannel_ext(bc_topic) and add Extension to frame")
}
