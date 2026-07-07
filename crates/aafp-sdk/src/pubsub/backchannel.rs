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

#![allow(dead_code)]

use aafp_cbor::{encode, Value};
use aafp_messaging::extensions::find_extension;
use aafp_messaging::framing::Frame;
use aafp_messaging::{decode_extensions, encode_extensions, Extension};

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

/// Encode a back-channel topic as an RFC-0006 extension payload (CBOR text).
pub fn encode_backchannel_ext(topic: &str) -> Result<Vec<u8>, aafp_cbor::CborError> {
    encode(&Value::TextString(topic.to_string()))
}

/// Decode a back-channel topic from an extension payload.
/// Returns `None` if the payload is not a valid CBOR text string.
pub fn decode_backchannel_ext(payload: &[u8]) -> Option<String> {
    // Simple CBOR text string decode: major type 3 (text)
    // We use the aafp_cbor decoder if available, otherwise manual parse.
    // CBOR text string: major type 3 (0x60 | len)
    if payload.is_empty() {
        return None;
    }
    let major = payload[0] >> 5;
    if major != 3 {
        return None;
    }
    let len_info = (payload[0] & 0x1f) as usize;
    let (len, offset) = match len_info {
        n if n < 24 => (n, 1),
        24 => {
            if payload.len() < 2 {
                return None;
            }
            (payload[1] as usize, 2)
        }
        25 => {
            if payload.len() < 3 {
                return None;
            }
            (u16::from_be_bytes([payload[1], payload[2]]) as usize, 3)
        }
        26 => {
            if payload.len() < 5 {
                return None;
            }
            (
                u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize,
                5,
            )
        }
        _ => return None,
    };
    if payload.len() < offset + len {
        return None;
    }
    String::from_utf8(payload[offset..offset + len].to_vec()).ok()
}

/// Extract the back-channel topic from a frame's extension list, if present.
///
/// Decodes the frame's extension section, finds the `EXT_BACKCHANNEL_TOPIC`
/// entry, and decodes its CBOR text payload. Returns `None` if the extension
/// is absent or the payload is not a valid CBOR text string.
pub fn extract_backchannel_topic(frame: &Frame) -> Option<String> {
    let exts = decode_extensions(&frame.extensions).ok()?;
    let ext = find_extension(&exts, EXT_BACKCHANNEL_TOPIC)?;
    decode_backchannel_ext(&ext.data)
}

/// Attach a back-channel topic extension to an RPC request frame.
///
/// Encodes the topic as a CBOR text payload in an `EXT_BACKCHANNEL_TOPIC`
/// extension and appends it to the frame's extension list. If encoding
/// fails, the frame is returned unmodified (degrades to unary RPC).
pub fn frame_with_backchannel(mut frame: Frame, bc_topic: &str) -> Frame {
    match encode_backchannel_ext(bc_topic) {
        Ok(data) => {
            // Decode existing extensions, append the new one, re-encode.
            let mut exts = decode_extensions(&frame.extensions).unwrap_or_default();
            exts.push(Extension {
                ext_type: EXT_BACKCHANNEL_TOPIC,
                critical: false,
                data,
            });
            match encode_extensions(&exts) {
                Ok(encoded) => frame.extensions = encoded,
                Err(e) => {
                    tracing::warn!("failed to encode backchannel extension: {e}");
                }
            }
        }
        Err(e) => {
            tracing::warn!("failed to encode backchannel topic: {e}");
        }
    }
    frame
}

/// Generate a cryptographically random 128-bit request id, hex-encoded (32 chars).
pub fn generate_request_id() -> String {
    use rand::Rng;
    let id: u128 = rand::thread_rng().gen();
    format!("{:032x}", id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backchannel_topic_format() {
        let topic = backchannel_topic("agent_server123", "req_abc");
        assert_eq!(topic, "rpc.agent_server123.req_abc.progress");
    }

    #[test]
    fn test_is_backchannel_topic_valid() {
        assert!(is_backchannel_topic("rpc.server.req123.progress"));
    }

    #[test]
    fn test_is_backchannel_topic_invalid() {
        assert!(!is_backchannel_topic("rpc.server.req123"));
        assert!(!is_backchannel_topic("agents/A/status"));
        assert!(!is_backchannel_topic("rpc.server.req123.progress.extra"));
    }

    #[test]
    fn test_parse_backchannel_topic_extracts_ids() {
        let (server, req) = parse_backchannel_topic("rpc.agent_X.req_42.progress").unwrap();
        assert_eq!(server, "agent_X");
        assert_eq!(req, "req_42");
    }

    #[test]
    fn test_parse_backchannel_topic_malformed() {
        assert!(parse_backchannel_topic("agents/A/status").is_none());
        assert!(parse_backchannel_topic("rpc.server").is_none());
    }

    #[test]
    fn test_encode_decode_backchannel_ext() {
        let topic = "rpc.server123.req_abc.progress";
        let encoded = encode_backchannel_ext(topic).unwrap();
        let decoded = decode_backchannel_ext(&encoded).unwrap();
        assert_eq!(decoded, topic);
    }

    #[test]
    fn test_frame_with_backchannel() {
        let frame = Frame::data(0, b"payload".to_vec());
        let bc_topic = "rpc.server.req123.progress";
        let frame = frame_with_backchannel(frame, bc_topic);
        let extracted = extract_backchannel_topic(&frame);
        assert_eq!(extracted.as_deref(), Some(bc_topic));
    }

    #[test]
    fn test_extract_backchannel_topic_absent() {
        let frame = Frame::data(0, b"payload".to_vec());
        assert!(extract_backchannel_topic(&frame).is_none());
    }
}
