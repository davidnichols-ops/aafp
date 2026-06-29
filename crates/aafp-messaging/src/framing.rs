//! AAFP v1 Frame Format (RFC-0002 §3-4)
//!
//! Wire format:
//! ```text
//! [28-byte header][extensions][payload]
//! ```
//!
//! Header layout (all big-endian):
//! - Version:      1 byte  (AAFP protocol version, 1 for v1)
//! - FrameType:    1 byte  (frame type, see §4)
//! - Flags:        1 byte  (frame-specific flags)
//! - Reserved:     1 byte  (MUST be 0, MUST be ignored by receivers)
//! - Stream ID:    8 bytes (stream this frame belongs to)
//! - Payload Len:  8 bytes (length of payload section)
//! - Extension Len:8 bytes (length of extension section)

use bytes::{Buf, BufMut, BytesMut};
use std::io;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// AAFP protocol version 1.
pub const AAFP_VERSION: u8 = 1;

/// Maximum payload size: 1 MiB (RFC-0002 §3.4).
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Frame header size: 28 bytes.
///
/// Per RFC-0002 §3.1 field table:
///   Version(1) + FrameType(1) + Flags(1) + Reserved(1) +
///   StreamID(8) + PayloadLen(8) + ExtensionLen(8) = 28 bytes.
pub const FRAME_HEADER_SIZE: usize = 28;

/// Frame types (RFC-0002 §4).
///
/// The `Unknown` variant is used for frame types not in the v1 registry.
/// Per RFC-0006 §4.2, the receiver checks the critical bit (0x80) in the
/// flags field to decide whether to reject (critical) or skip (non-critical)
/// unknown frame types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FrameType {
    Data,
    Handshake,
    RpcRequest,
    RpcResponse,
    Close,
    Error,
    Ping,
    Pong,
    /// An unknown frame type. The raw byte is preserved for logging/error reporting.
    Unknown(u8),
}

impl FrameType {
    /// Convert from raw u8. Returns `Unknown(val)` for types not in the v1 registry.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x01 => Self::Data,
            0x02 => Self::Handshake,
            0x03 => Self::RpcRequest,
            0x04 => Self::RpcResponse,
            0x05 => Self::Close,
            0x06 => Self::Error,
            0x07 => Self::Ping,
            0x08 => Self::Pong,
            other => Self::Unknown(other),
        }
    }

    /// Convert to raw u8.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Data => 0x01,
            Self::Handshake => 0x02,
            Self::RpcRequest => 0x03,
            Self::RpcResponse => 0x04,
            Self::Close => 0x05,
            Self::Error => 0x06,
            Self::Ping => 0x07,
            Self::Pong => 0x08,
            Self::Unknown(raw) => raw,
        }
    }

    /// Returns true if this is a known frame type (in the v1 registry).
    pub fn is_known(self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::Handshake
                | Self::RpcRequest
                | Self::RpcResponse
                | Self::Close
                | Self::Error
                | Self::Ping
                | Self::Pong
        )
    }

    /// Returns true if this is an unknown frame type.
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown(_))
    }
}

/// DATA frame flags (RFC-0002 §4.1).
pub mod flags {
    pub const MORE: u8 = 0x01;
    pub const COMPRESSED: u8 = 0x02;
    /// Critical bit for unknown frame types (RFC-0006 §4.2).
    pub const CRITICAL: u8 = 0x80;
}

/// AAFP frame: header + extensions + payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u64,
    pub extensions: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new DATA frame.
    pub fn data(stream_id: u64, payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id,
            extensions: Vec::new(),
            payload,
        }
    }

    /// Create a new HANDSHAKE frame (always on stream 0).
    pub fn handshake(payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::Handshake,
            flags: 0,
            stream_id: 0,
            extensions: Vec::new(),
            payload,
        }
    }

    /// Create a PING frame.
    pub fn ping(stream_id: u64) -> Self {
        Self {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id,
            extensions: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Create a PONG frame (same stream as PING).
    pub fn pong(stream_id: u64) -> Self {
        Self {
            frame_type: FrameType::Pong,
            flags: 0,
            stream_id,
            extensions: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Set the MORE flag (for DATA frame fragmentation).
    pub fn with_more(mut self) -> Self {
        self.flags |= flags::MORE;
        self
    }

    /// Check if the MORE flag is set.
    pub fn has_more(&self) -> bool {
        self.flags & flags::MORE != 0
    }

    /// Total wire size of this frame (header + extensions + payload).
    pub fn wire_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.extensions.len() + self.payload.len()
    }
}

/// Errors that can occur during frame encoding/decoding.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too large: payload {0} bytes (max {1})")]
    PayloadTooLarge(usize, usize),
    #[error("incomplete frame: need {needed} bytes, have {have}")]
    Incomplete { needed: usize, have: usize },
    #[error("invalid frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    #[error("invalid version: {0} (expected {1})")]
    InvalidVersion(u8, u8),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Encode a frame to bytes (RFC-0002 §3.1 wire format).
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    if frame.payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(
            frame.payload.len(),
            MAX_PAYLOAD_SIZE,
        ));
    }

    let ext_len = frame.extensions.len() as u64;
    let payload_len = frame.payload.len() as u64;

    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + frame.extensions.len() + frame.payload.len());

    // Header (28 bytes, big-endian)
    buf.push(AAFP_VERSION);
    buf.push(frame.frame_type.to_u8());
    buf.push(frame.flags);
    buf.push(0u8); // Reserved
    buf.extend_from_slice(&frame.stream_id.to_be_bytes());
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&ext_len.to_be_bytes());

    // Body: extensions first, then payload (RFC-0002 §3.2)
    buf.extend_from_slice(&frame.extensions);
    buf.extend_from_slice(&frame.payload);

    Ok(buf)
}

/// Decode a frame from bytes. Returns (frame, bytes_consumed).
pub fn decode_frame(data: &[u8]) -> Result<(Frame, usize), FrameError> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err(FrameError::Incomplete {
            needed: FRAME_HEADER_SIZE,
            have: data.len(),
        });
    }

    let version = data[0];
    let frame_type_raw = data[1];
    let flags = data[2];
    // data[3] is reserved, ignored per RFC-0002 §3.1
    let stream_id = u64::from_be_bytes(data[4..12].try_into().unwrap());
    let payload_len = u64::from_be_bytes(data[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(data[20..28].try_into().unwrap()) as usize;
    // Header is 28 bytes: 4 (V/T/F/R) + 8 (StreamID) + 8 (PayloadLen) + 8 (ExtLen)

    if version != AAFP_VERSION {
        return Err(FrameError::InvalidVersion(version, AAFP_VERSION));
    }

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    let total_body = ext_len.checked_add(payload_len).ok_or(FrameError::PayloadTooLarge(
        usize::MAX,
        MAX_PAYLOAD_SIZE,
    ))?;
    let total_frame = FRAME_HEADER_SIZE.checked_add(total_body).ok_or(FrameError::PayloadTooLarge(
        usize::MAX,
        MAX_PAYLOAD_SIZE,
    ))?;
    if data.len() < total_frame {
        return Err(FrameError::Incomplete {
            needed: total_frame,
            have: data.len(),
        });
    }

    let frame_type = FrameType::from_u8(frame_type_raw);

    // Per RFC-0006 §4.2:
    // - Unknown + critical bit set: reject with error (caller sends ERROR 8004)
    // - Unknown + critical bit clear: decode succeeds, caller MUST skip
    if frame_type.is_unknown() && (flags & flags::CRITICAL) != 0 {
        return Err(FrameError::UnknownFrameType(frame_type_raw));
    }

    let extensions = data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + ext_len].to_vec();
    let payload = data[FRAME_HEADER_SIZE + ext_len..total_frame].to_vec();

    let frame = Frame {
        frame_type,
        flags,
        stream_id,
        extensions,
        payload,
    };

    Ok((frame, total_frame))
}

/// Tokio codec for AAFP frames over QUIC streams.
pub struct FrameCodec {
    max_payload: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCodec {
    pub fn new() -> Self {
        Self {
            max_payload: MAX_PAYLOAD_SIZE,
        }
    }

    pub fn with_max_payload(max: usize) -> Self {
        Self { max_payload: max }
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if buf.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        // Peek at header to determine total frame size
        // Header layout: [0:4] V/T/F/R, [4:12] StreamID, [12:20] PayloadLen, [20:28] ExtLen
        let payload_len =
            u64::from_be_bytes(buf[12..20].try_into().unwrap()) as usize;
        let ext_len =
            u64::from_be_bytes(buf[20..28].try_into().unwrap()) as usize;

        if payload_len > self.max_payload {
            return Err(FrameError::PayloadTooLarge(payload_len, self.max_payload));
        }

        let total = FRAME_HEADER_SIZE + ext_len + payload_len;
        if buf.len() < total {
            buf.reserve(total - buf.len());
            return Ok(None);
        }

        let data = buf.split_to(total);
        let (frame, _) = decode_frame(&data)?;
        Ok(Some(frame))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, frame: Frame, buf: &mut BytesMut) -> Result<(), FrameError> {
        if frame.payload.len() > self.max_payload {
            return Err(FrameError::PayloadTooLarge(
                frame.payload.len(),
                self.max_payload,
            ));
        }

        let ext_len = frame.extensions.len() as u64;
        let payload_len = frame.payload.len() as u64;

        buf.reserve(FRAME_HEADER_SIZE + frame.extensions.len() + frame.payload.len());

        // Header
        buf.put_u8(AAFP_VERSION);
        buf.put_u8(frame.frame_type.to_u8());
        buf.put_u8(frame.flags);
        buf.put_u8(0); // Reserved
        buf.put_u64(frame.stream_id);
        buf.put_u64(payload_len);
        buf.put_u64(ext_len);

        // Body: extensions then payload
        buf.put_slice(&frame.extensions);
        buf.put_slice(&frame.payload);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_roundtrip() {
        for ft in [
            FrameType::Data,
            FrameType::Handshake,
            FrameType::RpcRequest,
            FrameType::RpcResponse,
            FrameType::Close,
            FrameType::Error,
            FrameType::Ping,
            FrameType::Pong,
        ] {
            let raw = ft.to_u8();
            assert_eq!(FrameType::from_u8(raw), ft);
        }
        // Unknown types return Unknown variant
        assert!(FrameType::from_u8(0x00).is_unknown());
        assert!(FrameType::from_u8(0xFF).is_unknown());
        assert!(FrameType::from_u8(0x80).is_unknown());
    }

    #[test]
    fn test_encode_decode_data_frame() {
        let frame = Frame::data(4, b"hello world".to_vec());
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(encoded.len(), FRAME_HEADER_SIZE + 11);

        let (decoded, consumed) = decode_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.stream_id, 4);
        assert_eq!(decoded.payload, b"hello world");
        assert_eq!(decoded.flags, 0);
        assert!(decoded.extensions.is_empty());
    }

    #[test]
    fn test_encode_decode_handshake_frame() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = Frame::handshake(payload.clone());
        let encoded = encode_frame(&frame).unwrap();

        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::Handshake);
        assert_eq!(decoded.stream_id, 0); // Handshake always on stream 0
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_frame_with_extensions() {
        let mut frame = Frame::data(4, b"payload".to_vec());
        frame.extensions = vec![0x00, 0x01, 0x02, 0x03];
        let encoded = encode_frame(&frame).unwrap();

        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.extensions, vec![0x00, 0x01, 0x02, 0x03]);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn test_more_flag() {
        let frame = Frame::data(4, b"fragment".to_vec()).with_more();
        assert!(frame.has_more());

        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert!(decoded.has_more());
    }

    #[test]
    fn test_ping_pong() {
        let ping = Frame::ping(0);
        let encoded = encode_frame(&ping).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert!(decoded.payload.is_empty());

        let pong = Frame::pong(0);
        let encoded = encode_frame(&pong).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::Pong);
    }

    #[test]
    fn test_payload_too_large() {
        let huge = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = Frame::data(4, huge);
        assert!(matches!(
            encode_frame(&frame),
            Err(FrameError::PayloadTooLarge(_, _))
        ));
    }

    #[test]
    fn test_incomplete_frame() {
        let data = [0u8; 10];
        assert!(matches!(
            decode_frame(&data),
            Err(FrameError::Incomplete { .. })
        ));
    }

    #[test]
    fn test_invalid_version() {
        let frame = Frame::data(4, b"test".to_vec());
        let mut encoded = encode_frame(&frame).unwrap();
        encoded[0] = 99; // Wrong version
        assert!(matches!(
            decode_frame(&encoded),
            Err(FrameError::InvalidVersion(99, 1))
        ));
    }

    #[test]
    fn test_unknown_frame_type() {
        // Unknown non-critical frame type: should decode successfully (caller skips)
        let mut encoded = encode_frame(&Frame::data(4, b"test".to_vec())).unwrap();
        encoded[1] = 0xFF; // Unknown frame type
        encoded[2] = 0x00; // No critical bit
        let result = decode_frame(&encoded);
        assert!(result.is_ok(), "non-critical unknown type should decode");
        let (frame, _) = result.unwrap();
        assert!(frame.frame_type.is_unknown());
        assert_eq!(frame.frame_type.to_u8(), 0xFF);

        // Unknown critical frame type: should be rejected
        let mut encoded = encode_frame(&Frame::data(4, b"test".to_vec())).unwrap();
        encoded[1] = 0xFF; // Unknown frame type
        encoded[2] = 0x80; // Critical bit set
        assert!(matches!(
            decode_frame(&encoded),
            Err(FrameError::UnknownFrameType(0xFF))
        ));
    }

    #[test]
    fn test_multiple_frames_in_buffer() {
        let f1 = Frame::data(4, b"first".to_vec());
        let f2 = Frame::data(5, b"second".to_vec());
        let mut buf = encode_frame(&f1).unwrap();
        buf.extend(encode_frame(&f2).unwrap());

        let (decoded1, consumed1) = decode_frame(&buf).unwrap();
        assert_eq!(decoded1.payload, b"first");

        let (decoded2, _) = decode_frame(&buf[consumed1..]).unwrap();
        assert_eq!(decoded2.payload, b"second");
    }

    #[test]
    fn test_codec_roundtrip() {
        let mut codec = FrameCodec::new();
        let frame = Frame::data(4, b"test payload".to_vec());
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_codec_partial_frame() {
        let mut codec = FrameCodec::new();
        let frame = Frame::data(4, b"test".to_vec());
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Only provide first 10 bytes
        let mut partial = buf.split_to(10);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // Provide the rest
        let mut rest = partial;
        rest.extend_from_slice(&buf);
        let decoded = codec.decode(&mut rest).unwrap().unwrap();
        assert_eq!(decoded.payload, b"test");
    }

    #[test]
    fn test_header_is_28_bytes() {
        let frame = Frame::data(4, b"".to_vec());
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(encoded.len(), FRAME_HEADER_SIZE); // No payload, no extensions
    }

    #[test]
    fn test_reserved_field_ignored() {
        let frame = Frame::data(4, b"test".to_vec());
        let mut encoded = encode_frame(&frame).unwrap();
        encoded[3] = 0xFF; // Set reserved field to non-zero
        // Should still decode successfully (reserved is ignored)
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.payload, b"test");
    }
}
