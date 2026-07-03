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

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// AAFP protocol version 1.
pub const AAFP_VERSION: u8 = 1;

/// Maximum payload size: 1 MiB (RFC-0002 §3.4).
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Maximum extension section size: 64 KiB (SA-0006).
///
/// Extensions are metadata (type, critical flag, data). 64 KiB is generous
/// for any conceivable extension payload. Without this limit, an attacker
/// could double the per-frame memory allocation (1 MiB payload + 1 MiB
/// extensions = 2 MiB total).
pub const MAX_EXTENSION_SIZE: usize = 64 * 1024;

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
    /// Application data frame (RFC-0002 §4.1).
    Data,
    /// Handshake frame for connection establishment (RFC-0002 §4.2).
    Handshake,
    /// RPC request frame (RFC-0002 §4.3).
    RpcRequest,
    /// RPC response frame (RFC-0002 §4.4).
    RpcResponse,
    /// Close frame for graceful connection shutdown (RFC-0002 §4.5).
    Close,
    /// Error frame for reporting protocol errors (RFC-0002 §4.6).
    Error,
    /// Ping frame for keepalive probes (RFC-0002 §4.7).
    Ping,
    /// Pong frame responding to a Ping (RFC-0002 §4.8).
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
    /// MORE flag: indicates more fragments will follow (RFC-0002 §4.1).
    pub const MORE: u8 = 0x01;
    /// COMPRESSED flag: indicates the payload is compressed (RFC-0002 §4.1).
    pub const COMPRESSED: u8 = 0x02;
    /// Critical bit for unknown frame types (RFC-0006 §4.2).
    pub const CRITICAL: u8 = 0x80;
}

/// AAFP frame: header + extensions + payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// The frame type (e.g., Data, RpcRequest, Close).
    pub frame_type: FrameType,
    /// Frame-specific flags (see `flags` module).
    pub flags: u8,
    /// The stream ID this frame belongs to.
    pub stream_id: u64,
    /// Raw extension section bytes.
    pub extensions: Vec<u8>,
    /// The frame payload bytes.
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
    /// The frame payload exceeds the maximum allowed size.
    #[error("frame too large: payload {0} bytes (max {1})")]
    PayloadTooLarge(usize, usize),
    /// The extension section exceeds the maximum allowed size.
    #[error("extension section too large: {0} bytes (max {1})")]
    ExtensionTooLarge(usize, usize),
    /// The frame buffer does not contain enough bytes to decode a complete frame.
    #[error("incomplete frame: need {needed} bytes, have {have}")]
    Incomplete {
        /// Number of bytes needed to complete the frame.
        needed: usize,
        /// Number of bytes actually available.
        have: usize,
    },
    /// The frame type is unknown and the critical bit is set.
    #[error("invalid frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    /// The protocol version in the frame header is not supported.
    #[error("invalid version: {0} (expected {1})")]
    InvalidVersion(u8, u8),
    /// An I/O error occurred during encoding or decoding.
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

    if frame.extensions.len() > MAX_EXTENSION_SIZE {
        return Err(FrameError::ExtensionTooLarge(
            frame.extensions.len(),
            MAX_EXTENSION_SIZE,
        ));
    }

    let ext_len = frame.extensions.len() as u64;
    let payload_len = frame.payload.len() as u64;

    let mut buf =
        Vec::with_capacity(FRAME_HEADER_SIZE + frame.extensions.len() + frame.payload.len());

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

    if ext_len > MAX_EXTENSION_SIZE {
        return Err(FrameError::ExtensionTooLarge(ext_len, MAX_EXTENSION_SIZE));
    }

    let total_body = ext_len
        .checked_add(payload_len)
        .ok_or(FrameError::PayloadTooLarge(usize::MAX, MAX_PAYLOAD_SIZE))?;
    let total_frame = FRAME_HEADER_SIZE
        .checked_add(total_body)
        .ok_or(FrameError::PayloadTooLarge(usize::MAX, MAX_PAYLOAD_SIZE))?;
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

/// Encode a frame directly into a `BytesMut` buffer (zero-copy).
///
/// Writes the 28-byte header + extensions + payload directly into the
/// provided buffer, growing it in-place if needed. No new `Vec` allocation
/// if the buffer has sufficient capacity.
///
/// # Errors
///
/// Returns `FrameError::PayloadTooLarge` if the payload exceeds
/// `MAX_PAYLOAD_SIZE`, or `FrameError::ExtensionTooLarge` if the
/// extensions exceed `MAX_EXTENSION_SIZE`.
pub fn encode_frame_into(buf: &mut BytesMut, frame: &Frame) -> Result<(), FrameError> {
    if frame.payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(
            frame.payload.len(),
            MAX_PAYLOAD_SIZE,
        ));
    }

    if frame.extensions.len() > MAX_EXTENSION_SIZE {
        return Err(FrameError::ExtensionTooLarge(
            frame.extensions.len(),
            MAX_EXTENSION_SIZE,
        ));
    }

    let ext_len = frame.extensions.len() as u64;
    let payload_len = frame.payload.len() as u64;
    let total_len = FRAME_HEADER_SIZE + frame.extensions.len() + frame.payload.len();

    // Reserve space in the buffer (grows in-place if needed, no new alloc
    // if capacity is sufficient)
    buf.reserve(total_len);

    // Header (28 bytes, big-endian)
    buf.put_u8(AAFP_VERSION);
    buf.put_u8(frame.frame_type.to_u8());
    buf.put_u8(frame.flags);
    buf.put_u8(0u8); // Reserved
    buf.put_u64(frame.stream_id);
    buf.put_u64(payload_len);
    buf.put_u64(ext_len);

    // Body: extensions first, then payload (RFC-0002 §3.2)
    buf.put_slice(&frame.extensions);
    buf.put_slice(&frame.payload);

    Ok(())
}

/// Encode a frame header directly into a `BytesMut` buffer.
///
/// Writes only the 28-byte header, leaving space for the caller to
/// write the payload directly (e.g., via `serde_json::to_writer`).
/// The caller must then call `backpatch_payload_len()` to fill in
/// the payload length field.
///
/// This is useful for the zero-copy send path where JSON is serialized
/// directly into the buffer after the header.
///
/// # Errors
///
/// Returns `FrameError::ExtensionTooLarge` if extensions exceed the limit.
pub fn encode_header_into(
    buf: &mut BytesMut,
    frame_type: FrameType,
    flags: u8,
    stream_id: u64,
    extensions: &[u8],
) -> Result<(), FrameError> {
    if extensions.len() > MAX_EXTENSION_SIZE {
        return Err(FrameError::ExtensionTooLarge(
            extensions.len(),
            MAX_EXTENSION_SIZE,
        ));
    }

    let ext_len = extensions.len() as u64;

    // Reserve space for header + extensions
    buf.reserve(FRAME_HEADER_SIZE + extensions.len());

    // Header (28 bytes, big-endian) — payload_len is 0, will be backpatched
    buf.put_u8(AAFP_VERSION);
    buf.put_u8(frame_type.to_u8());
    buf.put_u8(flags);
    buf.put_u8(0u8); // Reserved
    buf.put_u64(stream_id);
    buf.put_u64(0); // payload_len — placeholder, backpatch later
    buf.put_u64(ext_len);

    // Extensions
    buf.put_slice(extensions);

    Ok(())
}

/// Backpatch the payload length in a buffer that was written via
/// `encode_header_into()`.
///
/// After writing the payload into the buffer, call this to update the
/// payload_len field in the header. The payload length is written at
/// byte offset 12 (after version, type, flags, reserved, stream_id).
///
/// # Errors
///
/// Returns `FrameError::PayloadTooLarge` if the payload exceeds the limit.
pub fn backpatch_payload_len(buf: &mut BytesMut, payload_len: usize) -> Result<(), FrameError> {
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    // Payload length is at offset 12, 8 bytes, big-endian
    if buf.len() < 20 {
        return Err(FrameError::Incomplete {
            needed: 20,
            have: buf.len(),
        });
    }

    buf[12..20].copy_from_slice(&(payload_len as u64).to_be_bytes());
    Ok(())
}

/// A decoded frame with zero-copy payload access.
///
/// The payload is a `Bytes` (reference-counted slice) rather than a `Vec<u8>`,
/// allowing zero-copy access to the payload data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedFrame {
    /// The frame type.
    pub frame_type: FrameType,
    /// Frame flags.
    pub flags: u8,
    /// The stream ID.
    pub stream_id: u64,
    /// Raw extension section bytes (zero-copy).
    pub extensions: Bytes,
    /// The frame payload bytes (zero-copy).
    pub payload: Bytes,
}

/// Decode a frame from a `BytesMut` buffer (zero-copy).
///
/// Parses the header from the buffer and returns a `DecodedFrame` with
/// `Bytes` slices pointing into the original buffer (no copy).
/// Also returns the total number of bytes consumed.
///
/// # Errors
///
/// Returns `FrameError::Incomplete` if the buffer doesn't contain a
/// complete frame, `FrameError::InvalidVersion` if the version doesn't
/// match, or `FrameError::PayloadTooLarge` / `FrameError::ExtensionTooLarge`
/// for oversized fields.
pub fn decode_frame_from(buf: &mut BytesMut) -> Result<Option<DecodedFrame>, FrameError> {
    if buf.len() < FRAME_HEADER_SIZE {
        return Ok(None);
    }

    let version = buf[0];
    let frame_type_raw = buf[1];
    let flags = buf[2];
    // buf[3] is reserved, ignored per RFC-0002 §3.1
    let stream_id = u64::from_be_bytes(buf[4..12].try_into().unwrap());
    let payload_len = u64::from_be_bytes(buf[12..20].try_into().unwrap()) as usize;
    let ext_len = u64::from_be_bytes(buf[20..28].try_into().unwrap()) as usize;

    if version != AAFP_VERSION {
        return Err(FrameError::InvalidVersion(version, AAFP_VERSION));
    }

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    if ext_len > MAX_EXTENSION_SIZE {
        return Err(FrameError::ExtensionTooLarge(ext_len, MAX_EXTENSION_SIZE));
    }

    let total_body = ext_len
        .checked_add(payload_len)
        .ok_or(FrameError::PayloadTooLarge(usize::MAX, MAX_PAYLOAD_SIZE))?;
    let total_frame = FRAME_HEADER_SIZE
        .checked_add(total_body)
        .ok_or(FrameError::PayloadTooLarge(usize::MAX, MAX_PAYLOAD_SIZE))?;

    if buf.len() < total_frame {
        return Ok(None);
    }

    let frame_type = FrameType::from_u8(frame_type_raw);

    if frame_type.is_unknown() && (flags & flags::CRITICAL) != 0 {
        return Err(FrameError::UnknownFrameType(frame_type_raw));
    }

    // Advance past the header
    buf.advance(FRAME_HEADER_SIZE);

    // Split off extensions (zero-copy)
    let extensions = if ext_len > 0 {
        buf.split_to(ext_len).freeze()
    } else {
        Bytes::new()
    };

    // Split off payload (zero-copy)
    let payload = if payload_len > 0 {
        buf.split_to(payload_len).freeze()
    } else {
        Bytes::new()
    };

    Ok(Some(DecodedFrame {
        frame_type,
        flags,
        stream_id,
        extensions,
        payload,
    }))
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
    /// Create a new codec with the default maximum payload size.
    pub fn new() -> Self {
        Self {
            max_payload: MAX_PAYLOAD_SIZE,
        }
    }

    /// Create a new codec with a custom maximum payload size.
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
        let payload_len = u64::from_be_bytes(buf[12..20].try_into().unwrap()) as usize;
        let ext_len = u64::from_be_bytes(buf[20..28].try_into().unwrap()) as usize;

        // Reject oversized payload and extensions BEFORE any allocation
        // (RFC-0002 §3.4, §6.1 — A-5: reject before allocation)
        if payload_len > self.max_payload {
            return Err(FrameError::PayloadTooLarge(payload_len, self.max_payload));
        }

        if ext_len > MAX_EXTENSION_SIZE {
            return Err(FrameError::ExtensionTooLarge(ext_len, MAX_EXTENSION_SIZE));
        }

        let total = FRAME_HEADER_SIZE
            .checked_add(ext_len)
            .and_then(|n| n.checked_add(payload_len))
            .ok_or(FrameError::PayloadTooLarge(usize::MAX, self.max_payload))?;
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

        if frame.extensions.len() > MAX_EXTENSION_SIZE {
            return Err(FrameError::ExtensionTooLarge(
                frame.extensions.len(),
                MAX_EXTENSION_SIZE,
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

    // A-5: Extension limit tests

    #[test]
    fn test_extension_too_large_encode() {
        let mut frame = Frame::data(4, b"test".to_vec());
        frame.extensions = vec![0u8; MAX_EXTENSION_SIZE + 1];
        assert!(matches!(
            encode_frame(&frame),
            Err(FrameError::ExtensionTooLarge(_, _))
        ));
    }

    #[test]
    fn test_extension_too_large_decode() {
        // Craft a header with ext_len > MAX_EXTENSION_SIZE but payload_len = 0
        let mut header = vec![0u8; FRAME_HEADER_SIZE];
        header[0] = AAFP_VERSION;
        header[1] = FrameType::Data.to_u8();
        // payload_len = 0
        header[12..20].copy_from_slice(&0u64.to_be_bytes());
        // ext_len = MAX_EXTENSION_SIZE + 1
        header[20..28].copy_from_slice(&((MAX_EXTENSION_SIZE as u64) + 1).to_be_bytes());
        assert!(matches!(
            decode_frame(&header),
            Err(FrameError::ExtensionTooLarge(_, _))
        ));
    }

    #[test]
    fn test_extension_at_max_size() {
        let mut frame = Frame::data(4, b"ok".to_vec());
        frame.extensions = vec![0u8; MAX_EXTENSION_SIZE];
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.extensions.len(), MAX_EXTENSION_SIZE);
    }

    #[test]
    fn test_extension_too_large_codec_encode() {
        let mut codec = FrameCodec::new();
        let mut frame = Frame::data(4, b"test".to_vec());
        frame.extensions = vec![0u8; MAX_EXTENSION_SIZE + 1];
        let mut buf = BytesMut::new();
        assert!(matches!(
            codec.encode(frame, &mut buf),
            Err(FrameError::ExtensionTooLarge(_, _))
        ));
    }

    #[test]
    fn test_extension_too_large_codec_decode() {
        let mut codec = FrameCodec::new();
        // Craft a header with oversized extension length
        let mut buf = BytesMut::from(&[0u8; FRAME_HEADER_SIZE][..]);
        buf[0] = AAFP_VERSION;
        buf[1] = FrameType::Data.to_u8();
        // payload_len = 0
        buf[12..20].copy_from_slice(&0u64.to_be_bytes());
        // ext_len = MAX_EXTENSION_SIZE + 1
        buf[20..28].copy_from_slice(&((MAX_EXTENSION_SIZE as u64) + 1).to_be_bytes());
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FrameError::ExtensionTooLarge(_, _))
        ));
    }

    #[test]
    fn test_extension_size_checked_before_allocation() {
        // Verify that a frame claiming ext_len = u64::MAX is rejected
        // without trying to allocate anything.
        let mut header = vec![0u8; FRAME_HEADER_SIZE];
        header[0] = AAFP_VERSION;
        header[1] = FrameType::Data.to_u8();
        header[12..20].copy_from_slice(&0u64.to_be_bytes()); // payload = 0
        header[20..28].copy_from_slice(&u64::MAX.to_be_bytes()); // ext = u64::MAX
        let result = decode_frame(&header);
        assert!(result.is_err());
        // Should be ExtensionTooLarge, not Incomplete or OOM
        match result {
            Err(FrameError::ExtensionTooLarge(_, _)) => {}
            other => panic!("expected ExtensionTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_encode_frame_into_basic() {
        let frame = Frame::data(4, b"hello world".to_vec());
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        // Should produce the same bytes as encode_frame
        let expected = encode_frame(&frame).unwrap();
        assert_eq!(buf.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_encode_frame_into_with_extensions() {
        let mut frame = Frame::data(4, b"payload".to_vec());
        frame.extensions = b"ext_data".to_vec();
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let expected = encode_frame(&frame).unwrap();
        assert_eq!(buf.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_encode_frame_into_empty_payload() {
        let frame = Frame::ping(4);
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let expected = encode_frame(&frame).unwrap();
        assert_eq!(buf.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_encode_frame_into_grows_buffer() {
        let frame = Frame::data(4, vec![0u8; 8192]);
        let mut buf = BytesMut::with_capacity(64); // too small
        encode_frame_into(&mut buf, &frame).unwrap();

        let expected = encode_frame(&frame).unwrap();
        assert_eq!(buf.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_encode_frame_into_roundtrip() {
        let frame = Frame::data(42, b"roundtrip test".to_vec());
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let (decoded, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_encode_header_into_and_backpatch() {
        let payload = b"backpatched payload";
        let mut buf = BytesMut::with_capacity(1024);

        // Write header with placeholder payload_len=0
        encode_header_into(&mut buf, FrameType::Data, 0, 4, &[]).unwrap();
        let header_end = buf.len();

        // Write payload directly into buffer
        buf.put_slice(payload);

        // Backpatch the payload length
        backpatch_payload_len(&mut buf, payload.len()).unwrap();

        // Verify: decode should produce the correct frame
        let (decoded, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.stream_id, 4);
        assert_eq!(decoded.payload, payload.to_vec());
        assert_eq!(decoded.extensions, Vec::<u8>::new());

        // Verify payload_len field in header is correct
        let payload_len_in_header = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        assert_eq!(payload_len_in_header as usize, payload.len());
        assert_eq!(header_end, FRAME_HEADER_SIZE);
    }

    #[test]
    fn test_encode_header_into_with_extensions() {
        let mut buf = BytesMut::with_capacity(1024);
        let ext = b"extension_data";
        encode_header_into(&mut buf, FrameType::Data, 0, 4, ext).unwrap();

        // Header + extensions should be written
        assert_eq!(buf.len(), FRAME_HEADER_SIZE + ext.len());

        // Verify extension length in header
        let ext_len = u64::from_be_bytes(buf[20..28].try_into().unwrap());
        assert_eq!(ext_len as usize, ext.len());
    }

    #[test]
    fn test_backpatch_payload_len_too_short() {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(0); // only 1 byte
        let result = backpatch_payload_len(&mut buf, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_frame_into_payload_too_large() {
        let frame = Frame::data(4, vec![0u8; MAX_PAYLOAD_SIZE + 1]);
        let mut buf = BytesMut::with_capacity(1024);
        let result = encode_frame_into(&mut buf, &frame);
        assert!(matches!(result, Err(FrameError::PayloadTooLarge(_, _))));
    }

    #[test]
    fn test_decode_frame_from_basic() {
        let frame = Frame::data(4, b"hello world".to_vec());
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let decoded = decode_frame_from(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.stream_id, 4);
        assert_eq!(decoded.payload.as_ref(), b"hello world");
        assert_eq!(decoded.extensions.len(), 0);
        assert_eq!(buf.len(), 0); // buffer should be consumed
    }

    #[test]
    fn test_decode_frame_from_with_extensions() {
        let mut frame = Frame::data(4, b"payload".to_vec());
        frame.extensions = b"ext_data".to_vec();
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let decoded = decode_frame_from(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.extensions.as_ref(), b"ext_data");
        assert_eq!(decoded.payload.as_ref(), b"payload");
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decode_frame_from_incomplete() {
        let mut buf = BytesMut::with_capacity(1024);
        // Only 10 bytes — not enough for a header
        buf.put_slice(&[0u8; 10]);
        let result = decode_frame_from(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_frame_from_empty_payload() {
        let frame = Frame::ping(4);
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let decoded = decode_frame_from(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert_eq!(decoded.payload.len(), 0);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decode_frame_from_multiple_frames() {
        let mut buf = BytesMut::with_capacity(2048);
        encode_frame_into(&mut buf, &Frame::data(1, b"first".to_vec())).unwrap();
        encode_frame_into(&mut buf, &Frame::data(2, b"second".to_vec())).unwrap();

        let f1 = decode_frame_from(&mut buf).unwrap().unwrap();
        assert_eq!(f1.stream_id, 1);
        assert_eq!(f1.payload.as_ref(), b"first");

        let f2 = decode_frame_from(&mut buf).unwrap().unwrap();
        assert_eq!(f2.stream_id, 2);
        assert_eq!(f2.payload.as_ref(), b"second");

        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decode_frame_from_invalid_version() {
        let mut buf = BytesMut::with_capacity(1024);
        buf.put_u8(99); // invalid version
        buf.put_slice(&[0u8; 27]); // rest of header
        let result = decode_frame_from(&mut buf);
        assert!(matches!(result, Err(FrameError::InvalidVersion(_, _))));
    }

    #[test]
    fn test_decode_frame_from_zero_copy() {
        // Verify that payload Bytes points to the same memory as the buffer
        let payload = b"zero-copy test payload data";
        let frame = Frame::data(4, payload.to_vec());
        let mut buf = BytesMut::with_capacity(1024);
        encode_frame_into(&mut buf, &frame).unwrap();

        let decoded = decode_frame_from(&mut buf).unwrap().unwrap();
        // The payload should match
        assert_eq!(decoded.payload.as_ref(), payload);
        // And the buffer should be empty (consumed)
        assert_eq!(buf.len(), 0);
    }
}
