//! Length-prefixed framing for QUIC streams.
//!
//! Wire format: `[4 bytes: length (u32 BE)] [length bytes: payload]`
//! Payload is CBOR-encoded application data.

use bytes::{Buf, BufMut, BytesMut};
use std::io;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too large: {0} bytes (max {1})")]
    TooLarge(usize, usize),
    #[error("incomplete frame")]
    Incomplete,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Maximum frame size (1 MiB).
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// A frame containing arbitrary payload bytes.
#[derive(Clone, Debug)]
pub struct Frame {
    pub payload: Vec<u8>,
}

/// Length-prefixed frame codec for tokio_util.
pub struct FrameCodec {
    max_size: usize,
}

impl FrameCodec {
    pub fn new() -> Self {
        Self {
            max_size: MAX_FRAME_SIZE,
        }
    }

    pub fn with_max_size(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if buf.len() < 4 {
            return Ok(None);
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buf[..4]);
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > self.max_size {
            return Err(FrameError::TooLarge(len, self.max_size));
        }

        if buf.len() < 4 + len {
            buf.reserve(4 + len - buf.len());
            return Ok(None);
        }

        buf.advance(4);
        let payload = buf.split_to(len).to_vec();
        Ok(Some(Frame { payload }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, frame: Frame, buf: &mut BytesMut) -> Result<(), FrameError> {
        if frame.payload.len() > self.max_size {
            return Err(FrameError::TooLarge(frame.payload.len(), self.max_size));
        }
        buf.put_u32(frame.payload.len() as u32);
        buf.put_slice(&frame.payload);
        Ok(())
    }
}

/// Serialize a frame to bytes (length prefix + payload).
pub fn serialize_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Deserialize a frame from bytes. Returns (payload, remaining_bytes).
pub fn deserialize_frame(data: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    if data.len() < 4 {
        return Err(FrameError::Incomplete);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[..4]);
    let len = u32::from_be_bytes(len_bytes) as usize;

    if data.len() < 4 + len {
        return Err(FrameError::Incomplete);
    }

    Ok((&data[4..4 + len], &data[4 + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn serialize_deserialize() {
        let payload = b"hello world";
        let frame = serialize_frame(payload);
        assert_eq!(frame.len(), 4 + 11);
        let (decoded, remaining) = deserialize_frame(&frame).unwrap();
        assert_eq!(decoded, payload);
        assert!(remaining.is_empty());
    }

    #[test]
    fn multiple_frames() {
        let mut data = Vec::new();
        data.extend(serialize_frame(b"first"));
        data.extend(serialize_frame(b"second"));
        let (p1, rest) = deserialize_frame(&data).unwrap();
        assert_eq!(p1, b"first");
        let (p2, rest2) = deserialize_frame(rest).unwrap();
        assert_eq!(p2, b"second");
        assert!(rest2.is_empty());
    }

    #[test]
    fn incomplete_frame() {
        let data = [0u8; 2];
        assert!(deserialize_frame(&data).is_err());
    }

    #[test]
    fn codec_roundtrip() {
        let mut codec = FrameCodec::new();
        let frame = Frame {
            payload: b"test payload".to_vec(),
        };
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.payload, frame.payload);
    }

    #[test]
    fn too_large() {
        let mut codec = FrameCodec::with_max_size(10);
        let frame = Frame {
            payload: vec![0u8; 100],
        };
        let mut buf = BytesMut::new();
        assert!(codec.encode(frame, &mut buf).is_err());
    }
}
