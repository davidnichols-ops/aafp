//! Protocol-level frame transmission: ERROR and CLOSE frames (RFC-0002 §4.5-4.6).
//!
//! This module provides functions to send ERROR and CLOSE frames over a
//! QUIC stream, following the graceful shutdown sequence specified in
//! RFC-0002 §4.5 and the error transmission rules in RFC-0005 §4.
//!
//! ## CLOSE Frame (RFC-0002 §4.5)
//!
//! After sending a CLOSE frame, the sender MUST NOT send additional frames.
//! The receiver SHOULD send a CLOSE frame in response and then close the
//! QUIC connection.
//!
//! ## ERROR Frame (RFC-0002 §4.6)
//!
//! If `fatal` is true, the receiver MUST close the connection after
//! receiving the error frame. If `fatal` is false, the error is non-fatal
//! and the connection may continue.

use crate::SdkError;
use aafp_core::ProtocolError;
use aafp_messaging::{encode_frame, CloseMessage, ErrorMessage, Frame, FrameType};
use aafp_transport_quic::QuicConnection;

/// Send an ERROR frame to the peer (RFC-0002 §4.6, RFC-0005 §4.1).
///
/// The ERROR frame is sent on stream 0 (the control stream). If the error
/// is fatal, the caller SHOULD close the connection after sending.
///
/// # Arguments
/// * `conn` - The QUIC connection to send the frame on.
/// * `error` - The protocol error to transmit.
pub async fn send_error_frame(
    conn: &QuicConnection,
    error: &ProtocolError,
) -> Result<(), SdkError> {
    let msg = ErrorMessage {
        code: error.code,
        message: error.message.clone(),
        data: error.data.clone(),
        fatal: error.fatal,
    };
    let payload = msg
        .encode()
        .map_err(|e| SdkError::Messaging(format!("error frame encode: {e}")))?;
    let frame = Frame {
        frame_type: FrameType::Error,
        flags: 0,
        stream_id: 0,
        extensions: Vec::new(),
        payload,
    };
    let frame_bytes = encode_frame(&frame)?;
    let (mut send, _recv) = conn.open_bi().await?;
    send.write_all(&frame_bytes).await?;
    send.finish();
    Ok(())
}

/// Send a CLOSE frame to the peer (RFC-0002 §4.5).
///
/// After sending a CLOSE frame, the caller MUST NOT send additional frames.
/// The caller SHOULD then close the QUIC connection.
///
/// # Arguments
/// * `conn` - The QUIC connection to send the frame on.
/// * `code` - Close reason code (RFC-0005).
/// * `message` - Human-readable close reason.
pub async fn send_close_frame(
    conn: &QuicConnection,
    code: u32,
    message: impl Into<String>,
) -> Result<(), SdkError> {
    let msg = CloseMessage::new(code, message);
    let payload = msg
        .encode()
        .map_err(|e| SdkError::Messaging(format!("close frame encode: {e}")))?;
    let frame = Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        extensions: Vec::new(),
        payload,
    };
    let frame_bytes = encode_frame(&frame)?;
    let (mut send, _recv) = conn.open_bi().await?;
    send.write_all(&frame_bytes).await?;
    send.finish();
    Ok(())
}

/// Receive and parse an ERROR or CLOSE frame from a bidirectional stream.
///
/// Returns the parsed frame if it is an ERROR or CLOSE frame, or an error
/// if the frame is malformed or has an unexpected type.
pub fn parse_control_frame(frame: &Frame) -> Result<ControlFrame, SdkError> {
    match frame.frame_type {
        FrameType::Error => {
            let msg = ErrorMessage::decode(&frame.payload)
                .map_err(|e| SdkError::Messaging(format!("error frame decode: {e}")))?;
            Ok(ControlFrame::Error(msg))
        }
        FrameType::Close => {
            let msg = CloseMessage::decode(&frame.payload)
                .map_err(|e| SdkError::Messaging(format!("close frame decode: {e}")))?;
            Ok(ControlFrame::Close(msg))
        }
        other => Err(SdkError::Messaging(format!(
            "expected ERROR or CLOSE frame, got {:?}",
            other
        ))),
    }
}

/// A parsed control frame (ERROR or CLOSE).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlFrame {
    /// An ERROR control frame sent by a peer.
    Error(ErrorMessage),
    /// A CLOSE control frame sent by a peer.
    Close(CloseMessage),
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use aafp_core::codes;
    use aafp_messaging::decode_frame;

    #[test]
    fn test_error_frame_roundtrip() {
        let error = ProtocolError::new(codes::INVALID_SIGNATURE, "bad signature");
        let msg = ErrorMessage {
            code: error.code,
            message: error.message.clone(),
            data: error.data.clone(),
            fatal: error.fatal,
        };
        let payload = msg.encode().unwrap();
        let frame = Frame {
            frame_type: FrameType::Error,
            flags: 0,
            stream_id: 0,
            extensions: Vec::new(),
            payload,
        };
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        let parsed = parse_control_frame(&decoded).unwrap();
        match parsed {
            ControlFrame::Error(e) => {
                assert_eq!(e.code, codes::INVALID_SIGNATURE);
                assert_eq!(e.message, "bad signature");
                assert!(e.fatal); // Auth errors are always fatal
            }
            _ => panic!("expected Error frame"),
        }
    }

    #[test]
    fn test_close_frame_roundtrip() {
        let msg = CloseMessage::new(0, "goodbye");
        let payload = msg.encode().unwrap();
        let frame = Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            extensions: Vec::new(),
            payload,
        };
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        let parsed = parse_control_frame(&decoded).unwrap();
        match parsed {
            ControlFrame::Close(c) => {
                assert_eq!(c.code, 0);
                assert_eq!(c.message, "goodbye");
            }
            _ => panic!("expected Close frame"),
        }
    }

    #[test]
    fn test_parse_control_frame_rejects_data() {
        let frame = Frame::data(0, b"hello".to_vec());
        let result = parse_control_frame(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_frame_with_data() {
        let error = ProtocolError::new(codes::PROTOCOL_VIOLATION, "violation")
            .with_data(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let msg = ErrorMessage {
            code: error.code,
            message: error.message.clone(),
            data: error.data.clone(),
            fatal: error.fatal,
        };
        let payload = msg.encode().unwrap();
        let frame = Frame {
            frame_type: FrameType::Error,
            flags: 0,
            stream_id: 0,
            extensions: Vec::new(),
            payload,
        };
        let encoded = encode_frame(&frame).unwrap();
        let (decoded, _) = decode_frame(&encoded).unwrap();
        let parsed = parse_control_frame(&decoded).unwrap();
        match parsed {
            ControlFrame::Error(e) => {
                assert_eq!(e.code, codes::PROTOCOL_VIOLATION);
                assert_eq!(e.data, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
                assert!(e.fatal);
            }
            _ => panic!("expected Error frame"),
        }
    }

    #[tokio::test]
    async fn test_send_and_receive_close_frame_over_quic() {
        use aafp_messaging::decode_frame;
        use aafp_transport_quic::{QuicConfig, QuicTransport};
        use std::sync::Arc;

        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server = Arc::new(QuicTransport::new(server_config).unwrap());
        let server_addr = server.local_multiaddr().unwrap();

        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let client = QuicTransport::new(client_config).unwrap();

        // Spawn server: accept connection, then receive CLOSE frame.
        let server_clone = server.clone();
        let handle = tokio::spawn(async move {
            let conn = server_clone.accept().await.unwrap();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();

            // Read the full CLOSE frame.
            let mut header = [0u8; aafp_messaging::FRAME_HEADER_SIZE];
            recv.read_exact(&mut header).await.unwrap();
            let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
            let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
            let mut body = vec![0u8; payload_len + ext_len];
            if !body.is_empty() {
                recv.read_exact(&mut body).await.unwrap();
            }
            let mut full = header.to_vec();
            full.extend_from_slice(&body);
            let (frame, _) = decode_frame(&full).unwrap();

            // Verify it's a CLOSE frame.
            assert_eq!(frame.frame_type, FrameType::Close);
            let parsed = parse_control_frame(&frame).unwrap();
            match parsed {
                ControlFrame::Close(c) => {
                    assert_eq!(c.code, codes::OK);
                    assert_eq!(c.message, "graceful shutdown");
                }
                _ => panic!("expected Close frame"),
            }
        });

        // Client: connect and send CLOSE frame.
        let conn = client.dial(&server_addr).await.unwrap();
        send_close_frame(&conn, codes::OK, "graceful shutdown")
            .await
            .unwrap();

        handle.await.unwrap();
        client.close();
        drop(server);
    }

    #[tokio::test]
    async fn test_send_and_receive_error_frame_over_quic() {
        use aafp_messaging::decode_frame;
        use aafp_transport_quic::{QuicConfig, QuicTransport};
        use std::sync::Arc;

        let server_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let server = Arc::new(QuicTransport::new(server_config).unwrap());
        let server_addr = server.local_multiaddr().unwrap();

        let client_config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let client = QuicTransport::new(client_config).unwrap();

        // Spawn server: accept connection, then receive ERROR frame.
        let server_clone = server.clone();
        let handle = tokio::spawn(async move {
            let conn = server_clone.accept().await.unwrap();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();

            let mut header = [0u8; aafp_messaging::FRAME_HEADER_SIZE];
            recv.read_exact(&mut header).await.unwrap();
            let payload_len = u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
            let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
            let mut body = vec![0u8; payload_len + ext_len];
            if !body.is_empty() {
                recv.read_exact(&mut body).await.unwrap();
            }
            let mut full = header.to_vec();
            full.extend_from_slice(&body);
            let (frame, _) = decode_frame(&full).unwrap();

            assert_eq!(frame.frame_type, FrameType::Error);
            let parsed = parse_control_frame(&frame).unwrap();
            match parsed {
                ControlFrame::Error(e) => {
                    assert_eq!(e.code, codes::INVALID_SIGNATURE);
                    assert_eq!(e.message, "bad signature");
                    assert!(e.fatal); // Auth errors are always fatal
                }
                _ => panic!("expected Error frame"),
            }
        });

        let conn = client.dial(&server_addr).await.unwrap();
        let error = ProtocolError::new(codes::INVALID_SIGNATURE, "bad signature");
        send_error_frame(&conn, &error).await.unwrap();

        handle.await.unwrap();
        client.close();
        drop(server);
    }
}
