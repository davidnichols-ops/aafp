//! WAN test server — a standalone AAFP server for WAN/interop testing.
//!
//! Listens on a configurable address and handles ping, echo, streaming,
//! and discovery requests from remote test clients. Logs all connections
//! and requests to stderr.
//!
//! Run with:
//! ```bash
//! cargo run --example wan_test_server -p aafp-tests -- 0.0.0.0:4433
//! ```
//!
//! The server prints `Server listening on: quic://ADDR:PORT` on stdout
//! once it is ready to accept connections.

use aafp_messaging::{decode_frame, encode_frame, Frame, FRAME_HEADER_SIZE};
use aafp_sdk::AgentBuilder;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let bind_addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:4433".to_string())
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;

    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec![
                "echo".into(),
                "inference".into(),
                "translation".into(),
            ])
            .bind(bind_addr)
            .build()
            .await?,
    );

    let local_addr = server_agent.transport.local_addr()?;
    let multiaddr = format!("quic://{local_addr}");
    println!("Server listening on: {multiaddr}");
    eprintln!("[wan-server] Agent ID: {}", hex::encode(server_agent.id()));
    eprintln!(
        "[wan-server] Capabilities: {:?}",
        server_agent.capabilities()
    );

    // Accept connections in a loop.
    loop {
        eprintln!("[wan-server] Waiting for connection...");

        let conn = match server_agent.transport.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[wan-server] Accept error: {e}");
                continue;
            }
        };

        let remote = conn.remote_address();
        eprintln!("[wan-server] New connection from {remote}");

        // Handle each connection — accept bidirectional streams and echo.
        // This is a raw transport echo server (no AAFP handshake) for
        // transport-level WAN testing. The full handshake is tested in
        // the integration test suite.
        tokio::spawn(async move {
            loop {
                let (mut send, mut recv) = match conn.accept_bi().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };

                tokio::spawn(async move {
                    // Read frame header.
                    let mut header = [0u8; FRAME_HEADER_SIZE];
                    if recv.read_exact(&mut header).await.is_err() {
                        return;
                    }

                    // Parse payload + extension lengths.
                    let payload_len =
                        u64::from_be_bytes(header[12..20].try_into().unwrap()) as usize;
                    let ext_len = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
                    let body_len = payload_len + ext_len;

                    let mut body = vec![0u8; body_len];
                    if body_len > 0 && recv.read_exact(&mut body).await.is_err() {
                        return;
                    }

                    let mut full_frame = header.to_vec();
                    full_frame.extend_from_slice(&body);

                    let (frame, _) = match decode_frame(&full_frame) {
                        Ok(f) => f,
                        Err(_) => return,
                    };

                    // Echo back the payload.
                    let resp_frame = Frame::data(0, frame.payload.clone());
                    let resp_bytes = match encode_frame(&resp_frame) {
                        Ok(b) => b,
                        Err(_) => return,
                    };
                    let _ = send.write_all(&resp_bytes).await;
                    send.finish();
                });
            }
        });
    }
}
