//! Minimal MCP client over AAFP — connects to a specified address.
//!
//! Used by the cross-SDK interop test (test_cross_sdk.py) to verify
//! that a Rust rmcp client can connect to a Python MCP server over AAFP.
//!
//! Usage:
//! ```bash
//! cargo run --example mcp_client -- <quic://127.0.0.1:PORT>
//! ```
//!
//! The client:
//! 1. Creates an AAFP agent
//! 2. Connects to the given address
//! 3. Sends an `initialize` request and prints the response
//! 4. Sends a `tools/list` request and prints the response
//! 5. Closes the connection

use std::env;

use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::AafpMcpTransport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let addr = env::args()
        .nth(1)
        .ok_or("usage: mcp_client <quic://127.0.0.1:PORT>")?;

    eprintln!("[rust-client] Connecting to {addr}");

    let agent = AgentBuilder::new()
        .with_capabilities(vec!["mcp-client".into()])
        .bind("127.0.0.1:0".parse()?)
        .build()
        .await?;

    let mut transport = AafpMcpTransport::connect(&agent, &addr).await?;
    eprintln!("[rust-client] AAFP handshake complete");

    // Send initialize request via raw JSON (no rmcp dependency needed)
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "rust-cross-sdk-test", "version": "0.1.0"}
        },
        "id": 1
    });
    transport.send_raw_json(&init_req).await?;
    let init_resp = transport
        .recv_raw_json()
        .await
        .ok_or("no initialize response")?;
    eprintln!("[rust-client] Initialize response: {init_resp}");
    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert!(
        init_resp.get("result").is_some(),
        "expected result in init response"
    );

    // Send initialized notification
    let initialized_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    transport.send_raw_json(&initialized_notif).await?;

    // Send tools/list
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 2
    });
    transport.send_raw_json(&tools_req).await?;
    let tools_resp = transport
        .recv_raw_json()
        .await
        .ok_or("no tools/list response")?;
    eprintln!("[rust-client] Tools/list response: {tools_resp}");
    assert_eq!(tools_resp["jsonrpc"], "2.0");
    assert_eq!(tools_resp["id"], 2);
    assert!(
        tools_resp.get("result").is_some(),
        "expected result in tools response"
    );

    // Close
    transport.close_raw().await?;
    eprintln!("[rust-client] Connection closed cleanly");

    // Shut down the agent's QUIC endpoint
    agent.transport.close();
    agent.transport.wait_idle().await;

    eprintln!("[rust-client] Done");
    Ok(())
}
