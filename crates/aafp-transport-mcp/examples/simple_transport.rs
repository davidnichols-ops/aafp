//! Simple AAFP transport example: raw JSON-RPC over AAFP.
//!
//! This example shows the lowest-level usage of `AafpMcpTransport` —
//! sending and receiving raw JSON-RPC messages without the rmcp service
//! layer. This is useful for understanding how the transport works
//! underneath, or for building custom MCP integrations.
//!
//! Run with:
//! ```bash
//! cargo run --example simple_transport -p aafp-transport-mcp
//! ```

use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::AafpMcpTransport;
use rmcp::model::{ClientRequest, JsonRpcMessage, PingRequest, RequestId};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::{RoleClient, RoleServer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Simple AAFP Transport Example ===\n");

    // Create server agent
    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec!["mcp-server".into()])
            .bind("127.0.0.1:0".parse()?)
            .build()
            .await?,
    );
    let server_addr = format!("quic://{}", server_agent.transport.local_addr()?);
    println!("Server listening on: {server_addr}");

    // Spawn server: accept connection, receive ping, send pong
    let server_handle = tokio::spawn(async move {
        let mut transport = AafpMcpTransport::accept(&server_agent)
            .await
            .expect("server accept");

        println!("[server] Handshake complete, waiting for messages...");

        // Receive a ping request
        let msg = Transport::<RoleServer>::receive(&mut transport)
            .await
            .expect("should receive message");

        if let RxJsonRpcMessage::<RoleServer>::Request(req) = &msg {
            println!("[server] Received request with id={:?}", req.id);
            if matches!(req.request, ClientRequest::PingRequest(_)) {
                println!("[server]   → it's a ping!");
            }
        }

        // Send a ping response back (empty result for ping)
        let pong: TxJsonRpcMessage<RoleServer> = JsonRpcMessage::response(
            rmcp::model::ServerResult::EmptyResult(rmcp::model::EmptyResult {}),
            RequestId::Number(1),
        );
        Transport::<RoleServer>::send(&mut transport, pong)
            .await
            .expect("server send");

        println!("[server] Sent response");

        // Wait a bit for client to receive, then close
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        Transport::<RoleServer>::close(&mut transport)
            .await
            .expect("server close");
        println!("[server] Closed");
    });

    // Create client agent
    let client_agent = AgentBuilder::new()
        .with_capabilities(vec!["mcp-client".into()])
        .bind("127.0.0.1:0".parse()?)
        .build()
        .await?;

    println!("Client connecting to server...");

    // Connect via AAFP transport
    let mut transport = AafpMcpTransport::connect(&client_agent, &server_addr).await?;
    println!("Handshake complete!\n");

    // Send a ping request
    let ping: TxJsonRpcMessage<RoleClient> = JsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(1),
    );
    Transport::<RoleClient>::send(&mut transport, ping).await?;
    println!("[client] Sent ping request");

    // Receive the response
    let msg = Transport::<RoleClient>::receive(&mut transport).await;
    if let Some(RxJsonRpcMessage::<RoleClient>::Response(resp)) = &msg {
        println!("[client] Received response with id={:?}", resp.id);
    } else {
        println!("[client] Received: {msg:?}");
    }

    server_handle.await?;
    Transport::<RoleClient>::close(&mut transport).await?;

    println!("\n=== Done! ===");
    Ok(())
}
