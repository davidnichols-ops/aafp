//! MCP over AAFP: A complete client-server example.
//!
//! This example demonstrates how to use the AAFP transport with the MCP
//! Rust SDK (rmcp). It creates:
//!
//! 1. An AAFP server agent that hosts a simple MCP server with an "echo" tool
//! 2. An AAFP client agent that connects and calls the echo tool
//!
//! The full AAFP security stack is exercised:
//! - QUIC transport with post-quantum TLS (X25519MLKEM768)
//! - ML-DSA-65 identity verification during handshake
//! - Authorization (TestingAuthProvider — allows all)
//! - JSON-RPC messages framed as AAFP DATA frames
//!
//! Run with:
//! ```bash
//! cargo run --example mcp_over_aafp -p aafp-transport-mcp
//! ```

use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::AafpMcpTransport;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
    RawContent, RawTextContent, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, ServiceExt};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use std::sync::Arc;

/// A minimal MCP server with a single "echo" tool.
#[derive(Clone)]
struct EchoServer;

impl ServerHandler for EchoServer {
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        let tool = Tool::new(
            "echo",
            "Echoes back the input message",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back"
                    }
                },
                "required": ["message"]
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        );
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            next_cursor: None,
            tools: vec![tool],
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        let message = request
            .arguments
            .as_ref()
            .and_then(|args| args.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("(no message)");

        let content = rmcp::model::Content::new(
            RawContent::Text(RawTextContent {
                text: format!("Echo: {message}"),
                meta: None,
            }),
            None,
        );

        std::future::ready(Ok(CallToolResult::success(vec![content])))
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::default())
            .with_server_info(Implementation::new("aafp-echo-server", "0.1.0"))
            .with_instructions("A simple echo server over AAFP")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!("=== MCP over AAFP Example ===\n");

    // 1. Create server agent
    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec!["mcp-server".into()])
            .bind("127.0.0.1:0".parse()?)
            .build()
            .await?,
    );
    let server_addr = format!("quic://{}", server_agent.transport.local_addr()?);
    println!("Server agent listening on: {server_addr}");

    // 2. Spawn server task: accept AAFP connection, serve MCP
    let server_handle = tokio::spawn(async move {
        println!("[server] Waiting for AAFP connection...");

        let transport = AafpMcpTransport::accept(&server_agent)
            .await
            .expect("server accept");

        println!("[server] AAFP handshake complete, starting MCP server...");

        // Serve the MCP server over the AAFP transport
        let server = EchoServer;
        let running = server.serve(transport).await.expect("server serve");

        println!("[server] MCP server initialized, waiting for tool calls...");

        // Wait for the client to finish
        let quit_reason = running.waiting().await;
        println!("[server] Quit: {quit_reason:?}");
    });

    // 3. Create client agent
    let client_agent = AgentBuilder::new()
        .with_capabilities(vec!["mcp-client".into()])
        .bind("127.0.0.1:0".parse()?)
        .build()
        .await?;

    println!("Client agent created, connecting to server...");

    // 4. Connect via AAFP transport
    let transport = AafpMcpTransport::connect(&client_agent, &server_addr).await?;
    println!("AAFP handshake complete, starting MCP client...");

    // 5. Serve the MCP client over the AAFP transport
    // The client service is `()` — an empty handler that accepts server notifications.
    let client_service = ().serve(transport).await?;
    println!("MCP client initialized!\n");

    // 6. List tools
    println!("--- Listing tools ---");
    let tools = client_service.list_all_tools().await?;
    for tool in &tools {
        println!(
            "  Tool: {} — {}",
            tool.name,
            tool.description.as_deref().unwrap_or("")
        );
    }

    // 7. Call the echo tool
    println!("\n--- Calling echo tool ---");
    let params = CallToolRequestParams::new("echo").with_arguments(
        serde_json::json!({"message": "Hello from AAFP!"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    let result = client_service.call_tool(params).await?;

    for content in &result.content {
        if let RawContent::Text(text) = &**content {
            println!("  Result: {}", text.text);
        }
    }

    // 8. Cleanup
    println!("\nClosing connection...");
    let _ = client_service.cancel().await;
    server_handle.await?;

    println!("\n=== Example complete! ===");
    Ok(())
}
