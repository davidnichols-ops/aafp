//! MCP server over AAFP — a standalone server for interop testing.
//!
//! This example creates an AAFP server agent that hosts a simple MCP server
//! with an "echo" tool, and stays running until killed. It is used by the
//! Python MCP SDK interop test (`test_mcp_sdk_interop.py`) and other
//! cross-SDK interop tests that need a long-lived Rust MCP server.
//!
//! Run with:
//! ```bash
//! cargo run --example mcp_server -p aafp-transport-mcp
//! ```
//!
//! The server prints `Server agent listening on: quic://127.0.0.1:PORT`
//! once it is ready to accept connections, then accepts connections in a
//! loop. Each connection is served independently with the echo tool.

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

    // 2. Accept connections in a loop
    loop {
        eprintln!("[server] Waiting for AAFP connection...");

        let transport = match AafpMcpTransport::accept(&server_agent).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[server] Accept error: {e}");
                continue;
            }
        };

        eprintln!("[server] AAFP handshake complete, starting MCP server...");

        let server = EchoServer;
        let running = match server.serve(transport).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[server] Serve error: {e}");
                continue;
            }
        };

        eprintln!("[server] MCP server initialized, serving tool calls...");

        // Wait for this connection to finish, then accept the next one
        let quit_reason = running.waiting().await;
        eprintln!("[server] Connection ended: {quit_reason:?}");
    }
}
