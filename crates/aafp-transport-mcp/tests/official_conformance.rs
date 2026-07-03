//! MCP Conformance Tests based on the official MCP specification.
//!
//! These tests verify that AAFP's MCP transport binding meets the
//! conformance requirements from the MCP specification
//! (https://modelcontextprotocol.io/specification).
//!
//! The official `@modelcontextprotocol/conformance` suite only supports
//! HTTP/stdio transports and cannot directly test QUIC-based transports.
//! These tests replicate the conformance requirements using the rmcp
//! Rust SDK's client/server APIs over the AAFP QUIC transport.
//!
//! Conformance areas covered:
//! 1. Transport: connect, send, receive, close
//! 2. Initialize handshake (client→server, server responds with capabilities)
//! 3. tools/list — returns list of tools
//! 4. tools/call — executes a tool and returns results
//! 5. resources/list + resources/read — resource operations
//! 6. Ping (JSON-RPC level) — round-trip latency check
//! 7. Graceful close — clean shutdown without errors
//! 8. Error handling — invalid tool name returns error
//! 9. Server info — correct server name and version
//! 10. Multiple sequential operations
//! 11. Large tool result transmission

use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::AafpMcpTransport;
use rmcp::model::{
    CallToolRequestParams, ClientRequest, Content, Implementation, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, PingRequest, RawContent, RawTextContent,
    ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::service::{RequestContext, ServiceExt};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use std::sync::Arc;

/// A conformance test server with tools and resources.
#[derive(Clone)]
struct ConformanceServer;

impl ServerHandler for ConformanceServer {
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        let echo_tool = Tool::new(
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
            tools: vec![echo_tool],
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::CallToolResult, ErrorData>> + Send + '_
    {
        if &*request.name == "echo" {
            let message = request
                .arguments
                .as_ref()
                .and_then(|args| args.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("(no message)");
            let content = Content::new(
                RawContent::Text(RawTextContent {
                    text: format!("Echo: {message}"),
                    meta: None,
                }),
                None,
            );
            std::future::ready(Ok(rmcp::model::CallToolResult::success(vec![content])))
        } else {
            std::future::ready(Err(ErrorData::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                format!("Unknown tool: {}", request.name),
                None,
            )))
        }
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, ErrorData>> + Send + '_ {
        let raw = rmcp::model::RawResource::new("test://conformance/hello", "Hello Resource")
            .with_description("A test resource for conformance testing")
            .with_mime_type("text/plain");
        let resource = Resource::new(raw, None);
        std::future::ready(Ok(ListResourcesResult {
            meta: None,
            next_cursor: None,
            resources: vec![resource],
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, ErrorData>> + Send + '_ {
        if &*request.uri == "test://conformance/hello" {
            std::future::ready(Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: "test://conformance/hello".to_string(),
                    mime_type: Some("text/plain".to_string()),
                    text: "Hello, conformance world!".to_string(),
                    meta: None,
                },
            ])))
        } else {
            std::future::ready(Err(ErrorData::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                format!("Unknown resource: {}", request.uri),
                None,
            )))
        }
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::default())
            .with_server_info(Implementation::new("aafp-conformance-server", "1.0.0"))
            .with_instructions("Conformance test server over AAFP")
    }
}

/// Helper: set up a server and client, return the client service.
async fn setup_server_and_client() -> (
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
) {
    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec!["mcp-server".into()])
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap(),
    );
    let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let server_handle = tokio::spawn(async move {
        let transport = AafpMcpTransport::accept(&server_agent).await.unwrap();
        let server = ConformanceServer;
        let running = server.serve(transport).await.unwrap();
        let _ = running.waiting().await;
    });

    let client_agent = AgentBuilder::new()
        .with_capabilities(vec!["mcp-client".into()])
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let transport = AafpMcpTransport::connect(&client_agent, &addr)
        .await
        .unwrap();

    let client_service = ().serve(transport).await.unwrap();

    (client_service, server_handle)
}

// ===========================================================================
// 1. Transport Conformance: connect
// ===========================================================================

#[tokio::test]
async fn conf_transport_connect() {
    // Conformance: transport MUST establish a connection
    let (client_service, server_handle) = setup_server_and_client().await;
    assert!(!client_service.is_closed(), "client should be connected");

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 2. Initialize Handshake
// ===========================================================================

#[tokio::test]
async fn conf_initialize_handshake() {
    // Conformance: client MUST send initialize, server MUST respond with
    // server info and capabilities
    let (client_service, server_handle) = setup_server_and_client().await;

    // The serve() call already performed the initialize handshake.
    // Verify server info is available via peer_info().
    let peer_info = client_service.peer_info();
    assert!(
        peer_info.is_some(),
        "server info should be available after init"
    );

    let info = peer_info.unwrap();
    assert_eq!(
        info.server_info.name, "aafp-conformance-server",
        "server name should match"
    );
    assert_eq!(
        info.server_info.version, "1.0.0",
        "server version should match"
    );

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 3. tools/list
// ===========================================================================

#[tokio::test]
async fn conf_tools_list() {
    // Conformance: tools/list MUST return a list of tools
    let (client_service, server_handle) = setup_server_and_client().await;

    let tools = client_service.list_all_tools().await.unwrap();
    assert!(!tools.is_empty(), "should have at least one tool");
    assert_eq!(tools[0].name, "echo", "tool name should be 'echo'");
    assert!(
        tools[0].description.is_some(),
        "tool should have a description"
    );

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 4. tools/call
// ===========================================================================

#[tokio::test]
async fn conf_tools_call() {
    // Conformance: tools/call MUST execute a tool and return results
    let (client_service, server_handle) = setup_server_and_client().await;

    let params = CallToolRequestParams::new("echo").with_arguments(
        serde_json::json!({"message": "conformance test"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    let result = client_service.call_tool(params).await.unwrap();

    assert!(!result.content.is_empty(), "should have content");
    if let RawContent::Text(text) = &*result.content[0] {
        assert_eq!(text.text, "Echo: conformance test");
    } else {
        panic!("expected text content");
    }

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 5. resources/list + resources/read
// ===========================================================================

#[tokio::test]
async fn conf_resources_list_and_read() {
    // Conformance: resources/list MUST return resources, resources/read
    // MUST return resource contents
    let (client_service, server_handle) = setup_server_and_client().await;

    let resources = client_service.list_all_resources().await.unwrap();
    assert!(!resources.is_empty(), "should have at least one resource");
    assert_eq!(&resources[0].uri, "test://conformance/hello");
    assert_eq!(resources[0].name, "Hello Resource");

    let read_result = client_service
        .read_resource(ReadResourceRequestParams::new(
            "test://conformance/hello".to_string(),
        ))
        .await
        .unwrap();

    assert!(!read_result.contents.is_empty(), "should have content");
    if let ResourceContents::TextResourceContents { text, .. } = &read_result.contents[0] {
        assert_eq!(text, "Hello, conformance world!");
    } else {
        panic!("expected text resource contents");
    }

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 6. Ping (JSON-RPC level)
// ===========================================================================

#[tokio::test]
async fn conf_ping_roundtrip() {
    // Conformance: ping MUST return a response (JSON-RPC level ping, not AAFP)
    let (client_service, server_handle) = setup_server_and_client().await;

    // Send a JSON-RPC ping request via the peer's send_request method
    let result = client_service
        .peer()
        .send_request(ClientRequest::PingRequest(PingRequest::default()))
        .await;
    assert!(result.is_ok(), "ping should succeed: {:?}", result.err());

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 7. Error Handling: invalid tool name
// ===========================================================================

#[tokio::test]
async fn conf_error_invalid_tool() {
    // Conformance: calling a non-existent tool MUST return an error
    let (client_service, server_handle) = setup_server_and_client().await;

    let params = CallToolRequestParams::new("nonexistent_tool");
    let result = client_service.call_tool(params).await;

    assert!(result.is_err(), "should return error for unknown tool");

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 8. Graceful Close
// ===========================================================================

#[tokio::test]
async fn conf_graceful_close() {
    // Conformance: closing the connection MUST be clean (no panic, no hang)
    let (client_service, server_handle) = setup_server_and_client().await;

    // Perform some operations first
    let _ = client_service.list_all_tools().await.unwrap();

    // Graceful close
    let cancel_result = client_service.cancel().await;
    assert!(cancel_result.is_ok(), "cancel should succeed");

    // Server should terminate cleanly
    let server_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), server_handle).await;
    assert!(server_result.is_ok(), "server should terminate within 10s");
}

// ===========================================================================
// 9. Multiple operations in sequence
// ===========================================================================

#[tokio::test]
async fn conf_sequential_operations() {
    // Conformance: multiple operations in sequence MUST all succeed
    let (client_service, server_handle) = setup_server_and_client().await;

    // 1. List tools
    let tools = client_service.list_all_tools().await.unwrap();
    assert!(!tools.is_empty());

    // 2. Call tool
    let params = CallToolRequestParams::new("echo").with_arguments(
        serde_json::json!({"message": "first"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    let result1 = client_service.call_tool(params).await.unwrap();
    assert!(!result1.content.is_empty());

    // 3. List resources
    let resources = client_service.list_all_resources().await.unwrap();
    assert!(!resources.is_empty());

    // 4. Read resource
    let read_result = client_service
        .read_resource(ReadResourceRequestParams::new(
            "test://conformance/hello".to_string(),
        ))
        .await
        .unwrap();
    assert!(!read_result.contents.is_empty());

    // 5. Call tool again
    let params2 = CallToolRequestParams::new("echo").with_arguments(
        serde_json::json!({"message": "second"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    let result2 = client_service.call_tool(params2).await.unwrap();
    assert!(!result2.content.is_empty());

    // 6. Ping
    let ping_result = client_service
        .peer()
        .send_request(ClientRequest::PingRequest(PingRequest::default()))
        .await;
    assert!(ping_result.is_ok());

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}

// ===========================================================================
// 10. Large tool result
// ===========================================================================

#[tokio::test]
async fn conf_large_tool_result() {
    // Conformance: large results MUST be transmitted correctly
    let (client_service, server_handle) = setup_server_and_client().await;

    let large_message = "x".repeat(50_000);
    let params = CallToolRequestParams::new("echo").with_arguments(
        serde_json::json!({"message": large_message})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    let result = client_service.call_tool(params).await.unwrap();

    assert!(!result.content.is_empty());
    if let RawContent::Text(text) = &*result.content[0] {
        assert!(text.text.starts_with("Echo: "));
        assert_eq!(text.text.len(), "Echo: ".len() + 50_000);
    } else {
        panic!("expected text content");
    }

    let _ = client_service.cancel().await;
    server_handle.await.unwrap();
}
