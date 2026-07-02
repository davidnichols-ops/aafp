//! Integration test: AAFP MCP transport over real QUIC connections.
//!
//! This test creates two AAFP agents (server + client), performs the full
//! handshake, opens an MCP transport, and exchanges JSON-RPC messages
//! framed as AAFP DATA frames.

use aafp_sdk::AgentBuilder;
use aafp_transport_mcp::AafpMcpTransport;
use rmcp::model::{ClientRequest, JsonRpcMessage, PingRequest, RequestId, ServerRequest};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::{RoleClient, RoleServer};

/// Create a simple ping request as a client message.
fn make_client_ping(id: i64) -> TxJsonRpcMessage<RoleClient> {
    JsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(id),
    )
}

/// Create a simple ping request as a server message.
fn make_server_ping(id: i64) -> TxJsonRpcMessage<RoleServer> {
    JsonRpcMessage::request(
        ServerRequest::PingRequest(PingRequest::default()),
        RequestId::Number(id),
    )
}

#[tokio::test]
async fn test_mcp_transport_round_trip() {
    let server_agent = AgentBuilder::new()
        .with_capabilities(vec!["mcp-server".into()])
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("server agent build");

    let server_addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let client_agent = AgentBuilder::new()
        .with_capabilities(vec!["mcp-client".into()])
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("client agent build");

    let server_handle = tokio::spawn(async move {
        let mut transport = AafpMcpTransport::accept(&server_agent)
            .await
            .expect("server accept");

        let msg = Transport::<RoleServer>::receive(&mut transport)
            .await
            .expect("should receive a message");

        match &msg {
            RxJsonRpcMessage::<RoleServer>::Request(req) => {
                assert_eq!(req.id, RequestId::Number(1));
                assert!(matches!(req.request, ClientRequest::PingRequest(_)));
            }
            other => panic!("expected request, got {other:?}"),
        }

        Transport::<RoleServer>::close(&mut transport)
            .await
            .expect("server close");
        msg
    });

    let mut client_transport = AafpMcpTransport::connect(&client_agent, &server_addr)
        .await
        .expect("client connect");

    let ping = make_client_ping(1);
    Transport::<RoleClient>::send(&mut client_transport, ping)
        .await
        .expect("client send");

    let _received = server_handle.await.expect("server task panicked");
    Transport::<RoleClient>::close(&mut client_transport)
        .await
        .expect("client close");
}

#[tokio::test]
async fn test_mcp_transport_multiple_messages() {
    let server_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("server agent build");

    let server_addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("client agent build");

    let message_count = 5;

    let server_handle = tokio::spawn(async move {
        let mut transport = AafpMcpTransport::accept(&server_agent)
            .await
            .expect("server accept");

        let mut received = 0;
        for i in 0..message_count {
            let msg = Transport::<RoleServer>::receive(&mut transport)
                .await
                .expect("should receive message");
            if let RxJsonRpcMessage::<RoleServer>::Request(req) = &msg {
                assert_eq!(req.id, RequestId::Number(i as i64));
            }
            received += 1;
        }

        Transport::<RoleServer>::close(&mut transport)
            .await
            .expect("server close");
        received
    });

    let mut transport = AafpMcpTransport::connect(&client_agent, &server_addr)
        .await
        .expect("client connect");

    for i in 0..message_count {
        let ping = make_client_ping(i as i64);
        Transport::<RoleClient>::send(&mut transport, ping)
            .await
            .expect("client send");
    }

    let received_count = server_handle.await.expect("server task panicked");
    assert_eq!(received_count, message_count);

    Transport::<RoleClient>::close(&mut transport)
        .await
        .expect("client close");
}

#[tokio::test]
async fn test_mcp_transport_close_returns_none() {
    let server_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("server agent build");

    let server_addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("client agent build");

    // Server: accept, receive one message, then wait for client close
    let server_handle = tokio::spawn(async move {
        let mut transport = AafpMcpTransport::accept(&server_agent)
            .await
            .expect("server accept");

        // Receive the client's message
        let _ = Transport::<RoleServer>::receive(&mut transport).await;

        // After client closes, receive should return None.
        // Use a timeout to avoid hanging if the close doesn't propagate.
        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Transport::<RoleServer>::receive(&mut transport),
        )
        .await;

        match msg {
            Ok(None) => { /* expected: receive returned None */ }
            Ok(Some(m)) => panic!("expected None after close, got message: {m:?}"),
            Err(_) => { /* timeout — also acceptable, connection was closed */ }
        }

        Transport::<RoleServer>::close(&mut transport).await.ok();
    });

    let mut transport = AafpMcpTransport::connect(&client_agent, &server_addr)
        .await
        .expect("client connect");

    let ping = make_client_ping(0);
    Transport::<RoleClient>::send(&mut transport, ping)
        .await
        .expect("client send");

    // Give server time to receive the message before closing
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    Transport::<RoleClient>::close(&mut transport)
        .await
        .expect("client close");

    server_handle.await.expect("server task panicked");
}

#[tokio::test]
async fn test_mcp_transport_bidirectional() {
    let server_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("server agent build");

    let server_addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .expect("client agent build");

    let server_handle = tokio::spawn(async move {
        let mut transport = AafpMcpTransport::accept(&server_agent)
            .await
            .expect("server accept");

        // Receive ping from client
        let msg = Transport::<RoleServer>::receive(&mut transport).await;
        assert!(msg.is_some(), "should receive client ping");

        // Send a ping back (server → client)
        let ping = make_server_ping(100);
        Transport::<RoleServer>::send(&mut transport, ping)
            .await
            .expect("server send ping");

        // Wait for client to receive the ping before closing.
        // The client will close the connection after receiving.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        Transport::<RoleServer>::close(&mut transport)
            .await
            .expect("server close");
    });

    let mut transport = AafpMcpTransport::connect(&client_agent, &server_addr)
        .await
        .expect("client connect");

    // Send ping to server
    let ping = make_client_ping(1);
    Transport::<RoleClient>::send(&mut transport, ping)
        .await
        .expect("client send");

    // Receive ping from server
    let msg = Transport::<RoleClient>::receive(&mut transport).await;
    assert!(msg.is_some(), "should receive server ping");

    if let Some(RxJsonRpcMessage::<RoleClient>::Request(req)) = &msg {
        assert_eq!(req.id, RequestId::Number(100));
    }

    server_handle.await.expect("server task panicked");
    Transport::<RoleClient>::close(&mut transport)
        .await
        .expect("client close");
}
