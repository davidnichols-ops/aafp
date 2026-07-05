//! Integration test for the 3-line developer API.
//!
//! Verifies that a developer can serve and call an agent without
//! understanding the AAFP protocol.

use aafp_sdk::simple::{Agent, Request, Response};

#[tokio::test]
async fn test_serve_and_call() {
    // Serve an echo agent
    let serving = Agent::serve()
        .capability("echo")
        .handler(|req: Request| async move { Ok(Response::text(format!("echo: {}", req.body()))) })
        .start()
        .await
        .expect("failed to start serving agent");

    // Give the server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect and register the server's record in the client's DHT
    let mut client = Agent::connect().connect().await.expect("connect failed");
    client
        .register(serving.record())
        .expect("failed to register server record");

    // Call the echo agent
    let result = client
        .discover("echo")
        .call(Request::text("hello"))
        .await
        .expect("call failed");

    assert_eq!(result.body(), "echo: hello");

    // Clean up
    serving.stop();
}

#[tokio::test]
async fn test_request_response_types() {
    let req = Request::text("hello");
    assert_eq!(req.body(), "hello");
    assert_eq!(req.payload(), None);

    let resp = Response::text("world");
    assert_eq!(resp.body(), "world");
    assert_eq!(resp.payload(), None);

    let req_data = Request::data(vec![1, 2, 3]);
    assert_eq!(req_data.payload(), Some(&[1u8, 2, 3][..]));
    assert_eq!(req_data.body(), "");

    let resp_data = Response::data(vec![4, 5, 6]);
    assert_eq!(resp_data.payload(), Some(&[4u8, 5, 6][..]));
    assert_eq!(resp_data.body(), "");
}

#[tokio::test]
async fn test_serving_agent_addr_and_id() {
    let serving = Agent::serve()
        .capability("test")
        .handler(|_req: Request| async move { Ok(Response::text("ok")) })
        .start()
        .await
        .expect("failed to start");

    // Should have a valid multiaddr
    let addr = serving.addr();
    assert!(
        addr.contains("127.0.0.1"),
        "addr should contain 127.0.0.1: {}",
        addr
    );

    // Should have a valid ID
    let id = serving.id();
    assert_eq!(id.len(), 32);

    serving.stop();
}

#[tokio::test]
async fn test_discover_no_agents() {
    let client = Agent::connect().connect().await.expect("connect failed");
    let result = client
        .discover("nonexistent")
        .call(Request::text("test"))
        .await;
    assert!(result.is_err(), "should error when no agents found");
}

#[tokio::test]
async fn test_binary_data_roundtrip() {
    // Serve an agent that echoes binary data
    let serving = Agent::serve()
        .capability("binary-echo")
        .handler(
            |req: Request| async move { Ok(Response::data(req.payload().unwrap_or(&[]).to_vec())) },
        )
        .start()
        .await
        .expect("failed to start");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut client = Agent::connect().connect().await.expect("connect failed");
    client
        .register(serving.record())
        .expect("failed to register");

    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let result = client
        .discover("binary-echo")
        .call(Request::data(data.clone()))
        .await
        .expect("call failed");

    assert_eq!(result.payload(), Some(&data[..]));

    serving.stop();
}
