//! Basic AAFP agent example: create two agents, connect them, and exchange a message.

use aafp_messaging::encode_frame;
use aafp_sdk::{AgentBuilder, AgentClient};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create server agent with "echo" capability.
    let server_agent = Arc::new(
        AgentBuilder::new()
            .with_capabilities(vec!["echo".into()])
            .build()
            .await?,
    );
    let server_addr = server_agent.multiaddr()?;
    let server_id = *server_agent.id();

    println!("Server agent: {}", hex::encode(&server_id));
    println!("Server listening on: {}", server_addr);

    // Spawn server that accepts one connection and echoes.
    let server_handle = tokio::spawn(async move {
        let conn = server_agent.transport.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // Read framed message.
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await.unwrap();

        println!("Server received: {}", String::from_utf8_lossy(&payload));

        // Echo back.
        let resp_frame = aafp_messaging::Frame::data(0, payload.clone());
        let resp_bytes = encode_frame(&resp_frame).unwrap();
        send.write_all(&resp_bytes).await.unwrap();
        send.finish();

        // Keep connection alive so client can read.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    });

    // Create client agent.
    let client_agent = AgentBuilder::new()
        .with_capabilities(vec!["client".into()])
        .build()
        .await?;

    println!("Client agent: {}", hex::encode(client_agent.id()));

    // Connect to server and send a message using send_and_receive.
    let client = AgentClient::new();
    let peer_id = client.connect(&client_agent, &server_addr).await?;
    println!("Connected to peer: {}", hex::encode(&peer_id));

    // Send a message and get the echo response.
    let msg = b"Hello from AAFP agent!";
    let response = client.send_and_receive(&peer_id, msg).await?;
    println!("Sent: {}", String::from_utf8_lossy(msg));
    println!("Received echo: {}", String::from_utf8_lossy(&response));

    // Wait for server to finish.
    server_handle.await?;

    println!("Done!");
    Ok(())
}
