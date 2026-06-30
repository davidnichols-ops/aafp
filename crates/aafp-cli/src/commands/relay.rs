use aafp_identity::AgentKeypair;
use aafp_sdk::AgentBuilder;
use std::net::SocketAddr;

pub async fn run(bind: &str) -> anyhow::Result<()> {
    let keypair = AgentKeypair::generate();
    let agent_id = aafp_identity::derive_agent_id(&keypair.public_key);

    println!("Starting relay node");
    println!("Agent ID: {}", aafp_identity::agent_id_to_hex(&agent_id));

    let bind_addr: SocketAddr = bind.parse()?;
    println!("Binding to: {}", bind_addr);

    let agent = AgentBuilder::new()
        .with_keypair(keypair)
        .bind(bind_addr)
        .as_relay()
        .build()
        .await?;

    let local_addr = agent.multiaddr()?;
    println!("Relay listening on: {}", local_addr);
    println!("Relay mode: enabled");

    let server = aafp_sdk::AgentServer::new();
    server.start(&agent).await?;

    println!("Relay started. Press Ctrl+C to stop.");

    loop {
        if let Err(e) = server.accept_one(&agent).await {
            tracing::warn!("Connection error: {}", e);
        }
    }
}
