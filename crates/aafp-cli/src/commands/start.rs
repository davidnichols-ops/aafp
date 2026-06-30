use aafp_identity::AgentKeypair;
use aafp_sdk::AgentBuilder;
use std::net::SocketAddr;

pub async fn run(identity: &str, bind: &str, seeds: Option<Vec<String>>) -> anyhow::Result<()> {
    // Load or generate keypair.
    let keypair = if std::path::Path::new(identity).exists() {
        let data = std::fs::read(identity)?;
        AgentKeypair::from_bytes_full(&data)?
    } else {
        println!("Identity file not found, generating new keypair...");
        let kp = AgentKeypair::generate();
        std::fs::write(identity, kp.to_bytes())?;
        kp
    };

    let agent_id = aafp_identity::derive_agent_id(&keypair.public_key);
    println!("Agent ID: {}", aafp_identity::agent_id_to_hex(&agent_id));

    let bind_addr: SocketAddr = bind.parse()?;
    println!("Binding to: {}", bind_addr);

    let mut builder = AgentBuilder::new().with_keypair(keypair).bind(bind_addr);

    if let Some(seeds) = seeds {
        builder = builder.with_seeds(seeds);
    }

    let agent = builder.build().await?;
    let local_addr = agent.multiaddr()?;
    println!("Listening on: {}", local_addr);
    println!("Capabilities: {:?}", agent.capabilities());
    println!("NAT status: {}", agent.nat_status());

    // Start server.
    let server = aafp_sdk::AgentServer::new();
    server.start(&agent).await?;

    println!("Agent started. Press Ctrl+C to stop.");

    // Accept connections in a loop.
    loop {
        if let Err(e) = server.accept_one(&agent).await {
            tracing::warn!("Connection error: {}", e);
        }
    }
}
