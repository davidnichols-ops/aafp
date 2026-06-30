use aafp_identity::AgentKeypair;
use aafp_sdk::{AgentBuilder, AgentClient};

pub async fn run(addr: &str, identity: &str) -> anyhow::Result<()> {
    let keypair = if std::path::Path::new(identity).exists() {
        let data = std::fs::read(identity)?;
        AgentKeypair::from_bytes_full(&data)?
    } else {
        anyhow::bail!(
            "Identity file not found: {}. Run 'aafp init' first.",
            identity
        );
    };

    let agent = AgentBuilder::new().with_keypair(keypair).build().await?;

    println!("Connecting to: {}", addr);

    let client = AgentClient::new();
    let peer_id = client.connect(&agent, addr).await?;

    println!(
        "Connected to peer: {}",
        aafp_identity::agent_id_to_hex(&peer_id)
    );
    println!("Active connections: {}", client.connection_count().await);

    Ok(())
}
