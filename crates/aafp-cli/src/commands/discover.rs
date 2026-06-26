use aafp_sdk::AgentBuilder;
use aafp_identity::AgentKeypair;

pub async fn run(capability: &str, identity: &str) -> anyhow::Result<()> {
    let keypair = if std::path::Path::new(identity).exists() {
        let data = std::fs::read(identity)?;
        AgentKeypair::from_bytes_full(&data)?
    } else {
        anyhow::bail!("Identity file not found: {}. Run 'aafp init' first.", identity);
    };

    let agent = AgentBuilder::new()
        .with_keypair(keypair)
        .build()
        .await?;

    println!("Searching for agents with capability: {}", capability);

    let results = agent.find_by_capability(capability);
    if results.is_empty() {
        println!("No agents found with capability '{}'", capability);
    } else {
        println!("Found {} agent(s):", results.len());
        for record in results {
            let id_short = aafp_identity::agent_id_short(&record.agent_id);
            println!(
                "  - {} (caps: {:?}, endpoints: {:?})",
                id_short, record.capabilities, record.endpoints
            );
        }
    }

    Ok(())
}
