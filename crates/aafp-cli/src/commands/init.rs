use aafp_identity::{agent_id_to_hex, AgentKeypair};
use std::path::Path;

pub async fn run(output: &str, capabilities: Option<Vec<String>>) -> anyhow::Result<()> {
    println!("Generating new ML-DSA-65 keypair...");

    let keypair = AgentKeypair::generate();
    let agent_id = aafp_identity::derive_agent_id(&keypair.public_key);

    println!("Agent ID: {}", agent_id_to_hex(&agent_id));
    println!("Public key: {} bytes", keypair.public_key.len());
    println!("Secret key: {} bytes", keypair.secret_key.len());

    if let Some(caps) = &capabilities {
        println!("Capabilities: {}", caps.join(", "));
    }

    let bytes = keypair.to_bytes();
    std::fs::write(Path::new(output), &bytes)?;
    println!("Identity saved to: {}", output);

    Ok(())
}
