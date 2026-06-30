use aafp_identity::{agent_id_to_hex, AgentKeypair};

pub async fn run(identity: &str) -> anyhow::Result<()> {
    if !std::path::Path::new(identity).exists() {
        anyhow::bail!(
            "Identity file not found: {}. Run 'aafp init' first.",
            identity
        );
    }

    let data = std::fs::read(identity)?;
    let keypair = AgentKeypair::from_bytes_full(&data)?;
    let agent_id = aafp_identity::derive_agent_id(&keypair.public_key);

    println!("=== AAFP Agent Status ===");
    println!("Identity file: {}", identity);
    println!("Agent ID: {}", agent_id_to_hex(&agent_id));
    println!(
        "Agent ID (short): {}",
        aafp_identity::agent_id_short(&agent_id)
    );
    println!("Public key: {} bytes (ML-DSA-65)", keypair.public_key.len());
    println!("Secret key: {} bytes (ML-DSA-65)", keypair.secret_key.len());

    // Verify keypair works.
    let msg = b"status check";
    let sig = keypair.sign(msg);
    let valid = keypair.verify(msg, &sig);
    println!(
        "Keypair verification: {}",
        if valid { "PASS" } else { "FAIL" }
    );

    Ok(())
}
