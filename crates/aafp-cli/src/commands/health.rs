use aafp_sdk::AgentBuilder;
use colored::Colorize;

pub async fn run(identity: &str) -> anyhow::Result<()> {
    let keypair = crate::commands::util::load_or_generate_keypair(identity)?;

    let agent = AgentBuilder::new().with_keypair(keypair).build().await?;
    let health = agent.health_check();
    let agent_id = agent.id();

    let (status_str, exit_code) = match health {
        aafp_sdk::HealthStatus::Healthy => ("Healthy".green().bold().to_string(), 0),
        aafp_sdk::HealthStatus::Degraded => ("Degraded".yellow().bold().to_string(), 1),
        aafp_sdk::HealthStatus::Unhealthy => ("Unhealthy".red().bold().to_string(), 2),
    };

    println!(
        "Agent {} is {}",
        aafp_identity::agent_id_short(agent_id).cyan(),
        status_str
    );

    std::process::exit(exit_code);
}
