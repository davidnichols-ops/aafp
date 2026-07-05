use aafp_sdk::AgentBuilder;
use colored::Colorize;

pub async fn run(identity: &str) -> anyhow::Result<()> {
    let keypair = crate::commands::util::load_or_generate_keypair(identity)?;

    let agent = AgentBuilder::new().with_keypair(keypair).build().await?;

    let metrics = agent.metrics();
    let health = agent.health_check();
    let agent_id = agent.id();

    println!();
    println!("{}", "  AAFP Agent Metrics  ".bold().on_blue().white());
    println!();
    println!("  {}", "=".repeat(40).dimmed());
    println!(
        "  {:<16} {}",
        "Agent ID:".dimmed(),
        aafp_identity::agent_id_short(agent_id).cyan().bold()
    );

    let health_colored = match health {
        aafp_sdk::HealthStatus::Healthy => "Healthy".green().bold().to_string(),
        aafp_sdk::HealthStatus::Degraded => "Degraded".yellow().bold().to_string(),
        aafp_sdk::HealthStatus::Unhealthy => "Unhealthy".red().bold().to_string(),
    };
    println!("  {:<16} {}", "Status:".dimmed(), health_colored);
    println!("  {:<16} {}s", "Uptime:".dimmed(), metrics.uptime_seconds);
    println!(
        "  {:<16} {} active ({} total)",
        "Connections:".dimmed(),
        metrics.connections_active,
        metrics.connections_total
    );
    println!(
        "  {:<16} {} sent, {} received",
        "Messages:".dimmed(),
        metrics.messages_sent,
        metrics.messages_received
    );
    println!(
        "  {:<16} {} completed, {} failed",
        "Handshakes:".dimmed(),
        metrics.handshakes_completed,
        metrics.handshakes_failed
    );
    println!("  {:<16} {}", "DHT Records:".dimmed(), metrics.dht_records);
    println!(
        "  {:<16} {} sent, {} received",
        "Bytes:".dimmed(),
        metrics.bytes_sent,
        metrics.bytes_received
    );
    println!("  {}", "=".repeat(40).dimmed());
    println!();

    Ok(())
}
