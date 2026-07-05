#![allow(deprecated)]

use aafp_sdk::AgentBuilder;
use colored::Colorize;

pub async fn run(identity: &str) -> anyhow::Result<()> {
    let keypair = crate::commands::util::load_or_generate_keypair(identity)?;

    let agent = AgentBuilder::new().with_keypair(keypair).build().await?;

    let discovered = agent.discovered_agents();

    if discovered.is_empty() {
        crate::commands::util::print_warning(
            "No peers discovered. Try running `aafp serve` on another node.",
        );
        return Ok(());
    }

    println!();
    println!("{}", "  Discovered Peers  ".bold().on_cyan().black());
    println!();
    println!(
        "  {:<16} {:<20} {:<30} {}",
        "Agent ID".dimmed(),
        "Capabilities".dimmed(),
        "Multiaddr".dimmed(),
        "NAT Status".dimmed()
    );
    println!("  {}", "-".repeat(90).dimmed());

    for record in discovered {
        let id_short = aafp_identity::agent_id_short(&record.agent_id);
        let caps = record.capabilities.join(", ");
        let addr = record.endpoints.first().cloned().unwrap_or_default();

        println!(
            "  {:<16} {:<20} {:<30} {}",
            id_short.cyan(),
            caps.green(),
            addr.yellow(),
            "Unknown".dimmed()
        );
    }
    println!();

    Ok(())
}
