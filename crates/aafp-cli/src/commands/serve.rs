use aafp_sdk::simple::{Agent, Request, Response};
use colored::Colorize;
use std::net::SocketAddr;

pub async fn run(capabilities: &[String], bind: &str, identity: &str) -> anyhow::Result<()> {
    if capabilities.is_empty() {
        crate::commands::util::print_error("at least one --capability is required");
        anyhow::bail!("no capabilities specified");
    }

    let keypair = crate::commands::util::load_or_generate_keypair(identity)?;
    let agent_id = aafp_identity::derive_agent_id(&keypair.public_key);
    let bind_addr: SocketAddr = bind.parse()?;

    // Build and start the serving agent with an echo handler
    let mut builder = Agent::serve().with_keypair(keypair).bind(bind_addr);

    for cap in capabilities {
        builder = builder.capability(cap.clone());
    }

    let serving = builder
        .handler(|req: Request| async move { Ok(Response::text(req.body().to_string())) })
        .start()
        .await?;

    // Print startup banner
    println!();
    println!("{}", "  AAFP Agent Serving  ".bold().on_green().black());
    println!();
    println!(
        "  {} {}",
        "Agent ID:".dimmed(),
        aafp_identity::agent_id_short(&agent_id).cyan().bold()
    );
    println!("  {} {}", "Address:".dimmed(), serving.addr().yellow());
    println!(
        "  {} {}",
        "Capabilities:".dimmed(),
        capabilities
            .iter()
            .map(|c| c.cyan().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
    println!("  {}", "Press Ctrl+C to stop.".dimmed());
    println!();

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!();
    println!("{} {}", "✓".green(), "Shutting down...".dimmed());
    serving.stop();

    Ok(())
}
