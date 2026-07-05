use aafp_sdk::simple::{Agent, Request, Response};
use colored::Colorize;
use std::io::{self, BufRead, Write};

pub async fn run() -> anyhow::Result<()> {
    println!();
    println!("{}", "  ╔═══════════════════════════════════════╗  ".bold());
    println!("{}", "  ║   Welcome to AAFP Quickstart Wizard!  ║  ".bold());
    println!("{}", "  ╚═══════════════════════════════════════╝  ".bold());
    println!();
    println!("{}", "Let's set up your first agent in 3 steps.".dimmed());
    println!();

    // Step 1: Generate identity
    println!(
        "{} {}",
        "Step 1/3".cyan().bold(),
        "Generating identity...".dimmed()
    );
    let keypair = aafp_identity::AgentKeypair::generate();
    let agent_id = aafp_identity::derive_agent_id(&keypair.public_key);
    let identity_path = "aafp-identity.bin";
    std::fs::write(identity_path, keypair.to_bytes())?;
    println!(
        "  {} Agent ID: {}",
        "✓".green(),
        aafp_identity::agent_id_short(&agent_id).cyan().bold()
    );
    println!("  {} Saved to: {}", "✓".green(), identity_path.yellow());
    println!();

    // Step 2: Ask for capability
    println!(
        "{} {}",
        "Step 2/3".cyan().bold(),
        "Choose a capability".dimmed()
    );
    print!("  What capability would you like to serve? (default: echo): ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    let capability = input.trim();
    let capability = if capability.is_empty() {
        "echo"
    } else {
        capability
    };

    println!(
        "  {} Will serve capability: {}",
        "✓".green(),
        capability.cyan()
    );
    println!();

    // Step 3: Start serving
    println!(
        "{} {}",
        "Step 3/3".cyan().bold(),
        "Starting agent...".dimmed()
    );

    let serving = Agent::serve()
        .with_keypair(keypair)
        .capability(capability)
        .handler(|req: Request| async move { Ok(Response::text(req.body().to_string())) })
        .start()
        .await?;

    println!();
    println!(
        "  {} Your agent is now {}!",
        "✓".green(),
        "serving".green().bold()
    );
    println!();
    println!("  {}", "Agent Details:".dimmed());
    println!(
        "    {} {}",
        "Agent ID:".dimmed(),
        aafp_identity::agent_id_short(&agent_id).cyan()
    );
    println!("    {} {}", "Address:".dimmed(), serving.addr().yellow());
    println!("    {} {}", "Capability:".dimmed(), capability.cyan());
    println!();
    println!("  {}", "Try it out:".bold());
    println!(
        "    {}",
        format!("aafp call {} \"hello\"", capability).yellow()
    );
    println!();
    println!("  {}", "Press Ctrl+C to stop.".dimmed());
    println!();

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!();
    println!("{} {}", "✓".green(), "Shutting down...".dimmed());
    serving.stop();

    println!();
    println!(
        "{}",
        "Thanks for trying AAFP! Your identity is saved in aafp-identity.bin.".dimmed()
    );

    Ok(())
}
