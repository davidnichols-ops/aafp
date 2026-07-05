use aafp_sdk::simple::{Agent, Request};
use colored::Colorize;

pub async fn run(
    capability: &str,
    message: &str,
    identity: &str,
    json: bool,
    addr: Option<&str>,
) -> anyhow::Result<()> {
    let keypair = crate::commands::util::load_or_generate_keypair(identity)?;

    let agent = Agent::connect().with_keypair(keypair).connect().await?;

    // If --addr is provided, call directly without discovery
    let result = if let Some(addr) = addr {
        if !json {
            eprintln!("{} calling agent at {}...", "→".dimmed(), addr.yellow());
        }
        agent.call_at(addr, Request::text(message)).await
    } else {
        if !json {
            eprintln!(
                "{} discovering agents with capability '{}'...",
                "→".dimmed(),
                capability.cyan()
            );
        }
        agent
            .discover(capability)
            .call(Request::text(message))
            .await
    };

    match result {
        Ok(response) => {
            if json {
                let output = serde_json::json!({
                    "capability": capability,
                    "request": message,
                    "response": response.body(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", response.body());
            }
            Ok(())
        }
        Err(e) => {
            if !json {
                if addr.is_some() {
                    crate::commands::util::print_error(&format!(
                        "Failed to call agent at {}",
                        addr.unwrap().yellow()
                    ));
                    eprintln!("  {} {}", "detail:".dimmed(), e.to_string().dimmed());
                } else {
                    crate::commands::util::print_error(&format!(
                        "No agents with capability '{}' found.\n  \
                         Run `aafp serve --capability {}` in another terminal,\n  \
                         or use --addr to call a specific address.",
                        capability.cyan(),
                        capability
                    ));
                    eprintln!("  {} {}", "detail:".dimmed(), e.to_string().dimmed());
                }
            } else {
                let output = serde_json::json!({
                    "error": e.to_string(),
                    "capability": capability,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            std::process::exit(1);
        }
    }
}
