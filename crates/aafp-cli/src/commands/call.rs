use aafp_sdk::simple::{Agent, Request};
use colored::Colorize;

pub async fn run(
    capability: &str,
    message: &str,
    identity: &str,
    json: bool,
) -> anyhow::Result<()> {
    let keypair = crate::commands::util::load_or_generate_keypair(identity)?;

    let agent = Agent::connect().with_keypair(keypair).connect().await?;

    if !json {
        eprintln!(
            "{} discovering agents with capability '{}'...",
            "→".dimmed(),
            capability.cyan()
        );
    }

    // Try to discover and call
    let result = agent
        .discover(capability)
        .call(Request::text(message))
        .await;

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
                crate::commands::util::print_error(&format!(
                    "No agents with capability '{}' found. Is an agent serving on this network?\n  \
                     Run `aafp serve --capability {}` in another terminal.",
                    capability.cyan(),
                    capability
                ));
                eprintln!("  {} {}", "detail:".dimmed(), e.to_string().dimmed());
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
