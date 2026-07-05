//! Shared utilities for CLI commands.

use aafp_identity::{agent_id_short, AgentKeypair};
use colored::Colorize;

/// Load a keypair from file, or generate and save a new one.
pub fn load_or_generate_keypair(identity_path: &str) -> anyhow::Result<AgentKeypair> {
    if std::path::Path::new(identity_path).exists() {
        let data = std::fs::read(identity_path)?;
        let kp = AgentKeypair::from_bytes_full(&data)?;
        let id = aafp_identity::derive_agent_id(&kp.public_key);
        eprintln!(
            "{} identity from {} (agent: {})",
            "→".dimmed(),
            identity_path,
            agent_id_short(&id).cyan()
        );
        Ok(kp)
    } else {
        eprintln!("{} generating new identity...", "→".dimmed());
        let kp = AgentKeypair::generate();
        let id = aafp_identity::derive_agent_id(&kp.public_key);
        std::fs::write(identity_path, kp.to_bytes())?;
        eprintln!(
            "{} saved to {} (agent: {})",
            "✓".green(),
            identity_path,
            agent_id_short(&id).cyan()
        );
        Ok(kp)
    }
}

/// Print an error message in red.
pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg.red());
}

/// Print a success message in green.
#[allow(dead_code)]
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg.green());
}

/// Print a warning message in yellow.
pub fn print_warning(msg: &str) {
    println!("{} {}", "!".yellow().bold(), msg.yellow());
}

/// Print an info message with a cyan arrow.
#[allow(dead_code)]
pub fn print_info(msg: &str) {
    println!("{} {}", "→".cyan(), msg);
}
