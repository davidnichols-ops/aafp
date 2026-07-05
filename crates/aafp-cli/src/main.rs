//! AAFP CLI: command-line tool for agent management.
//!
//! Provides commands for key generation, agent creation, and testing.

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "aafp")]
#[command(about = "AAFP: Agent-Agent First Networking Protocol CLI")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new agent identity
    Init {
        #[arg(long, default_value = "aafp-identity.bin")]
        output: String,
        #[arg(long, value_delimiter = ',')]
        capabilities: Option<Vec<String>>,
    },
    /// Start an agent node
    Start {
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
        #[arg(long, default_value = "127.0.0.1:4433")]
        bind: String,
        #[arg(long, value_delimiter = ',')]
        seeds: Option<Vec<String>>,
    },
    /// Discover agents by capability
    Discover {
        #[arg(long)]
        capability: String,
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Connect to a peer
    Connect {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Send a message to a peer
    Send {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        message: String,
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Show agent status
    Status {
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Start a relay node
    Relay {
        #[arg(long, default_value = "127.0.0.1:4434")]
        bind: String,
    },
    /// Serve an agent with a capability (one-command startup)
    Serve {
        #[arg(long)]
        capability: Vec<String>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Call an agent by capability
    Call {
        capability: String,
        message: String,
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
        #[arg(long)]
        json: bool,
    },
    /// List discovered peers
    Peers {
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Show agent metrics
    Metrics {
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Show health status
    Health {
        #[arg(long, default_value = "aafp-identity.bin")]
        identity: String,
    },
    /// Interactive quickstart wizard
    Quickstart,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            output,
            capabilities,
        } => {
            commands::init::run(&output, capabilities).await?;
        }
        Commands::Start {
            identity,
            bind,
            seeds,
        } => {
            commands::start::run(&identity, &bind, seeds).await?;
        }
        Commands::Discover {
            capability,
            identity,
        } => {
            commands::discover::run(&capability, &identity).await?;
        }
        Commands::Connect { addr, identity } => {
            commands::connect::run(&addr, &identity).await?;
        }
        Commands::Send {
            addr,
            message,
            identity,
        } => {
            commands::send::run(&addr, &message, &identity).await?;
        }
        Commands::Status { identity } => {
            commands::status::run(&identity).await?;
        }
        Commands::Relay { bind } => {
            commands::relay::run(&bind).await?;
        }
        Commands::Serve {
            capability,
            bind,
            identity,
        } => {
            commands::serve::run(&capability, &bind, &identity).await?;
        }
        Commands::Call {
            capability,
            message,
            identity,
            json,
        } => {
            commands::call::run(&capability, &message, &identity, json).await?;
        }
        Commands::Peers { identity } => {
            commands::peers::run(&identity).await?;
        }
        Commands::Metrics { identity } => {
            commands::metrics::run(&identity).await?;
        }
        Commands::Health { identity } => {
            commands::health::run(&identity).await?;
        }
        Commands::Quickstart => {
            commands::quickstart::run().await?;
        }
    }

    Ok(())
}
