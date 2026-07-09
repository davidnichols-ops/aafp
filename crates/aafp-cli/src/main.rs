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
        #[arg(long)]
        addr: Option<String>,
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
    /// Search the web (DuckDuckGo, free, no API key)
    Search {
        /// Search query
        query: String,
        /// Maximum results (default 10)
        #[arg(long, default_value = "10")]
        num: u32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Browse a web page (Firecrawl, requires FIRECRAWL_API_KEY)
    Browse {
        /// URL to browse
        url: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Read a PDF document (PyMuPDF, requires pymupdf installed)
    ReadPdf {
        /// Path to PDF file
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Python interpreter path (default: python3 or AAFP_PYTHON env)
        #[arg(long)]
        python: Option<String>,
    },
    /// Run OCR on an image (Tesseract, requires tesseract installed)
    Ocr {
        /// Path to image file (.png, .jpg, .webp, .tiff)
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Language hint (e.g. "eng", "fra")
        #[arg(long)]
        lang: Option<String>,
    },
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
            addr,
        } => {
            commands::call::run(&capability, &message, &identity, json, addr.as_deref()).await?;
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
        Commands::Search { query, num, json } => {
            commands::search::run(&query, num, json).await?;
        }
        Commands::Browse { url, json } => {
            commands::browse::run(&url, json).await?;
        }
        Commands::ReadPdf { path, json, python } => {
            commands::read_pdf::run(&path, json, python.as_deref()).await?;
        }
        Commands::Ocr { path, json, lang } => {
            commands::ocr::run(&path, json, lang.as_deref()).await?;
        }
    }

    Ok(())
}
