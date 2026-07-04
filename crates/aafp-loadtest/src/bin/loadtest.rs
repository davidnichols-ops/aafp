//! CLI binary for running AAFP load tests (Track S1).
//!
//! Usage:
//! ```bash
//! cargo run --features cli --bin loadtest -- --agents 100 --messages 1000 --size 1024 --topology star
//! ```

use aafp_loadtest::{run_load_test, LoadTestConfig, Topology};
use clap::{Parser, ValueEnum};
use std::time::Duration;

#[derive(Clone, Debug, ValueEnum)]
enum CliTopology {
    Mesh,
    Star,
    Ring,
    Random,
}

impl From<CliTopology> for Topology {
    fn from(t: CliTopology) -> Self {
        match t {
            CliTopology::Mesh => Self::Mesh,
            CliTopology::Star => Self::Star,
            CliTopology::Ring => Self::Ring,
            CliTopology::Random => Self::Random,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "loadtest", about = "AAFP load testing tool (Track S)")]
struct Args {
    /// Number of agents.
    #[arg(long, default_value_t = 10)]
    agents: usize,

    /// Messages per agent per edge.
    #[arg(long, default_value_t = 100)]
    messages: usize,

    /// Message size in bytes.
    #[arg(long, default_value_t = 1024)]
    size: usize,

    /// Test duration in seconds.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Network topology.
    #[arg(long, value_enum, default_value_t = CliTopology::Mesh)]
    topology: CliTopology,

    /// Max connections per agent (mesh topology).
    #[arg(long, default_value_t = 10)]
    max_conn: usize,

    /// Random degree (random topology).
    #[arg(long, default_value_t = 5)]
    degree: usize,

    /// Concurrency (in-flight messages per agent).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Output JSON file path (default: stdout).
    #[arg(long)]
    output: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();

    let config = LoadTestConfig {
        num_agents: args.agents,
        messages_per_agent: args.messages,
        message_size: args.size,
        duration: Duration::from_secs(args.duration),
        topology: args.topology.into(),
        max_connections_per_agent: args.max_conn,
        random_degree: args.degree,
        concurrency: args.concurrency,
    };

    println!(
        "Running load test: {} agents, {} topology, {} messages/agent, {} bytes",
        config.num_agents, config.topology, config.messages_per_agent, config.message_size
    );

    let metrics = run_load_test(&config).await;
    metrics.print_summary();

    let json = metrics.to_json().unwrap();

    if let Some(path) = args.output {
        std::fs::write(&path, &json).expect("failed to write output file");
        println!("Results written to {}", path);
    } else {
        println!("\n{}", json);
    }
}
