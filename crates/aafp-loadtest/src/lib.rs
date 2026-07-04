//! AAFP Load Testing Harness (Track S).
//!
//! This crate provides infrastructure for load testing AAFP with many
//! concurrent agents. It supports multiple network topologies (mesh, star,
//! ring, random) and collects throughput, latency, and error metrics.
//!
//! ## Quick Start
//!
//! ```no_run
//! # use aafp_loadtest::{LoadTestConfig, Topology, run_load_test};
//! # let rt = tokio::runtime::Runtime::new().unwrap();
//! # rt.block_on(async {
//! let config = LoadTestConfig {
//!     num_agents: 10,
//!     messages_per_agent: 100,
//!     message_size: 1024,
//!     topology: Topology::Mesh,
//!     ..Default::default()
//! };
//! let metrics = run_load_test(&config).await;
//! metrics.print_summary();
//! # });
//! ```
//!
//! ## Topologies
//!
//! - **Mesh**: Every agent connects to every other (capped at
//!   `max_connections_per_agent` to avoid N² explosion).
//! - **Star**: All agents connect to a central hub (agent 0).
//! - **Ring**: Each agent connects to its neighbor (N edges).
//! - **Random**: Each agent connects to K random peers (deterministic).

pub mod config;
pub mod metrics;
pub mod runner;
pub mod topology;

pub use config::{LoadTestConfig, Topology};
pub use metrics::{ConfigSummary, LatencyStats, LoadTestMetrics, ResourceUsage};
pub use runner::run_load_test;
pub use topology::{generate_edges, Edge};
