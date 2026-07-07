//! Execution Fabric — orchestrates fluid execution of task DAGs across the network.
//!
//! This module implements the execution fabric's plan, scheduler,
//! checkpoint manager, and migration manager:
//! - [`plan::ExecutionPlan`] — a DAG of tasks with scheduling metadata,
//!   checkpointing, and CBOR serialization. This is distinct from
//!   `aafp_discovery::semantic::planner::ExecutionPlan` (the SCG planning
//!   domain). The fabric's plan carries scheduling metadata, resource
//!   requirements, and assignment state.
//! - [`scheduler::TaskScheduler`] — assigns tasks to the best available
//!   agents using the adaptive routing plane, with load balancing,
//!   dependency-aware scheduling, and failure recovery.
//! - [`checkpoint::CheckpointManager`] — saves and restores execution plan
//!   state to disk for crash recovery and resumption, with configurable
//!   retention policies.
//! - [`migration::MigrationManager`] — migrates execution plan and
//!   checkpoint state between schema versions, supporting multi-step
//!   version chains.

pub mod checkpoint;
pub mod migration;
pub mod plan;
pub mod scheduler;

pub use checkpoint::*;
pub use migration::*;
pub use plan::*;
pub use scheduler::*;
