//! Execution Fabric — orchestrates fluid execution of task DAGs across the network.
//!
//! This module implements the execution fabric's plan and scheduler:
//! - [`plan::ExecutionPlan`] — a DAG of tasks with scheduling metadata,
//!   checkpointing, and CBOR serialization. This is distinct from
//!   `aafp_discovery::semantic::planner::ExecutionPlan` (the SCG planning
//!   domain). The fabric's plan carries scheduling metadata, resource
//!   requirements, and assignment state.
//! - [`scheduler::TaskScheduler`] — assigns tasks to the best available
//!   agents using the adaptive routing plane, with load balancing,
//!   dependency-aware scheduling, and failure recovery.

pub mod plan;
pub mod scheduler;

pub use plan::*;
pub use scheduler::*;
