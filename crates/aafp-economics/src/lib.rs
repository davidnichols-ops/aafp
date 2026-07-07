//! AAFP Economics Layer — resource accounting, pricing, priority queuing, and
//! compensation (Phase 4, Tracks X1-X4).
//!
//! This crate provides four complementary subsystems for the Intelligence
//! Plane:
//!
//! - **[`account`]** — `ResourceAccount` tracks per-agent resource consumption
//!   (CPU, memory, storage, network, API calls, inference tokens) with debit,
//!   credit, transfer, and configurable per-agent limits.
//! - **[`pricing`]** — `PricingEngine` computes task costs from measured or
//!   estimated resource usage using fixed, per-unit, tiered, or dynamic pricing
//!   models. Costs are expressed in the abstract unit "credits".
//! - **[`priority`]** — `PriorityQueue` orders pending tasks by a composite
//!   score derived from urgency, cost, resource availability, and agent
//!   reputation. Supports priority bands, temporary boosts/degradation, and
//!   aging to prevent starvation.
//! - **[`compensation`]** — `CompensationProtocol` manages refund and
//!   compensation requests with auto-approval thresholds, batch processing,
//!   dispute resolution, and integration with `ResourceAccount`.
//!
//! All persistent structures encode to canonical CBOR int-keyed maps (RFC-0002
//! §8) via [`aafp_cbor`]. The crate is self-contained and depends only on
//! `aafp-cbor` and `sha2`.

pub mod account;
pub mod compensation;
pub mod pricing;
pub mod priority;

pub use account::*;
pub use compensation::*;
pub use pricing::*;
pub use priority::*;

use thiserror::Error;

/// Errors produced by the economics layer.
#[derive(Debug, Error)]
pub enum EconomicsError {
    /// A CBOR value could not be decoded into the expected structure.
    #[error("CBOR decode error: {0}")]
    CborDecode(String),
    /// A required field was missing from a CBOR map.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A field was present but held an invalid value.
    #[error("invalid field {field}: {message}")]
    InvalidField {
        /// Name of the offending field.
        field: &'static str,
        /// Human-readable description of the problem.
        message: String,
    },
    /// An agent exceeded its configured resource limits.
    #[error("limit exceeded for agent {agent}: {resource} would be {would_be} > {limit}")]
    LimitExceeded {
        /// The agent identifier.
        agent: String,
        /// The resource that exceeded the limit.
        resource: String,
        /// The projected usage after the debit.
        would_be: u64,
        /// The configured limit.
        limit: u64,
    },
    /// A transfer was attempted with insufficient balance.
    #[error("insufficient balance for agent {agent}: have {have}, need {need}")]
    InsufficientBalance {
        /// The agent identifier.
        agent: String,
        /// Current balance.
        have: u64,
        /// Required amount.
        need: u64,
    },
    /// The referenced agent is unknown to the account.
    #[error("unknown agent: {0}")]
    UnknownAgent(String),
    /// The pricing configuration is invalid.
    #[error("invalid pricing config: {0}")]
    InvalidPricingConfig(String),
    /// A currency conversion could not be performed.
    #[error("currency conversion error: {0}")]
    CurrencyConversion(String),
    /// The priority configuration is invalid.
    #[error("invalid priority config: {0}")]
    InvalidPriorityConfig(String),
    /// The referenced task was not found in the priority queue.
    #[error("task not found in priority queue: {0}")]
    TaskNotFound(String),
    /// The referenced compensation was not found.
    #[error("compensation not found: {0}")]
    CompensationNotFound(String),
    /// The compensation is in a state that does not allow the requested action.
    #[error("invalid compensation state for {id}: {message}")]
    InvalidCompensationState {
        /// The compensation identifier.
        id: String,
        /// Human-readable description of the problem.
        message: String,
    },
    /// The compensation amount exceeds the policy maximum.
    #[error("compensation amount {amount} exceeds maximum {maximum}")]
    CompensationExceedsMaximum {
        /// The requested amount (milli-credits).
        amount: i64,
        /// The configured maximum (milli-credits).
        maximum: i64,
    },
    /// The compensation policy was violated.
    #[error("compensation policy violation: {0}")]
    CompensationPolicyViolation(String),
}
