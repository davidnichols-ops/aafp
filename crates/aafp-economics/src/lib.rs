//! AAFP Economics Layer — resource accounting, pricing, priority queuing,
//! compensation, and slashing (Phase 4, Tracks X1-X5).
//!
//! This crate provides five complementary subsystems for the Intelligence
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
//! - **[`slashing`]** — `SlashingEngine` evaluates slashing conditions (downtime,
//!   missed tasks, malicious behavior, resource misuse, contract violations,
//!   repeated failures) and applies penalties to agent accounts, with an appeal
//!   process and per-agent rate limiting.
//!
//! All persistent structures encode to canonical CBOR int-keyed maps (RFC-0002
//! §8) via [`aafp_cbor`]. The crate is self-contained and depends only on
//! `aafp-cbor` and `sha2`.

pub mod account;
pub mod compensation;
pub mod pricing;
pub mod priority;
pub mod slashing;

pub use account::*;
pub use compensation::*;
pub use pricing::*;
pub use priority::*;
pub use slashing::*;

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
    /// The referenced slash record was not found.
    #[error("slash record not found: {0}")]
    SlashNotFound(String),
    /// The slash record is in a state that does not allow the requested action.
    #[error("invalid slash state for {id}: {message}")]
    InvalidSlashState {
        /// The slash record identifier.
        id: String,
        /// Human-readable description of the problem.
        message: String,
    },
    /// The slashing condition was not met for the given agent.
    #[error("slashing condition not met for agent {agent}: {condition:?}")]
    SlashConditionNotMet {
        /// The agent identifier.
        agent: String,
        /// The condition that was not met.
        condition: SlashingCondition,
    },
    /// The agent has been rate-limited for slashing (too many slashes in the
    /// time window).
    #[error("slash rate limited for agent {0}")]
    SlashRateLimited(String),
    /// A slashing cooldown is still active for the agent and condition.
    #[error("slash cooldown active for agent {agent}, condition {condition:?}, {remaining_ms}ms remaining")]
    SlashCooldownActive {
        /// The agent identifier.
        agent: String,
        /// The condition on cooldown.
        condition: SlashingCondition,
        /// Milliseconds remaining in the cooldown.
        remaining_ms: u64,
    },
    /// The slash amount exceeds the maximum percentage of the agent's balance.
    #[error("slash amount {amount} exceeds maximum {max}")]
    SlashExceedsMax {
        /// The requested slash amount (milli-credits).
        amount: i64,
        /// The maximum allowed (milli-credits).
        max: i64,
    },
    /// The slashing configuration is invalid.
    #[error("invalid slashing config: {0}")]
    InvalidSlashingConfig(String),
}
