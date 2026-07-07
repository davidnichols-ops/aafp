//! AAFP Economics Layer — resource accounting and pricing (Phase 4, Tracks X1-X2).
//!
//! This crate provides two complementary subsystems for the Intelligence Plane:
//!
//! - **[`account`]** — `ResourceAccount` tracks per-agent resource consumption
//!   (CPU, memory, storage, network, API calls, inference tokens) with debit,
//!   credit, transfer, and configurable per-agent limits.
//! - **[`pricing`]** — `PricingEngine` computes task costs from measured or
//!   estimated resource usage using fixed, per-unit, tiered, or dynamic pricing
//!   models. Costs are expressed in the abstract unit "credits".
//!
//! All persistent structures encode to canonical CBOR int-keyed maps (RFC-0002
//! §8) via [`aafp_cbor`]. The crate is self-contained and depends only on
//! `aafp-cbor` and `sha2`.

pub mod account;
pub mod pricing;

pub use account::*;
pub use pricing::*;

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
}
