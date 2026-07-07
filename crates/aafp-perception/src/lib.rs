//! AAFP Perception Layer — agent-native interface to the external internet.
//!
//! Provides structured content schemas and capabilities for searching,
//! browsing, and reading web content. Content is represented in
//! agent-native structured CBOR (int-keyed maps) rather than raw HTML,
//! enabling deterministic consumption by autonomous agents.

pub mod capabilities;
pub mod schema;

pub use capabilities::*;
pub use schema::*;

use thiserror::Error;

/// Errors produced by the perception layer.
#[derive(Debug, Error)]
pub enum PerceptionError {
    /// A CBOR value could not be decoded into the expected schema.
    #[error("CBOR decode error: {0}")]
    CborDecode(String),
    /// A required field was missing from a CBOR map.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A field was present but held an invalid value.
    #[error("invalid field: {field}: {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
    /// An underlying provider returned an error.
    #[error("provider error: {0}")]
    Provider(String),
    /// The caller has exceeded the configured rate limit.
    #[error("rate limited")]
    RateLimited,
    /// The target URL is disallowed by robots.txt.
    #[error("robots.txt disallows: {0}")]
    RobotsDisallowed(String),
    /// The operation did not complete within the timeout.
    #[error("timeout")]
    Timeout,
    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),
}
