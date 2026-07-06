//! Retry with exponential backoff + jitter.
//!
//! Retry handles *transient* errors (transport timeouts, stream resets)
//! but **not** `CircuitOpen` or `ConcurrencyLimit` (those are routing
//! signals — skip to the next candidate, don't retry the same peer) and
//! **not** application-level errors (the handler ran and returned an
//! error — retrying would be a duplicate side-effect for non-idempotent
//! calls).
//!
//! See `AR_T3_T4_BREAKER_HEDGING.md` Part 5.
//!
//! **Stub:** function bodies are `todo!()` — to be implemented in the
//! T3-T4 build phase.

use crate::SdkError;
use std::time::Duration;

/// Retry policy configuration.
#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the initial call).
    pub max_retries: u32,
    /// Base delay for the first retry.
    pub base_delay: Duration,
    /// Maximum delay cap (prevents absurd waits at high attempt counts).
    pub max_delay: Duration,
    /// Jitter factor in `[0.0, 1.0]`. Full jitter (`1.0`) randomizes the
    /// delay uniformly in `[0, computed_delay]`. "Equal jitter" (`0.5`)
    /// uses `[computed_delay/2, computed_delay]`.
    pub jitter: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
            jitter: 1.0, // full jitter
        }
    }
}

/// Compute the delay before the next retry attempt (0-indexed).
///
/// Exponential growth: `base * multiplier^attempt`, capped at `max_delay`,
/// then jittered.
pub fn retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    let _ = (config, attempt);
    todo!("implement exponential backoff + jitter per AR_T3_T4 Part 5")
}

/// Determine whether an error is retryable.
///
/// `CircuitOpen` and `ConcurrencyLimit` are NOT retryable (routing
/// signals). Application errors (handler returned an error response) are
/// NOT retryable (the call succeeded at the transport level).
/// Transport-level errors ARE retryable.
pub fn is_retryable(err: &SdkError) -> bool {
    let _ = err;
    todo!("implement retryability classification per AR_T3_T4 Part 5")
}

/// Execute a fallible async operation with retry + backoff.
///
/// `operation` is called up to `max_retries + 1` times. Between retries,
/// sleeps for the computed backoff duration. Only retries if
/// `is_retryable()` returns `true` for the error.
pub async fn with_retry<F, Fut, T>(config: &RetryConfig, operation: F) -> Result<T, SdkError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, SdkError>>,
{
    let _ = (config, operation);
    todo!("implement retry loop with backoff sleep per AR_T3_T4 Part 5")
}
