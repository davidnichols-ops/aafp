//! Perception capabilities: search and web-browse.

pub mod search;
pub mod web_browse;

pub use search::*;
pub use web_browse::*;

/// A callable clock returning the current time as unix milliseconds.
/// Used for rate limiting and cache TTL. Injectable for testing.
pub(crate) type Clock = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;

/// Default clock backed by the system monotonic-ish wall clock.
pub(crate) fn default_clock() -> Clock {
    std::sync::Arc::new(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}
