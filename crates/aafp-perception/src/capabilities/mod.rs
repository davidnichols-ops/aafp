//! Perception capabilities: search, web-browse, document-read, API-call,
//! API-discover, code-execute, and media (OCR + transcribe).

pub mod api_call;
pub mod api_discover;
pub mod code_execute;
pub mod document_read;
pub mod media;
pub mod search;
pub mod web_browse;

pub use api_call::*;
pub use api_discover::*;
pub use code_execute::*;
pub use document_read::*;
pub use media::*;
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
