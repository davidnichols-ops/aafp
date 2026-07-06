//! Retry with exponential backoff and jitter.
//!
//! Provides `with_retry` for retrying fallible async operations, `retry_delay`
//! for computing backoff delays, and `is_retryable` for classifying errors.

use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for retry behavior.
#[derive(Clone, Debug)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            jitter: true,
        }
    }
}

/// Compute the delay before the next retry attempt.
///
/// Uses exponential backoff: `base_delay * 2^(attempt - 1)`, capped at `max_delay`.
/// If `jitter` is enabled, adds up to 50% random jitter to avoid thundering herd.
pub fn retry_delay(config: &RetryConfig, attempt: u32, rng: &mut impl Rng) -> Duration {
    let exp = (attempt - 1).min(30);
    let base_ms = config.base_delay.as_millis() as u64;
    let delay_ms = base_ms.saturating_mul(1u64 << exp);
    let mut delay = Duration::from_millis(delay_ms.min(config.max_delay.as_millis() as u64));
    if config.jitter {
        let jitter_max = delay.as_millis() / 2;
        if jitter_max > 0 {
            let jitter = rng.gen_range(0..=jitter_max as u64);
            delay += Duration::from_millis(jitter);
        }
    }
    delay
}

/// Classify whether an error string is retryable.
///
/// Non-retryable errors include: circuit open, concurrency limit, no viable candidate,
/// authentication failures, and bad request errors. Everything else is considered retryable.
pub fn is_retryable(error: &str) -> bool {
    let lower = error.to_lowercase();
    const NON_RETRYABLE: &[&str] = &[
        "circuit open",
        "concurrency limit",
        "no viable candidate",
        "not authenticated",
        "not connected",
        "bad request",
        "invalid",
        "unauthorized",
        "forbidden",
        "not found",
    ];
    !NON_RETRYABLE.iter().any(|nr| lower.contains(nr))
}

/// Retry an async operation with exponential backoff.
///
/// Calls `operation` up to `config.max_attempts` times. Between attempts,
/// sleeps for the computed backoff delay. If `is_retryable` returns `false`
/// for an error, retries stop immediately.
pub async fn with_retry<T, E, F, Fut>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut rng = rand::thread_rng();
    let mut last_err: Option<E> = None;
    let max = config.max_attempts.max(1);
    for attempt in 1..=max {
        match operation().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if !is_retryable(&e.to_string()) {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt < max {
                    let delay = retry_delay(config, attempt, &mut rng);
                    sleep(delay).await;
                }
            }
        }
    }
    Err(last_err.expect("at least one attempt was made"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_delay_exponential() {
        let config = RetryConfig {
            jitter: false,
            ..Default::default()
        };
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(retry_delay(&config, 1, &mut rng), Duration::from_millis(100));
        assert_eq!(retry_delay(&config, 2, &mut rng), Duration::from_millis(200));
        assert_eq!(retry_delay(&config, 3, &mut rng), Duration::from_millis(400));
        assert_eq!(retry_delay(&config, 4, &mut rng), Duration::from_millis(800));
    }

    #[test]
    fn test_retry_delay_capped_at_max() {
        let config = RetryConfig {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            jitter: false,
            ..Default::default()
        };
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(retry_delay(&config, 1, &mut rng), Duration::from_secs(1));
        assert_eq!(retry_delay(&config, 2, &mut rng), Duration::from_secs(2));
        assert_eq!(retry_delay(&config, 3, &mut rng), Duration::from_secs(4));
        assert_eq!(retry_delay(&config, 4, &mut rng), Duration::from_secs(5));
        assert_eq!(retry_delay(&config, 10, &mut rng), Duration::from_secs(5));
    }

    #[test]
    fn test_retry_delay_with_jitter() {
        let config = RetryConfig {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            jitter: true,
            ..Default::default()
        };
        let mut rng = StdRng::seed_from_u64(42);
        let d1 = retry_delay(&config, 1, &mut rng);
        let d2 = retry_delay(&config, 1, &mut rng);
        // With jitter, two calls should likely differ.
        assert!(d1 >= Duration::from_millis(100));
        assert!(d1 <= Duration::from_millis(150));
        assert!(d2 >= Duration::from_millis(100));
    }

    #[test]
    fn test_is_retryable_transient_errors() {
        assert!(is_retryable("timeout"));
        assert!(is_retryable("connection reset by peer"));
        assert!(is_retryable("internal server error"));
        assert!(is_retryable("service unavailable"));
    }

    #[test]
    fn test_is_retryable_non_retryable_errors() {
        assert!(!is_retryable("circuit open"));
        assert!(!is_retryable("concurrency limit reached"));
        assert!(!is_retryable("no viable candidate"));
        assert!(!is_retryable("not authenticated"));
        assert!(!is_retryable("bad request"));
        assert!(!is_retryable("unauthorized"));
        assert!(!is_retryable("forbidden"));
    }

    #[tokio::test]
    async fn test_with_retry_succeeds_on_first_attempt() {
        let config = RetryConfig::default();
        let result = with_retry(&config, || async { Ok::<_, String>(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_with_retry_succeeds_after_failures() {
        let config = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter: false,
            ..Default::default()
        };
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        let result = with_retry(&config, || {
            let c = count_clone.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err("timeout".to_string())
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_exhausts_attempts() {
        let config = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter: false,
            ..Default::default()
        };
        let result: Result<i32, String> = with_retry(&config, || async {
            Err("timeout".to_string())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "timeout");
    }

    #[tokio::test]
    async fn test_with_retry_stops_on_non_retryable() {
        let config = RetryConfig {
            max_attempts: 5,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter: false,
            ..Default::default()
        };
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        let result: Result<i32, String> = with_retry(&config, || {
            let c = count_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err("circuit open".to_string())
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_with_retry_zero_attempts_tries_once() {
        let config = RetryConfig {
            max_attempts: 0,
            ..Default::default()
        };
        let result = with_retry(&config, || async { Ok::<_, String>(42) }).await;
        assert_eq!(result, Ok(42));
    }
}
