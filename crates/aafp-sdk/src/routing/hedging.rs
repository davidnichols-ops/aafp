//! Hedged requests: send a secondary request after a delay if the primary
//! hasn't responded, racing the two futures and taking the first result.

use crate::routing::metrics::PeerMetricsRegistry;
use aafp_identity::identity_v1::AgentId;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for adaptive hedging.
#[derive(Clone, Debug)]
pub struct HedgeConfig {
    /// Percentile of latency distribution to use as the hedge delay (0.0–1.0).
    pub latency_percentile: f64,
    /// Multiplier applied to the percentile latency to get the hedge delay.
    pub delay_multiplier: f64,
    /// Minimum hedge delay (floor).
    pub min_delay: Duration,
    /// Maximum hedge delay (ceiling).
    pub max_delay: Duration,
    /// Whether hedging is enabled at all.
    pub enabled: bool,
}

impl Default for HedgeConfig {
    fn default() -> Self {
        Self {
            latency_percentile: 0.95,
            delay_multiplier: 1.0,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(5),
            enabled: true,
        }
    }
}

/// Decide whether to hedge based on the peer's latency EWMA.
///
/// Returns the delay to wait before sending the hedged request, or `None`
/// if hedging should not be performed.
pub fn should_hedge_adaptive(
    registry: &PeerMetricsRegistry,
    agent_id: &AgentId,
    config: &HedgeConfig,
) -> Option<Duration> {
    if !config.enabled {
        return None;
    }
    let metrics = registry.get_or_create(agent_id);
    if !metrics.latency_ewma_ms.is_initialized() {
        // No latency data — use the minimum delay as a conservative hedge.
        return Some(config.min_delay);
    }
    let ewma = metrics.latency_ewma_ms.value();
    if !ewma.is_finite() || ewma <= 0.0 {
        return Some(config.min_delay);
    }
    // Approximate the percentile as a multiple of EWMA.
    let p95_estimate = ewma * (1.0 + (config.latency_percentile - 0.5).max(0.0) * 2.0);
    let delay_ms = p95_estimate * config.delay_multiplier;
    if !delay_ms.is_finite() || delay_ms <= 0.0 {
        return Some(config.min_delay);
    }
    let delay = Duration::from_millis(delay_ms.max(1.0) as u64);
    Some(delay.clamp(config.min_delay, config.max_delay))
}

/// Call a primary future, and if it doesn't complete within `hedge_delay`,
/// start a secondary (hedged) future and race them, returning whichever
/// finishes first.
///
/// The primary future is not cancelled — both may run to completion, but
/// only the first result is returned. The caller is responsible for any
/// cleanup of the losing future.
pub async fn call_with_hedging<T, E, F1, F2>(
    primary: F1,
    secondary: F2,
    hedge_delay: Duration,
) -> Result<T, E>
where
    F1: Future<Output = Result<T, E>>,
    F2: Future<Output = Result<T, E>>,
{
    tokio::select! {
        result = primary => result,
        result = async {
            sleep(hedge_delay).await;
            secondary.await
        } => result,
    }
}

/// Type-erased boxed future for hedged calls.
pub type BoxedHedgeFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Call with hedging using boxed futures (for dynamic dispatch).
pub async fn call_with_hedging_boxed<T, E>(
    primary: BoxedHedgeFuture<'static, T, E>,
    secondary: BoxedHedgeFuture<'static, T, E>,
    hedge_delay: Duration,
) -> Result<T, E> {
    call_with_hedging(primary, secondary, hedge_delay).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_hedge_disabled_returns_none() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([1u8; 32]);
        let mut config = HedgeConfig::default();
        config.enabled = false;
        assert_eq!(should_hedge_adaptive(&registry, &id, &config), None);
    }

    #[test]
    fn test_should_hedge_no_latency_data_uses_min() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([2u8; 32]);
        let config = HedgeConfig::default();
        let delay = should_hedge_adaptive(&registry, &id, &config).unwrap();
        assert_eq!(delay, config.min_delay);
    }

    #[test]
    fn test_should_hedge_with_latency_data() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([3u8; 32]);
        registry.record_outcome(&id, 100.0, true);
        let config = HedgeConfig::default();
        let delay = should_hedge_adaptive(&registry, &id, &config).unwrap();
        assert!(delay >= config.min_delay);
        assert!(delay <= config.max_delay);
    }

    #[test]
    fn test_should_hedge_clamps_to_max() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([4u8; 32]);
        for _ in 0..10 {
            registry.record_outcome(&id, 10_000.0, true);
        }
        let config = HedgeConfig::default();
        let delay = should_hedge_adaptive(&registry, &id, &config).unwrap();
        assert_eq!(delay, config.max_delay);
    }

    #[test]
    fn test_should_hedge_clamps_to_min() {
        let registry = PeerMetricsRegistry::new();
        let id = AgentId([5u8; 32]);
        registry.record_outcome(&id, 0.01, true);
        let config = HedgeConfig::default();
        let delay = should_hedge_adaptive(&registry, &id, &config).unwrap();
        assert_eq!(delay, config.min_delay);
    }

    #[tokio::test]
    async fn test_hedging_primary_wins() {
        let primary = async { Ok::<_, ()>(42) };
        let secondary = async {
            sleep(Duration::from_secs(10)).await;
            Ok(99)
        };
        let result = call_with_hedging(primary, secondary, Duration::from_millis(50)).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_hedging_secondary_wins() {
        let primary = async {
            sleep(Duration::from_secs(10)).await;
            Ok::<_, ()>(42)
        };
        let secondary = async { Ok(99) };
        let result = call_with_hedging(primary, secondary, Duration::from_millis(10)).await;
        assert_eq!(result, Ok(99));
    }

    #[tokio::test]
    async fn test_hedging_primary_error_propagates() {
        let primary = async { Err::<(), _>("primary failed") };
        let secondary = async {
            sleep(Duration::from_secs(10)).await;
            Ok(())
        };
        let result = call_with_hedging(primary, secondary, Duration::from_millis(50)).await;
        assert_eq!(result, Err("primary failed"));
    }

    #[tokio::test]
    async fn test_hedging_secondary_error_when_secondary_wins() {
        let primary = async {
            sleep(Duration::from_secs(10)).await;
            Ok::<_, &str>(42)
        };
        let secondary = async { Err("secondary failed") };
        let result = call_with_hedging(primary, secondary, Duration::from_millis(10)).await;
        assert_eq!(result, Err("secondary failed"));
    }

    #[tokio::test]
    async fn test_hedging_boxed() {
        let primary: BoxedHedgeFuture<'static, i32, ()> =
            Box::pin(async { Ok(42) });
        let secondary: BoxedHedgeFuture<'static, i32, ()> =
            Box::pin(async {
                sleep(Duration::from_secs(10)).await;
                Ok(99)
            });
        let result = call_with_hedging_boxed(primary, secondary, Duration::from_millis(50)).await;
        assert_eq!(result, Ok(42));
    }
}
