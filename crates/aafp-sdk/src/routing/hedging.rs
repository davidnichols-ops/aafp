//! Request hedging — send to two agents, keep the first response.
//!
//! Hedging sends the same request to a primary and a secondary agent and
//! uses the first response; the loser is cancelled by dropping its future
//! (QUIC stream reset). An adaptive policy uses the primary's latency
//! profile to decide whether hedging is worth the extra load.
//!
//! See `AR_T3_T4_BREAKER_HEDGING.md` Parts 4 & 4b (ADAPTIVE_ROUTING_PLANE.md
//! §6.2–6.3).
//!
//! **Stub:** function bodies are `todo!()` — to be implemented in the
//! T3-T4 build phase.

use crate::simple::{Request, Response};
use crate::{Agent as SdkAgent, ConnectionPool, SdkError};
use std::time::Duration;

/// Policy for request hedging.
#[derive(Clone, Debug)]
pub struct HedgePolicy {
    /// Whether hedging is enabled at all.
    pub enabled: bool,
    /// Delay before sending the secondary (backup) request. If the
    /// primary responds within this delay, the secondary never fires.
    pub delay: Duration,
    /// If `true`, only hedge when the primary is predicted to miss the
    /// deadline (adaptive policy — see `should_hedge_adaptive`).
    pub adaptive: bool,
}

impl Default for HedgePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            delay: Duration::from_millis(50),
            adaptive: true,
        }
    }
}

/// Send a request to two agents and return the first response.
///
/// `primary` is tried first. After `hedge_delay`, `secondary` is also
/// started. Whichever responds first wins. If the primary responds before
/// the delay, the secondary never fires (zero overhead). The losing future
/// is dropped, which resets the underlying QUIC stream.
pub async fn call_with_hedging(
    agent: &SdkAgent,
    pool: &ConnectionPool,
    primary_addr: &str,
    secondary_addr: &str,
    request: Request,
    hedge_delay: Duration,
) -> Result<Response, SdkError> {
    let _ = (agent, pool, primary_addr, secondary_addr, request, hedge_delay);
    todo!("implement hedged race per AR_T3_T4 §6.2 (tokio::select + timeout)")
}

/// Decide whether to hedge based on the primary's latency profile.
///
/// Hedges only when:
/// 1. Latency data is available (EWMA initialized).
/// 2. The estimated p99 (`EWMA * 2.5`) exceeds the caller's deadline.
/// 3. Latency variance is high (the peer is *sometimes* slow, not
///    consistently slow — consistently slow peers should be deprioritized
///    by the scorer, not hedged).
pub fn should_hedge_adaptive(
    primary_metrics: &super::metrics::PeerMetrics,
    deadline_ms: f64,
) -> bool {
    let _ = (primary_metrics, deadline_ms);
    todo!("implement adaptive hedge decision per AR_T3_T4 §6.3")
}
