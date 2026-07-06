//! Self-reported performance profile extension (namespace `"aafp.perf.v1"`).
//!
//! See AGENT_RECORD_EXTENSIONS.md §5 for the field specification.

use aafp_cbor::Value;
use crate::identity_v1::IdentityError;
use super::AgentRecordExtension;

/// Self-reported performance profile (key 11, namespace `"aafp.perf.v1"`).
///
/// These are *claims*, not verified metrics — verified metrics come from
/// third-party attestations (Phase E3).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PerformanceExtension {
    /// Average latency in milliseconds (self-measured, EWMA).
    pub avg_latency_ms: u64,
    /// P99 latency in milliseconds.
    pub p99_latency_ms: u64,
    /// Throughput in requests per second.
    pub throughput_rps: u64,
    /// Maximum batch size supported in a single request.
    pub max_batch_size: u32,
    /// Uptime percentage in basis points (10000 = 100%).
    pub uptime_bps: u64,
    /// Measurement window in seconds (how long the stats cover).
    pub window_secs: u32,
    /// When the stats were last updated (unix seconds).
    pub updated_at: u64,
}

impl AgentRecordExtension for PerformanceExtension {
    const NAMESPACE: &'static str = "aafp.perf.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        todo!("implement PerformanceExtension::to_cbor")
    }

    fn from_cbor(_val: &Value) -> Result<Self, IdentityError> {
        todo!("implement PerformanceExtension::from_cbor")
    }
}
