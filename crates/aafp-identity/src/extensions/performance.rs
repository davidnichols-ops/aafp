//! Self-reported performance profile extension (namespace `"aafp.perf.v1"`).
//!
//! See AGENT_RECORD_EXTENSIONS.md §5 for the field specification.

use super::AgentRecordExtension;
use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// Self-reported performance profile (key 11, namespace `"aafp.perf.v1"`).
///
/// These are *claims*, not verified metrics — verified metrics come from
/// third-party attestations (Phase E3).
///
/// CBOR encoding (inner data):
/// ```cbor
/// PerfData = {
///     ? 1: uint,   // avg_latency_ms
///     ? 2: uint,   // p99_latency_ms
///     ? 3: uint,   // throughput_rps
///     ? 4: uint,   // max_batch_size
///     ? 5: uint,   // uptime_bps (basis points, 10000 = 100%)
///     ? 6: uint,   // window_secs
///     ? 7: uint,   // updated_at
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PerformanceExtension {
    /// Extension version (always 1 for v1).
    pub version: u64,
    /// Average latency in milliseconds (self-measured, EWMA).
    pub avg_latency_ms: Option<u16>,
    /// P99 latency in milliseconds.
    pub p99_latency_ms: Option<u16>,
    /// Throughput in requests per second.
    pub throughput_rps: Option<u32>,
    /// Maximum batch size supported in a single request.
    pub max_batch_size: Option<u32>,
    /// Uptime percentage in basis points (10000 = 100%).
    pub uptime_bps: Option<u16>,
    /// Measurement window in seconds (how long the stats cover).
    pub window_secs: u32,
    /// When the stats were last updated (unix seconds).
    pub updated_at: u64,
}

impl AgentRecordExtension for PerformanceExtension {
    const NAMESPACE: &'static str = "aafp.perf.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if let Some(lat) = self.avg_latency_ms {
            entries.push((1, Value::Unsigned(lat as u64)));
        }
        if let Some(p99) = self.p99_latency_ms {
            entries.push((2, Value::Unsigned(p99 as u64)));
        }
        if let Some(rps) = self.throughput_rps {
            entries.push((3, Value::Unsigned(rps as u64)));
        }
        if let Some(bs) = self.max_batch_size {
            entries.push((4, Value::Unsigned(bs as u64)));
        }
        if let Some(upt) = self.uptime_bps {
            entries.push((5, Value::Unsigned(upt as u64)));
        }
        if self.window_secs > 0 {
            entries.push((6, Value::Unsigned(self.window_secs as u64)));
        }
        if self.updated_at > 0 {
            entries.push((7, Value::Unsigned(self.updated_at)));
        }
        int_map(entries)
    }

    fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        Ok(Self {
            version: 1,
            avg_latency_ms: match int_map_get(val, 1) {
                Some(Value::Unsigned(n)) => Some(*n as u16),
                _ => None,
            },
            p99_latency_ms: match int_map_get(val, 2) {
                Some(Value::Unsigned(n)) => Some(*n as u16),
                _ => None,
            },
            throughput_rps: match int_map_get(val, 3) {
                Some(Value::Unsigned(n)) => Some(*n as u32),
                _ => None,
            },
            max_batch_size: match int_map_get(val, 4) {
                Some(Value::Unsigned(n)) => Some(*n as u32),
                _ => None,
            },
            uptime_bps: match int_map_get(val, 5) {
                Some(Value::Unsigned(n)) => Some(*n as u16),
                _ => None,
            },
            window_secs: match int_map_get(val, 6) {
                Some(Value::Unsigned(n)) => *n as u32,
                _ => 0,
            },
            updated_at: match int_map_get(val, 7) {
                Some(Value::Unsigned(n)) => *n,
                _ => 0,
            },
        })
    }
}
