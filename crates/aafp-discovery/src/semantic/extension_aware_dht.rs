//! Extension-aware DHT wrapper (Phase E5, §10).
//!
//! Wraps the existing [`CapabilityDht`] to add extension-aware operations.
//! The wrapper delegates to the inner DHT for capability-based retrieval,
//! then filters results using the [`ExtensionIndex`] secondary index.
//!
//! This is a stub module — function bodies are `todo!()` and will be
//! implemented in a subsequent build phase.

use crate::capability_dht::CapabilityDht;

/// Maximum encoded record size accepted by the DHT (64 KiB).
/// Records exceeding this are rejected to prevent DHT bloat (§8.2.3, §12.4).
pub const MAX_RECORD_SIZE_BYTES: usize = 64 * 1024;

/// Soft limit: records exceeding this produce a warning but are accepted.
pub const SOFT_RECORD_SIZE_BYTES: usize = 8 * 1024;

/// Extension-aware wrapper around [`CapabilityDht`].
///
/// Provides capability-based lookup (delegated to inner DHT) plus
/// extension-based filtering (via local [`ExtensionIndex`]).
///
/// # Stub
/// This struct is a scaffold. Method bodies are `todo!()` and will be
/// implemented in a subsequent build phase.
#[derive(Debug, Default)]
pub struct ExtensionAwareDht {
    /// The underlying capability DHT (primary index by capability name).
    pub inner: CapabilityDht,
    /// Local secondary index built from extension data.
    pub index: super::extension_index::ExtensionIndex,
}

impl ExtensionAwareDht {
    /// Create a new extension-aware DHT wrapping an empty [`CapabilityDht`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Find agents by capability, then filter by geo country.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn get_by_capability_and_country(
        &self,
        capability: &str,
        country: &str,
    ) -> Vec<&aafp_identity::AgentRecordV1> {
        let _ = (capability, country);
        todo!("get_by_capability_and_country: inner.get(cap) intersect index.query_by_geo(country)")
    }

    /// Find agents by capability with latency <= `max_latency_ms`.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn get_by_capability_and_latency(
        &self,
        capability: &str,
        max_latency_ms: u16,
    ) -> Vec<&aafp_identity::AgentRecordV1> {
        let _ = (capability, max_latency_ms);
        todo!("get_by_capability_and_latency: inner.get(cap) intersect index.query_by_latency(max)")
    }

    /// Find agents by capability with reputation score >= `min_score`.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn get_by_capability_and_reputation(
        &self,
        capability: &str,
        min_score: u8,
    ) -> Vec<&aafp_identity::AgentRecordV1> {
        let _ = (capability, min_score);
        todo!("get_by_capability_and_reputation: inner.get(cap) intersect index.query_by_reputation(min)")
    }

    /// Find agents by capability, excluding stale-heartbeat records.
    ///
    /// # Stub
    /// This is a stub — implementation will be added in a subsequent phase.
    pub fn get_live_by_capability(
        &self,
        capability: &str,
        now: u64,
    ) -> Vec<&aafp_identity::AgentRecordV1> {
        let _ = (capability, now);
        todo!("get_live_by_capability: inner.get(cap) filter out stale-heartbeat agents")
    }

    /// Access the underlying capability DHT.
    pub fn inner_dht(&self) -> &CapabilityDht {
        &self.inner
    }

    /// Access the extension index.
    pub fn index(&self) -> &super::extension_index::ExtensionIndex {
        &self.index
    }
}


