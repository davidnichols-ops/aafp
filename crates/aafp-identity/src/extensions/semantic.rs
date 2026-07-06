//! Semantic capability extension (Phase E4).
//!
//! Namespace: `"aafp.semantic.v1"`. Carries agent-level semantic capability
//! attributes (languages, modalities, hardware, frameworks, precision) and
//! per-capability semantic descriptors linking to the Track U Semantic
//! Capability Graphs.

use aafp_cbor::Value;
use crate::identity_v1::IdentityError;
use super::AgentRecordExtension;

/// Agent-level semantic capability extension (key 11, namespace
/// "aafp.semantic.v1").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SemanticExtension {
    /// Per-capability semantic descriptors.
    pub capabilities: Vec<SemanticCapabilityData>,
}

impl AgentRecordExtension for SemanticExtension {
    const NAMESPACE: &'static str = "aafp.semantic.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        todo!()
    }

    fn from_cbor(_val: &Value) -> Result<Self, IdentityError> {
        todo!()
    }
}

/// Per-capability semantic data (key 3 in CapabilityDescriptor-v2).
///
/// This links the AgentRecord extension system to the Track U Semantic
/// Capability Graphs. Agents that don't understand key 3 ignore it and
/// use the base name + metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SemanticCapabilityData {
    /// Structured attributes for multi-dimensional queries.
    pub attributes: CapabilityAttributes,
    /// Performance characteristics (self-reported).
    pub performance: PerformanceProfile,
    /// Quality/trust metrics (self-reported — see Attestation for verified).
    pub quality: QualityMetrics,
}

/// Structured attributes (subset of SEMANTIC_CAPABILITY_GRAPHS.md §3.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityAttributes {
    /// Agent-wide supported languages (BCP-47 tags, e.g., "en", "fr").
    pub languages: Vec<String>,
    /// Supported modalities: "text", "image", "audio", "video".
    pub modalities: Vec<String>,
    /// Hardware available (e.g., "gpu:rtx5090", "npu:apple-m4").
    pub hardware: Vec<String>,
    /// Software frameworks (e.g., "cuda", "tensorrt", "coreml").
    pub frameworks: Vec<String>,
    /// Precision modes supported (e.g., "fp32", "fp16", "fp8").
    pub precision: Vec<String>,
}

/// Self-reported performance profile.
/// Uses integer types to avoid floating point on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerformanceProfile {
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<u16>,
    /// P99 latency in milliseconds.
    pub p99_latency_ms: Option<u16>,
    /// Throughput in requests per second.
    pub throughput_rps: Option<u32>,
    /// Maximum batch size supported.
    pub max_batch_size: Option<u32>,
}

/// Self-reported quality metrics. Verified metrics come from attestations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QualityMetrics {
    /// Trust score (0-100). Self-reported — treat as unverified.
    pub trust_score: u8,
    /// Accuracy metric (0-10000 basis points, 10000 = 100%).
    pub accuracy_bps: Option<u16>,
    /// Uptime percentage (0-10000 basis points).
    pub uptime_bps: Option<u16>,
    /// Total successful invocations.
    pub success_count: u64,
}
