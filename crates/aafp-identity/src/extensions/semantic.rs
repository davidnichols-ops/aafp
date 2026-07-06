//! Semantic capability extension (Phase E4).
//!
//! Namespace: `"aafp.semantic.v1"`. Carries agent-level semantic capability
//! attributes (languages, modalities, hardware, frameworks, precision) and
//! per-capability semantic descriptors.

use super::AgentRecordExtension;
use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// Agent-level semantic capability extension (key 11, namespace
/// "aafp.semantic.v1").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SemanticExtension {
    /// Extension version (always 1 for v1).
    pub version: u64,
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

impl AgentRecordExtension for SemanticExtension {
    const NAMESPACE: &'static str = "aafp.semantic.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if !self.languages.is_empty() {
            entries.push((
                1,
                Value::Array(
                    self.languages
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        if !self.modalities.is_empty() {
            entries.push((
                2,
                Value::Array(
                    self.modalities
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        if !self.hardware.is_empty() {
            entries.push((
                3,
                Value::Array(
                    self.hardware
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        if !self.frameworks.is_empty() {
            entries.push((
                4,
                Value::Array(
                    self.frameworks
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        if !self.precision.is_empty() {
            entries.push((
                5,
                Value::Array(
                    self.precision
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        int_map(entries)
    }

    fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let extract_arr = |k: i64| -> Vec<String> {
            match int_map_get(val, k) {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| match v {
                        Value::TextString(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            }
        };
        Ok(Self {
            version: 1,
            languages: extract_arr(1),
            modalities: extract_arr(2),
            hardware: extract_arr(3),
            frameworks: extract_arr(4),
            precision: extract_arr(5),
        })
    }
}

/// Per-capability semantic data (key 3 in CapabilityDescriptor-v2).
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerformanceProfile {
    pub avg_latency_ms: Option<u16>,
    pub p99_latency_ms: Option<u16>,
    pub throughput_rps: Option<u32>,
    pub max_batch_size: Option<u32>,
}

/// Self-reported quality metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QualityMetrics {
    pub trust_score: u8,
    pub accuracy_bps: Option<u16>,
    pub uptime_bps: Option<u16>,
    pub success_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_semantic_roundtrip() {
        let ext = SemanticExtension {
            version: 1,
            languages: vec!["en".into(), "fr".into()],
            modalities: vec!["text".into(), "image".into()],
            hardware: vec!["gpu:rtx5090".into()],
            frameworks: vec!["cuda".into()],
            precision: vec!["fp16".into()],
        };
        let cbor = ext.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let ext2 = SemanticExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(ext, ext2);
    }
}
