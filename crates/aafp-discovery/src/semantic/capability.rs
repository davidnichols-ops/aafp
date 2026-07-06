//! `SemanticCapability` and its component structs (D1).
//!
//! This is a scaffolding module: all structs and enums are defined with their
//! full field layout, but method bodies are `todo!()` stubs. The CBOR
//! encoding/decoding logic lives in [`super::encoding`].
//!
//! See `SEMANTIC_CAPABILITY_GRAPHS.md` §3.1 and the builder prompt
//! `SCG_D1_D2_DESCRIPTOR_QUERY.md` for the data model.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// `MetadataValue` is re-exported from `aafp-identity` so that
// `CapabilityDescriptor` and `SemanticCapability` share the same type.
// ---------------------------------------------------------------------------

/// Metadata value kind used inside `CapabilityAttributes.custom`.
pub use aafp_identity::MetadataValue;

/// A semantic category for a capability.
///
/// Encoded in CBOR as a uint discriminant (0-9) with an additional tstr
/// payload for the `Custom` variant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CapabilityCategory {
    /// LLM/text inference.
    Inference,
    /// Language translation.
    Translation,
    /// Optical character recognition.
    Ocr,
    /// Information retrieval / search / RAG.
    InformationRetrieval,
    /// Navigation / planning.
    Navigation,
    /// Structured-data parsing.
    Parsing,
    /// External system integration / tool calling.
    Integration,
    /// Numerical / symbolic computation.
    Computation,
    /// Sensory perception (vision, audio analysis).
    Perception,
    /// Streaming / real-time data.
    Streaming,
    /// User-defined category (carries the raw label).
    Custom(String),
}

/// Supported input/output modalities.
///
/// Encoded in CBOR as a uint discriminant: Text=0, Image=1, Audio=2, Video=3.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Modality {
    /// Text modality.
    Text,
    /// Image modality.
    Image,
    /// Audio modality.
    Audio,
    /// Video modality.
    Video,
}

/// Hardware specification for a capability.
///
/// CBOR IntMap keys: 1: `kind` (tstr), 2: `model` (optional tstr),
/// 3: `vram_mb` (optional uint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareSpec {
    /// Hardware kind: `"gpu"`, `"cpu"`, `"tpu"`, `"npu"`.
    pub kind: String,
    /// Optional model identifier (e.g. `"RTX5090"`).
    pub model: Option<String>,
    /// Optional VRAM in megabytes.
    pub vram_mb: Option<u32>,
}

/// Structured attributes for multi-dimensional capability queries.
///
/// CBOR IntMap keys:
/// - 1: `languages` (array of tstr)
/// - 2: `modalities` (array of uint)
/// - 3: `hardware` (array of IntMaps)
/// - 4: `frameworks` (array of tstr)
/// - 5: `precision` (array of tstr)
/// - 6: `custom` (StrMap of `MetadataValue`)
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CapabilityAttributes {
    /// Supported languages (BCP-47 tags or ISO 639-1 codes).
    pub languages: Vec<String>,
    /// Supported modalities.
    pub modalities: Vec<Modality>,
    /// Hardware requirements/recommendations.
    pub hardware: Vec<HardwareSpec>,
    /// Supported runtime frameworks (e.g. `"TensorRT"`, `"ONNX"`).
    pub frameworks: Vec<String>,
    /// Supported precision modes (e.g. `"FP8"`, `"FP16"`).
    pub precision: Vec<String>,
    /// Arbitrary user-defined attributes.
    pub custom: HashMap<String, MetadataValue>,
}

/// Performance characteristics.
///
/// All `f64` fields are encoded as scaled `u64` integers in CBOR because
/// `aafp_cbor::Value` has no Float variant:
/// - `avg_latency_ms`, `p99_latency_ms`: encoded as `u64` microseconds
///   (value * 1000).
/// - `throughput_rps`: encoded as `u64` rounded to nearest integer.
///
/// CBOR IntMap keys: 1: `avg_latency_ms`, 2: `p99_latency_ms`,
/// 3: `throughput_rps`, 4: `max_batch_size` (optional uint).
#[derive(Clone, Debug, PartialEq)]
pub struct PerformanceProfile {
    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
    /// 99th-percentile latency in milliseconds.
    pub p99_latency_ms: f64,
    /// Sustained throughput in requests per second.
    pub throughput_rps: f64,
    /// Optional maximum supported batch size.
    pub max_batch_size: Option<u32>,
}

/// Quality and trust metrics.
///
/// `accuracy` is encoded as `u64` * 1_000_000 (i.e. parts per million) to
/// avoid float encoding. Other fields are plain uints.
///
/// CBOR IntMap keys: 1: `trust_score` (uint 0-100), 2: `accuracy`
/// (optional uint, ppm), 3: `uptime_pct` (uint, scaled *100),
/// 4: `success_count` (uint).
#[derive(Clone, Debug, PartialEq)]
pub struct QualityMetrics {
    /// Trust score in the range 0-100.
    pub trust_score: u8,
    /// Optional accuracy in the range 0.0-1.0.
    pub accuracy: Option<f64>,
    /// Uptime percentage in the range 0.0-100.0.
    pub uptime_pct: f64,
    /// Cumulative successful invocation count.
    pub success_count: u64,
}

/// Cost model in micro-dollars (1e-6 USD).
///
/// CBOR IntMap keys: 1: `per_invocation_micro_usd` (uint),
/// 2: `per_token_micro_usd` (optional uint), 3: `has_free_tier` (bool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CostModel {
    /// Cost per invocation in micro-USD.
    pub per_invocation_micro_usd: u64,
    /// Optional cost per token in micro-USD.
    pub per_token_micro_usd: Option<u64>,
    /// Whether a free tier is available.
    pub has_free_tier: bool,
}

/// Semantic version (major.minor.patch).
///
/// CBOR IntMap keys: 1: `major` (uint), 2: `minor` (uint), 3: `patch` (uint).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

/// Geographic constraint.
///
/// CBOR IntMap keys: 1: `region` (tstr), 2: `countries` (array of tstr),
/// 3: `latency_optimized` (bool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoConstraint {
    /// Region code (e.g. `"na"`, `"eu"`, `"apac"`).
    pub region: String,
    /// Countries as ISO 3166-1 alpha-2 codes.
    pub countries: Vec<String>,
    /// Whether the deployment is latency-optimized for the region.
    pub latency_optimized: bool,
}

/// The full semantic capability descriptor (D1).
///
/// Encoded as a CBOR IntMap with integer keys 1-9 (see
/// `SCG_D1_D2_DESCRIPTOR_QUERY.md` §"CBOR key assignment"). When embedded in
/// a `CapabilityDescriptor`, the encoded bytes are stored under the reserved
/// metadata key `"semantic"` as `MetadataValue::Bytes`.
#[derive(Clone, Debug, PartialEq)]
pub struct SemanticCapability {
    /// Human-readable capability name (also the DHT key).
    pub name: String,
    /// Semantic category.
    pub category: CapabilityCategory,
    /// Structured attributes for querying.
    pub attributes: CapabilityAttributes,
    /// Performance profile.
    pub performance: PerformanceProfile,
    /// Quality and trust metrics.
    pub quality: QualityMetrics,
    /// Cost model.
    pub cost: CostModel,
    /// Dependency edges to other capabilities.
    pub dependencies: Vec<crate::semantic::edge::CapabilityEdge>,
    /// Semantic version.
    pub version: SemanticVersion,
    /// Optional geographic constraint.
    pub geo: Option<GeoConstraint>,
    /// Required inputs for this capability.
    pub requirements: Vec<Requirement>,
    /// Outputs produced by this capability.
    pub provides: Vec<OutputSpec>,
}

impl SemanticCapability {
    /// Create a new `SemanticCapability` with the given name and default
    /// values for all other fields.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: CapabilityCategory::Custom("unknown".into()),
            attributes: CapabilityAttributes::default(),
            performance: PerformanceProfile {
                avg_latency_ms: 0.0,
                p99_latency_ms: 0.0,
                throughput_rps: 0.0,
                max_batch_size: None,
            },
            quality: QualityMetrics {
                trust_score: 0,
                accuracy: None,
                uptime_pct: 0.0,
                success_count: 0,
            },
            cost: CostModel {
                per_invocation_micro_usd: 0,
                per_token_micro_usd: None,
                has_free_tier: false,
            },
            dependencies: vec![],
            version: SemanticVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
            geo: None,
            requirements: vec![],
            provides: vec![],
        }
    }

    /// Wrap into a `CapabilityDescriptor` by embedding the encoded semantic
    /// payload under the `"semantic"` metadata key.
    ///
    /// The CBOR encoding itself is implemented in [`super::encoding`].
    pub fn to_descriptor(&self) -> aafp_identity::CapabilityDescriptor {
        let cbor = self.to_cbor();
        let bytes = aafp_cbor::encode(&cbor).unwrap_or_default();
        aafp_identity::CapabilityDescriptor {
            name: self.name.clone(),
            metadata: vec![("semantic".into(), MetadataValue::Bytes(bytes))],
        }
    }

    /// Extract a `SemanticCapability` from a `CapabilityDescriptor`'s
    /// metadata, if the `"semantic"` key is present.
    ///
    /// The CBOR decoding itself is implemented in [`super::encoding`].
    pub fn from_descriptor(desc: &aafp_identity::CapabilityDescriptor) -> Option<Self> {
        for (key, value) in &desc.metadata {
            if key == "semantic" {
                if let MetadataValue::Bytes(ref bytes) = value {
                    if let Ok((decoded, _)) = aafp_cbor::decode(bytes) {
                        return Self::from_cbor(&decoded).ok();
                    }
                }
            }
        }
        None
    }
}

/// A required input for a capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    /// The kind of input required (e.g., "document-bytes", "image-bytes").
    pub kind: String,
    /// Whether this requirement is optional.
    pub optional: bool,
}

/// An output produced by a capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSpec {
    /// The kind of output produced (e.g., "search-results", "web-content").
    pub kind: String,
    /// Additional attributes describing the output.
    pub attributes: HashMap<String, MetadataValue>,
}

/// Errors raised by semantic capability encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum SemanticError {
    /// A required field was missing from the CBOR payload.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A field was present but had an invalid value.
    #[error("invalid field '{field}': {message}")]
    InvalidField {
        /// The field name.
        field: &'static str,
        /// A human-readable description of the problem.
        message: String,
    },
    /// An underlying CBOR encode/decode error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
}
