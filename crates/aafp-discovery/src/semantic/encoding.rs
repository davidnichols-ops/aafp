//! CBOR encoding/decoding for `SemanticCapability` and its components (D1).
//!
//! Encoding strategy: `SemanticCapability` is encoded as a CBOR IntMap with
//! integer keys 1-11, then embedded in a `CapabilityDescriptor`'s metadata
//! under the reserved key `"semantic"` as `MetadataValue::Bytes`. This keeps
//! the encoding backward compatible — old agents see an unknown metadata key
//! and ignore it.
//!
//! ## Float handling
//! `aafp_cbor::Value` has no Float variant. All `f64` fields are encoded as
//! scaled `u64` integers:
//! - Latencies (`avg_latency_ms`, `p99_latency_ms`): `u64` microseconds
//!   (value * 1000).
//! - `throughput_rps`: `u64` rounded to nearest integer.
//! - `accuracy`: `u64` parts-per-million (value * 1_000_000).
//! - `uptime_pct`: `u64` scaled by 100 (value * 100).

use super::capability::{
    CapabilityAttributes, CapabilityCategory, CostModel, GeoConstraint, HardwareSpec,
    MetadataValue, Modality, OutputSpec, PerformanceProfile, QualityMetrics, Requirement,
    SemanticCapability, SemanticError, SemanticVersion,
};
use super::edge::{CapabilityEdge, EdgeType};
use aafp_cbor::{int_map, int_map_get, Value};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// SemanticCapability
// ---------------------------------------------------------------------------

impl SemanticCapability {
    /// Encode to a CBOR `Value` (IntMap with keys 1-11).
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (1, Value::TextString(self.name.clone())),
            (2, self.category.to_cbor()),
            (3, self.attributes.to_cbor()),
            (4, self.performance.to_cbor()),
            (5, self.quality.to_cbor()),
            (6, self.cost.to_cbor()),
            (
                7,
                Value::Array(self.dependencies.iter().map(|e| e.to_cbor()).collect()),
            ),
            (8, self.version.to_cbor()),
        ];
        if let Some(ref geo) = self.geo {
            entries.push((9, geo.to_cbor()));
        }
        entries.push((
            10,
            Value::Array(self.requirements.iter().map(requirement_to_cbor).collect()),
        ));
        entries.push((
            11,
            Value::Array(self.provides.iter().map(output_spec_to_cbor).collect()),
        ));
        int_map(entries)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let name = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SemanticError::MissingField("name")),
        };
        let category = CapabilityCategory::from_cbor(
            int_map_get(val, 2).ok_or(SemanticError::MissingField("category"))?,
        )?;
        let attributes = CapabilityAttributes::from_cbor(
            int_map_get(val, 3).ok_or(SemanticError::MissingField("attributes"))?,
        )?;
        let performance = PerformanceProfile::from_cbor(
            int_map_get(val, 4).ok_or(SemanticError::MissingField("performance"))?,
        )?;
        let quality = QualityMetrics::from_cbor(
            int_map_get(val, 5).ok_or(SemanticError::MissingField("quality"))?,
        )?;
        let cost =
            CostModel::from_cbor(int_map_get(val, 6).ok_or(SemanticError::MissingField("cost"))?)?;
        let dependencies = match int_map_get(val, 7) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(CapabilityEdge::from_cbor)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        let version = SemanticVersion::from_cbor(
            int_map_get(val, 8).ok_or(SemanticError::MissingField("version"))?,
        )?;
        let geo = match int_map_get(val, 9) {
            Some(v) => Some(GeoConstraint::from_cbor(v)?),
            None => None,
        };
        let requirements = match int_map_get(val, 10) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(requirement_from_cbor)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        let provides = match int_map_get(val, 11) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(output_spec_from_cbor)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        Ok(Self {
            name,
            category,
            attributes,
            performance,
            quality,
            cost,
            dependencies,
            version,
            geo,
            requirements,
            provides,
        })
    }
}

// ---------------------------------------------------------------------------
// CapabilityCategory
// ---------------------------------------------------------------------------

impl CapabilityCategory {
    /// Encode to a CBOR `Value` (uint discriminant, or uint + tstr for
    /// `Custom`).
    pub fn to_cbor(&self) -> Value {
        match self {
            CapabilityCategory::Inference => Value::Unsigned(0),
            CapabilityCategory::Translation => Value::Unsigned(1),
            CapabilityCategory::Ocr => Value::Unsigned(2),
            CapabilityCategory::InformationRetrieval => Value::Unsigned(3),
            CapabilityCategory::Navigation => Value::Unsigned(4),
            CapabilityCategory::Parsing => Value::Unsigned(5),
            CapabilityCategory::Integration => Value::Unsigned(6),
            CapabilityCategory::Computation => Value::Unsigned(7),
            CapabilityCategory::Perception => Value::Unsigned(8),
            CapabilityCategory::Streaming => Value::Unsigned(9),
            CapabilityCategory::Custom(s) => int_map(vec![
                (0, Value::Unsigned(10)),
                (1, Value::TextString(s.clone())),
            ]),
        }
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        match val {
            Value::Unsigned(0) => Ok(CapabilityCategory::Inference),
            Value::Unsigned(1) => Ok(CapabilityCategory::Translation),
            Value::Unsigned(2) => Ok(CapabilityCategory::Ocr),
            Value::Unsigned(3) => Ok(CapabilityCategory::InformationRetrieval),
            Value::Unsigned(4) => Ok(CapabilityCategory::Navigation),
            Value::Unsigned(5) => Ok(CapabilityCategory::Parsing),
            Value::Unsigned(6) => Ok(CapabilityCategory::Integration),
            Value::Unsigned(7) => Ok(CapabilityCategory::Computation),
            Value::Unsigned(8) => Ok(CapabilityCategory::Perception),
            Value::Unsigned(9) => Ok(CapabilityCategory::Streaming),
            Value::IntMap(_) => {
                let s = match int_map_get(val, 1) {
                    Some(Value::TextString(s)) => s.clone(),
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "category",
                            message: "missing custom name".into(),
                        })
                    }
                };
                Ok(CapabilityCategory::Custom(s))
            }
            _ => Err(SemanticError::InvalidField {
                field: "category",
                message: format!("invalid discriminant: {:?}", val),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Modality
// ---------------------------------------------------------------------------

impl Modality {
    /// Encode to a CBOR `Value` (uint discriminant).
    pub fn to_cbor(&self) -> Value {
        match self {
            Modality::Text => Value::Unsigned(0),
            Modality::Image => Value::Unsigned(1),
            Modality::Audio => Value::Unsigned(2),
            Modality::Video => Value::Unsigned(3),
        }
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        match val {
            Value::Unsigned(0) => Ok(Modality::Text),
            Value::Unsigned(1) => Ok(Modality::Image),
            Value::Unsigned(2) => Ok(Modality::Audio),
            Value::Unsigned(3) => Ok(Modality::Video),
            _ => Err(SemanticError::InvalidField {
                field: "modality",
                message: format!("invalid discriminant: {:?}", val),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// HardwareSpec
// ---------------------------------------------------------------------------

impl HardwareSpec {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![(1, Value::TextString(self.kind.clone()))];
        if let Some(ref model) = self.model {
            entries.push((2, Value::TextString(model.clone())));
        }
        if let Some(vram) = self.vram_mb {
            entries.push((3, Value::Unsigned(vram as u64)));
        }
        int_map(entries)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let kind = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SemanticError::MissingField("hardware.kind")),
        };
        let model = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => Some(s.clone()),
            _ => None,
        };
        let vram_mb = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => Some(*n as u32),
            _ => None,
        };
        Ok(Self {
            kind,
            model,
            vram_mb,
        })
    }
}

// ---------------------------------------------------------------------------
// CapabilityAttributes
// ---------------------------------------------------------------------------

impl CapabilityAttributes {
    /// Encode to a CBOR `Value` (IntMap keys 1-6).
    pub fn to_cbor(&self) -> Value {
        let languages = Value::Array(
            self.languages
                .iter()
                .map(|l| Value::TextString(l.clone()))
                .collect(),
        );
        let modalities = Value::Array(self.modalities.iter().map(|m| m.to_cbor()).collect());
        let hardware = Value::Array(self.hardware.iter().map(|h| h.to_cbor()).collect());
        let frameworks = Value::Array(
            self.frameworks
                .iter()
                .map(|f| Value::TextString(f.clone()))
                .collect(),
        );
        let precision = Value::Array(
            self.precision
                .iter()
                .map(|p| Value::TextString(p.clone()))
                .collect(),
        );
        let custom = if self.custom.is_empty() {
            Value::Null
        } else {
            Value::StrMap(
                self.custom
                    .iter()
                    .map(|(k, v)| (k.clone(), metadata_value_to_cbor(v)))
                    .collect(),
            )
        };
        int_map(vec![
            (1, languages),
            (2, modalities),
            (3, hardware),
            (4, frameworks),
            (5, precision),
            (6, custom),
        ])
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let languages = match int_map_get(val, 1) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::TextString(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let modalities = match int_map_get(val, 2) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(Modality::from_cbor)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        let hardware = match int_map_get(val, 3) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(HardwareSpec::from_cbor)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        let frameworks = match int_map_get(val, 4) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::TextString(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let precision = match int_map_get(val, 5) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::TextString(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let custom = match int_map_get(val, 6) {
            Some(Value::StrMap(entries)) => {
                let mut map = HashMap::new();
                for (k, v) in entries {
                    if let Some(mv) = metadata_value_from_cbor(v) {
                        map.insert(k.clone(), mv);
                    }
                }
                map
            }
            _ => HashMap::new(),
        };
        Ok(Self {
            languages,
            modalities,
            hardware,
            frameworks,
            precision,
            custom,
        })
    }
}

// ---------------------------------------------------------------------------
// PerformanceProfile
// ---------------------------------------------------------------------------

impl PerformanceProfile {
    /// Encode to a CBOR `Value` (IntMap keys 1-4, floats scaled to uint).
    pub fn to_cbor(&self) -> Value {
        let scale = |v: f64| -> u64 {
            if v.is_finite() && v >= 0.0 {
                v as u64
            } else {
                0
            }
        };
        let mut entries = vec![
            (1, Value::Unsigned(scale(self.avg_latency_ms * 1000.0))),
            (2, Value::Unsigned(scale(self.p99_latency_ms * 1000.0))),
            (3, Value::Unsigned(scale(self.throughput_rps.round()))),
        ];
        if let Some(batch) = self.max_batch_size {
            entries.push((4, Value::Unsigned(batch as u64)));
        }
        int_map(entries)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let avg_latency_ms = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n as f64 / 1000.0,
            _ => return Err(SemanticError::MissingField("avg_latency_ms")),
        };
        let p99_latency_ms = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => *n as f64 / 1000.0,
            _ => return Err(SemanticError::MissingField("p99_latency_ms")),
        };
        let throughput_rps = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n as f64,
            _ => return Err(SemanticError::MissingField("throughput_rps")),
        };
        let max_batch_size = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => Some(*n as u32),
            _ => None,
        };
        Ok(Self {
            avg_latency_ms,
            p99_latency_ms,
            throughput_rps,
            max_batch_size,
        })
    }
}

// ---------------------------------------------------------------------------
// QualityMetrics
// ---------------------------------------------------------------------------

impl QualityMetrics {
    /// Encode to a CBOR `Value` (IntMap keys 1-4, floats scaled to uint).
    pub fn to_cbor(&self) -> Value {
        let scale = |v: f64| -> u64 {
            if v.is_finite() && v >= 0.0 {
                v as u64
            } else {
                0
            }
        };
        let mut entries = vec![
            (1, Value::Unsigned(self.trust_score as u64)),
            (3, Value::Unsigned(scale(self.uptime_pct * 100.0))),
            (4, Value::Unsigned(self.success_count)),
        ];
        if let Some(acc) = self.accuracy {
            entries.push((2, Value::Unsigned(scale(acc * 1_000_000.0))));
        }
        // Sort by key for deterministic ordering
        entries.sort_by_key(|(k, _)| *k);
        int_map(entries)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let trust_score = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) if *n <= u8::MAX as u64 => *n as u8,
            _ => return Err(SemanticError::MissingField("trust_score")),
        };
        let accuracy = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => Some(*n as f64 / 1_000_000.0),
            _ => None,
        };
        let uptime_pct = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n as f64 / 100.0,
            _ => return Err(SemanticError::MissingField("uptime_pct")),
        };
        let success_count = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => *n,
            _ => 0,
        };
        Ok(Self {
            trust_score,
            accuracy,
            uptime_pct,
            success_count,
        })
    }
}

// ---------------------------------------------------------------------------
// CostModel
// ---------------------------------------------------------------------------

impl CostModel {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (1, Value::Unsigned(self.per_invocation_micro_usd)),
            (3, Value::Bool(self.has_free_tier)),
        ];
        if let Some(token_cost) = self.per_token_micro_usd {
            entries.push((2, Value::Unsigned(token_cost)));
        }
        entries.sort_by_key(|(k, _)| *k);
        int_map(entries)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let per_invocation_micro_usd = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(SemanticError::MissingField("per_invocation_micro_usd")),
        };
        let per_token_micro_usd = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => Some(*n),
            _ => None,
        };
        let has_free_tier = match int_map_get(val, 3) {
            Some(Value::Bool(b)) => *b,
            _ => false,
        };
        Ok(Self {
            per_invocation_micro_usd,
            per_token_micro_usd,
            has_free_tier,
        })
    }
}

// ---------------------------------------------------------------------------
// SemanticVersion
// ---------------------------------------------------------------------------

impl SemanticVersion {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.major as u64)),
            (2, Value::Unsigned(self.minor as u64)),
            (3, Value::Unsigned(self.patch as u64)),
        ])
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let major = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n as u32,
            _ => return Err(SemanticError::MissingField("major")),
        };
        let minor = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => *n as u32,
            _ => return Err(SemanticError::MissingField("minor")),
        };
        let patch = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n as u32,
            _ => return Err(SemanticError::MissingField("patch")),
        };
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

// ---------------------------------------------------------------------------
// GeoConstraint
// ---------------------------------------------------------------------------

impl GeoConstraint {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.region.clone())),
            (
                2,
                Value::Array(
                    self.countries
                        .iter()
                        .map(|c| Value::TextString(c.clone()))
                        .collect(),
                ),
            ),
            (3, Value::Bool(self.latency_optimized)),
        ])
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let region = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SemanticError::MissingField("geo.region")),
        };
        let countries = match int_map_get(val, 2) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::TextString(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let latency_optimized = match int_map_get(val, 3) {
            Some(Value::Bool(b)) => *b,
            _ => false,
        };
        Ok(Self {
            region,
            countries,
            latency_optimized,
        })
    }
}

// ---------------------------------------------------------------------------
// CapabilityEdge / EdgeType
// ---------------------------------------------------------------------------

impl EdgeType {
    /// Encode to a CBOR `Value` (uint discriminant).
    pub fn to_cbor(&self) -> Value {
        match self {
            EdgeType::Requires => Value::Unsigned(0),
            EdgeType::Enables => Value::Unsigned(1),
            EdgeType::Precedes => Value::Unsigned(2),
            EdgeType::Alternative => Value::Unsigned(3),
            EdgeType::Specializes => Value::Unsigned(4),
        }
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        match val {
            Value::Unsigned(0) => Ok(EdgeType::Requires),
            Value::Unsigned(1) => Ok(EdgeType::Enables),
            Value::Unsigned(2) => Ok(EdgeType::Precedes),
            Value::Unsigned(3) => Ok(EdgeType::Alternative),
            Value::Unsigned(4) => Ok(EdgeType::Specializes),
            _ => Err(SemanticError::InvalidField {
                field: "edge_type",
                message: format!("invalid discriminant: {:?}", val),
            }),
        }
    }
}

impl CapabilityEdge {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (1, Value::TextString(self.target.clone())),
            (2, self.edge_type.to_cbor()),
        ];
        if let Some(ref constraint) = self.constraint {
            entries.push((3, Value::TextString(constraint.clone())));
        }
        int_map(entries)
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let target = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SemanticError::MissingField("edge.target")),
        };
        let edge_type = EdgeType::from_cbor(
            int_map_get(val, 2).ok_or(SemanticError::MissingField("edge.edge_type"))?,
        )?;
        let constraint = match int_map_get(val, 3) {
            Some(Value::TextString(s)) => Some(s.clone()),
            _ => None,
        };
        Ok(Self {
            target,
            edge_type,
            constraint,
        })
    }
}

// ---------------------------------------------------------------------------
// Requirement / OutputSpec helpers
// ---------------------------------------------------------------------------

fn requirement_to_cbor(r: &Requirement) -> Value {
    let mut entries = vec![(1, Value::TextString(r.kind.clone()))];
    if r.optional {
        entries.push((2, Value::Bool(true)));
    }
    int_map(entries)
}

fn requirement_from_cbor(val: &Value) -> Result<Requirement, SemanticError> {
    let kind = match int_map_get(val, 1) {
        Some(Value::TextString(s)) => s.clone(),
        _ => return Err(SemanticError::MissingField("requirement.kind")),
    };
    let optional = match int_map_get(val, 2) {
        Some(Value::Bool(b)) => *b,
        _ => false,
    };
    Ok(Requirement { kind, optional })
}

fn output_spec_to_cbor(o: &OutputSpec) -> Value {
    let mut entries = vec![(1, Value::TextString(o.kind.clone()))];
    if !o.attributes.is_empty() {
        entries.push((
            2,
            Value::StrMap(
                o.attributes
                    .iter()
                    .map(|(k, v)| (k.clone(), metadata_value_to_cbor(v)))
                    .collect(),
            ),
        ));
    }
    int_map(entries)
}

fn output_spec_from_cbor(val: &Value) -> Result<OutputSpec, SemanticError> {
    let kind = match int_map_get(val, 1) {
        Some(Value::TextString(s)) => s.clone(),
        _ => return Err(SemanticError::MissingField("output.kind")),
    };
    let attributes = match int_map_get(val, 2) {
        Some(Value::StrMap(entries)) => {
            let mut map = HashMap::new();
            for (k, v) in entries {
                if let Some(mv) = metadata_value_from_cbor(v) {
                    map.insert(k.clone(), mv);
                }
            }
            map
        }
        _ => HashMap::new(),
    };
    Ok(OutputSpec { kind, attributes })
}

fn metadata_value_to_cbor(v: &MetadataValue) -> Value {
    match v {
        MetadataValue::Bool(b) => Value::Bool(*b),
        MetadataValue::Int(n) => Value::Unsigned(*n as u64),
        MetadataValue::Text(s) => Value::TextString(s.clone()),
        MetadataValue::Bytes(b) => Value::ByteString(b.clone()),
    }
}

fn metadata_value_from_cbor(v: &Value) -> Option<MetadataValue> {
    match v {
        Value::Bool(b) => Some(MetadataValue::Bool(*b)),
        Value::Unsigned(n) => Some(MetadataValue::Int(*n as i64)),
        Value::Negative(n) => Some(MetadataValue::Int(*n)),
        Value::TextString(s) => Some(MetadataValue::Text(s.clone())),
        Value::ByteString(b) => Some(MetadataValue::Bytes(b.clone())),
        _ => None,
    }
}
