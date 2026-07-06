//! `CapabilityQuery` builder and filter types (D2).
//!
//! See `SEMANTIC_CAPABILITY_GRAPHS.md` §4 and the builder prompt
//! `SCG_D1_D2_DESCRIPTOR_QUERY.md` for the query language specification.

use super::capability::{MetadataValue, SemanticVersion};

/// Comparison operator for range filters.
#[derive(Clone, Debug, PartialEq)]
pub enum RangeOp {
    /// `value < operand`
    LessThan,
    /// `value <= operand`
    LessThanOrEqual,
    /// `value > operand`
    GreaterThan,
    /// `value >= operand`
    GreaterThanOrEqual,
}

/// A single filter predicate applied to a capability's attributes or
/// metadata.
///
/// See §4.1 of the design doc.
#[derive(Clone, Debug, PartialEq)]
pub enum QueryFilter {
    /// Exact match against a metadata/attribute value (e.g. `language = "en"`).
    Equality {
        /// The flattened attribute key (see key resolution rules in §4.3).
        key: String,
        /// The value to compare against.
        value: MetadataValue,
    },
    /// Numeric range comparison (e.g. `latency < 40ms`).
    Range {
        /// The flattened attribute key.
        key: String,
        /// The comparison operator.
        op: RangeOp,
        /// The operand (compared as `f64`).
        value: f64,
    },
    /// Set membership (e.g. `language in ["en", "fr"]`).
    In {
        /// The flattened attribute key.
        key: String,
        /// The set of acceptable values.
        values: Vec<MetadataValue>,
    },
    /// Existence check (e.g. `has hardware.gpu`).
    Exists {
        /// The flattened attribute key.
        key: String,
    },
    /// Lightweight semantic/substring match (e.g. `"translation"` matches
    /// `"translate"`). Uses case-insensitive substring matching — no full
    /// ontology.
    SemanticMatch {
        /// The flattened attribute key.
        key: String,
        /// The substring pattern to match.
        pattern: String,
    },
}

/// Performance requirements.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PerformanceFilter {
    /// Maximum acceptable average latency in milliseconds.
    pub max_avg_latency_ms: Option<f64>,
    /// Maximum acceptable p99 latency in milliseconds.
    pub max_p99_latency_ms: Option<f64>,
    /// Minimum acceptable throughput in requests per second.
    pub min_throughput_rps: Option<f64>,
    /// Minimum acceptable batch size.
    pub min_batch_size: Option<u32>,
}

/// Quality requirements.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QualityFilter {
    /// Minimum acceptable trust score (0-100).
    pub min_trust_score: Option<u8>,
    /// Minimum acceptable accuracy (0.0-1.0).
    pub min_accuracy: Option<f64>,
    /// Minimum acceptable uptime percentage (0.0-100.0).
    pub min_uptime_pct: Option<f64>,
}

/// Cost constraints.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CostFilter {
    /// Maximum acceptable per-invocation cost in micro-USD.
    pub max_per_invocation_micro_usd: Option<u64>,
    /// Maximum acceptable per-token cost in micro-USD.
    pub max_per_token_micro_usd: Option<u64>,
    /// If true, require a free tier to be available.
    pub require_free_tier: bool,
}

/// Geographic constraints.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoFilter {
    /// Required region code (e.g. `"na"`, `"eu"`).
    pub region: Option<String>,
    /// Required country (ISO 3166-1 alpha-2).
    pub country: Option<String>,
}

/// Version constraints (§7.2).
#[derive(Clone, Debug, PartialEq)]
pub enum VersionFilter {
    /// Match exactly this version.
    Exact(SemanticVersion),
    /// Match any version greater than or equal to this.
    Minimum(SemanticVersion),
    /// Match any version within the inclusive range `[min, max]`.
    Range {
        /// Minimum (inclusive) version.
        min: SemanticVersion,
        /// Maximum (inclusive) version.
        max: SemanticVersion,
    },
}

/// A structured capability query.
///
/// The `name` field is required and is used for the DHT lookup; all other
/// fields are optional local filters evaluated after retrieval (§4.3).
#[derive(Clone, Debug, PartialEq)]
pub struct CapabilityQuery {
    /// The capability name to look up in the DHT.
    pub name: String,
    /// Attribute/metadata filter predicates.
    pub filters: Vec<QueryFilter>,
    /// Optional performance requirements.
    pub performance: Option<PerformanceFilter>,
    /// Optional quality requirements.
    pub quality: Option<QualityFilter>,
    /// Optional cost constraints.
    pub cost: Option<CostFilter>,
    /// Optional geographic constraints.
    pub geo: Option<GeoFilter>,
    /// Optional version constraints.
    pub version: Option<VersionFilter>,
}

impl CapabilityQuery {
    /// Create a new query for the given capability name.
    pub fn new(name: impl Into<String>) -> Self {
        todo!()
    }

    /// Add an attribute/metadata filter predicate (builder pattern).
    pub fn with_filter(mut self, filter: QueryFilter) -> Self {
        todo!()
    }

    /// Set performance requirements (builder pattern).
    pub fn with_performance(mut self, perf: PerformanceFilter) -> Self {
        todo!()
    }

    /// Set quality requirements (builder pattern).
    pub fn with_quality(mut self, qual: QualityFilter) -> Self {
        todo!()
    }

    /// Set cost constraints (builder pattern).
    pub fn with_cost(mut self, cost: CostFilter) -> Self {
        todo!()
    }

    /// Set geographic constraints (builder pattern).
    pub fn with_geo(mut self, geo: GeoFilter) -> Self {
        todo!()
    }

    /// Set version constraints (builder pattern).
    pub fn with_version(mut self, ver: VersionFilter) -> Self {
        todo!()
    }

    /// Terminal builder method — returns `self`. Follows the design-doc
    /// pattern for ergonomic query construction.
    pub fn build(self) -> Self {
        todo!()
    }
}

impl VersionFilter {
    /// Returns true if `ver` satisfies this version constraint.
    pub fn matches(&self, ver: &SemanticVersion) -> bool {
        todo!()
    }
}
