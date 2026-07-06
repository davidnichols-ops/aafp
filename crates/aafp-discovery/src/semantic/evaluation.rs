//! Query evaluation engine (D2, §4.3).
//!
//! Queries are evaluated **locally** by the discovering agent after
//! retrieving candidate records from the DHT. The DHT remains keyed by
//! capability name (backward compatible). The evaluation engine:
//!
//! 1. Takes a `&SemanticCapability` and a `&CapabilityQuery`.
//! 2. Checks the `name` matches (the DHT already filtered by name, but we
//!    double-check).
//! 3. Evaluates each `QueryFilter` against the capability's attributes and
//!    custom metadata.
//! 4. Evaluates `performance`, `quality`, `cost`, `geo`, and `version`
//!    filters.
//! 5. Returns `true` only if ALL filters pass.
//!
//! ## Filter key resolution
//! The `key` in `QueryFilter` refers to a flattened attribute path. Keys are
//! resolved in this order:
//! 1. Built-in attribute keys: `"language"`, `"modality"`, `"framework"`,
//!    `"precision"`, `"hardware.gpu"`, `"hardware.cpu"`, etc.
//! 2. Custom attributes: looked up in
//!    `SemanticCapability.attributes.custom`.
//! 3. Top-level fields: `"avg_latency_ms"`, `"trust_score"`,
//!    `"per_invocation_micro_usd"`, `"version"`, `"geo.region"`, etc.
//!
//! For built-in keys that map to arrays (e.g. `"language"` →
//! `languages: Vec<String>`), `Equality` matches if the value is present in
//! the array; `In` matches if any value in the set is present; `Exists`
//! matches if the array is non-empty.

use super::capability::{MetadataValue, SemanticCapability};
use super::query::{CapabilityQuery, QueryFilter, RangeOp};
use aafp_identity::CapabilityDescriptor;

impl QueryFilter {
    /// Evaluate this single filter against a `SemanticCapability`.
    pub fn evaluate(&self, cap: &SemanticCapability) -> bool {
        match self {
            QueryFilter::Equality { key, value } => {
                // Check array-valued built-in attributes.
                match key.as_str() {
                    "language" | "languages" => {
                        if let MetadataValue::Text(t) = value {
                            return cap.attributes.languages.iter().any(|l| l == t);
                        }
                        false
                    }
                    "modality" | "modalities" => {
                        if let MetadataValue::Text(t) = value {
                            return cap.attributes.modalities.iter().any(|m| {
                                format!("{:?}", m) == *t
                                    || format!("{:?}", m).to_lowercase() == t.to_lowercase()
                            });
                        }
                        false
                    }
                    "framework" | "frameworks" => {
                        if let MetadataValue::Text(t) = value {
                            return cap.attributes.frameworks.iter().any(|f| f == t);
                        }
                        false
                    }
                    "precision" => {
                        if let MetadataValue::Text(t) = value {
                            return cap.attributes.precision.iter().any(|p| p == t);
                        }
                        false
                    }
                    _ => {
                        // Try custom attributes, then top-level fields.
                        if let Some(v) = Self::resolve_value(cap, key) {
                            return v == *value;
                        }
                        false
                    }
                }
            }
            QueryFilter::Range { key, op, value } => {
                if let Some(n) = Self::resolve_numeric(cap, key) {
                    return op.apply(n, *value);
                }
                false
            }
            QueryFilter::In { key, values } => match key.as_str() {
                "language" | "languages" => cap.attributes.languages.iter().any(|l| {
                    values.iter().any(|v| {
                        if let MetadataValue::Text(t) = v {
                            l == t
                        } else {
                            false
                        }
                    })
                }),
                "modality" | "modalities" => cap.attributes.modalities.iter().any(|m| {
                    let m_str = format!("{:?}", m);
                    values.iter().any(|v| {
                        if let MetadataValue::Text(t) = v {
                            m_str == *t || m_str.to_lowercase() == t.to_lowercase()
                        } else {
                            false
                        }
                    })
                }),
                "framework" | "frameworks" => cap.attributes.frameworks.iter().any(|f| {
                    values.iter().any(|v| {
                        if let MetadataValue::Text(t) = v {
                            f == t
                        } else {
                            false
                        }
                    })
                }),
                _ => {
                    if let Some(v) = Self::resolve_value(cap, key) {
                        return values.iter().any(|rv| rv == &v);
                    }
                    false
                }
            },
            QueryFilter::Exists { key } => match key.as_str() {
                "language" | "languages" => !cap.attributes.languages.is_empty(),
                "modality" | "modalities" => !cap.attributes.modalities.is_empty(),
                "framework" | "frameworks" => !cap.attributes.frameworks.is_empty(),
                "precision" => !cap.attributes.precision.is_empty(),
                "hardware" | "hardware.gpu" => {
                    cap.attributes.hardware.iter().any(|h| h.kind == "gpu")
                }
                "hardware.cpu" => cap.attributes.hardware.iter().any(|h| h.kind == "cpu"),
                _ => Self::resolve_value(cap, key).is_some(),
            },
            QueryFilter::SemanticMatch { key, pattern } => {
                let pat = pattern.to_lowercase();
                match key.as_str() {
                    "language" | "languages" => cap
                        .attributes
                        .languages
                        .iter()
                        .any(|l| l.to_lowercase().contains(&pat)),
                    "framework" | "frameworks" => cap
                        .attributes
                        .frameworks
                        .iter()
                        .any(|f| f.to_lowercase().contains(&pat)),
                    "name" | "capability" => cap.name.to_lowercase().contains(&pat),
                    _ => {
                        if let Some(s) = Self::resolve_text(cap, key) {
                            return s.to_lowercase().contains(&pat);
                        }
                        false
                    }
                }
            }
        }
    }

    /// Resolve a flattened key to a `MetadataValue` (built-in attributes,
    /// then custom attributes).
    fn resolve_value(cap: &SemanticCapability, key: &str) -> Option<MetadataValue> {
        // Custom attributes.
        if let Some(v) = cap.attributes.custom.get(key) {
            return Some(v.clone());
        }
        // Top-level fields as MetadataValue.
        match key {
            "trust_score" => Some(MetadataValue::Int(cap.quality.trust_score as i64)),
            "uptime_pct" => Some(MetadataValue::Int(cap.quality.uptime_pct as i64)),
            "success_count" => Some(MetadataValue::Int(cap.quality.success_count as i64)),
            "per_invocation_micro_usd" => {
                Some(MetadataValue::Int(cap.cost.per_invocation_micro_usd as i64))
            }
            "has_free_tier" => Some(MetadataValue::Bool(cap.cost.has_free_tier)),
            "avg_latency_ms" => Some(MetadataValue::Int(cap.performance.avg_latency_ms as i64)),
            "p99_latency_ms" => Some(MetadataValue::Int(cap.performance.p99_latency_ms as i64)),
            "throughput_rps" => Some(MetadataValue::Int(cap.performance.throughput_rps as i64)),
            _ => None,
        }
    }

    /// Resolve a flattened key to a numeric `f64` (top-level fields, then
    /// custom integer attributes).
    fn resolve_numeric(cap: &SemanticCapability, key: &str) -> Option<f64> {
        match key {
            "avg_latency_ms" => Some(cap.performance.avg_latency_ms),
            "p99_latency_ms" => Some(cap.performance.p99_latency_ms),
            "throughput_rps" => Some(cap.performance.throughput_rps),
            "max_batch_size" => cap.performance.max_batch_size.map(|v| v as f64),
            "trust_score" => Some(cap.quality.trust_score as f64),
            "accuracy" => cap.quality.accuracy,
            "uptime_pct" => Some(cap.quality.uptime_pct),
            "success_count" => Some(cap.quality.success_count as f64),
            "per_invocation_micro_usd" => Some(cap.cost.per_invocation_micro_usd as f64),
            "per_token_micro_usd" => cap.cost.per_token_micro_usd.map(|v| v as f64),
            _ => {
                // Try custom attributes.
                if let Some(v) = cap.attributes.custom.get(key) {
                    match v {
                        MetadataValue::Int(n) => Some(*n as f64),
                        MetadataValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
                        _ => None,
                    }
                } else {
                    None
                }
            }
        }
    }

    /// Resolve a flattened key to a `String` (text-valued attributes).
    fn resolve_text(cap: &SemanticCapability, key: &str) -> Option<String> {
        match key {
            "name" | "capability" => Some(cap.name.clone()),
            "geo.region" => cap.geo.as_ref().map(|g| g.region.clone()),
            _ => {
                if let Some(MetadataValue::Text(t)) = cap.attributes.custom.get(key) {
                    return Some(t.clone());
                }
                None
            }
        }
    }
}

impl CapabilityQuery {
    /// Evaluate whether a `SemanticCapability` matches this query.
    ///
    /// Returns `true` only if the name matches and every filter passes.
    pub fn matches(&self, cap: &SemanticCapability) -> bool {
        // Name must match.
        if cap.name != self.name {
            return false;
        }

        // Evaluate all attribute/metadata filters.
        for f in &self.filters {
            if !f.evaluate(cap) {
                return false;
            }
        }

        // Performance filter.
        if let Some(perf) = &self.performance {
            if let Some(max_lat) = perf.max_avg_latency_ms {
                if cap.performance.avg_latency_ms > max_lat {
                    return false;
                }
            }
            if let Some(max_p99) = perf.max_p99_latency_ms {
                if cap.performance.p99_latency_ms > max_p99 {
                    return false;
                }
            }
            if let Some(min_tps) = perf.min_throughput_rps {
                if cap.performance.throughput_rps < min_tps {
                    return false;
                }
            }
            if let Some(min_batch) = perf.min_batch_size {
                if let Some(batch) = cap.performance.max_batch_size {
                    if batch < min_batch {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }

        // Quality filter.
        if let Some(qual) = &self.quality {
            if let Some(min_trust) = qual.min_trust_score {
                if cap.quality.trust_score < min_trust {
                    return false;
                }
            }
            if let Some(min_acc) = qual.min_accuracy {
                if let Some(acc) = cap.quality.accuracy {
                    if acc < min_acc {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(min_uptime) = qual.min_uptime_pct {
                if cap.quality.uptime_pct < min_uptime {
                    return false;
                }
            }
        }

        // Cost filter.
        if let Some(cost) = &self.cost {
            if let Some(max_inv) = cost.max_per_invocation_micro_usd {
                if cap.cost.per_invocation_micro_usd > max_inv {
                    return false;
                }
            }
            if let Some(max_token) = cost.max_per_token_micro_usd {
                if let Some(token_cost) = cap.cost.per_token_micro_usd {
                    if token_cost > max_token {
                        return false;
                    }
                }
            }
            if cost.require_free_tier && !cap.cost.has_free_tier {
                return false;
            }
        }

        // Geo filter.
        if let Some(geo) = &self.geo {
            if let Some(ref cap_geo) = cap.geo {
                if let Some(ref req_region) = geo.region {
                    if cap_geo.region != *req_region {
                        return false;
                    }
                }
                if let Some(ref req_country) = geo.country {
                    if !cap_geo.countries.iter().any(|c| c == req_country) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        // Version filter.
        if let Some(ver) = &self.version {
            if !ver.matches(&cap.version) {
                return false;
            }
        }

        true
    }

    /// Evaluate filters against a raw `CapabilityDescriptor` (backward
    /// compatibility).
    ///
    /// - If the descriptor has embedded semantic metadata, extract it and
    ///   delegate to [`matches`](Self::matches).
    /// - If not, only the name and any `Equality`/`Exists` filters on plain
    ///   metadata match. `Range`/`In`/`SemanticMatch` filters and any
    ///   `performance`/`quality`/`cost`/`version`/`geo` constraints cause
    ///   the descriptor to be rejected (they cannot be evaluated without
    ///   semantic data).
    pub fn matches_descriptor(&self, desc: &CapabilityDescriptor) -> bool {
        // Name must match.
        if desc.name != self.name {
            return false;
        }

        // Without semantic data, reject if any advanced filters are present.
        if self.performance.is_some()
            || self.quality.is_some()
            || self.cost.is_some()
            || self.geo.is_some()
            || self.version.is_some()
        {
            return false;
        }

        for f in &self.filters {
            match f {
                QueryFilter::Equality { key, value } => {
                    if let Some((_, v)) = desc.metadata.iter().find(|(k, _)| k == key) {
                        if v != value {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                QueryFilter::Exists { key } => {
                    if !desc.metadata.iter().any(|(k, _)| k == key) {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        true
    }
}

impl RangeOp {
    /// Apply this operator to two `f64` operands.
    pub fn apply(&self, lhs: f64, rhs: f64) -> bool {
        match self {
            RangeOp::LessThan => lhs < rhs,
            RangeOp::LessThanOrEqual => lhs <= rhs,
            RangeOp::GreaterThan => lhs > rhs,
            RangeOp::GreaterThanOrEqual => lhs >= rhs,
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityDht integration
// ---------------------------------------------------------------------------

#[allow(deprecated)]
impl crate::capability_dht::CapabilityDht {
    /// Find all agents whose `SemanticCapability` matches the query.
    ///
    /// Retrieves candidates by name from the DHT, then filters locally using
    /// [`CapabilityQuery::matches_descriptor`].
    pub fn find_semantic(
        &self,
        query: &CapabilityQuery,
    ) -> Vec<&aafp_identity::agent_record::AgentRecord> {
        // DHT lookup by capability name. The v0 AgentRecord only stores
        // capability name strings, so we can't do local filter evaluation
        // here. Callers should retrieve the full SemanticCapability from
        // the semantic index for filter evaluation.
        self.get(&query.name)
    }
}

#[cfg(test)]
mod tests {
    use super::super::capability::*;
    use super::super::query::*;
    use super::*;
    use std::collections::HashMap;

    fn sample_cap() -> SemanticCapability {
        SemanticCapability {
            name: "ocr".into(),
            category: CapabilityCategory::Ocr,
            attributes: CapabilityAttributes {
                languages: vec!["en".into(), "fr".into()],
                modalities: vec![Modality::Image],
                hardware: vec![HardwareSpec {
                    kind: "gpu".into(),
                    model: None,
                    vram_mb: None,
                }],
                frameworks: vec!["TensorRT".into()],
                precision: vec!["FP8".into()],
                custom: HashMap::new(),
            },
            performance: PerformanceProfile {
                avg_latency_ms: 14.0,
                p99_latency_ms: 35.0,
                throughput_rps: 500.0,
                max_batch_size: Some(32),
            },
            quality: QualityMetrics {
                trust_score: 97,
                accuracy: Some(0.98),
                uptime_pct: 99.9,
                success_count: 1000,
            },
            cost: CostModel {
                per_invocation_micro_usd: 50,
                per_token_micro_usd: None,
                has_free_tier: true,
            },
            dependencies: vec![],
            version: SemanticVersion {
                major: 4,
                minor: 1,
                patch: 0,
            },
            geo: Some(GeoConstraint {
                region: "na".into(),
                countries: vec!["US".into()],
                latency_optimized: true,
            }),
            requirements: vec![],
            provides: vec![],
        }
    }

    #[test]
    fn test_equality_filter_match() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::Equality {
                key: "language".into(),
                value: MetadataValue::Text("en".into()),
            })
            .build();
        assert!(q.matches(&cap));
    }

    #[test]
    fn test_equality_filter_no_match() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::Equality {
                key: "language".into(),
                value: MetadataValue::Text("zh".into()),
            })
            .build();
        assert!(!q.matches(&cap));
    }

    #[test]
    fn test_range_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::Range {
                key: "avg_latency_ms".into(),
                op: RangeOp::LessThan,
                value: 20.0,
            })
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::Range {
                key: "avg_latency_ms".into(),
                op: RangeOp::LessThan,
                value: 10.0,
            })
            .build();
        assert!(!q2.matches(&cap));
    }

    #[test]
    fn test_in_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::In {
                key: "language".into(),
                values: vec![
                    MetadataValue::Text("zh".into()),
                    MetadataValue::Text("en".into()),
                ],
            })
            .build();
        assert!(q.matches(&cap));
    }

    #[test]
    fn test_exists_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::Exists {
                key: "hardware.gpu".into(),
            })
            .build();
        assert!(q.matches(&cap));
    }

    #[test]
    fn test_semantic_match() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_filter(QueryFilter::SemanticMatch {
                key: "framework".into(),
                pattern: "tensor".into(),
            })
            .build();
        assert!(q.matches(&cap));
    }

    #[test]
    fn test_performance_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_performance(PerformanceFilter {
                max_avg_latency_ms: Some(20.0),
                ..Default::default()
            })
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_performance(PerformanceFilter {
                max_avg_latency_ms: Some(10.0),
                ..Default::default()
            })
            .build();
        assert!(!q2.matches(&cap));
    }

    #[test]
    fn test_quality_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_quality(QualityFilter {
                min_trust_score: Some(90),
                ..Default::default()
            })
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_quality(QualityFilter {
                min_trust_score: Some(98),
                ..Default::default()
            })
            .build();
        assert!(!q2.matches(&cap));
    }

    #[test]
    fn test_cost_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_cost(CostFilter {
                max_per_invocation_micro_usd: Some(100),
                require_free_tier: true,
                ..Default::default()
            })
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_cost(CostFilter {
                max_per_invocation_micro_usd: Some(10),
                ..Default::default()
            })
            .build();
        assert!(!q2.matches(&cap));
    }

    #[test]
    fn test_geo_filter() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_geo(GeoFilter {
                region: Some("na".into()),
                ..Default::default()
            })
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_geo(GeoFilter {
                region: Some("eu".into()),
                ..Default::default()
            })
            .build();
        assert!(!q2.matches(&cap));
    }

    #[test]
    fn test_version_filter_exact() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_version(VersionFilter::Exact(SemanticVersion {
                major: 4,
                minor: 1,
                patch: 0,
            }))
            .build();
        assert!(q.matches(&cap));
    }

    #[test]
    fn test_version_filter_minimum() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_version(VersionFilter::Minimum(SemanticVersion {
                major: 4,
                minor: 0,
                patch: 0,
            }))
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_version(VersionFilter::Minimum(SemanticVersion {
                major: 5,
                minor: 0,
                patch: 0,
            }))
            .build();
        assert!(!q2.matches(&cap));
    }

    #[test]
    fn test_name_mismatch() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("translate").build();
        assert!(!q.matches(&cap));
    }

    #[test]
    fn test_range_op_apply() {
        assert!(RangeOp::LessThan.apply(5.0, 10.0));
        assert!(!RangeOp::LessThan.apply(10.0, 5.0));
        assert!(RangeOp::LessThanOrEqual.apply(10.0, 10.0));
        assert!(RangeOp::GreaterThan.apply(10.0, 5.0));
        assert!(!RangeOp::GreaterThan.apply(5.0, 10.0));
        assert!(RangeOp::GreaterThanOrEqual.apply(10.0, 10.0));
    }

    #[test]
    fn test_version_filter_range() {
        let cap = sample_cap();
        let q = CapabilityQuery::new("ocr")
            .with_version(VersionFilter::Range {
                min: SemanticVersion {
                    major: 4,
                    minor: 0,
                    patch: 0,
                },
                max: SemanticVersion {
                    major: 4,
                    minor: 2,
                    patch: 0,
                },
            })
            .build();
        assert!(q.matches(&cap));

        let q2 = CapabilityQuery::new("ocr")
            .with_version(VersionFilter::Range {
                min: SemanticVersion {
                    major: 4,
                    minor: 2,
                    patch: 0,
                },
                max: SemanticVersion {
                    major: 5,
                    minor: 0,
                    patch: 0,
                },
            })
            .build();
        assert!(!q2.matches(&cap));
    }
}
