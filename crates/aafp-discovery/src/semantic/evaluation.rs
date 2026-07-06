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
        todo!()
    }

    /// Resolve a flattened key to a `MetadataValue` (built-in attributes,
    /// then custom attributes).
    fn resolve_value(cap: &SemanticCapability, key: &str) -> Option<MetadataValue> {
        todo!()
    }

    /// Resolve a flattened key to a numeric `f64` (top-level fields, then
    /// custom integer attributes).
    fn resolve_numeric(cap: &SemanticCapability, key: &str) -> Option<f64> {
        todo!()
    }

    /// Resolve a flattened key to a `String` (text-valued attributes).
    fn resolve_text(cap: &SemanticCapability, key: &str) -> Option<String> {
        todo!()
    }
}

impl CapabilityQuery {
    /// Evaluate whether a `SemanticCapability` matches this query.
    ///
    /// Returns `true` only if the name matches and every filter passes.
    pub fn matches(&self, cap: &SemanticCapability) -> bool {
        todo!()
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
        todo!()
    }
}

impl RangeOp {
    /// Apply this operator to two `f64` operands.
    pub fn apply(&self, lhs: f64, rhs: f64) -> bool {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// CapabilityDht integration
// ---------------------------------------------------------------------------

impl crate::capability_dht::CapabilityDht {
    /// Find all agents whose `SemanticCapability` matches the query.
    ///
    /// Retrieves candidates by name from the DHT, then filters locally using
    /// [`CapabilityQuery::matches_descriptor`].
    #[allow(deprecated)]
    pub fn find_semantic(&self, query: &CapabilityQuery) -> Vec<&aafp_identity::AgentRecord> {
        todo!()
    }
}
