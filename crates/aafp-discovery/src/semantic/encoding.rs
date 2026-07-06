//! CBOR encoding/decoding for `SemanticCapability` and its components (D1).
//!
//! Encoding strategy: `SemanticCapability` is encoded as a CBOR IntMap with
//! integer keys 1-9, then embedded in a `CapabilityDescriptor`'s metadata
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
//!
//! See `SCG_D1_D2_DESCRIPTOR_QUERY.md` §"CBOR key assignment" for the full
//! key table.

use super::capability::{
    CapabilityAttributes, CapabilityCategory, CostModel, GeoConstraint, HardwareSpec, Modality,
    PerformanceProfile, QualityMetrics, SemanticCapability, SemanticError, SemanticVersion,
};
use super::edge::{CapabilityEdge, EdgeType};

// ---------------------------------------------------------------------------
// SemanticCapability
// ---------------------------------------------------------------------------

impl SemanticCapability {
    /// Encode to a CBOR `Value` (IntMap with keys 1-9).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// CapabilityCategory
// ---------------------------------------------------------------------------

impl CapabilityCategory {
    /// Encode to a CBOR `Value` (uint discriminant, or uint + tstr for
    /// `Custom`).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// Modality
// ---------------------------------------------------------------------------

impl Modality {
    /// Encode to a CBOR `Value` (uint discriminant).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// HardwareSpec
// ---------------------------------------------------------------------------

impl HardwareSpec {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// CapabilityAttributes
// ---------------------------------------------------------------------------

impl CapabilityAttributes {
    /// Encode to a CBOR `Value` (IntMap keys 1-6).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// PerformanceProfile
// ---------------------------------------------------------------------------

impl PerformanceProfile {
    /// Encode to a CBOR `Value` (IntMap keys 1-4, floats scaled to uint).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// QualityMetrics
// ---------------------------------------------------------------------------

impl QualityMetrics {
    /// Encode to a CBOR `Value` (IntMap keys 1-4, floats scaled to uint).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// CostModel
// ---------------------------------------------------------------------------

impl CostModel {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// SemanticVersion
// ---------------------------------------------------------------------------

impl SemanticVersion {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// GeoConstraint
// ---------------------------------------------------------------------------

impl GeoConstraint {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// CapabilityEdge / EdgeType
// ---------------------------------------------------------------------------

impl EdgeType {
    /// Encode to a CBOR `Value` (uint discriminant).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}

impl CapabilityEdge {
    /// Encode to a CBOR `Value` (IntMap keys 1-3).
    pub fn to_cbor(&self) -> aafp_cbor::Value {
        todo!()
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &aafp_cbor::Value) -> Result<Self, SemanticError> {
        todo!()
    }
}
