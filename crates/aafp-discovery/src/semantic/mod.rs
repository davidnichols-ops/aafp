//! Semantic Capability Graphs (Track U, Phases D1-D2).
//!
//! This module groups the scaffolding for the extended `SemanticCapability`
//! descriptor (D1) and the `CapabilityQuery` builder + evaluation engine (D2).
//!
//! ## Submodules
//! - [`capability`] — `SemanticCapability` and its component structs/enums.
//! - [`edge`] — `CapabilityEdge` and `EdgeType` for the dependency graph.
//! - [`query`] — `CapabilityQuery`, `QueryFilter`, and filter structs.
//! - [`encoding`] — CBOR encoding/decoding for `SemanticCapability`.
//! - [`evaluation`] — local query evaluation engine.
//! - [`planner`] — `CapabilityPlanner` trait and `HeuristicPlanner` (D5).
//! - [`bridge_capabilities`] — canonical descriptors for the 11 internet
//!   bridge capabilities (D6).

pub mod bridge_capabilities;
pub mod capability;
pub mod edge;
pub mod encoding;
pub mod evaluation;
pub mod planner;
pub mod query;

pub use capability::{
    CapabilityAttributes, CapabilityCategory, CostModel, GeoConstraint, HardwareSpec, Modality,
    PerformanceProfile, QualityMetrics, SemanticCapability, SemanticVersion,
};
pub use edge::{CapabilityEdge, EdgeType};
pub use query::{
    CapabilityQuery, CostFilter, GeoFilter, PerformanceFilter, QualityFilter, QueryFilter,
    RangeOp, VersionFilter,
};
