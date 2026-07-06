//! Capability dependency-graph edges (D1).
//!
//! See `SEMANTIC_CAPABILITY_GRAPHS.md` §3.1 for the edge semantics.

/// The type of a dependency edge between two capabilities.
///
/// Encoded in CBOR as a uint discriminant:
/// `Requires=0`, `Enables=1`, `Precedes=2`, `Alternative=3`,
/// `Specializes=4`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeType {
    /// The source capability requires the target to function.
    Requires,
    /// The source capability enables / unlocks the target.
    Enables,
    /// The source capability must run before the target.
    Precedes,
    /// The target is an alternative to the source.
    Alternative,
    /// The source is a specialization of the target.
    Specializes,
}

/// A dependency edge pointing from a `SemanticCapability` to another
/// capability (identified by name).
///
/// CBOR IntMap keys: 1: `target` (tstr), 2: `edge_type` (uint discriminant),
/// 3: `constraint` (optional tstr).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityEdge {
    /// The name of the target capability.
    pub target: String,
    /// The semantic relationship to the target.
    pub edge_type: EdgeType,
    /// Optional human-readable constraint description.
    pub constraint: Option<String>,
}

impl CapabilityEdge {
    /// Create a new edge with no constraint.
    pub fn new(target: impl Into<String>, edge_type: EdgeType) -> Self {
        Self {
            target: target.into(),
            edge_type,
            constraint: None,
        }
    }
}
