//! Capability versioning extension (Phase E4).
//!
//! Namespace: `"aafp.capver.v1"`. Per-capability semantic versions,
//! enabling queries like "version >= 4.1".

use std::collections::HashMap;

use aafp_cbor::Value;
use crate::identity_v1::IdentityError;
use super::AgentRecordExtension;

/// Semantic version (major.minor.patch).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Check if this version satisfies a minimum requirement.
    pub fn satisfies_min(&self, _min: &SemanticVersion) -> bool {
        todo!()
    }

    /// Check if this version is within a range [min, max].
    pub fn satisfies_range(&self, _min: &SemanticVersion, _max: &SemanticVersion) -> bool {
        todo!()
    }
}

/// Per-capability semantic version extension (key 11, namespace
/// "aafp.capver.v1").
///
/// CBOR encoding:
/// ```cbor
/// CapabilityVersionData = {
///     1: [ *{ 1: tstr, 2: SemanticVersion } ],  // versions
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityVersionExtension {
    /// Map: capability_name → SemanticVersion.
    pub versions: HashMap<String, SemanticVersion>,
}

impl AgentRecordExtension for CapabilityVersionExtension {
    const NAMESPACE: &'static str = "aafp.capver.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        todo!()
    }

    fn from_cbor(_val: &Value) -> Result<Self, IdentityError> {
        todo!()
    }
}
