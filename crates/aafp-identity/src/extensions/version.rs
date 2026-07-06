//! Capability versioning extension (Phase E4).
//!
//! Namespace: `"aafp.capver.v1"`. Per-capability semantic versions,
//! enabling queries like "version >= 4.1".

use std::collections::HashMap;

use super::AgentRecordExtension;
use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// Semantic version (major.minor.patch).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Check if this version satisfies a minimum requirement.
    pub fn satisfies_min(&self, min: &SemanticVersion) -> bool {
        self >= min
    }

    /// Check if this version is within a range [min, max].
    pub fn satisfies_range(&self, min: &SemanticVersion, max: &SemanticVersion) -> bool {
        self >= min && self <= max
    }

    /// Encode as CBOR: {1: major, 2: minor, 3: patch}.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.major as u64)),
            (2, Value::Unsigned(self.minor as u64)),
            (3, Value::Unsigned(self.patch as u64)),
        ])
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        Ok(Self {
            major: match int_map_get(val, 1) {
                Some(Value::Unsigned(n)) => *n as u32,
                _ => 0,
            },
            minor: match int_map_get(val, 2) {
                Some(Value::Unsigned(n)) => *n as u32,
                _ => 0,
            },
            patch: match int_map_get(val, 3) {
                Some(Value::Unsigned(n)) => *n as u32,
                _ => 0,
            },
        })
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
    /// Extension version (always 1 for v1).
    pub version: u64,
    /// Map: capability_name → SemanticVersion.
    pub versions: HashMap<String, SemanticVersion>,
}

impl AgentRecordExtension for CapabilityVersionExtension {
    const NAMESPACE: &'static str = "aafp.capver.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        let entries: Vec<Value> = self
            .versions
            .iter()
            .map(|(name, ver)| {
                int_map(vec![
                    (1, Value::TextString(name.clone())),
                    (2, ver.to_cbor()),
                ])
            })
            .collect();
        int_map(vec![(1, Value::Array(entries))])
    }

    fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let mut versions = HashMap::new();
        if let Some(Value::Array(arr)) = int_map_get(val, 1) {
            for entry in arr {
                if let Some(Value::TextString(s)) = int_map_get(entry, 1) {
                    if let Some(ver_val) = int_map_get(entry, 2) {
                        let ver = SemanticVersion::from_cbor(ver_val)?;
                        versions.insert(s.clone(), ver);
                    }
                }
            }
        }
        Ok(Self {
            version: 1,
            versions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_semver_ordering() {
        let v1 = SemanticVersion::new(1, 0, 0);
        let v2 = SemanticVersion::new(1, 1, 0);
        let v3 = SemanticVersion::new(2, 0, 0);
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v2.satisfies_min(&v1));
        assert!(!v1.satisfies_min(&v2));
        assert!(v2.satisfies_range(&v1, &v3));
    }

    #[test]
    fn test_capver_roundtrip() {
        let mut versions = HashMap::new();
        versions.insert("inference".into(), SemanticVersion::new(2, 1, 0));
        versions.insert("translation".into(), SemanticVersion::new(1, 0, 5));
        let ext = CapabilityVersionExtension {
            version: 1,
            versions,
        };
        let cbor = ext.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let ext2 = CapabilityVersionExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(ext, ext2);
    }
}
