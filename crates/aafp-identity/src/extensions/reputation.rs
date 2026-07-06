//! Reputation extension (Phase E4).
//!
//! Namespace: `"aafp.reputation.v1"`. **Self-reported reputation is NOT
//! trustworthy.** This extension carries only a self-claimed score and
//! references to third-party attestations. The actual trust score is
//! computed by the *discovering* agent from the referenced attestations.

use super::AgentRecordExtension;
use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// Reputation extension: self-claimed score and attestation references.
///
/// CBOR encoding:
/// ```cbor
/// ReputationExtensionData = {
///     ? 1: [ *tstr ],   // attestation_refs (SHA-256 hashes, hex)
///     ? 2: uint,        // self_claimed_score (0-100, unverified)
///     ? 3: [ *tstr ],   // sources (DHT keys / URLs)
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReputationExtension {
    /// Extension version (always 1 for v1).
    pub version: u64,
    /// References to attestation records. Each entry is
    /// SHA-256(attestation_bytes), hex-encoded.
    pub attestation_refs: Vec<String>,
    /// Self-claimed trust score (0-100). Treated as unverified by
    /// consumers. Useful only as a hint, never for ranking.
    pub self_claimed_score: Option<u8>,
    /// URLs or DHT keys where attestations can be fetched.
    pub sources: Vec<String>,
}

impl AgentRecordExtension for ReputationExtension {
    const NAMESPACE: &'static str = "aafp.reputation.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if !self.attestation_refs.is_empty() {
            entries.push((
                1,
                Value::Array(
                    self.attestation_refs
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        if let Some(score) = self.self_claimed_score {
            entries.push((2, Value::Unsigned(score as u64)));
        }
        if !self.sources.is_empty() {
            entries.push((
                3,
                Value::Array(
                    self.sources
                        .iter()
                        .map(|s| Value::TextString(s.clone()))
                        .collect(),
                ),
            ));
        }
        int_map(entries)
    }

    fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        Ok(Self {
            version: 1,
            attestation_refs: match int_map_get(val, 1) {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| match v {
                        Value::TextString(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
            self_claimed_score: match int_map_get(val, 2) {
                Some(Value::Unsigned(n)) => Some(*n as u8),
                _ => None,
            },
            sources: match int_map_get(val, 3) {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| match v {
                        Value::TextString(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_reputation_roundtrip() {
        let rep = ReputationExtension {
            version: 1,
            attestation_refs: vec!["abc123".into(), "def456".into()],
            self_claimed_score: Some(85),
            sources: vec!["dht://key1".into()],
        };
        let cbor = rep.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let rep2 = ReputationExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(rep, rep2);
    }

    #[test]
    fn test_reputation_minimal() {
        let rep = ReputationExtension {
            version: 1,
            self_claimed_score: Some(50),
            ..Default::default()
        };
        let cbor = rep.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let rep2 = ReputationExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(rep, rep2);
        assert!(rep2.attestation_refs.is_empty());
    }
}
