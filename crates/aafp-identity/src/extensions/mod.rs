//! AgentRecord extensions: versioned extension map at CBOR key 11.
//!
//! See AGENT_RECORD_EXTENSIONS.md §4 (architecture), §5 (fields),
//! §9 (concrete implementation).

pub mod attestation;
pub mod attestation_store;
pub mod cost;
pub mod geo;
pub mod heartbeat;
pub mod performance;
pub mod reputation;
pub mod reputation_scoring;
pub mod semantic;
pub mod version;

use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// A versioned extension that can be encoded into the AgentRecord
/// extension map (CBOR key 11).
///
/// Each extension has:
/// - A unique namespace string (e.g., `"aafp.geo.v1"`) used as the
///   outer map key.
/// - A semantic version number (independent per namespace).
/// - A CBOR encoding of its inner data.
///
/// The wire format for a single extension is:
/// ```cbor
/// Extension = {
///     1: uint,   // extension_version
///     2: any,    // extension_data (namespace-specific)
/// }
/// ```
pub trait AgentRecordExtension: Sized + Clone {
    /// Namespace string (e.g., `"aafp.geo.v1"`).
    const NAMESPACE: &'static str;

    /// Current extension version.
    const VERSION: u64;

    /// Encode the inner data to CBOR (NOT including the version wrapper).
    fn to_cbor(&self) -> Value;

    /// Decode the inner data from CBOR.
    fn from_cbor(val: &Value) -> Result<Self, IdentityError>;

    /// Encode as a full Extension wrapper `{1: version, 2: data}`.
    fn to_extension_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(Self::VERSION)),
            (2, self.to_cbor()),
        ])
    }

    /// Decode from a full Extension wrapper, checking the version field.
    fn from_extension_cbor(val: &Value) -> Result<Self, IdentityError> {
        let version = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            Some(other) => {
                return Err(IdentityError::InvalidField {
                    field: "extension_version",
                    message: format!("expected uint, got {:?}", other),
                });
            }
            None => return Err(IdentityError::MissingField("extension_version")),
        };
        if version != Self::VERSION {
            return Err(IdentityError::InvalidField {
                field: "extension_version",
                message: format!("expected {}, got {}", Self::VERSION, version),
            });
        }
        let data = int_map_get(val, 2).ok_or(IdentityError::MissingField("extension_data"))?;
        Self::from_cbor(data)
    }
}

// Re-export concrete extensions.
pub use attestation::{
    compute_reputation, delegate_attest_capability, verify_attestation_authorization, Attestation,
    AttestationData, AttestationError, ATTESTATION_DOMAIN_SEPARATOR, ATTESTATION_TYPE_V1,
};
pub use attestation_store::{AttestationKey, AttestationStore, AttestationStoreError};
pub use cost::CostExtension;
pub use geo::GeoExtension;
pub use heartbeat::{adaptive_ttl, HeartbeatExtension, HeartbeatTracker, HeartbeatUpdate};
pub use performance::PerformanceExtension;
pub use reputation::ReputationExtension;
pub use reputation_scoring::{
    Interaction, PerformanceHistory, ReputationConfig, ReputationScore, ReputationScoreEngine,
};
pub use semantic::SemanticExtension;
pub use version::{CapabilityVersionExtension, SemanticVersion};

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_geo_extension_roundtrip_full() {
        let geo = GeoExtension {
            version: 1,
            country: Some("US".into()),
            region: Some("US-CA".into()),
            lat_micro_deg: Some(37_774_900),
            lon_micro_deg: Some(-122_419_400),
            continent: Some("NA".into()),
            data_residency: vec!["US".into()],
        };
        let cbor = geo.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let geo2 = GeoExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(geo, geo2);
    }

    #[test]
    fn test_geo_extension_roundtrip_minimal() {
        let geo = GeoExtension {
            version: 1,
            country: Some("DE".into()),
            ..Default::default()
        };
        let cbor = geo.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let geo2 = GeoExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(geo, geo2);
        assert!(geo2.lat_micro_deg.is_none());
        assert!(geo2.data_residency.is_empty());
    }

    #[test]
    fn test_geo_extension_negative_coords() {
        let geo = GeoExtension {
            version: 1,
            lat_micro_deg: Some(-33_868_800),
            lon_micro_deg: Some(151_209_300),
            ..Default::default()
        };
        let cbor = geo.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let geo2 = GeoExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(geo2.lat_micro_deg, Some(-33_868_800));
        assert_eq!(geo2.lon_micro_deg, Some(151_209_300));
    }

    #[test]
    fn test_perf_extension_roundtrip_full() {
        let perf = PerformanceExtension {
            version: 1,
            avg_latency_ms: Some(14),
            p99_latency_ms: Some(45),
            throughput_rps: Some(1000),
            max_batch_size: Some(32),
            uptime_bps: Some(9999),
            window_secs: 3600,
            updated_at: 1700000000,
        };
        let cbor = perf.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let perf2 = PerformanceExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(perf, perf2);
    }

    #[test]
    fn test_perf_extension_roundtrip_minimal() {
        let perf = PerformanceExtension {
            version: 1,
            avg_latency_ms: Some(50),
            throughput_rps: Some(500),
            ..Default::default()
        };
        let cbor = perf.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let perf2 = PerformanceExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(perf, perf2);
        assert!(perf2.p99_latency_ms.is_none());
        assert_eq!(perf2.window_secs, 0);
    }

    #[test]
    fn test_extension_version_mismatch() {
        let cbor = int_map(vec![(1, Value::Unsigned(99)), (2, int_map(vec![]))]);
        let result = GeoExtension::from_extension_cbor(&cbor);
        assert!(result.is_err());
    }
}
