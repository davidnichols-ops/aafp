//! Geographic location extension (namespace `"aafp.geo.v1"`).
//!
//! See AGENT_RECORD_EXTENSIONS.md §5 for the field specification.

use aafp_cbor::Value;
use crate::identity_v1::IdentityError;
use super::AgentRecordExtension;

/// Geographic location extension (key 11, namespace `"aafp.geo.v1"`).
///
/// All fields are optional for privacy — an agent may publish only
/// country/continent and omit coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoExtension {
    /// Approximate latitude in micro-degrees (lat * 1,000,000).
    /// Precision is intentionally coarse for privacy.
    pub latitude: i32,
    /// Approximate longitude in micro-degrees (lon * 1,000,000).
    pub longitude: i32,
    /// ISO 3166-2 region code (e.g., "US-CA").
    pub region: String,
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "DE", "JP").
    pub country_code: String,
    /// City name (optional, for finer-grained routing).
    pub city: Option<String>,
    /// Continent code (e.g., "NA", "EU", "AS").
    pub continent: Option<String>,
    /// Data residency constraints: jurisdiction where data MUST stay.
    pub data_residency: Option<String>,
}

impl AgentRecordExtension for GeoExtension {
    const NAMESPACE: &'static str = "aafp.geo.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        todo!("implement GeoExtension::to_cbor")
    }

    fn from_cbor(_val: &Value) -> Result<Self, IdentityError> {
        todo!("implement GeoExtension::from_cbor")
    }
}
