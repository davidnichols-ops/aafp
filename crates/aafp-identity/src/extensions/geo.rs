//! Geographic location extension (namespace `"aafp.geo.v1"`).
//!
//! See AGENT_RECORD_EXTENSIONS.md §5 for the field specification.

use super::AgentRecordExtension;
use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// Geographic location extension (key 11, namespace `"aafp.geo.v1"`).
///
/// All fields are optional for privacy — an agent may publish only
/// country/continent and omit coordinates.
///
/// CBOR encoding (inner data):
/// ```cbor
/// GeoData = {
///     ? 1: tstr,        // country (ISO 3166-1 alpha-2)
///     ? 2: tstr,        // region (ISO 3166-2)
///     ? 3: int,         // lat_micro_deg (latitude * 1,000,000)
///     ? 4: int,         // lon_micro_deg (longitude * 1,000,000)
///     ? 5: tstr,        // continent
///     ? 6: [ *tstr ],   // data_residency
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoExtension {
    /// Extension version (always 1 for v1).
    pub version: u64,
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "DE", "JP").
    pub country: Option<String>,
    /// ISO 3166-2 region code (e.g., "US-CA").
    pub region: Option<String>,
    /// Approximate latitude in micro-degrees (lat * 1,000,000).
    /// Precision is intentionally coarse for privacy.
    pub lat_micro_deg: Option<i32>,
    /// Approximate longitude in micro-degrees (lon * 1,000,000).
    pub lon_micro_deg: Option<i32>,
    /// Continent code (e.g., "NA", "EU", "AS").
    pub continent: Option<String>,
    /// Data residency constraints: jurisdictions where data MUST stay.
    /// e.g., `["EU", "US-CA"]` means data cannot leave EU or US-CA.
    pub data_residency: Vec<String>,
}

impl AgentRecordExtension for GeoExtension {
    const NAMESPACE: &'static str = "aafp.geo.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if let Some(c) = &self.country {
            entries.push((1, Value::TextString(c.clone())));
        }
        if let Some(r) = &self.region {
            entries.push((2, Value::TextString(r.clone())));
        }
        if let Some(lat) = self.lat_micro_deg {
            if lat >= 0 {
                entries.push((3, Value::Unsigned(lat as u64)));
            } else {
                entries.push((3, Value::Negative(lat as i64)));
            }
        }
        if let Some(lon) = self.lon_micro_deg {
            if lon >= 0 {
                entries.push((4, Value::Unsigned(lon as u64)));
            } else {
                entries.push((4, Value::Negative(lon as i64)));
            }
        }
        if let Some(cont) = &self.continent {
            entries.push((5, Value::TextString(cont.clone())));
        }
        if !self.data_residency.is_empty() {
            entries.push((
                6,
                Value::Array(
                    self.data_residency
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
            country: match int_map_get(val, 1) {
                Some(Value::TextString(s)) => Some(s.clone()),
                _ => None,
            },
            region: match int_map_get(val, 2) {
                Some(Value::TextString(s)) => Some(s.clone()),
                _ => None,
            },
            lat_micro_deg: match int_map_get(val, 3) {
                Some(Value::Negative(n)) => Some(*n as i32),
                Some(Value::Unsigned(n)) => Some(*n as i32),
                _ => None,
            },
            lon_micro_deg: match int_map_get(val, 4) {
                Some(Value::Negative(n)) => Some(*n as i32),
                Some(Value::Unsigned(n)) => Some(*n as i32),
                _ => None,
            },
            continent: match int_map_get(val, 5) {
                Some(Value::TextString(s)) => Some(s.clone()),
                _ => None,
            },
            data_residency: match int_map_get(val, 6) {
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
