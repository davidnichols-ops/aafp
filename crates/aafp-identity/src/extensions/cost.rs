//! Cost model extension (Phase E4).
//!
//! Namespace: `"aafp.cost.v1"`. Pricing information for cost-aware agent
//! selection. All monetary values are in micro-USD (1 USD = 1,000,000
//! micro-USD) to avoid floating point on the wire.

use super::AgentRecordExtension;
use crate::identity_v1::IdentityError;
use aafp_cbor::{int_map, int_map_get, Value};

/// Cost model extension (key 11, namespace "aafp.cost.v1").
///
/// CBOR encoding (integer keys inside the data map):
/// ```cbor
/// CostExtensionData = {
///     ? 1: uint,    // per_invocation_micro_usd
///     ? 2: uint,    // per_token_micro_usd
///     ? 3: bool,    // has_free_tier
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CostExtension {
    /// Extension version (always 1 for v1).
    pub version: u64,
    /// Cost per invocation in micro-USD (1 USD = 1,000,000 micro-USD).
    pub per_invocation_micro_usd: Option<u64>,
    /// Cost per token in micro-USD (for LLM capabilities).
    pub per_token_micro_usd: Option<u64>,
    /// Whether a free tier is available.
    pub has_free_tier: bool,
}

impl AgentRecordExtension for CostExtension {
    const NAMESPACE: &'static str = "aafp.cost.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if let Some(cost) = self.per_invocation_micro_usd {
            entries.push((1, Value::Unsigned(cost)));
        }
        if let Some(cost) = self.per_token_micro_usd {
            entries.push((2, Value::Unsigned(cost)));
        }
        if self.has_free_tier {
            entries.push((3, Value::Bool(true)));
        }
        int_map(entries)
    }

    fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        Ok(Self {
            version: 1,
            per_invocation_micro_usd: match int_map_get(val, 1) {
                Some(Value::Unsigned(n)) => Some(*n),
                _ => None,
            },
            per_token_micro_usd: match int_map_get(val, 2) {
                Some(Value::Unsigned(n)) => Some(*n),
                _ => None,
            },
            has_free_tier: matches!(int_map_get(val, 3), Some(Value::Bool(true))),
        })
    }
}

impl CostExtension {
    /// Compute the cost of a single invocation given a token count.
    /// Returns micro-USD.
    pub fn estimate_cost(&self, token_count: u64) -> u64 {
        let mut total = 0u64;
        if let Some(inv) = self.per_invocation_micro_usd {
            total += inv;
        }
        if let Some(pt) = self.per_token_micro_usd {
            total += pt.saturating_mul(token_count);
        }
        total
    }

    /// Check if a request would fall within the free tier.
    pub fn is_free_eligible(&self, _daily_usage: u32) -> bool {
        self.has_free_tier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_cost_roundtrip() {
        let cost = CostExtension {
            version: 1,
            per_invocation_micro_usd: Some(500),
            per_token_micro_usd: Some(20),
            has_free_tier: true,
        };
        let cbor = cost.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let cost2 = CostExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(cost, cost2);
    }

    #[test]
    fn test_cost_estimate() {
        let cost = CostExtension {
            version: 1,
            per_invocation_micro_usd: Some(1000),
            per_token_micro_usd: Some(50),
            has_free_tier: false,
        };
        assert_eq!(cost.estimate_cost(100), 6000); // 1000 + 50*100
    }
}
