//! Cost model extension (Phase E4).
//!
//! Namespace: `"aafp.cost.v1"`. Pricing information for cost-aware agent
//! selection. All monetary values are in micro-USD (1 USD = 1,000,000
//! micro-USD) to avoid floating point on the wire.

use aafp_cbor::Value;
use crate::identity_v1::IdentityError;
use super::AgentRecordExtension;

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
    /// Cost per invocation in micro-USD (1 USD = 1,000,000 micro-USD).
    pub per_invocation_micro_usd: u64,
    /// Cost per token in micro-USD (for LLM capabilities).
    pub per_token_micro_usd: u64,
    /// Whether a free tier is available.
    pub has_free_tier: bool,
}

impl AgentRecordExtension for CostExtension {
    const NAMESPACE: &'static str = "aafp.cost.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        todo!()
    }

    fn from_cbor(_val: &Value) -> Result<Self, IdentityError> {
        todo!()
    }
}

impl CostExtension {
    /// Compute the cost of a single invocation given a token count.
    /// Returns micro-USD.
    pub fn estimate_cost(&self, _token_count: u64) -> u64 {
        todo!()
    }

    /// Check if a request would fall within the free tier.
    pub fn is_free_eligible(&self, _daily_usage: u32) -> bool {
        todo!()
    }
}
