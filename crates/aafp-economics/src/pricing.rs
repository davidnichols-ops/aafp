//! Pricing engine (Track X2).
//!
//! [`PricingEngine`] computes the cost of tasks in the abstract unit
//! "credits" based on measured or estimated [`ResourceUsage`](crate::ResourceUsage).
//! Four pricing models are supported via [`PricingModel`]:
//!
//! - **`Fixed`** — a flat cost regardless of usage.
//! - **`PerUnit`** — linear: each resource unit is multiplied by its unit
//!   price and the results are summed.
//! - **`Tiered`** — volume discounts: per-unit price decreases as
//!   cumulative usage crosses configured tier boundaries.
//! - **`Dynamic`** — supply/demand adjustment: a base per-unit price is
//!   multiplied by a demand factor derived from current load relative to
//!   capacity.
//!
//! The engine produces [`PriceQuote`] structs (for estimates) and settles
//! actual costs via [`PricingEngine::settle`]. All persistent structures
//! encode to canonical CBOR int-keyed maps (RFC-0002 §8).

use std::collections::HashMap;

use aafp_cbor::{int_map, int_map_get, Value};

use crate::account::ResourceUsage;
use crate::EconomicsError;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn enc_u64(n: u64) -> Value {
    Value::Unsigned(n)
}

fn enc_i64(n: i64) -> Value {
    if n >= 0 {
        Value::Unsigned(n as u64)
    } else {
        Value::Negative(n)
    }
}

fn dec_u64(val: &Value, field: &'static str) -> Result<u64, EconomicsError> {
    match val {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(EconomicsError::InvalidField {
            field,
            message: format!("expected unsigned integer, got {val:?}"),
        }),
    }
}

fn dec_i64(val: &Value, field: &'static str) -> Result<i64, EconomicsError> {
    match val {
        Value::Unsigned(n) => Ok(*n as i64),
        Value::Negative(n) => Ok(*n),
        _ => Err(EconomicsError::InvalidField {
            field,
            message: format!("expected integer, got {val:?}"),
        }),
    }
}

fn req<'a>(map: &'a Value, key: i64, field: &'static str) -> Result<&'a Value, EconomicsError> {
    int_map_get(map, key).ok_or(EconomicsError::MissingField(field))
}

fn opt(map: &Value, key: i64) -> Option<&Value> {
    int_map_get(map, key)
}

// ---------------------------------------------------------------------------
// PricingModel
// ---------------------------------------------------------------------------

/// Pricing model selection.
///
/// Encoded as an unsigned integer: `Fixed = 0`, `PerUnit = 1`, `Tiered = 2`,
/// `Dynamic = 3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PricingModel {
    /// A flat cost regardless of resource usage.
    #[default]
    Fixed = 0,
    /// Linear per-unit pricing: cost = Σ (usage_i × price_i).
    PerUnit = 1,
    /// Tiered pricing with volume discounts per resource.
    Tiered = 2,
    /// Dynamic pricing adjusted by supply/demand.
    Dynamic = 3,
}

impl PricingModel {
    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Fixed),
            Value::Unsigned(1) => Ok(Self::PerUnit),
            Value::Unsigned(2) => Ok(Self::Tiered),
            Value::Unsigned(3) => Ok(Self::Dynamic),
            _ => Err(EconomicsError::InvalidField {
                field: "pricing_model",
                message: format!("expected 0/1/2/3, got {val:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// PriceTier
// ---------------------------------------------------------------------------

/// A volume-discount tier for a single resource.
///
/// When cumulative usage of a resource exceeds `threshold` units, the
/// `price_milli` rate applies to units *above* the threshold. Tiers are
/// stacked: the first N units use the base price, units between tier
/// boundaries use the corresponding tier price.
#[derive(Clone, Debug, PartialEq)]
pub struct PriceTier {
    /// Cumulative usage threshold at which this tier activates.
    pub threshold: u64, // key 1
    /// Price per unit (in milli-credits) for usage above this threshold.
    pub price_milli: i64, // key 2
}

impl PriceTier {
    /// Create a new tier.
    pub fn new(threshold: u64, price_milli: i64) -> Self {
        Self {
            threshold,
            price_milli,
        }
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_u64(self.threshold)),
            (2, enc_i64(self.price_milli)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            threshold: dec_u64(req(val, 1, "threshold")?, "threshold")?,
            price_milli: dec_i64(req(val, 2, "price_milli")?, "price_milli")?,
        })
    }
}

// ---------------------------------------------------------------------------
// ResourcePricing
// ---------------------------------------------------------------------------

/// Per-resource pricing configuration.
///
/// For `PerUnit` and `Dynamic` models, `price_milli` is the base unit price
/// (in milli-credits). For `Tiered` models, `tiers` provides the volume
/// discount schedule; the base `price_milli` applies below the first tier
/// threshold.
#[derive(Clone, Debug)]
pub struct ResourcePricing {
    /// Base price per unit in milli-credits (1 credit = 1000 milli-credits).
    pub price_milli: i64, // key 1
    /// Volume-discount tiers (sorted by threshold during evaluation).
    pub tiers: Vec<PriceTier>, // key 2
}

impl ResourcePricing {
    /// Create per-unit pricing with a base price (in credits).
    pub fn per_unit(price: f64) -> Self {
        Self {
            price_milli: (price * 1000.0).round() as i64,
            tiers: Vec::new(),
        }
    }

    /// Create tiered pricing with a base price and tier schedule.
    pub fn tiered(price: f64, tiers: Vec<PriceTier>) -> Self {
        Self {
            price_milli: (price * 1000.0).round() as i64,
            tiers,
        }
    }

    /// Compute the cost (in milli-credits) for `units` of this resource
    /// using the tier schedule. Tiers are sorted by threshold; each tier's
    /// price applies to units above its threshold and below the next.
    fn tiered_cost_milli(&self, units: u64) -> i64 {
        if self.tiers.is_empty() {
            // No tiers: simple per-unit.
            return self.price_milli.saturating_mul(units as i64);
        }
        // Sort tiers by threshold (clone to avoid mutating self).
        let mut sorted: Vec<PriceTier> = self.tiers.clone();
        sorted.sort_by_key(|t| t.threshold);

        let mut cost: i64 = 0;
        let mut prev_threshold: u64 = 0;
        let mut current_price = self.price_milli;
        for tier in &sorted {
            if units <= prev_threshold {
                break;
            }
            let upper = units.min(tier.threshold);
            if upper > prev_threshold {
                let span = (upper - prev_threshold) as i64;
                cost = cost.saturating_add(current_price.saturating_mul(span));
            }
            prev_threshold = tier.threshold;
            current_price = tier.price_milli;
        }
        // Units above the last tier threshold.
        if units > prev_threshold {
            let span = (units - prev_threshold) as i64;
            cost = cost.saturating_add(current_price.saturating_mul(span));
        }
        cost
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let tiers_arr: Vec<Value> = self.tiers.iter().map(|t| t.to_cbor()).collect();
        int_map(vec![
            (1, enc_i64(self.price_milli)),
            (2, Value::Array(tiers_arr)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        let price_milli = dec_i64(req(val, 1, "price_milli")?, "price_milli")?;
        let mut tiers = Vec::new();
        if let Some(v) = opt(val, 2) {
            match v {
                Value::Array(arr) => {
                    for item in arr {
                        tiers.push(PriceTier::from_cbor(item)?);
                    }
                }
                _ => {
                    return Err(EconomicsError::InvalidField {
                        field: "tiers",
                        message: format!("expected array, got {v:?}"),
                    });
                }
            }
        }
        Ok(Self { price_milli, tiers })
    }
}

// ---------------------------------------------------------------------------
// PricingConfig
// ---------------------------------------------------------------------------

/// Configuration for the [`PricingEngine`].
///
/// Unit prices are expressed in milli-credits (1 credit = 1000 milli) to
/// keep the CBOR representation integral and deterministic. The
/// [`PricingConfig::unit_price`] helper converts to credits as `f64`.
#[derive(Clone, Debug)]
pub struct PricingConfig {
    /// Default pricing model.
    pub model: PricingModel, // key 1
    /// CPU millisecond pricing.
    pub cpu_ms: ResourcePricing, // key 2
    /// Memory megabyte pricing.
    pub memory_mb: ResourcePricing, // key 3
    /// Storage megabyte pricing.
    pub storage_mb: ResourcePricing, // key 4
    /// Network kilobyte pricing.
    pub network_kb: ResourcePricing, // key 5
    /// API call pricing.
    pub api_calls: ResourcePricing, // key 6
    /// Inference token pricing.
    pub inference_tokens: ResourcePricing, // key 7
    /// Fixed cost (in milli-credits) for the `Fixed` model.
    pub fixed_cost_milli: i64, // key 8
    /// Capacity estimate (in weighted-total units) for dynamic pricing.
    pub capacity: u64, // key 9
    /// Current load (in weighted-total units) for dynamic pricing.
    pub current_load: u64, // key 10
    /// Elasticity exponent for dynamic pricing (default 1.0).
    pub elasticity_milli: i64, // key 11
}

impl PricingConfig {
    /// Create a config with per-unit pricing and the given unit prices
    /// (in credits as `f64`).
    #[allow(clippy::too_many_arguments)]
    pub fn per_unit(
        cpu_ms_price: f64,
        memory_mb_price: f64,
        storage_mb_price: f64,
        network_kb_price: f64,
        api_calls_price: f64,
        inference_tokens_price: f64,
    ) -> Self {
        Self {
            model: PricingModel::PerUnit,
            cpu_ms: ResourcePricing::per_unit(cpu_ms_price),
            memory_mb: ResourcePricing::per_unit(memory_mb_price),
            storage_mb: ResourcePricing::per_unit(storage_mb_price),
            network_kb: ResourcePricing::per_unit(network_kb_price),
            api_calls: ResourcePricing::per_unit(api_calls_price),
            inference_tokens: ResourcePricing::per_unit(inference_tokens_price),
            fixed_cost_milli: 0,
            capacity: 1000,
            current_load: 0,
            elasticity_milli: 1000, // 1.0
        }
    }

    /// Create a config with a fixed cost (in credits).
    pub fn fixed(cost: f64) -> Self {
        Self {
            model: PricingModel::Fixed,
            cpu_ms: ResourcePricing::per_unit(0.0),
            memory_mb: ResourcePricing::per_unit(0.0),
            storage_mb: ResourcePricing::per_unit(0.0),
            network_kb: ResourcePricing::per_unit(0.0),
            api_calls: ResourcePricing::per_unit(0.0),
            inference_tokens: ResourcePricing::per_unit(0.0),
            fixed_cost_milli: (cost * 1000.0).round() as i64,
            capacity: 1000,
            current_load: 0,
            elasticity_milli: 1000,
        }
    }

    /// Set the pricing model.
    pub fn with_model(mut self, model: PricingModel) -> Self {
        self.model = model;
        self
    }

    /// Set the capacity for dynamic pricing.
    pub fn with_capacity(mut self, capacity: u64) -> Self {
        self.capacity = capacity;
        self
    }

    /// Set the current load for dynamic pricing.
    pub fn with_current_load(mut self, load: u64) -> Self {
        self.current_load = load;
        self
    }

    /// Set the elasticity exponent for dynamic pricing.
    pub fn with_elasticity(mut self, elasticity: f64) -> Self {
        self.elasticity_milli = (elasticity * 1000.0).round() as i64;
        self
    }

    /// Set tiered pricing for CPU.
    pub fn with_cpu_tiers(mut self, base: f64, tiers: Vec<PriceTier>) -> Self {
        self.cpu_ms = ResourcePricing::tiered(base, tiers);
        self
    }

    /// Compute the dynamic demand factor. Uses the formula:
    /// `factor = (1 + load/capacity) ^ elasticity`, floored at 1.0.
    ///
    /// When `capacity` is 0 the factor is `elasticity` (treats full scarcity).
    fn demand_factor(&self) -> f64 {
        let elasticity = self.elasticity_milli as f64 / 1000.0;
        if self.capacity == 0 {
            return 1.0_f64.max(elasticity);
        }
        let ratio = self.current_load as f64 / self.capacity as f64;
        let base = 1.0 + ratio;
        base.powf(elasticity)
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, self.model.to_cbor()),
            (2, self.cpu_ms.to_cbor()),
            (3, self.memory_mb.to_cbor()),
            (4, self.storage_mb.to_cbor()),
            (5, self.network_kb.to_cbor()),
            (6, self.api_calls.to_cbor()),
            (7, self.inference_tokens.to_cbor()),
            (8, enc_i64(self.fixed_cost_milli)),
            (9, enc_u64(self.capacity)),
            (10, enc_u64(self.current_load)),
            (11, enc_i64(self.elasticity_milli)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        let model = match opt(val, 1) {
            Some(v) => PricingModel::from_cbor(v)?,
            None => PricingModel::default(),
        };
        Ok(Self {
            model,
            cpu_ms: ResourcePricing::from_cbor(req(val, 2, "cpu_ms")?)?,
            memory_mb: ResourcePricing::from_cbor(req(val, 3, "memory_mb")?)?,
            storage_mb: ResourcePricing::from_cbor(req(val, 4, "storage_mb")?)?,
            network_kb: ResourcePricing::from_cbor(req(val, 5, "network_kb")?)?,
            api_calls: ResourcePricing::from_cbor(req(val, 6, "api_calls")?)?,
            inference_tokens: ResourcePricing::from_cbor(req(val, 7, "inference_tokens")?)?,
            fixed_cost_milli: match opt(val, 8) {
                Some(v) => dec_i64(v, "fixed_cost_milli")?,
                None => 0,
            },
            capacity: match opt(val, 9) {
                Some(v) => dec_u64(v, "capacity")?,
                None => 1000,
            },
            current_load: match opt(val, 10) {
                Some(v) => dec_u64(v, "current_load")?,
                None => 0,
            },
            elasticity_milli: match opt(val, 11) {
                Some(v) => dec_i64(v, "elasticity_milli")?,
                None => 1000,
            },
        })
    }
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self::per_unit(0.001, 0.01, 0.0001, 0.0001, 1.0, 0.000002)
    }
}

// ---------------------------------------------------------------------------
// CostBreakdown
// ---------------------------------------------------------------------------

/// Per-resource cost breakdown (in milli-credits).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CostBreakdown {
    /// CPU cost (milli-credits).
    pub cpu_ms: i64, // key 1
    /// Memory cost (milli-credits).
    pub memory_mb: i64, // key 2
    /// Storage cost (milli-credits).
    pub storage_mb: i64, // key 3
    /// Network cost (milli-credits).
    pub network_kb: i64, // key 4
    /// API calls cost (milli-credits).
    pub api_calls: i64, // key 5
    /// Inference tokens cost (milli-credits).
    pub inference_tokens: i64, // key 6
}

impl CostBreakdown {
    /// Total cost across all resources (milli-credits).
    pub fn total_milli(&self) -> i64 {
        self.cpu_ms
            .saturating_add(self.memory_mb)
            .saturating_add(self.storage_mb)
            .saturating_add(self.network_kb)
            .saturating_add(self.api_calls)
            .saturating_add(self.inference_tokens)
    }

    /// Total cost in credits (as `f64`).
    pub fn total_credits(&self) -> f64 {
        self.total_milli() as f64 / 1000.0
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_i64(self.cpu_ms)),
            (2, enc_i64(self.memory_mb)),
            (3, enc_i64(self.storage_mb)),
            (4, enc_i64(self.network_kb)),
            (5, enc_i64(self.api_calls)),
            (6, enc_i64(self.inference_tokens)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            cpu_ms: dec_i64(req(val, 1, "cpu_ms")?, "cpu_ms")?,
            memory_mb: dec_i64(req(val, 2, "memory_mb")?, "memory_mb")?,
            storage_mb: dec_i64(req(val, 3, "storage_mb")?, "storage_mb")?,
            network_kb: dec_i64(req(val, 4, "network_kb")?, "network_kb")?,
            api_calls: dec_i64(req(val, 5, "api_calls")?, "api_calls")?,
            inference_tokens: dec_i64(req(val, 6, "inference_tokens")?, "inference_tokens")?,
        })
    }
}

// ---------------------------------------------------------------------------
// PriceQuote
// ---------------------------------------------------------------------------

/// A price estimate for a task.
///
/// The `estimated_cost_milli` field is the central estimate; `low_milli` and
/// `high_milli` form a confidence interval. The `breakdown` gives per-resource
/// cost detail.
#[derive(Clone, Debug, PartialEq)]
pub struct PriceQuote {
    /// Estimated total cost (milli-credits).
    pub estimated_cost_milli: i64, // key 1
    /// Lower bound of the confidence interval (milli-credits).
    pub low_milli: i64, // key 2
    /// Upper bound of the confidence interval (milli-credits).
    pub high_milli: i64, // key 3
    /// Per-resource cost breakdown (milli-credits).
    pub breakdown: CostBreakdown, // key 4
    /// Pricing model used.
    pub model: PricingModel, // key 5
    /// The expected resource usage the quote was based on.
    pub expected_usage: ResourceUsage, // key 6
}

impl PriceQuote {
    /// Estimated cost in credits (as `f64`).
    pub fn estimated_credits(&self) -> f64 {
        self.estimated_cost_milli as f64 / 1000.0
    }

    /// Lower bound in credits.
    pub fn low_credits(&self) -> f64 {
        self.low_milli as f64 / 1000.0
    }

    /// Upper bound in credits.
    pub fn high_credits(&self) -> f64 {
        self.high_milli as f64 / 1000.0
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_i64(self.estimated_cost_milli)),
            (2, enc_i64(self.low_milli)),
            (3, enc_i64(self.high_milli)),
            (4, self.breakdown.to_cbor()),
            (5, self.model.to_cbor()),
            (6, self.expected_usage.to_cbor()),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            estimated_cost_milli: dec_i64(
                req(val, 1, "estimated_cost_milli")?,
                "estimated_cost_milli",
            )?,
            low_milli: dec_i64(req(val, 2, "low_milli")?, "low_milli")?,
            high_milli: dec_i64(req(val, 3, "high_milli")?, "high_milli")?,
            breakdown: CostBreakdown::from_cbor(req(val, 4, "breakdown")?)?,
            model: match opt(val, 5) {
                Some(v) => PricingModel::from_cbor(v)?,
                None => PricingModel::default(),
            },
            expected_usage: ResourceUsage::from_cbor(req(val, 6, "expected_usage")?)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

/// The result of settling a task's actual cost against measured usage.
#[derive(Clone, Debug, PartialEq)]
pub struct Settlement {
    /// Actual total cost (milli-credits).
    pub actual_cost_milli: i64, // key 1
    /// Per-resource cost breakdown (milli-credits).
    pub breakdown: CostBreakdown, // key 2
    /// The measured usage the settlement was based on.
    pub actual_usage: ResourceUsage, // key 3
    /// The pricing model used.
    pub model: PricingModel, // key 4
}

impl Settlement {
    /// Actual cost in credits (as `f64`).
    pub fn actual_credits(&self) -> f64 {
        self.actual_cost_milli as f64 / 1000.0
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_i64(self.actual_cost_milli)),
            (2, self.breakdown.to_cbor()),
            (3, self.actual_usage.to_cbor()),
            (4, self.model.to_cbor()),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            actual_cost_milli: dec_i64(req(val, 1, "actual_cost_milli")?, "actual_cost_milli")?,
            breakdown: CostBreakdown::from_cbor(req(val, 2, "breakdown")?)?,
            actual_usage: ResourceUsage::from_cbor(req(val, 3, "actual_usage")?)?,
            model: match opt(val, 4) {
                Some(v) => PricingModel::from_cbor(v)?,
                None => PricingModel::default(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// CurrencyConverter
// ---------------------------------------------------------------------------

/// A simple currency converter that translates credits into external units.
///
/// Rates are expressed as "external units per credit". The converter is
/// intentionally abstract — it does not fetch live rates; callers supply
/// rates at construction time.
#[derive(Clone, Debug)]
pub struct CurrencyConverter {
    rates: HashMap<String, f64>,
}

impl CurrencyConverter {
    /// Create an empty converter (no rates).
    pub fn new() -> Self {
        Self {
            rates: HashMap::new(),
        }
    }

    /// Set the exchange rate for a currency (external units per credit).
    pub fn set_rate(&mut self, currency: impl Into<String>, units_per_credit: f64) {
        self.rates.insert(currency.into(), units_per_credit);
    }

    /// Convert an amount in credits to the given currency.
    pub fn convert(&self, credits: f64, currency: &str) -> Result<f64, EconomicsError> {
        let rate = self
            .rates
            .get(currency)
            .copied()
            .ok_or_else(|| EconomicsError::CurrencyConversion(currency.to_string()))?;
        Ok(credits * rate)
    }

    /// List known currency codes.
    pub fn currencies(&self) -> Vec<String> {
        let mut codes: Vec<String> = self.rates.keys().cloned().collect();
        codes.sort();
        codes
    }
}

impl Default for CurrencyConverter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PricingEngine
// ---------------------------------------------------------------------------

/// Computes task costs from resource usage according to a [`PricingConfig`].
pub struct PricingEngine {
    config: PricingConfig,
    converter: CurrencyConverter,
}

impl PricingEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: PricingConfig) -> Self {
        Self {
            config,
            converter: CurrencyConverter::new(),
        }
    }

    /// Create a new engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PricingConfig::default())
    }

    /// Return a reference to the pricing configuration.
    pub fn config(&self) -> &PricingConfig {
        &self.config
    }

    /// Return a mutable reference to the pricing configuration.
    pub fn config_mut(&mut self) -> &mut PricingConfig {
        &mut self.config
    }

    /// Return a reference to the currency converter.
    pub fn converter(&self) -> &CurrencyConverter {
        &self.converter
    }

    /// Return a mutable reference to the currency converter.
    pub fn converter_mut(&mut self) -> &mut CurrencyConverter {
        &mut self.converter
    }

    /// Compute the per-resource cost breakdown (in milli-credits) for
    /// `usage` under the current config and model.
    fn compute_breakdown(&self, usage: &ResourceUsage) -> CostBreakdown {
        let factor = match self.config.model {
            PricingModel::Dynamic => self.config.demand_factor(),
            _ => 1.0,
        };
        match self.config.model {
            PricingModel::Fixed => CostBreakdown::default(),
            PricingModel::PerUnit | PricingModel::Dynamic => {
                let apply = |pricing: &ResourcePricing, units: u64| -> i64 {
                    let base = pricing.price_milli.saturating_mul(units as i64);
                    (base as f64 * factor).round() as i64
                };
                CostBreakdown {
                    cpu_ms: apply(&self.config.cpu_ms, usage.cpu_ms),
                    memory_mb: apply(&self.config.memory_mb, usage.memory_mb),
                    storage_mb: apply(&self.config.storage_mb, usage.storage_mb),
                    network_kb: apply(&self.config.network_kb, usage.network_kb),
                    api_calls: apply(&self.config.api_calls, usage.api_calls),
                    inference_tokens: apply(&self.config.inference_tokens, usage.inference_tokens),
                }
            }
            PricingModel::Tiered => {
                let apply = |pricing: &ResourcePricing, units: u64| -> i64 {
                    pricing.tiered_cost_milli(units)
                };
                CostBreakdown {
                    cpu_ms: apply(&self.config.cpu_ms, usage.cpu_ms),
                    memory_mb: apply(&self.config.memory_mb, usage.memory_mb),
                    storage_mb: apply(&self.config.storage_mb, usage.storage_mb),
                    network_kb: apply(&self.config.network_kb, usage.network_kb),
                    api_calls: apply(&self.config.api_calls, usage.api_calls),
                    inference_tokens: apply(&self.config.inference_tokens, usage.inference_tokens),
                }
            }
        }
    }

    /// Estimate the cost of a task based on expected resource usage.
    ///
    /// The confidence interval is derived from a configurable margin
    /// (default ±10%). Returns a [`PriceQuote`].
    pub fn quote(&self, expected_usage: &ResourceUsage) -> PriceQuote {
        let breakdown = self.compute_breakdown(expected_usage);
        let estimated = if self.config.model == PricingModel::Fixed {
            self.config.fixed_cost_milli
        } else {
            breakdown.total_milli()
        };
        // ±10% confidence interval.
        let margin = (estimated as f64 * 0.10).round() as i64;
        let low = estimated.saturating_sub(margin);
        let high = estimated.saturating_add(margin);
        PriceQuote {
            estimated_cost_milli: estimated,
            low_milli: low,
            high_milli: high,
            breakdown,
            model: self.config.model,
            expected_usage: expected_usage.clone(),
        }
    }

    /// Compute the actual cost from measured usage.
    pub fn settle(&self, actual_usage: &ResourceUsage) -> Settlement {
        let breakdown = self.compute_breakdown(actual_usage);
        let actual = if self.config.model == PricingModel::Fixed {
            self.config.fixed_cost_milli
        } else {
            breakdown.total_milli()
        };
        Settlement {
            actual_cost_milli: actual,
            breakdown,
            actual_usage: actual_usage.clone(),
            model: self.config.model,
        }
    }

    /// Convert a cost in credits to an external currency.
    pub fn convert(&self, credits: f64, currency: &str) -> Result<f64, EconomicsError> {
        self.converter.convert(credits, currency)
    }
}

impl Default for PricingEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::ResourceUsage;

    fn usage(cpu: u64, mem: u64, stor: u64, net: u64, api: u64, tok: u64) -> ResourceUsage {
        ResourceUsage::new(cpu, mem, stor, net, api, tok)
    }

    // --- PricingModel tests ---

    #[test]
    fn test_pricing_model_default_is_fixed() {
        assert_eq!(PricingModel::default(), PricingModel::Fixed);
    }

    #[test]
    fn test_pricing_model_cbor_roundtrip() {
        for m in [
            PricingModel::Fixed,
            PricingModel::PerUnit,
            PricingModel::Tiered,
            PricingModel::Dynamic,
        ] {
            let val = m.to_cbor();
            assert_eq!(PricingModel::from_cbor(&val).unwrap(), m);
        }
    }

    #[test]
    fn test_pricing_model_invalid() {
        assert!(PricingModel::from_cbor(&Value::Unsigned(99)).is_err());
    }

    // --- PriceTier tests ---

    #[test]
    fn test_price_tier_cbor_roundtrip() {
        let t = PriceTier::new(1000, 500);
        let val = t.to_cbor();
        let t2 = PriceTier::from_cbor(&val).unwrap();
        assert_eq!(t, t2);
    }

    // --- ResourcePricing tests ---

    #[test]
    fn test_resource_pricing_per_unit() {
        let p = ResourcePricing::per_unit(0.001);
        assert_eq!(p.price_milli, 1);
        assert!(p.tiers.is_empty());
    }

    #[test]
    fn test_resource_pricing_tiered_cost_no_tiers() {
        let p = ResourcePricing::per_unit(0.01); // 10 milli/unit
        assert_eq!(p.tiered_cost_milli(100), 1000);
    }

    #[test]
    fn test_resource_pricing_tiered_cost_with_tiers() {
        // Base 10 milli/unit, tier at 100 → 5 milli/unit, tier at 500 → 2 milli/unit
        let p = ResourcePricing::tiered(0.01, vec![PriceTier::new(100, 5), PriceTier::new(500, 2)]);
        // 50 units: all at base 10 → 500
        assert_eq!(p.tiered_cost_milli(50), 500);
        // 300 units: 100 at 10 = 1000, 200 at 5 = 1000 → 2000
        assert_eq!(p.tiered_cost_milli(300), 2000);
        // 700 units: 100 at 10 = 1000, 400 at 5 = 2000, 200 at 2 = 400 → 3400
        assert_eq!(p.tiered_cost_milli(700), 3400);
    }

    #[test]
    fn test_resource_pricing_tiered_unsorted_input() {
        // Tiers provided out of order should still compute correctly.
        let p = ResourcePricing::tiered(0.01, vec![PriceTier::new(500, 2), PriceTier::new(100, 5)]);
        assert_eq!(p.tiered_cost_milli(300), 2000);
    }

    #[test]
    fn test_resource_pricing_cbor_roundtrip() {
        let p = ResourcePricing::tiered(0.01, vec![PriceTier::new(100, 5), PriceTier::new(500, 2)]);
        let val = p.to_cbor();
        let p2 = ResourcePricing::from_cbor(&val).unwrap();
        assert_eq!(p.price_milli, p2.price_milli);
        assert_eq!(p.tiers, p2.tiers);
    }

    // --- PricingConfig tests ---

    #[test]
    fn test_config_default() {
        let c = PricingConfig::default();
        assert_eq!(c.model, PricingModel::PerUnit);
        assert_eq!(c.capacity, 1000);
        assert_eq!(c.elasticity_milli, 1000);
    }

    #[test]
    fn test_config_per_unit_builder() {
        let c = PricingConfig::per_unit(0.001, 0.01, 0.0001, 0.0001, 1.0, 0.002);
        assert_eq!(c.cpu_ms.price_milli, 1);
        assert_eq!(c.memory_mb.price_milli, 10);
        assert_eq!(c.api_calls.price_milli, 1000);
        assert_eq!(c.inference_tokens.price_milli, 2);
    }

    #[test]
    fn test_config_fixed_builder() {
        let c = PricingConfig::fixed(5.0);
        assert_eq!(c.model, PricingModel::Fixed);
        assert_eq!(c.fixed_cost_milli, 5000);
    }

    #[test]
    fn test_config_demand_factor_no_load() {
        let c = PricingConfig::per_unit(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Dynamic)
            .with_capacity(1000)
            .with_current_load(0)
            .with_elasticity(1.0);
        assert!((c.demand_factor() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_config_demand_factor_half_load() {
        let c = PricingConfig::per_unit(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Dynamic)
            .with_capacity(1000)
            .with_current_load(500)
            .with_elasticity(1.0);
        // (1 + 0.5)^1 = 1.5
        assert!((c.demand_factor() - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_config_demand_factor_full_load() {
        let c = PricingConfig::per_unit(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Dynamic)
            .with_capacity(1000)
            .with_current_load(1000)
            .with_elasticity(2.0);
        // (1 + 1.0)^2 = 4.0
        assert!((c.demand_factor() - 4.0).abs() < 1e-9);
    }

    #[test]
    fn test_config_cbor_roundtrip() {
        let c = PricingConfig::per_unit(0.001, 0.01, 0.0001, 0.0001, 1.0, 0.000002)
            .with_model(PricingModel::Dynamic)
            .with_capacity(2000)
            .with_current_load(500)
            .with_elasticity(1.5)
            .with_cpu_tiers(0.01, vec![PriceTier::new(100, 5)]);
        let val = c.to_cbor();
        let c2 = PricingConfig::from_cbor(&val).unwrap();
        assert_eq!(c2.model, c.model);
        assert_eq!(c2.capacity, c.capacity);
        assert_eq!(c2.current_load, c.current_load);
        assert_eq!(c2.elasticity_milli, c.elasticity_milli);
        assert_eq!(c2.cpu_ms.tiers, c.cpu_ms.tiers);
    }

    // --- CostBreakdown tests ---

    #[test]
    fn test_cost_breakdown_total() {
        let b = CostBreakdown {
            cpu_ms: 100,
            memory_mb: 200,
            storage_mb: 300,
            network_kb: 400,
            api_calls: 500,
            inference_tokens: 600,
        };
        assert_eq!(b.total_milli(), 2100);
        assert!((b.total_credits() - 2.1).abs() < 1e-9);
    }

    #[test]
    fn test_cost_breakdown_cbor_roundtrip() {
        let b = CostBreakdown {
            cpu_ms: 100,
            memory_mb: -50,
            storage_mb: 300,
            network_kb: 0,
            api_calls: 500,
            inference_tokens: 600,
        };
        let val = b.to_cbor();
        let b2 = CostBreakdown::from_cbor(&val).unwrap();
        assert_eq!(b, b2);
    }

    // --- PricingEngine: Fixed model ---

    #[test]
    fn test_engine_fixed_cost() {
        let engine = PricingEngine::new(PricingConfig::fixed(5.0));
        let u = usage(100, 50, 10, 5, 2, 1000);
        let settlement = engine.settle(&u);
        assert_eq!(settlement.actual_cost_milli, 5000);
        assert!((settlement.actual_credits() - 5.0).abs() < 1e-9);
    }

    #[test]
    fn test_engine_fixed_quote() {
        let engine = PricingEngine::new(PricingConfig::fixed(10.0));
        let u = usage(0, 0, 0, 0, 0, 0);
        let quote = engine.quote(&u);
        assert_eq!(quote.estimated_cost_milli, 10000);
        // ±10% of 10000 = 1000
        assert_eq!(quote.low_milli, 9000);
        assert_eq!(quote.high_milli, 11000);
    }

    #[test]
    fn test_engine_fixed_ignores_usage() {
        let engine = PricingEngine::new(PricingConfig::fixed(5.0));
        let a = engine.settle(&usage(0, 0, 0, 0, 0, 0));
        let b = engine.settle(&usage(1000, 500, 100, 50, 20, 10000));
        assert_eq!(a.actual_cost_milli, b.actual_cost_milli);
    }

    // --- PricingEngine: PerUnit model ---

    #[test]
    fn test_engine_per_unit_basic() {
        // cpu: 0.001 credits/ms = 1 milli/ms
        // tokens: 0.002 credits/token = 2 milli/token
        let engine = PricingEngine::new(PricingConfig::per_unit(0.001, 0.0, 0.0, 0.0, 0.0, 0.002));
        let u = usage(1000, 0, 0, 0, 0, 500);
        let settlement = engine.settle(&u);
        // cpu: 1000 * 1 = 1000 milli, tokens: 500 * 2 = 1000 milli → 2000 milli = 2.0 credits
        assert_eq!(settlement.actual_cost_milli, 2000);
        assert!((settlement.actual_credits() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_engine_per_unit_breakdown() {
        let engine = PricingEngine::new(PricingConfig::per_unit(
            0.001, 0.01, 0.0001, 0.0001, 1.0, 0.002,
        ));
        let u = usage(100, 10, 5, 2, 3, 1000);
        let settlement = engine.settle(&u);
        // cpu: 100*1=100, mem: 10*10=100, stor: 5*0=0, net: 2*0=0, api: 3*1000=3000, tok: 1000*2=2000
        assert_eq!(settlement.breakdown.cpu_ms, 100);
        assert_eq!(settlement.breakdown.memory_mb, 100);
        assert_eq!(settlement.breakdown.api_calls, 3000);
        assert_eq!(settlement.breakdown.inference_tokens, 2000);
    }

    #[test]
    fn test_engine_per_unit_quote_confidence_interval() {
        let engine = PricingEngine::new(PricingConfig::per_unit(0.001, 0.0, 0.0, 0.0, 0.0, 0.0));
        let u = usage(10000, 0, 0, 0, 0, 0);
        let quote = engine.quote(&u);
        // estimated = 10000 * 1 = 10000 milli
        assert_eq!(quote.estimated_cost_milli, 10000);
        assert_eq!(quote.low_milli, 9000);
        assert_eq!(quote.high_milli, 11000);
    }

    #[test]
    fn test_engine_per_unit_zero_usage() {
        let engine = PricingEngine::new(PricingConfig::per_unit(1.0, 1.0, 1.0, 1.0, 1.0, 1.0));
        let settlement = engine.settle(&usage(0, 0, 0, 0, 0, 0));
        assert_eq!(settlement.actual_cost_milli, 0);
    }

    // --- PricingEngine: Tiered model ---

    #[test]
    fn test_engine_tiered_cost() {
        let config = PricingConfig::per_unit(0.01, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Tiered)
            .with_cpu_tiers(0.01, vec![PriceTier::new(100, 5), PriceTier::new(500, 2)]);
        let engine = PricingEngine::new(config);
        // 300 cpu_ms: 100 at 10 = 1000, 200 at 5 = 1000 → 2000 milli
        let u = usage(300, 0, 0, 0, 0, 0);
        let settlement = engine.settle(&u);
        assert_eq!(settlement.actual_cost_milli, 2000);
    }

    #[test]
    fn test_engine_tiered_below_first_tier() {
        let config = PricingConfig::per_unit(0.01, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Tiered)
            .with_cpu_tiers(0.01, vec![PriceTier::new(100, 5)]);
        let engine = PricingEngine::new(config);
        let u = usage(50, 0, 0, 0, 0, 0);
        let settlement = engine.settle(&u);
        // 50 * 10 = 500
        assert_eq!(settlement.actual_cost_milli, 500);
    }

    #[test]
    fn test_engine_tiered_above_all_tiers() {
        let config = PricingConfig::per_unit(0.01, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Tiered)
            .with_cpu_tiers(0.01, vec![PriceTier::new(100, 5), PriceTier::new(500, 2)]);
        let engine = PricingEngine::new(config);
        let u = usage(700, 0, 0, 0, 0, 0);
        let settlement = engine.settle(&u);
        // 100@10 + 400@5 + 200@2 = 1000 + 2000 + 400 = 3400
        assert_eq!(settlement.actual_cost_milli, 3400);
    }

    // --- PricingEngine: Dynamic model ---

    #[test]
    fn test_engine_dynamic_no_load() {
        let config = PricingConfig::per_unit(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Dynamic)
            .with_capacity(1000)
            .with_current_load(0)
            .with_elasticity(1.0);
        let engine = PricingEngine::new(config);
        let u = usage(100, 0, 0, 0, 0, 0);
        let settlement = engine.settle(&u);
        // factor = 1.0, cost = 100 * 1000 * 1.0 = 100000 milli = 100 credits
        assert_eq!(settlement.actual_cost_milli, 100000);
    }

    #[test]
    fn test_engine_dynamic_half_load() {
        let config = PricingConfig::per_unit(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Dynamic)
            .with_capacity(1000)
            .with_current_load(500)
            .with_elasticity(1.0);
        let engine = PricingEngine::new(config);
        let u = usage(100, 0, 0, 0, 0, 0);
        let settlement = engine.settle(&u);
        // factor = 1.5, cost = 100 * 1000 * 1.5 = 150000 milli
        assert_eq!(settlement.actual_cost_milli, 150000);
    }

    #[test]
    fn test_engine_dynamic_increases_with_load() {
        let base_config = PricingConfig::per_unit(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            .with_model(PricingModel::Dynamic)
            .with_capacity(1000)
            .with_elasticity(1.0);
        let u = usage(100, 0, 0, 0, 0, 0);
        let low = PricingEngine::new(base_config.clone().with_current_load(100)).settle(&u);
        let high = PricingEngine::new(base_config.with_current_load(900)).settle(&u);
        assert!(high.actual_cost_milli > low.actual_cost_milli);
    }

    // --- PriceQuote / Settlement CBOR ---

    #[test]
    fn test_price_quote_cbor_roundtrip() {
        let engine = PricingEngine::new(PricingConfig::per_unit(0.001, 0.01, 0.0, 0.0, 1.0, 0.0));
        let u = usage(100, 10, 0, 0, 2, 0);
        let quote = engine.quote(&u);
        let val = quote.to_cbor();
        let quote2 = PriceQuote::from_cbor(&val).unwrap();
        assert_eq!(quote, quote2);
    }

    #[test]
    fn test_settlement_cbor_roundtrip() {
        let engine = PricingEngine::new(PricingConfig::per_unit(0.001, 0.01, 0.0, 0.0, 1.0, 0.0));
        let u = usage(100, 10, 0, 0, 2, 0);
        let settlement = engine.settle(&u);
        let val = settlement.to_cbor();
        let settlement2 = Settlement::from_cbor(&val).unwrap();
        assert_eq!(settlement, settlement2);
    }

    // --- CurrencyConverter ---

    #[test]
    fn test_converter_basic() {
        let mut converter = CurrencyConverter::new();
        converter.set_rate("USD", 0.01);
        converter.set_rate("EUR", 0.009);
        assert!((converter.convert(100.0, "USD").unwrap() - 1.0).abs() < 1e-9);
        assert!((converter.convert(100.0, "EUR").unwrap() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn test_converter_unknown_currency() {
        let converter = CurrencyConverter::new();
        assert!(converter.convert(100.0, "XYZ").is_err());
    }

    #[test]
    fn test_converter_currencies_sorted() {
        let mut converter = CurrencyConverter::new();
        converter.set_rate("EUR", 0.009);
        converter.set_rate("USD", 0.01);
        converter.set_rate("GBP", 0.008);
        assert_eq!(converter.currencies(), vec!["EUR", "GBP", "USD"]);
    }

    #[test]
    fn test_engine_convert_via_converter() {
        let mut engine = PricingEngine::with_defaults();
        engine.converter_mut().set_rate("USD", 0.01);
        assert!((engine.convert(100.0, "USD").unwrap() - 1.0).abs() < 1e-9);
    }

    // --- Integration: quote then settle ---

    #[test]
    fn test_quote_then_settle_per_unit() {
        let engine = PricingEngine::new(PricingConfig::per_unit(0.001, 0.0, 0.0, 0.0, 0.0, 0.0));
        let expected = usage(1000, 0, 0, 0, 0, 0);
        let quote = engine.quote(&expected);
        // estimated = 1000 milli
        assert_eq!(quote.estimated_cost_milli, 1000);
        let actual = usage(900, 0, 0, 0, 0, 0);
        let settlement = engine.settle(&actual);
        assert_eq!(settlement.actual_cost_milli, 900);
        // actual within the quote's confidence interval
        assert!(settlement.actual_cost_milli >= quote.low_milli);
        assert!(settlement.actual_cost_milli <= quote.high_milli);
    }

    #[test]
    fn test_engine_default() {
        let engine = PricingEngine::default();
        assert_eq!(engine.config().model, PricingModel::PerUnit);
    }
}
