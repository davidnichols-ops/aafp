//! Resource accounting (Track X1).
//!
//! [`ResourceAccount`] tracks per-agent resource consumption across six
//! resource dimensions: CPU milliseconds, memory megabytes, storage
//! megabytes, network kilobytes, API calls, and inference tokens. Each
//! agent has an independent ledger of debits (consumption) and credits
//! (refunds/returns) that can be queried via [`ResourceAccount::balance`]
//! and transferred between agents via [`ResourceAccount::transfer`].
//!
//! Per-agent [`ResourceLimits`] and an [`OverflowPolicy`] (configured via
//! [`AccountConfig`]) control whether debits that would exceed a limit are
//! rejected, allowed, or trigger a warning. All persistent structures
//! encode to canonical CBOR int-keyed maps (RFC-0002 §8).

use std::collections::HashMap;

use aafp_cbor::{decode, encode, int_map, int_map_get, Value};

use crate::EconomicsError;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn enc_u64(n: u64) -> Value {
    Value::Unsigned(n)
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

fn req<'a>(map: &'a Value, key: i64, field: &'static str) -> Result<&'a Value, EconomicsError> {
    int_map_get(map, key).ok_or(EconomicsError::MissingField(field))
}

fn opt(map: &Value, key: i64) -> Option<&Value> {
    int_map_get(map, key)
}

// ---------------------------------------------------------------------------
// ResourceUsage
// ---------------------------------------------------------------------------

/// Measured or estimated resource consumption for a single task or interval.
///
/// All fields are unsigned 64-bit integers in their natural units. The struct
/// is additive: two usages can be combined with `+` (via [`Self::add`]) and
/// a refund can be represented with [`Self::saturating_sub`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// CPU time consumed, in milliseconds.
    pub cpu_ms: u64, // key 1
    /// Peak memory allocated, in megabytes.
    pub memory_mb: u64, // key 2
    /// Persistent storage used, in megabytes.
    pub storage_mb: u64, // key 3
    /// Network traffic, in kilobytes.
    pub network_kb: u64, // key 4
    /// Number of external API calls made.
    pub api_calls: u64, // key 5
    /// Number of LLM inference tokens consumed.
    pub inference_tokens: u64, // key 6
}

impl ResourceUsage {
    /// Create a zero usage record.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Create a usage record from individual resource amounts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cpu_ms: u64,
        memory_mb: u64,
        storage_mb: u64,
        network_kb: u64,
        api_calls: u64,
        inference_tokens: u64,
    ) -> Self {
        Self {
            cpu_ms,
            memory_mb,
            storage_mb,
            network_kb,
            api_calls,
            inference_tokens,
        }
    }

    /// Add another usage record to this one (component-wise saturating add).
    pub fn add(&self, other: &Self) -> Self {
        Self {
            cpu_ms: self.cpu_ms.saturating_add(other.cpu_ms),
            memory_mb: self.memory_mb.saturating_add(other.memory_mb),
            storage_mb: self.storage_mb.saturating_add(other.storage_mb),
            network_kb: self.network_kb.saturating_add(other.network_kb),
            api_calls: self.api_calls.saturating_add(other.api_calls),
            inference_tokens: self.inference_tokens.saturating_add(other.inference_tokens),
        }
    }

    /// Subtract another usage record (component-wise saturating sub).
    pub fn saturating_sub(&self, other: &Self) -> Self {
        Self {
            cpu_ms: self.cpu_ms.saturating_sub(other.cpu_ms),
            memory_mb: self.memory_mb.saturating_sub(other.memory_mb),
            storage_mb: self.storage_mb.saturating_sub(other.storage_mb),
            network_kb: self.network_kb.saturating_sub(other.network_kb),
            api_calls: self.api_calls.saturating_sub(other.api_calls),
            inference_tokens: self.inference_tokens.saturating_sub(other.inference_tokens),
        }
    }

    /// Returns `true` if every component is zero.
    pub fn is_zero(&self) -> bool {
        self.cpu_ms == 0
            && self.memory_mb == 0
            && self.storage_mb == 0
            && self.network_kb == 0
            && self.api_calls == 0
            && self.inference_tokens == 0
    }

    /// Total scalar weight using a simple weighted sum. Useful for ranking
    /// tasks by overall resource intensity. Weights are arbitrary but fixed.
    pub fn weighted_total(&self) -> u64 {
        let cpu = self.cpu_ms;
        let mem = self.memory_mb.saturating_mul(10);
        let storage = self.storage_mb.saturating_mul(2);
        let net = self.network_kb.saturating_mul(5);
        let api = self.api_calls.saturating_mul(100);
        let tokens = self.inference_tokens;
        cpu.saturating_add(mem)
            .saturating_add(storage)
            .saturating_add(net)
            .saturating_add(api)
            .saturating_add(tokens)
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_u64(self.cpu_ms)),
            (2, enc_u64(self.memory_mb)),
            (3, enc_u64(self.storage_mb)),
            (4, enc_u64(self.network_kb)),
            (5, enc_u64(self.api_calls)),
            (6, enc_u64(self.inference_tokens)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            cpu_ms: dec_u64(req(val, 1, "cpu_ms")?, "cpu_ms")?,
            memory_mb: dec_u64(req(val, 2, "memory_mb")?, "memory_mb")?,
            storage_mb: dec_u64(req(val, 3, "storage_mb")?, "storage_mb")?,
            network_kb: dec_u64(req(val, 4, "network_kb")?, "network_kb")?,
            api_calls: dec_u64(req(val, 5, "api_calls")?, "api_calls")?,
            inference_tokens: dec_u64(req(val, 6, "inference_tokens")?, "inference_tokens")?,
        })
    }

    /// Encode to canonical CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicsError> {
        encode(&self.to_cbor()).map_err(|e| EconomicsError::CborDecode(e.to_string()))
    }

    /// Decode from canonical CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EconomicsError> {
        let (val, _) = decode(data).map_err(|e| EconomicsError::CborDecode(e.to_string()))?;
        Self::from_cbor(&val)
    }
}

// ---------------------------------------------------------------------------
// ResourceLimits
// ---------------------------------------------------------------------------

/// Per-agent resource limits. A value of `u64::MAX` means "unlimited".
///
/// Limits are checked against the *cumulative* balance after a debit, not
/// against individual task usage. This allows an agent to consume resources
/// across many tasks up to its aggregate cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum cumulative CPU milliseconds.
    pub cpu_ms: u64, // key 1
    /// Maximum cumulative memory megabytes.
    pub memory_mb: u64, // key 2
    /// Maximum cumulative storage megabytes.
    pub storage_mb: u64, // key 3
    /// Maximum cumulative network kilobytes.
    pub network_kb: u64, // key 4
    /// Maximum cumulative API calls.
    pub api_calls: u64, // key 5
    /// Maximum cumulative inference tokens.
    pub inference_tokens: u64, // key 6
}

impl ResourceLimits {
    /// Create limits with explicit per-resource caps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cpu_ms: u64,
        memory_mb: u64,
        storage_mb: u64,
        network_kb: u64,
        api_calls: u64,
        inference_tokens: u64,
    ) -> Self {
        Self {
            cpu_ms,
            memory_mb,
            storage_mb,
            network_kb,
            api_calls,
            inference_tokens,
        }
    }

    /// Create limits where every dimension is unlimited (`u64::MAX`).
    pub fn unlimited() -> Self {
        Self {
            cpu_ms: u64::MAX,
            memory_mb: u64::MAX,
            storage_mb: u64::MAX,
            network_kb: u64::MAX,
            api_calls: u64::MAX,
            inference_tokens: u64::MAX,
        }
    }

    /// Create limits where every dimension is zero (nothing allowed).
    pub fn zero() -> Self {
        Self {
            cpu_ms: 0,
            memory_mb: 0,
            storage_mb: 0,
            network_kb: 0,
            api_calls: 0,
            inference_tokens: 0,
        }
    }

    /// Create limits from a [`ResourceUsage`] baseline (each field becomes
    /// the cap for that resource).
    pub fn from_usage(usage: &ResourceUsage) -> Self {
        Self {
            cpu_ms: usage.cpu_ms,
            memory_mb: usage.memory_mb,
            storage_mb: usage.storage_mb,
            network_kb: usage.network_kb,
            api_calls: usage.api_calls,
            inference_tokens: usage.inference_tokens,
        }
    }

    /// Check whether `usage` fits within these limits. Returns `Ok(())` if
    /// every component is within its cap, or an `Err` naming the first
    /// resource that exceeds.
    pub fn check(&self, usage: &ResourceUsage) -> Result<(), (&'static str, u64, u64)> {
        if usage.cpu_ms > self.cpu_ms {
            return Err(("cpu_ms", usage.cpu_ms, self.cpu_ms));
        }
        if usage.memory_mb > self.memory_mb {
            return Err(("memory_mb", usage.memory_mb, self.memory_mb));
        }
        if usage.storage_mb > self.storage_mb {
            return Err(("storage_mb", usage.storage_mb, self.storage_mb));
        }
        if usage.network_kb > self.network_kb {
            return Err(("network_kb", usage.network_kb, self.network_kb));
        }
        if usage.api_calls > self.api_calls {
            return Err(("api_calls", usage.api_calls, self.api_calls));
        }
        if usage.inference_tokens > self.inference_tokens {
            return Err((
                "inference_tokens",
                usage.inference_tokens,
                self.inference_tokens,
            ));
        }
        Ok(())
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_u64(self.cpu_ms)),
            (2, enc_u64(self.memory_mb)),
            (3, enc_u64(self.storage_mb)),
            (4, enc_u64(self.network_kb)),
            (5, enc_u64(self.api_calls)),
            (6, enc_u64(self.inference_tokens)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            cpu_ms: dec_u64(req(val, 1, "cpu_ms")?, "cpu_ms")?,
            memory_mb: dec_u64(req(val, 2, "memory_mb")?, "memory_mb")?,
            storage_mb: dec_u64(req(val, 3, "storage_mb")?, "storage_mb")?,
            network_kb: dec_u64(req(val, 4, "network_kb")?, "network_kb")?,
            api_calls: dec_u64(req(val, 5, "api_calls")?, "api_calls")?,
            inference_tokens: dec_u64(req(val, 6, "inference_tokens")?, "inference_tokens")?,
        })
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

// ---------------------------------------------------------------------------
// OverflowPolicy
// ---------------------------------------------------------------------------

/// Policy applied when a debit would push an agent's cumulative balance
/// past a configured [`ResourceLimits`] cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OverflowPolicy {
    /// Reject the debit — return an error and leave the balance unchanged.
    #[default]
    Reject,
    /// Allow the debit to proceed even though it exceeds the limit.
    Allow,
    /// Allow the debit but record a warning (returned via [`LimitCheck`]).
    Warn,
}

impl OverflowPolicy {
    /// Encode as an unsigned integer: Reject=0, Allow=1, Warn=2.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Reject),
            Value::Unsigned(1) => Ok(Self::Allow),
            Value::Unsigned(2) => Ok(Self::Warn),
            _ => Err(EconomicsError::InvalidField {
                field: "overflow_policy",
                message: format!("expected 0/1/2, got {val:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// AccountConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`ResourceAccount`].
///
/// The default limits are unlimited and the default overflow policy is
/// [`OverflowPolicy::Reject`].
#[derive(Clone, Debug)]
#[derive(Default)]
pub struct AccountConfig {
    /// Default limits applied to any agent without an explicit override.
    pub default_limits: ResourceLimits, // key 1
    /// Per-agent limit overrides (agent id → limits).
    pub agent_limits: HashMap<String, ResourceLimits>, // key 2
    /// Policy when a debit exceeds the applicable limit.
    pub overflow_policy: OverflowPolicy, // key 3
}

impl AccountConfig {
    /// Create a config with unlimited default limits and `Reject` policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default limits.
    pub fn with_default_limits(mut self, limits: ResourceLimits) -> Self {
        self.default_limits = limits;
        self
    }

    /// Set the overflow policy.
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    /// Add a per-agent limit override.
    pub fn with_agent_limit(mut self, agent: impl Into<String>, limits: ResourceLimits) -> Self {
        self.agent_limits.insert(agent.into(), limits);
        self
    }

    /// Look up the limits applicable to `agent`, falling back to the default.
    pub fn limits_for(&self, agent: &str) -> &ResourceLimits {
        self.agent_limits.get(agent).unwrap_or(&self.default_limits)
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        // Sort agent limits by key for deterministic encoding.
        let mut entries: Vec<(&String, &ResourceLimits)> = self.agent_limits.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        let agent_limits_arr: Vec<Value> = entries
            .into_iter()
            .map(|(k, v)| Value::Array(vec![Value::TextString(k.clone()), v.to_cbor()]))
            .collect();
        int_map(vec![
            (1, self.default_limits.to_cbor()),
            (2, Value::Array(agent_limits_arr)),
            (3, self.overflow_policy.to_cbor()),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        let default_limits = ResourceLimits::from_cbor(req(val, 1, "default_limits")?)?;
        let overflow_policy = match opt(val, 3) {
            Some(v) => OverflowPolicy::from_cbor(v)?,
            None => OverflowPolicy::default(),
        };
        let mut agent_limits = HashMap::new();
        if let Some(v) = opt(val, 2) {
            match v {
                Value::Array(arr) => {
                    for item in arr {
                        match item {
                            Value::Array(pair) if pair.len() == 2 => {
                                let k = match &pair[0] {
                                    Value::TextString(s) => s.clone(),
                                    _ => {
                                        return Err(EconomicsError::InvalidField {
                                            field: "agent_limits",
                                            message: format!(
                                                "expected text string key, got {:?}",
                                                pair[0]
                                            ),
                                        });
                                    }
                                };
                                let l = ResourceLimits::from_cbor(&pair[1])?;
                                agent_limits.insert(k, l);
                            }
                            _ => {
                                return Err(EconomicsError::InvalidField {
                                    field: "agent_limits",
                                    message: format!("expected 2-element array, got {item:?}"),
                                });
                            }
                        }
                    }
                }
                _ => {
                    return Err(EconomicsError::InvalidField {
                        field: "agent_limits",
                        message: format!("expected array, got {v:?}"),
                    });
                }
            }
        }
        Ok(Self {
            default_limits,
            agent_limits,
            overflow_policy,
        })
    }
}


// ---------------------------------------------------------------------------
// LimitCheck
// ---------------------------------------------------------------------------

/// Result of a limit check performed during a debit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitCheck {
    /// The debit is within all limits.
    Ok,
    /// The debit exceeds a limit but was allowed by the policy.
    Warning {
        /// The resource that exceeded the limit.
        resource: String,
        /// The projected usage after the debit.
        would_be: u64,
        /// The configured limit.
        limit: u64,
    },
}

// ---------------------------------------------------------------------------
// AgentLedger
// ---------------------------------------------------------------------------

/// Per-agent ledger of net resource consumption (debits minus credits).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentLedger {
    /// Net cumulative usage (debits − credits, floored at zero per component).
    pub net_usage: ResourceUsage,
    /// Total debits recorded (gross, before credits).
    pub total_debited: ResourceUsage,
    /// Total credits recorded (refunds/returns).
    pub total_credited: ResourceUsage,
}

impl AgentLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a debit (add to net and total_debited).
    pub fn debit(&mut self, usage: &ResourceUsage) {
        self.net_usage = self.net_usage.add(usage);
        self.total_debited = self.total_debited.add(usage);
    }

    /// Record a credit (subtract from net, add to total_credited).
    pub fn credit(&mut self, usage: &ResourceUsage) {
        self.net_usage = self.net_usage.saturating_sub(usage);
        self.total_credited = self.total_credited.add(usage);
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, self.net_usage.to_cbor()),
            (2, self.total_debited.to_cbor()),
            (3, self.total_credited.to_cbor()),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            net_usage: ResourceUsage::from_cbor(req(val, 1, "net_usage")?)?,
            total_debited: ResourceUsage::from_cbor(req(val, 2, "total_debited")?)?,
            total_credited: ResourceUsage::from_cbor(req(val, 3, "total_credited")?)?,
        })
    }
}

// ---------------------------------------------------------------------------
// ResourceAccount
// ---------------------------------------------------------------------------

/// Tracks resource consumption per agent.
///
/// The account maintains a [`AgentLedger`] for each known agent and enforces
/// [`ResourceLimits`] according to the configured [`AccountConfig`]. All
/// mutations go through [`ResourceAccount::debit`], [`ResourceAccount::credit`],
/// and [`ResourceAccount::transfer`], which are synchronous and in-memory.
pub struct ResourceAccount {
    config: AccountConfig,
    ledgers: HashMap<String, AgentLedger>,
}

impl ResourceAccount {
    /// Create a new account with the given configuration.
    pub fn new(config: AccountConfig) -> Self {
        Self {
            config,
            ledgers: HashMap::new(),
        }
    }

    /// Create a new account with default (unlimited) configuration.
    pub fn with_defaults() -> Self {
        Self::new(AccountConfig::default())
    }

    /// Return a reference to the account configuration.
    pub fn config(&self) -> &AccountConfig {
        &self.config
    }

    /// Return a mutable reference to the account configuration.
    pub fn config_mut(&mut self) -> &mut AccountConfig {
        &mut self.config
    }

    /// Register an agent with an empty ledger. Returns `false` if the agent
    /// already exists.
    pub fn register(&mut self, agent: &str) -> bool {
        if self.ledgers.contains_key(agent) {
            return false;
        }
        self.ledgers.insert(agent.to_string(), AgentLedger::new());
        true
    }

    /// Returns `true` if the agent has a ledger.
    pub fn contains(&self, agent: &str) -> bool {
        self.ledgers.contains_key(agent)
    }

    /// List all known agent ids.
    pub fn agents(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.ledgers.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get the net usage balance for an agent. Returns zero usage if the
    /// agent is unknown.
    pub fn balance(&self, agent: &str) -> ResourceUsage {
        self.ledgers
            .get(agent)
            .map(|l| l.net_usage.clone())
            .unwrap_or_default()
    }

    /// Get the full ledger for an agent, if present.
    pub fn ledger(&self, agent: &str) -> Option<&AgentLedger> {
        self.ledgers.get(agent)
    }

    /// Verify whether applying `usage` as a debit to `agent` would stay
    /// within the agent's limits. Does not mutate state.
    pub fn check_limits(
        &self,
        agent: &str,
        usage: &ResourceUsage,
    ) -> Result<(), (&'static str, u64, u64)> {
        let current = self.balance(agent);
        let projected = current.add(usage);
        let limits = self.config.limits_for(agent);
        limits.check(&projected)
    }

    /// Record resource consumption (a debit) for `agent`.
    ///
    /// If the debit would exceed the agent's limits, the behavior depends on
    /// [`OverflowPolicy`]:
    /// - `Reject` → returns `Err(LimitExceeded)` and the ledger is unchanged.
    /// - `Allow` → the debit is applied and `Ok(())` is returned.
    /// - `Warn` → the debit is applied and `Ok(())` is returned (the warning
    ///   is available via [`Self::last_warning`] after the call, but for
    ///   simplicity this method returns `Ok(())`; use [`Self::debit_checked`]
    ///   to receive the [`LimitCheck`] inline).
    pub fn debit(&mut self, agent: &str, usage: &ResourceUsage) -> Result<(), EconomicsError> {
        self.debit_checked(agent, usage)
            .map(|_| ())}

    /// Like [`Self::debit`] but returns a [`LimitCheck`] describing whether
    /// the debit was within limits or triggered a warning.
    pub fn debit_checked(
        &mut self,
        agent: &str,
        usage: &ResourceUsage,
    ) -> Result<LimitCheck, EconomicsError> {
        let current = self.balance(agent);
        let projected = current.add(usage);
        let limits = self.config.limits_for(agent).clone();

        match limits.check(&projected) {
            Ok(()) => {
                self.ledgers
                    .entry(agent.to_string())
                    .or_default()
                    .debit(usage);
                Ok(LimitCheck::Ok)
            }
            Err((resource, would_be, limit)) => match self.config.overflow_policy {
                OverflowPolicy::Reject => Err(EconomicsError::LimitExceeded {
                    agent: agent.to_string(),
                    resource: resource.to_string(),
                    would_be,
                    limit,
                }),
                OverflowPolicy::Allow => {
                    self.ledgers
                        .entry(agent.to_string())
                        .or_default()
                        .debit(usage);
                    Ok(LimitCheck::Ok)
                }
                OverflowPolicy::Warn => {
                    self.ledgers
                        .entry(agent.to_string())
                        .or_default()
                        .debit(usage);
                    Ok(LimitCheck::Warning {
                        resource: resource.to_string(),
                        would_be,
                        limit,
                    })
                }
            },
        }
    }

    /// Record a resource return/refund (a credit) for `agent`.
    ///
    /// Credits reduce the net usage but never below zero (saturating). Credits
    /// are not subject to limit checks.
    pub fn credit(&mut self, agent: &str, usage: &ResourceUsage) {
        self.ledgers
            .entry(agent.to_string())
            .or_default()
            .credit(usage);
    }

    /// Transfer `usage` of resources from `from_agent` to `to_agent`.
    ///
    /// The transfer is rejected if `from_agent` does not have sufficient net
    /// balance in *every* component to cover the transfer. On success, the
    /// debit is applied to `from_agent` and the credit-equivalent is applied
    /// to `to_agent` (as a debit, since the receiving agent is consuming the
    /// transferred resources).
    ///
    /// Note: a transfer is modeled as a debit from the source and a debit to
    /// the destination — i.e. the destination's balance *increases* because
    /// it now "owns" the consumption. This matches the semantics of moving
    /// an obligation from one agent to another.
    pub fn transfer(
        &mut self,
        from_agent: &str,
        to_agent: &str,
        usage: &ResourceUsage,
    ) -> Result<(), EconomicsError> {
        let from_balance = self.balance(from_agent);
        // Verify the source has enough in every component.
        if from_balance.cpu_ms < usage.cpu_ms
            || from_balance.memory_mb < usage.memory_mb
            || from_balance.storage_mb < usage.storage_mb
            || from_balance.network_kb < usage.network_kb
            || from_balance.api_calls < usage.api_calls
            || from_balance.inference_tokens < usage.inference_tokens
        {
            return Err(EconomicsError::InsufficientBalance {
                agent: from_agent.to_string(),
                have: from_balance.weighted_total(),
                need: usage.weighted_total(),
            });
        }

        // Credit the source (reduces its net usage).
        self.ledgers
            .entry(from_agent.to_string())
            .or_default()
            .credit(usage);
        // Debit the destination (increases its net usage).
        self.ledgers
            .entry(to_agent.to_string())
            .or_default()
            .debit(usage);
        Ok(())
    }

    /// Reset an agent's ledger to zero (e.g. after a billing cycle).
    pub fn reset(&mut self, agent: &str) {
        if let Some(ledger) = self.ledgers.get_mut(agent) {
            *ledger = AgentLedger::new();
        }
    }

    /// Remove an agent's ledger entirely. Returns `true` if the agent existed.
    pub fn remove(&mut self, agent: &str) -> bool {
        self.ledgers.remove(agent).is_some()
    }

    /// Total number of registered agents.
    pub fn agent_count(&self) -> usize {
        self.ledgers.len()
    }

    /// Encode the entire account state (config + all ledgers) to CBOR bytes
    /// for persistence.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicsError> {
        // Sort ledgers by agent id for deterministic encoding.
        let mut entries: Vec<(&String, &AgentLedger)> = self.ledgers.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        let ledgers_arr: Vec<Value> = entries
            .into_iter()
            .map(|(k, v)| Value::Array(vec![Value::TextString(k.clone()), v.to_cbor()]))
            .collect();
        let map = int_map(vec![
            (1, self.config.to_cbor()),
            (2, Value::Array(ledgers_arr)),
        ]);
        encode(&map).map_err(|e| EconomicsError::CborDecode(e.to_string()))
    }

    /// Decode an account state from CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EconomicsError> {
        let (val, _) = decode(data).map_err(|e| EconomicsError::CborDecode(e.to_string()))?;
        let config = AccountConfig::from_cbor(req(&val, 1, "config")?)?;
        let mut ledgers = HashMap::new();
        if let Some(v) = opt(&val, 2) {
            match v {
                Value::Array(arr) => {
                    for item in arr {
                        match item {
                            Value::Array(pair) if pair.len() == 2 => {
                                let k = match &pair[0] {
                                    Value::TextString(s) => s.clone(),
                                    _ => {
                                        return Err(EconomicsError::InvalidField {
                                            field: "ledgers",
                                            message: format!(
                                                "expected text string key, got {:?}",
                                                pair[0]
                                            ),
                                        });
                                    }
                                };
                                let l = AgentLedger::from_cbor(&pair[1])?;
                                ledgers.insert(k, l);
                            }
                            _ => {
                                return Err(EconomicsError::InvalidField {
                                    field: "ledgers",
                                    message: format!("expected 2-element array, got {item:?}"),
                                });
                            }
                        }
                    }
                }
                _ => {
                    return Err(EconomicsError::InvalidField {
                        field: "ledgers",
                        message: format!("expected array, got {v:?}"),
                    });
                }
            }
        }
        Ok(Self { config, ledgers })
    }
}

impl Default for ResourceAccount {
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

    fn usage(cpu: u64, mem: u64, stor: u64, net: u64, api: u64, tok: u64) -> ResourceUsage {
        ResourceUsage::new(cpu, mem, stor, net, api, tok)
    }

    // --- ResourceUsage tests ---

    #[test]
    fn test_usage_zero() {
        let z = ResourceUsage::zero();
        assert!(z.is_zero());
        assert_eq!(z.cpu_ms, 0);
        assert_eq!(z.inference_tokens, 0);
    }

    #[test]
    fn test_usage_new() {
        let u = usage(1, 2, 3, 4, 5, 6);
        assert_eq!(u.cpu_ms, 1);
        assert_eq!(u.memory_mb, 2);
        assert_eq!(u.storage_mb, 3);
        assert_eq!(u.network_kb, 4);
        assert_eq!(u.api_calls, 5);
        assert_eq!(u.inference_tokens, 6);
    }

    #[test]
    fn test_usage_add() {
        let a = usage(10, 20, 30, 40, 50, 60);
        let b = usage(1, 2, 3, 4, 5, 6);
        let c = a.add(&b);
        assert_eq!(c.cpu_ms, 11);
        assert_eq!(c.memory_mb, 22);
        assert_eq!(c.inference_tokens, 66);
    }

    #[test]
    fn test_usage_saturating_sub() {
        let a = usage(10, 20, 30, 40, 50, 60);
        let b = usage(5, 25, 0, 40, 100, 10);
        let c = a.saturating_sub(&b);
        assert_eq!(c.cpu_ms, 5);
        assert_eq!(c.memory_mb, 0); // saturates
        assert_eq!(c.storage_mb, 30);
        assert_eq!(c.network_kb, 0);
        assert_eq!(c.api_calls, 0); // saturates
        assert_eq!(c.inference_tokens, 50);
    }

    #[test]
    fn test_usage_is_zero() {
        assert!(ResourceUsage::zero().is_zero());
        assert!(!usage(1, 0, 0, 0, 0, 0).is_zero());
    }

    #[test]
    fn test_usage_weighted_total() {
        let u = usage(100, 10, 5, 2, 3, 1000);
        let total = u.weighted_total();
        // cpu=100, mem=10*10=100, stor=5*2=10, net=2*5=10, api=3*100=300, tok=1000
        assert_eq!(total, 100 + 100 + 10 + 10 + 300 + 1000);
    }

    #[test]
    fn test_usage_cbor_roundtrip() {
        let u = usage(100, 200, 300, 400, 500, 600);
        let val = u.to_cbor();
        let u2 = ResourceUsage::from_cbor(&val).unwrap();
        assert_eq!(u, u2);
    }

    #[test]
    fn test_usage_bytes_roundtrip() {
        let u = usage(1, 2, 3, 4, 5, 6);
        let bytes = u.to_bytes().unwrap();
        let u2 = ResourceUsage::from_bytes(&bytes).unwrap();
        assert_eq!(u, u2);
    }

    #[test]
    fn test_usage_add_saturates() {
        let a = ResourceUsage::new(u64::MAX, 0, 0, 0, 0, 0);
        let b = usage(1, 0, 0, 0, 0, 0);
        let c = a.add(&b);
        assert_eq!(c.cpu_ms, u64::MAX);
    }

    // --- ResourceLimits tests ---

    #[test]
    fn test_limits_unlimited() {
        let l = ResourceLimits::unlimited();
        assert_eq!(l.cpu_ms, u64::MAX);
        let huge = usage(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        assert!(l.check(&huge).is_ok());
    }

    #[test]
    fn test_limits_zero() {
        let l = ResourceLimits::zero();
        let small = usage(1, 0, 0, 0, 0, 0);
        assert!(l.check(&small).is_err());
        assert!(l.check(&ResourceUsage::zero()).is_ok());
    }

    #[test]
    fn test_limits_check_ok() {
        let l = ResourceLimits::new(100, 200, 300, 400, 500, 600);
        let u = usage(50, 100, 150, 200, 250, 300);
        assert!(l.check(&u).is_ok());
    }

    #[test]
    fn test_limits_check_exceeds() {
        let l = ResourceLimits::new(100, 200, 300, 400, 500, 600);
        let u = usage(150, 100, 150, 200, 250, 300);
        let err = l.check(&u).unwrap_err();
        assert_eq!(err.0, "cpu_ms");
        assert_eq!(err.1, 150);
        assert_eq!(err.2, 100);
    }

    #[test]
    fn test_limits_from_usage() {
        let u = usage(10, 20, 30, 40, 50, 60);
        let l = ResourceLimits::from_usage(&u);
        assert_eq!(l.cpu_ms, 10);
        assert_eq!(l.inference_tokens, 60);
    }

    #[test]
    fn test_limits_default_is_unlimited() {
        let l = ResourceLimits::default();
        assert_eq!(l, ResourceLimits::unlimited());
    }

    #[test]
    fn test_limits_cbor_roundtrip() {
        let l = ResourceLimits::new(100, 200, 300, 400, 500, 600);
        let val = l.to_cbor();
        let l2 = ResourceLimits::from_cbor(&val).unwrap();
        assert_eq!(l, l2);
    }

    // --- OverflowPolicy tests ---

    #[test]
    fn test_overflow_policy_default_is_reject() {
        assert_eq!(OverflowPolicy::default(), OverflowPolicy::Reject);
    }

    #[test]
    fn test_overflow_policy_cbor_roundtrip() {
        for p in [
            OverflowPolicy::Reject,
            OverflowPolicy::Allow,
            OverflowPolicy::Warn,
        ] {
            let val = p.to_cbor();
            assert_eq!(OverflowPolicy::from_cbor(&val).unwrap(), p);
        }
    }

    #[test]
    fn test_overflow_policy_invalid() {
        let val = Value::Unsigned(99);
        assert!(OverflowPolicy::from_cbor(&val).is_err());
    }

    // --- AccountConfig tests ---

    #[test]
    fn test_config_default() {
        let c = AccountConfig::default();
        assert_eq!(c.default_limits, ResourceLimits::unlimited());
        assert_eq!(c.overflow_policy, OverflowPolicy::Reject);
        assert!(c.agent_limits.is_empty());
    }

    #[test]
    fn test_config_builder() {
        let c = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(1000, 2000, 3000, 4000, 5000, 6000))
            .with_overflow_policy(OverflowPolicy::Warn)
            .with_agent_limit("agent-a", ResourceLimits::new(10, 0, 0, 0, 0, 0));
        assert_eq!(c.default_limits.cpu_ms, 1000);
        assert_eq!(c.overflow_policy, OverflowPolicy::Warn);
        assert_eq!(c.limits_for("agent-a").cpu_ms, 10);
        // unknown agent falls back to default
        assert_eq!(c.limits_for("unknown").cpu_ms, 1000);
    }

    #[test]
    fn test_config_cbor_roundtrip() {
        let mut c = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(100, 200, 300, 400, 500, 600))
            .with_overflow_policy(OverflowPolicy::Allow);
        c = c.with_agent_limit("a1", ResourceLimits::new(1, 2, 3, 4, 5, 6));
        let val = c.to_cbor();
        let c2 = AccountConfig::from_cbor(&val).unwrap();
        assert_eq!(c2.default_limits, c.default_limits);
        assert_eq!(c2.overflow_policy, c.overflow_policy);
        assert_eq!(c2.agent_limits.get("a1"), c.agent_limits.get("a1"));
    }

    // --- ResourceAccount basic tests ---

    #[test]
    fn test_account_register_and_contains() {
        let mut acct = ResourceAccount::with_defaults();
        assert!(!acct.contains("a"));
        assert!(acct.register("a"));
        assert!(acct.contains("a"));
        assert!(!acct.register("a")); // duplicate
        assert_eq!(acct.agent_count(), 1);
    }

    #[test]
    fn test_account_balance_unknown_is_zero() {
        let acct = ResourceAccount::with_defaults();
        assert!(acct.balance("unknown").is_zero());
    }

    #[test]
    fn test_account_debit_basic() {
        let mut acct = ResourceAccount::with_defaults();
        let u = usage(100, 10, 5, 2, 1, 50);
        acct.debit("a", &u).unwrap();
        let bal = acct.balance("a");
        assert_eq!(bal.cpu_ms, 100);
        assert_eq!(bal.inference_tokens, 50);
    }

    #[test]
    fn test_account_debit_accumulates() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(100, 0, 0, 0, 0, 0)).unwrap();
        acct.debit("a", &usage(50, 0, 0, 0, 0, 0)).unwrap();
        assert_eq!(acct.balance("a").cpu_ms, 150);
    }

    #[test]
    fn test_account_credit_reduces_balance() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(100, 0, 0, 0, 0, 0)).unwrap();
        acct.credit("a", &usage(30, 0, 0, 0, 0, 0));
        assert_eq!(acct.balance("a").cpu_ms, 70);
    }

    #[test]
    fn test_account_credit_saturates_at_zero() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(50, 0, 0, 0, 0, 0)).unwrap();
        acct.credit("a", &usage(100, 0, 0, 0, 0, 0));
        assert_eq!(acct.balance("a").cpu_ms, 0);
    }

    #[test]
    fn test_account_ledger_tracks_totals() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(100, 0, 0, 0, 0, 0)).unwrap();
        acct.credit("a", &usage(30, 0, 0, 0, 0, 0));
        let ledger = acct.ledger("a").unwrap();
        assert_eq!(ledger.total_debited.cpu_ms, 100);
        assert_eq!(ledger.total_credited.cpu_ms, 30);
        assert_eq!(ledger.net_usage.cpu_ms, 70);
    }

    // --- Limit enforcement tests ---

    #[test]
    fn test_account_debit_rejected_on_limit() {
        let config = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(
                100,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ))
            .with_overflow_policy(OverflowPolicy::Reject);
        let mut acct = ResourceAccount::new(config);
        acct.debit("a", &usage(90, 0, 0, 0, 0, 0)).unwrap();
        let err = acct.debit("a", &usage(20, 0, 0, 0, 0, 0)).unwrap_err();
        assert!(matches!(err, EconomicsError::LimitExceeded { .. }));
        // balance unchanged after rejection
        assert_eq!(acct.balance("a").cpu_ms, 90);
    }

    #[test]
    fn test_account_debit_allowed_on_limit() {
        let config = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(
                100,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ))
            .with_overflow_policy(OverflowPolicy::Allow);
        let mut acct = ResourceAccount::new(config);
        acct.debit("a", &usage(90, 0, 0, 0, 0, 0)).unwrap();
        acct.debit("a", &usage(20, 0, 0, 0, 0, 0)).unwrap();
        assert_eq!(acct.balance("a").cpu_ms, 110);
    }

    #[test]
    fn test_account_debit_warn_on_limit() {
        let config = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(
                100,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ))
            .with_overflow_policy(OverflowPolicy::Warn);
        let mut acct = ResourceAccount::new(config);
        acct.debit("a", &usage(90, 0, 0, 0, 0, 0)).unwrap();
        let check = acct.debit_checked("a", &usage(20, 0, 0, 0, 0, 0)).unwrap();
        assert!(matches!(check, LimitCheck::Warning { .. }));
        assert_eq!(acct.balance("a").cpu_ms, 110);
    }

    #[test]
    fn test_account_debit_checked_ok() {
        let mut acct = ResourceAccount::with_defaults();
        let check = acct.debit_checked("a", &usage(10, 0, 0, 0, 0, 0)).unwrap();
        assert_eq!(check, LimitCheck::Ok);
    }

    #[test]
    fn test_account_check_limits_ok() {
        let config = AccountConfig::new().with_default_limits(ResourceLimits::new(
            100,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        ));
        let acct = ResourceAccount::new(config);
        assert!(acct.check_limits("a", &usage(50, 0, 0, 0, 0, 0)).is_ok());
    }

    #[test]
    fn test_account_check_limits_exceeds() {
        let config = AccountConfig::new().with_default_limits(ResourceLimits::new(
            100,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        ));
        let mut acct = ResourceAccount::new(config);
        acct.debit("a", &usage(90, 0, 0, 0, 0, 0)).unwrap();
        let err = acct
            .check_limits("a", &usage(20, 0, 0, 0, 0, 0))
            .unwrap_err();
        assert_eq!(err.0, "cpu_ms");
    }

    #[test]
    fn test_account_per_agent_limits() {
        let config = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(
                1000,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ))
            .with_agent_limit(
                "special",
                ResourceLimits::new(10, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            );
        let mut acct = ResourceAccount::new(config);
        // default agent can debit up to 1000
        acct.debit("normal", &usage(500, 0, 0, 0, 0, 0)).unwrap();
        // special agent limited to 10
        acct.debit("special", &usage(5, 0, 0, 0, 0, 0)).unwrap();
        assert!(acct.debit("special", &usage(10, 0, 0, 0, 0, 0)).is_err());
    }

    // --- Transfer tests ---

    #[test]
    fn test_account_transfer_success() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(100, 50, 0, 0, 0, 0)).unwrap();
        acct.transfer("a", "b", &usage(40, 20, 0, 0, 0, 0)).unwrap();
        assert_eq!(acct.balance("a").cpu_ms, 60);
        assert_eq!(acct.balance("a").memory_mb, 30);
        assert_eq!(acct.balance("b").cpu_ms, 40);
        assert_eq!(acct.balance("b").memory_mb, 20);
    }

    #[test]
    fn test_account_transfer_insufficient() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(50, 0, 0, 0, 0, 0)).unwrap();
        let err = acct
            .transfer("a", "b", &usage(100, 0, 0, 0, 0, 0))
            .unwrap_err();
        assert!(matches!(err, EconomicsError::InsufficientBalance { .. }));
        // balances unchanged
        assert_eq!(acct.balance("a").cpu_ms, 50);
        assert_eq!(acct.balance("b").cpu_ms, 0);
    }

    #[test]
    fn test_account_transfer_partial_component_insufficient() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(100, 10, 0, 0, 0, 0)).unwrap();
        // memory insufficient
        let err = acct
            .transfer("a", "b", &usage(50, 20, 0, 0, 0, 0))
            .unwrap_err();
        assert!(matches!(err, EconomicsError::InsufficientBalance { .. }));
    }

    // --- Reset / remove / agents tests ---

    #[test]
    fn test_account_reset() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(100, 0, 0, 0, 0, 0)).unwrap();
        acct.reset("a");
        assert!(acct.balance("a").is_zero());
    }

    #[test]
    fn test_account_remove() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("a", &usage(10, 0, 0, 0, 0, 0)).unwrap();
        assert!(acct.remove("a"));
        assert!(!acct.contains("a"));
        assert!(!acct.remove("a"));
    }

    #[test]
    fn test_account_agents_sorted() {
        let mut acct = ResourceAccount::with_defaults();
        acct.debit("c", &usage(1, 0, 0, 0, 0, 0)).unwrap();
        acct.debit("a", &usage(1, 0, 0, 0, 0, 0)).unwrap();
        acct.debit("b", &usage(1, 0, 0, 0, 0, 0)).unwrap();
        assert_eq!(acct.agents(), vec!["a", "b", "c"]);
    }

    // --- Persistence tests ---

    #[test]
    fn test_account_persistence_roundtrip() {
        let config = AccountConfig::new()
            .with_default_limits(ResourceLimits::new(1000, 2000, 3000, 4000, 5000, 6000))
            .with_overflow_policy(OverflowPolicy::Warn)
            .with_agent_limit("a", ResourceLimits::new(100, 0, 0, 0, 0, 0));
        let mut acct = ResourceAccount::new(config);
        acct.debit("a", &usage(50, 10, 5, 2, 1, 100)).unwrap();
        acct.debit("b", &usage(20, 5, 0, 0, 0, 50)).unwrap();
        acct.credit("a", &usage(10, 0, 0, 0, 0, 0));

        let bytes = acct.to_bytes().unwrap();
        let acct2 = ResourceAccount::from_bytes(&bytes).unwrap();

        assert_eq!(acct2.balance("a"), acct.balance("a"));
        assert_eq!(acct2.balance("b"), acct.balance("b"));
        assert_eq!(acct2.config().default_limits, acct.config().default_limits);
        assert_eq!(
            acct2.config().overflow_policy,
            acct.config().overflow_policy
        );
    }

    #[test]
    fn test_account_persistence_empty() {
        let acct = ResourceAccount::with_defaults();
        let bytes = acct.to_bytes().unwrap();
        let acct2 = ResourceAccount::from_bytes(&bytes).unwrap();
        assert_eq!(acct2.agent_count(), 0);
    }

    #[test]
    fn test_agent_ledger_cbor_roundtrip() {
        let mut ledger = AgentLedger::new();
        ledger.debit(&usage(100, 10, 5, 2, 1, 50));
        ledger.credit(&usage(30, 5, 0, 0, 0, 10));
        let val = ledger.to_cbor();
        let ledger2 = AgentLedger::from_cbor(&val).unwrap();
        assert_eq!(ledger, ledger2);
    }

    #[test]
    fn test_account_default_impl() {
        let acct = ResourceAccount::default();
        assert_eq!(acct.agent_count(), 0);
        assert_eq!(acct.config().overflow_policy, OverflowPolicy::Reject);
    }
}
