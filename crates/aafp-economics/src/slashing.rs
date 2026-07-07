//! Slashing conditions and penalties (Track X5).
//!
//! [`SlashingEngine`] evaluates slashing conditions and applies penalties to
//! agent accounts. It integrates with [`ResourceAccount`] to debit slashed
//! amounts and maintains a per-agent history of slash records with an appeal
//! process.
//!
//! ## Conditions
//!
//! A [`SlashingCondition`] describes the reason an agent may be slashed:
//!
//! - [`SlashingCondition::Downtime`] — agent was offline for too long.
//! - [`SlashingCondition::MissedTasks`] — agent failed to complete assigned
//!   tasks.
//! - [`SlashingCondition::MaliciousBehavior`] — agent acted maliciously (e.g.
//!   submitted false results).
//! - [`SlashingCondition::ResourceMisuse`] — agent over-consumed resources.
//! - [`SlashingCondition::ContractViolation`] — agent violated contract terms.
//! - [`SlashingCondition::RepeatedFailures`] — agent has too many consecutive
//!   failures.
//!
//! ## Severity
//!
//! Each penalty has a [`Severity`] — `Minor` (1× multiplier), `Major` (5×),
//! or `Critical` (10×) — that scales the base slashing amount.
//!
//! ## Lifecycle
//!
//! A [`SlashRecord`] starts in [`SlashStatus::Pending`]. When
//! [`SlashingEngine::slash`] executes the penalty, the record transitions to
//! [`SlashStatus::Executed`] and the slashed amount is debited from the
//! agent's [`ResourceAccount`] (if attached). The agent can then
//! [`SlashingEngine::appeal`] the slash, transitioning the record to
//! [`SlashStatus::Appealed`]. An arbiter resolves the appeal via
//! [`SlashingEngine::resolve_appeal`], transitioning to either
//! [`SlashStatus::Reversed`] (appeal upheld — the slash is refunded) or
//! [`SlashStatus::Upheld`] (appeal denied — the slash stands).
//!
//! ## Rate limiting and cooldown
//!
//! [`SlashingConfig`] enforces two protective mechanisms:
//!
//! - **Rate limiting** — at most `max_slashes_per_window` slashes per agent
//!   within `rate_limit_window_ms`.
//! - **Cooldown** — after a slash for a specific condition, the same
//!   condition cannot be slashed again for `cooldown_period_ms`.
//!
//! All persistent structures encode to canonical CBOR int-keyed maps
//! (RFC-0002 §8).

use std::collections::HashMap;

use aafp_cbor::{int_map, int_map_get, Value};

use crate::account::{ResourceAccount, ResourceUsage};
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

fn dec_str(val: &Value, field: &'static str) -> Result<String, EconomicsError> {
    match val {
        Value::TextString(s) => Ok(s.clone()),
        _ => Err(EconomicsError::InvalidField {
            field,
            message: format!("expected text string, got {val:?}"),
        }),
    }
}

fn dec_opt_str(val: &Value, field: &'static str) -> Result<Option<String>, EconomicsError> {
    match val {
        Value::Null => Ok(None),
        Value::TextString(s) => Ok(Some(s.clone())),
        _ => Err(EconomicsError::InvalidField {
            field,
            message: format!("expected text string or null, got {val:?}"),
        }),
    }
}

fn enc_opt_str(s: &Option<String>) -> Value {
    match s {
        Some(s) => Value::TextString(s.clone()),
        None => Value::Null,
    }
}

fn dec_opt_u64(val: &Value, field: &'static str) -> Result<Option<u64>, EconomicsError> {
    match val {
        Value::Null => Ok(None),
        Value::Unsigned(n) => Ok(Some(*n)),
        _ => Err(EconomicsError::InvalidField {
            field,
            message: format!("expected unsigned integer or null, got {val:?}"),
        }),
    }
}

fn enc_opt_u64(n: Option<u64>) -> Value {
    match n {
        Some(n) => enc_u64(n),
        None => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// SlashingCondition
// ---------------------------------------------------------------------------

/// The condition that triggered a slashing penalty.
///
/// Encoded as an unsigned integer: `Downtime = 0`, `MissedTasks = 1`,
/// `MaliciousBehavior = 2`, `ResourceMisuse = 3`, `ContractViolation = 4`,
/// `RepeatedFailures = 5`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SlashingCondition {
    /// Agent was offline for too long.
    #[default]
    Downtime = 0,
    /// Agent failed to complete assigned tasks.
    MissedTasks = 1,
    /// Agent acted maliciously (e.g. submitted false results).
    MaliciousBehavior = 2,
    /// Agent over-consumed resources beyond allowed limits.
    ResourceMisuse = 3,
    /// Agent violated contract terms.
    ContractViolation = 4,
    /// Agent has too many consecutive failures.
    RepeatedFailures = 5,
}

impl SlashingCondition {
    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Downtime),
            Value::Unsigned(1) => Ok(Self::MissedTasks),
            Value::Unsigned(2) => Ok(Self::MaliciousBehavior),
            Value::Unsigned(3) => Ok(Self::ResourceMisuse),
            Value::Unsigned(4) => Ok(Self::ContractViolation),
            Value::Unsigned(5) => Ok(Self::RepeatedFailures),
            _ => Err(EconomicsError::InvalidField {
                field: "slashing_condition",
                message: format!("expected 0/1/2/3/4/5, got {val:?}"),
            }),
        }
    }

    /// Human-readable name of the condition.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Downtime => "downtime",
            Self::MissedTasks => "missed_tasks",
            Self::MaliciousBehavior => "malicious_behavior",
            Self::ResourceMisuse => "resource_misuse",
            Self::ContractViolation => "contract_violation",
            Self::RepeatedFailures => "repeated_failures",
        }
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity of a slashing penalty, with an associated multiplier that scales
/// the base slashing amount.
///
/// Encoded as an unsigned integer: `Minor = 0`, `Major = 1`, `Critical = 2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Severity {
    /// Minor offense — 1× multiplier.
    #[default]
    Minor = 0,
    /// Major offense — 5× multiplier.
    Major = 1,
    /// Critical offense — 10× multiplier.
    Critical = 2,
}

impl Severity {
    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Minor),
            Value::Unsigned(1) => Ok(Self::Major),
            Value::Unsigned(2) => Ok(Self::Critical),
            _ => Err(EconomicsError::InvalidField {
                field: "severity",
                message: format!("expected 0/1/2, got {val:?}"),
            }),
        }
    }

    /// Multiplier applied to the base slashing amount: Minor = 1×, Major = 5×,
    /// Critical = 10×.
    pub fn multiplier(&self) -> u32 {
        match self {
            Self::Minor => 1,
            Self::Major => 5,
            Self::Critical => 10,
        }
    }
}

// ---------------------------------------------------------------------------
// SlashingPenalty
// ---------------------------------------------------------------------------

/// A slashing penalty to be applied to an agent.
#[derive(Clone, Debug)]
pub struct SlashingPenalty {
    /// The condition that triggered the penalty.
    pub condition: SlashingCondition, // key 1
    /// Slashing amount in milli-credits (1 credit = 1000 milli-credits).
    pub amount_milli: i64, // key 2
    /// Severity of the offense.
    pub severity: Severity, // key 3
    /// Free-text evidence or justification for the penalty.
    pub evidence: String, // key 4
}

impl SlashingPenalty {
    /// Create a new penalty. The amount is computed from `base_amount_milli`
    /// and the severity multiplier.
    pub fn new(
        condition: SlashingCondition,
        severity: Severity,
        base_amount_milli: i64,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            condition,
            amount_milli: Self::compute_amount(base_amount_milli, severity),
            severity,
            evidence: evidence.into(),
        }
    }

    /// Create a penalty with an explicit amount (overriding the computed
    /// amount).
    pub fn with_amount(
        condition: SlashingCondition,
        severity: Severity,
        amount_milli: i64,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            condition,
            amount_milli,
            severity,
            evidence: evidence.into(),
        }
    }

    /// Compute the slashing amount from a base amount and severity multiplier.
    pub fn compute_amount(base_amount_milli: i64, severity: Severity) -> i64 {
        base_amount_milli.saturating_mul(severity.multiplier() as i64)
    }

    /// Amount in credits (as `f64`).
    pub fn amount_credits(&self) -> f64 {
        self.amount_milli as f64 / 1000.0
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, self.condition.to_cbor()),
            (2, enc_i64(self.amount_milli)),
            (3, self.severity.to_cbor()),
            (4, Value::TextString(self.evidence.clone())),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            condition: match opt(val, 1) {
                Some(v) => SlashingCondition::from_cbor(v)?,
                None => SlashingCondition::default(),
            },
            amount_milli: dec_i64(req(val, 2, "amount_milli")?, "amount_milli")?,
            severity: match opt(val, 3) {
                Some(v) => Severity::from_cbor(v)?,
                None => Severity::default(),
            },
            evidence: dec_str(req(val, 4, "evidence")?, "evidence")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SlashingConfig
// ---------------------------------------------------------------------------

/// Configuration for the [`SlashingEngine`].
///
/// Amounts are in milli-credits (1 credit = 1000 milli-credits).
#[derive(Clone, Debug)]
pub struct SlashingConfig {
    /// Downtime threshold in milliseconds. If `now - last_seen_ms` exceeds
    /// this value, the `Downtime` condition is met. Default 3_600_000 (1 hour).
    pub downtime_threshold_ms: u64, // key 1
    /// Number of missed tasks that triggers the `MissedTasks` condition.
    /// Default 5.
    pub missed_tasks_threshold: u32, // key 2
    /// Number of malicious behavior flags that triggers the
    /// `MaliciousBehavior` condition. Default 1.
    pub malicious_behavior_threshold: u32, // key 3
    /// Number of resource overuse incidents that triggers the
    /// `ResourceMisuse` condition. Default 3.
    pub resource_misuse_threshold: u32, // key 4
    /// Number of contract violations that triggers the
    /// `ContractViolation` condition. Default 1.
    pub contract_violation_threshold: u32, // key 5
    /// Number of consecutive failures that triggers the `RepeatedFailures`
    /// condition. Default 3.
    pub repeated_failures_threshold: u32, // key 6
    /// Maximum percentage of an agent's balance that can be slashed in a single
    /// penalty (0-100). Default 50.
    pub max_slash_percentage: u32, // key 7
    /// Cooldown period in milliseconds after a slash for a specific condition
    /// before the same condition can be slashed again. Default 3_600_000
    /// (1 hour).
    pub cooldown_period_ms: u64, // key 8
    /// Base slashing amount in milli-credits. The actual amount is
    /// `base_amount_milli * severity.multiplier()`. Default 10_000
    /// (10 credits for Minor).
    pub base_amount_milli: i64, // key 9
    /// Maximum number of slashes per agent within the rate-limit window.
    /// Default 5.
    pub max_slashes_per_window: u32, // key 10
    /// Rate-limit window in milliseconds. Default 3_600_000 (1 hour).
    pub rate_limit_window_ms: u64, // key 11
}

impl SlashingConfig {
    /// Create a config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the downtime threshold (milliseconds).
    pub fn with_downtime_threshold(mut self, ms: u64) -> Self {
        self.downtime_threshold_ms = ms;
        self
    }

    /// Set the missed-tasks threshold.
    pub fn with_missed_tasks_threshold(mut self, count: u32) -> Self {
        self.missed_tasks_threshold = count;
        self
    }

    /// Set the malicious-behavior threshold.
    pub fn with_malicious_behavior_threshold(mut self, count: u32) -> Self {
        self.malicious_behavior_threshold = count;
        self
    }

    /// Set the resource-misuse threshold.
    pub fn with_resource_misuse_threshold(mut self, count: u32) -> Self {
        self.resource_misuse_threshold = count;
        self
    }

    /// Set the contract-violation threshold.
    pub fn with_contract_violation_threshold(mut self, count: u32) -> Self {
        self.contract_violation_threshold = count;
        self
    }

    /// Set the repeated-failures threshold.
    pub fn with_repeated_failures_threshold(mut self, count: u32) -> Self {
        self.repeated_failures_threshold = count;
        self
    }

    /// Set the max slash percentage (0-100).
    pub fn with_max_slash_percentage(mut self, pct: u32) -> Self {
        self.max_slash_percentage = pct;
        self
    }

    /// Set the cooldown period (milliseconds).
    pub fn with_cooldown_period(mut self, ms: u64) -> Self {
        self.cooldown_period_ms = ms;
        self
    }

    /// Set the base slashing amount (milli-credits).
    pub fn with_base_amount(mut self, milli: i64) -> Self {
        self.base_amount_milli = milli;
        self
    }

    /// Set the rate-limit (max slashes per window).
    pub fn with_rate_limit(mut self, count: u32, window_ms: u64) -> Self {
        self.max_slashes_per_window = count;
        self.rate_limit_window_ms = window_ms;
        self
    }

    /// Validate the configuration. Returns an error if any field is invalid.
    pub fn validate(&self) -> Result<(), EconomicsError> {
        if self.max_slash_percentage > 100 {
            return Err(EconomicsError::InvalidSlashingConfig(
                "max_slash_percentage must be 0-100".to_string(),
            ));
        }
        if self.base_amount_milli < 0 {
            return Err(EconomicsError::InvalidSlashingConfig(
                "base_amount_milli must be non-negative".to_string(),
            ));
        }
        Ok(())
    }

    /// Get the threshold value for a specific condition.
    pub fn threshold_for(&self, condition: SlashingCondition) -> u64 {
        match condition {
            SlashingCondition::Downtime => self.downtime_threshold_ms,
            SlashingCondition::MissedTasks => self.missed_tasks_threshold as u64,
            SlashingCondition::MaliciousBehavior => self.malicious_behavior_threshold as u64,
            SlashingCondition::ResourceMisuse => self.resource_misuse_threshold as u64,
            SlashingCondition::ContractViolation => self.contract_violation_threshold as u64,
            SlashingCondition::RepeatedFailures => self.repeated_failures_threshold as u64,
        }
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_u64(self.downtime_threshold_ms)),
            (2, enc_u64(self.missed_tasks_threshold as u64)),
            (3, enc_u64(self.malicious_behavior_threshold as u64)),
            (4, enc_u64(self.resource_misuse_threshold as u64)),
            (5, enc_u64(self.contract_violation_threshold as u64)),
            (6, enc_u64(self.repeated_failures_threshold as u64)),
            (7, enc_u64(self.max_slash_percentage as u64)),
            (8, enc_u64(self.cooldown_period_ms)),
            (9, enc_i64(self.base_amount_milli)),
            (10, enc_u64(self.max_slashes_per_window as u64)),
            (11, enc_u64(self.rate_limit_window_ms)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            downtime_threshold_ms: match opt(val, 1) {
                Some(v) => dec_u64(v, "downtime_threshold_ms")?,
                None => 3_600_000,
            },
            missed_tasks_threshold: match opt(val, 2) {
                Some(v) => dec_u64(v, "missed_tasks_threshold")? as u32,
                None => 5,
            },
            malicious_behavior_threshold: match opt(val, 3) {
                Some(v) => dec_u64(v, "malicious_behavior_threshold")? as u32,
                None => 1,
            },
            resource_misuse_threshold: match opt(val, 4) {
                Some(v) => dec_u64(v, "resource_misuse_threshold")? as u32,
                None => 3,
            },
            contract_violation_threshold: match opt(val, 5) {
                Some(v) => dec_u64(v, "contract_violation_threshold")? as u32,
                None => 1,
            },
            repeated_failures_threshold: match opt(val, 6) {
                Some(v) => dec_u64(v, "repeated_failures_threshold")? as u32,
                None => 3,
            },
            max_slash_percentage: match opt(val, 7) {
                Some(v) => dec_u64(v, "max_slash_percentage")? as u32,
                None => 50,
            },
            cooldown_period_ms: match opt(val, 8) {
                Some(v) => dec_u64(v, "cooldown_period_ms")?,
                None => 3_600_000,
            },
            base_amount_milli: match opt(val, 9) {
                Some(v) => dec_i64(v, "base_amount_milli")?,
                None => 10_000,
            },
            max_slashes_per_window: match opt(val, 10) {
                Some(v) => dec_u64(v, "max_slashes_per_window")? as u32,
                None => 5,
            },
            rate_limit_window_ms: match opt(val, 11) {
                Some(v) => dec_u64(v, "rate_limit_window_ms")?,
                None => 3_600_000,
            },
        })
    }
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            downtime_threshold_ms: 3_600_000,
            missed_tasks_threshold: 5,
            malicious_behavior_threshold: 1,
            resource_misuse_threshold: 3,
            contract_violation_threshold: 1,
            repeated_failures_threshold: 3,
            max_slash_percentage: 50,
            cooldown_period_ms: 3_600_000,
            base_amount_milli: 10_000,
            max_slashes_per_window: 5,
            rate_limit_window_ms: 3_600_000,
        }
    }
}

// ---------------------------------------------------------------------------
// SlashStatus
// ---------------------------------------------------------------------------

/// Lifecycle state of a slash record.
///
/// Encoded as an unsigned integer: `Pending = 0`, `Executed = 1`,
/// `Appealed = 2`, `Reversed = 3`, `Upheld = 4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SlashStatus {
    /// Created but not yet executed.
    #[default]
    Pending = 0,
    /// Penalty has been applied (debited from the agent's account).
    Executed = 1,
    /// Agent has filed an appeal; awaiting resolution.
    Appealed = 2,
    /// Appeal was upheld; the penalty has been reversed (refunded).
    Reversed = 3,
    /// Appeal was denied; the penalty stands.
    Upheld = 4,
}

impl SlashStatus {
    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Pending),
            Value::Unsigned(1) => Ok(Self::Executed),
            Value::Unsigned(2) => Ok(Self::Appealed),
            Value::Unsigned(3) => Ok(Self::Reversed),
            Value::Unsigned(4) => Ok(Self::Upheld),
            _ => Err(EconomicsError::InvalidField {
                field: "slash_status",
                message: format!("expected 0/1/2/3/4, got {val:?}"),
            }),
        }
    }

    /// Returns `true` if the status is terminal (no further transitions
    /// expected).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Reversed | Self::Upheld)
    }
}

// ---------------------------------------------------------------------------
// AppealInfo
// ---------------------------------------------------------------------------

/// Information attached to an appealed slash record.
#[derive(Clone, Debug)]
pub struct AppealInfo {
    /// The agent or operator who filed the appeal.
    pub filed_by: String, // key 1
    /// Free-text evidence or justification for the appeal.
    pub evidence: String, // key 2
    /// Timestamp when the appeal was filed (ms since epoch).
    pub filed_at: u64, // key 3
    /// The arbiter assigned to resolve the appeal (empty if unassigned).
    pub arbiter: String, // key 4
    /// Optional resolution note set by the arbiter.
    pub resolution_note: Option<String>, // key 5
}

impl AppealInfo {
    /// Create new appeal info.
    pub fn new(filed_by: impl Into<String>, evidence: impl Into<String>, filed_at: u64) -> Self {
        Self {
            filed_by: filed_by.into(),
            evidence: evidence.into(),
            filed_at,
            arbiter: String::new(),
            resolution_note: None,
        }
    }

    /// Assign an arbiter.
    pub fn with_arbiter(mut self, arbiter: impl Into<String>) -> Self {
        self.arbiter = arbiter.into();
        self
    }

    /// Set a resolution note.
    pub fn with_resolution(mut self, note: impl Into<String>) -> Self {
        self.resolution_note = Some(note.into());
        self
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.filed_by.clone())),
            (2, Value::TextString(self.evidence.clone())),
            (3, enc_u64(self.filed_at)),
            (4, Value::TextString(self.arbiter.clone())),
            (5, enc_opt_str(&self.resolution_note)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            filed_by: dec_str(req(val, 1, "filed_by")?, "filed_by")?,
            evidence: dec_str(req(val, 2, "evidence")?, "evidence")?,
            filed_at: dec_u64(req(val, 3, "filed_at")?, "filed_at")?,
            arbiter: match opt(val, 4) {
                Some(v) => dec_str(v, "arbiter")?,
                None => String::new(),
            },
            resolution_note: match opt(val, 5) {
                Some(v) => dec_opt_str(v, "resolution_note")?,
                None => None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// SlashRecord
// ---------------------------------------------------------------------------

/// A single slash record tracking the penalty applied to an agent.
#[derive(Clone, Debug)]
pub struct SlashRecord {
    /// Unique slash record identifier.
    pub id: String, // key 1
    /// The agent that was slashed.
    pub agent_id: String, // key 2
    /// The penalty applied.
    pub penalty: SlashingPenalty, // key 3
    /// Timestamp when the slash was created (ms since epoch).
    pub timestamp: u64, // key 4
    /// Current status.
    pub status: SlashStatus, // key 5
    /// Appeal information, if the slash has been appealed.
    pub appeal: Option<AppealInfo>, // key 6
    /// Timestamp when the slash was executed (ms since epoch), if executed.
    pub executed_at: Option<u64>, // key 7
    /// The actual amount debited from the agent's account (may be less than
    /// `penalty.amount_milli` due to max-slash-percentage cap). If no
    /// [`ResourceAccount`] is attached, this equals `penalty.amount_milli`.
    pub executed_amount_milli: i64, // key 8
}

impl SlashRecord {
    /// Create a new pending slash record.
    pub fn new(
        id: impl Into<String>,
        agent_id: impl Into<String>,
        penalty: SlashingPenalty,
        timestamp: u64,
    ) -> Self {
        let amount = penalty.amount_milli;
        Self {
            id: id.into(),
            agent_id: agent_id.into(),
            penalty,
            timestamp,
            status: SlashStatus::Pending,
            appeal: None,
            executed_at: None,
            executed_amount_milli: amount,
        }
    }

    /// Amount in credits (as `f64`), using the executed amount.
    pub fn executed_credits(&self) -> f64 {
        self.executed_amount_milli as f64 / 1000.0
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.id.clone())),
            (2, Value::TextString(self.agent_id.clone())),
            (3, self.penalty.to_cbor()),
            (4, enc_u64(self.timestamp)),
            (5, self.status.to_cbor()),
            (
                6,
                match &self.appeal {
                    Some(a) => a.to_cbor(),
                    None => Value::Null,
                },
            ),
            (7, enc_opt_u64(self.executed_at)),
            (8, enc_i64(self.executed_amount_milli)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            id: dec_str(req(val, 1, "id")?, "id")?,
            agent_id: dec_str(req(val, 2, "agent_id")?, "agent_id")?,
            penalty: match opt(val, 3) {
                Some(v) => SlashingPenalty::from_cbor(v)?,
                None => SlashingPenalty::with_amount(
                    SlashingCondition::default(),
                    Severity::default(),
                    0,
                    "",
                ),
            },
            timestamp: dec_u64(req(val, 4, "timestamp")?, "timestamp")?,
            status: match opt(val, 5) {
                Some(v) => SlashStatus::from_cbor(v)?,
                None => SlashStatus::default(),
            },
            appeal: match opt(val, 6) {
                Some(Value::Null) | None => None,
                Some(v) => Some(AppealInfo::from_cbor(v)?),
            },
            executed_at: match opt(val, 7) {
                Some(Value::Null) | None => None,
                Some(v) => dec_opt_u64(v, "executed_at")?,
            },
            executed_amount_milli: match opt(val, 8) {
                Some(v) => dec_i64(v, "executed_amount_milli")?,
                None => 0,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// AgentHistory
// ---------------------------------------------------------------------------

/// Per-agent history data used by [`SlashingEngine::evaluate_condition`] to
/// determine whether a slashing condition is met.
#[derive(Clone, Debug, Default)]
pub struct AgentHistory {
    /// Last time the agent was seen online (ms since epoch).
    pub last_seen_ms: u64, // key 1
    /// Number of tasks the agent failed to complete.
    pub missed_task_count: u32, // key 2
    /// Current streak of consecutive failures.
    pub consecutive_failures: u32, // key 3
    /// Number of resource overuse incidents.
    pub resource_overuse_count: u32, // key 4
    /// Number of contract violations.
    pub contract_violations: u32, // key 5
    /// Number of malicious behavior flags.
    pub malicious_flags: u32, // key 6
}

impl AgentHistory {
    /// Create a new empty agent history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an agent history with the given last-seen timestamp.
    pub fn with_last_seen(last_seen_ms: u64) -> Self {
        Self {
            last_seen_ms,
            ..Self::default()
        }
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_u64(self.last_seen_ms)),
            (2, enc_u64(self.missed_task_count as u64)),
            (3, enc_u64(self.consecutive_failures as u64)),
            (4, enc_u64(self.resource_overuse_count as u64)),
            (5, enc_u64(self.contract_violations as u64)),
            (6, enc_u64(self.malicious_flags as u64)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            last_seen_ms: match opt(val, 1) {
                Some(v) => dec_u64(v, "last_seen_ms")?,
                None => 0,
            },
            missed_task_count: match opt(val, 2) {
                Some(v) => dec_u64(v, "missed_task_count")? as u32,
                None => 0,
            },
            consecutive_failures: match opt(val, 3) {
                Some(v) => dec_u64(v, "consecutive_failures")? as u32,
                None => 0,
            },
            resource_overuse_count: match opt(val, 4) {
                Some(v) => dec_u64(v, "resource_overuse_count")? as u32,
                None => 0,
            },
            contract_violations: match opt(val, 5) {
                Some(v) => dec_u64(v, "contract_violations")? as u32,
                None => 0,
            },
            malicious_flags: match opt(val, 6) {
                Some(v) => dec_u64(v, "malicious_flags")? as u32,
                None => 0,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// SlashingEngine
// ---------------------------------------------------------------------------

/// Evaluates slashing conditions and applies penalties to agent accounts.
///
/// The engine maintains:
///
/// - A `HashMap` of all [`SlashRecord`]s keyed by their unique `id`.
/// - Per-agent [`AgentHistory`] used by [`Self::evaluate_condition`].
/// - Per-agent slash timestamps for rate limiting and cooldown enforcement.
/// - An optional [`ResourceAccount`] for debiting slashed amounts.
///
/// ## Integration with `ResourceAccount`
///
/// When a [`ResourceAccount`] is attached via [`Self::set_account`], the
/// slashed amount is debited from the agent's account as a
/// [`ResourceUsage`] debit (using `inference_tokens` as the credit-like
/// dimension). If an appeal is reversed, the slashed amount is credited back.
pub struct SlashingEngine {
    config: SlashingConfig,
    records: HashMap<String, SlashRecord>,
    agent_history: HashMap<String, AgentHistory>,
    /// Maps agent_id → list of (condition, timestamp) for rate limiting and
    /// cooldown tracking.
    slash_timestamps: HashMap<String, Vec<(SlashingCondition, u64)>>,
    /// Optional resource account for debiting slashed amounts.
    account: Option<ResourceAccount>,
    /// Counter for generating unique slash record IDs.
    id_counter: u64,
}

impl SlashingEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            records: HashMap::new(),
            agent_history: HashMap::new(),
            slash_timestamps: HashMap::new(),
            account: None,
            id_counter: 0,
        }
    }

    /// Create a new engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SlashingConfig::default())
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &SlashingConfig {
        &self.config
    }

    /// Return a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut SlashingConfig {
        &mut self.config
    }

    /// Attach a [`ResourceAccount`] for debiting slashed amounts.
    pub fn set_account(&mut self, account: ResourceAccount) {
        self.account = Some(account);
    }

    /// Return a reference to the attached account, if any.
    pub fn account(&self) -> Option<&ResourceAccount> {
        self.account.as_ref()
    }

    /// Return a mutable reference to the attached account, if any.
    pub fn account_mut(&mut self) -> Option<&mut ResourceAccount> {
        self.account.as_mut()
    }

    /// Generate a unique slash record ID.
    fn next_id(&mut self) -> String {
        self.id_counter += 1;
        format!("slash-{}", self.id_counter)
    }

    // -- Agent history management -------------------------------------------

    /// Update the agent history for `agent_id`.
    pub fn set_agent_history(&mut self, agent_id: &str, history: AgentHistory) {
        self.agent_history.insert(agent_id.to_string(), history);
    }

    /// Get the agent history for `agent_id`, if present.
    pub fn agent_history(&self, agent_id: &str) -> Option<&AgentHistory> {
        self.agent_history.get(agent_id)
    }

    /// Get a mutable reference to the agent history for `agent_id`, creating
    /// an empty one if it does not exist.
    pub fn agent_history_mut(&mut self, agent_id: &str) -> &mut AgentHistory {
        self.agent_history.entry(agent_id.to_string()).or_default()
    }

    // -- Rate limiting and cooldown -----------------------------------------

    /// Count the number of slashes for `agent` within the rate-limit window
    /// ending at `now`.
    fn count_recent_slashes(&self, agent: &str, now: u64) -> u32 {
        let window = self.config.rate_limit_window_ms;
        match self.slash_timestamps.get(agent) {
            Some(timestamps) => timestamps
                .iter()
                .filter(|(_, t)| now.saturating_sub(*t) <= window)
                .count() as u32,
            None => 0,
        }
    }

    /// Find the last slash timestamp for `agent` and `condition`. Returns
    /// `None` if no slash has been recorded for that condition.
    fn last_slash_for_condition(&self, agent: &str, condition: SlashingCondition) -> Option<u64> {
        self.slash_timestamps.get(agent).and_then(|timestamps| {
            timestamps
                .iter()
                .filter(|(c, _)| *c == condition)
                .map(|(_, t)| *t)
                .max()
        })
    }

    /// Record a slash timestamp for `agent` and `condition`.
    fn record_slash_timestamp(&mut self, agent: &str, condition: SlashingCondition, now: u64) {
        self.slash_timestamps
            .entry(agent.to_string())
            .or_default()
            .push((condition, now));
    }

    /// Evict expired slash timestamps older than the rate-limit window. This
    /// prevents unbounded growth of the history.
    pub fn evict_expired(&mut self, now: u64) {
        let window = self.config.rate_limit_window_ms;
        for timestamps in self.slash_timestamps.values_mut() {
            timestamps.retain(|(_, t)| now.saturating_sub(*t) <= window);
        }
    }

    /// Check whether the agent is rate-limited (too many slashes in the
    /// window).
    pub fn is_rate_limited(&self, agent: &str, now: u64) -> bool {
        self.count_recent_slashes(agent, now) >= self.config.max_slashes_per_window
    }

    /// Check whether a cooldown is active for `agent` and `condition`. Returns
    /// the remaining milliseconds if active, or `None` if no cooldown.
    pub fn cooldown_remaining(
        &self,
        agent: &str,
        condition: SlashingCondition,
        now: u64,
    ) -> Option<u64> {
        match self.last_slash_for_condition(agent, condition) {
            Some(last) => {
                let elapsed = now.saturating_sub(last);
                let cooldown = self.config.cooldown_period_ms;
                if elapsed < cooldown {
                    Some(cooldown - elapsed)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    // -- Condition evaluation -----------------------------------------------

    /// Check if a slashing condition is met for the given agent, based on
    /// the agent's history and the current time.
    ///
    /// Returns `true` if the condition is met, `false` otherwise. If the
    /// agent has no recorded history, all conditions return `false`.
    pub fn evaluate_condition(
        &self,
        agent_id: &str,
        condition: SlashingCondition,
        now: u64,
    ) -> bool {
        let Some(history) = self.agent_history.get(agent_id) else {
            return false;
        };
        match condition {
            SlashingCondition::Downtime => {
                let elapsed = now.saturating_sub(history.last_seen_ms);
                elapsed > self.config.downtime_threshold_ms
            }
            SlashingCondition::MissedTasks => {
                history.missed_task_count >= self.config.missed_tasks_threshold
            }
            SlashingCondition::MaliciousBehavior => {
                history.malicious_flags >= self.config.malicious_behavior_threshold
            }
            SlashingCondition::ResourceMisuse => {
                history.resource_overuse_count >= self.config.resource_misuse_threshold
            }
            SlashingCondition::ContractViolation => {
                history.contract_violations >= self.config.contract_violation_threshold
            }
            SlashingCondition::RepeatedFailures => {
                history.consecutive_failures >= self.config.repeated_failures_threshold
            }
        }
    }

    /// Evaluate all conditions for an agent and return the list of conditions
    /// that are currently met.
    pub fn evaluate_all_conditions(&self, agent_id: &str, now: u64) -> Vec<SlashingCondition> {
        let conditions = [
            SlashingCondition::Downtime,
            SlashingCondition::MissedTasks,
            SlashingCondition::MaliciousBehavior,
            SlashingCondition::ResourceMisuse,
            SlashingCondition::ContractViolation,
            SlashingCondition::RepeatedFailures,
        ];
        conditions
            .into_iter()
            .filter(|&c| self.evaluate_condition(agent_id, c, now))
            .collect()
    }

    // -- Slashing -----------------------------------------------------------

    /// Apply a slashing penalty to an agent. This creates a [`SlashRecord`],
    /// executes the penalty (debiting from the agent's [`ResourceAccount`] if
    /// attached), and records the slash for rate limiting and cooldown.
    ///
    /// The penalty's `amount_milli` is capped by `max_slash_percentage` of the
    /// agent's current balance (if an account is attached). The actual
    /// debited amount is recorded in `executed_amount_milli`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The agent is rate-limited (too many slashes in the window).
    /// - A cooldown is active for the same condition.
    /// - The agent's account has insufficient balance for the debit.
    pub fn slash(
        &mut self,
        agent_id: &str,
        penalty: SlashingPenalty,
        now: u64,
    ) -> Result<SlashRecord, EconomicsError> {
        // Validate config.
        self.config.validate()?;

        // Check rate limiting.
        if self.is_rate_limited(agent_id, now) {
            return Err(EconomicsError::SlashRateLimited(agent_id.to_string()));
        }

        // Check cooldown.
        if let Some(remaining) = self.cooldown_remaining(agent_id, penalty.condition, now) {
            return Err(EconomicsError::SlashCooldownActive {
                agent: agent_id.to_string(),
                condition: penalty.condition,
                remaining_ms: remaining,
            });
        }

        // Compute the effective amount (capped by max_slash_percentage).
        let mut effective_amount = penalty.amount_milli;
        if let Some(account) = &self.account {
            let balance = account.balance(agent_id);
            let balance_tokens = balance.inference_tokens;
            if self.config.max_slash_percentage > 0 && self.config.max_slash_percentage < 100 {
                let max_slash = (balance_tokens / 100) * self.config.max_slash_percentage as u64;
                effective_amount = effective_amount.min(max_slash as i64);
            }
        }

        // Ensure non-negative.
        if effective_amount < 0 {
            effective_amount = 0;
        }

        // Create the slash record.
        let id = self.next_id();
        let mut record = SlashRecord::new(id, agent_id, penalty, now);
        record.executed_amount_milli = effective_amount;

        // Debit from the agent's account if attached.
        if let Some(account) = &mut self.account {
            if effective_amount > 0 {
                let debit_usage = ResourceUsage::new(0, 0, 0, 0, 0, effective_amount as u64);
                account.debit(agent_id, &debit_usage)?;
            }
        }

        // Mark as executed.
        record.status = SlashStatus::Executed;
        record.executed_at = Some(now);

        // Record for rate limiting and cooldown.
        self.record_slash_timestamp(agent_id, record.penalty.condition, now);

        // Store the record.
        self.records.insert(record.id.clone(), record.clone());
        Ok(record)
    }

    /// Apply a slashing penalty with a specific ID (useful for deterministic
    /// testing or external ID assignment).
    pub fn slash_with_id(
        &mut self,
        id: &str,
        agent_id: &str,
        penalty: SlashingPenalty,
        now: u64,
    ) -> Result<SlashRecord, EconomicsError> {
        if self.records.contains_key(id) {
            return Err(EconomicsError::InvalidSlashState {
                id: id.to_string(),
                message: "slash record ID already exists".to_string(),
            });
        }

        // Validate config.
        self.config.validate()?;

        // Check rate limiting.
        if self.is_rate_limited(agent_id, now) {
            return Err(EconomicsError::SlashRateLimited(agent_id.to_string()));
        }

        // Check cooldown.
        if let Some(remaining) = self.cooldown_remaining(agent_id, penalty.condition, now) {
            return Err(EconomicsError::SlashCooldownActive {
                agent: agent_id.to_string(),
                condition: penalty.condition,
                remaining_ms: remaining,
            });
        }

        // Compute the effective amount.
        let mut effective_amount = penalty.amount_milli;
        if let Some(account) = &self.account {
            let balance = account.balance(agent_id);
            let balance_tokens = balance.inference_tokens;
            if self.config.max_slash_percentage > 0 && self.config.max_slash_percentage < 100 {
                let max_slash = (balance_tokens / 100) * self.config.max_slash_percentage as u64;
                effective_amount = effective_amount.min(max_slash as i64);
            }
        }
        if effective_amount < 0 {
            effective_amount = 0;
        }

        let mut record = SlashRecord::new(id, agent_id, penalty, now);
        record.executed_amount_milli = effective_amount;

        if let Some(account) = &mut self.account {
            if effective_amount > 0 {
                let debit_usage = ResourceUsage::new(0, 0, 0, 0, 0, effective_amount as u64);
                account.debit(agent_id, &debit_usage)?;
            }
        }

        record.status = SlashStatus::Executed;
        record.executed_at = Some(now);

        self.record_slash_timestamp(agent_id, record.penalty.condition, now);
        self.records.insert(record.id.clone(), record.clone());
        Ok(record)
    }

    /// Evaluate a condition and, if met, apply the corresponding slashing
    /// penalty. This is a convenience method that combines
    /// [`Self::evaluate_condition`] and [`Self::slash`].
    ///
    /// If the condition is not met, returns
    /// [`EconomicsError::SlashConditionNotMet`].
    pub fn evaluate_and_slash(
        &mut self,
        agent_id: &str,
        condition: SlashingCondition,
        severity: Severity,
        evidence: &str,
        now: u64,
    ) -> Result<SlashRecord, EconomicsError> {
        if !self.evaluate_condition(agent_id, condition, now) {
            return Err(EconomicsError::SlashConditionNotMet {
                agent: agent_id.to_string(),
                condition,
            });
        }
        let penalty =
            SlashingPenalty::new(condition, severity, self.config.base_amount_milli, evidence);
        self.slash(agent_id, penalty, now)
    }

    // -- Appeals ------------------------------------------------------------

    /// File an appeal against an executed slash. The slash record must be in
    /// the [`SlashStatus::Executed`] state.
    pub fn appeal(
        &mut self,
        slash_id: &str,
        filed_by: &str,
        evidence: &str,
        now: u64,
    ) -> Result<SlashRecord, EconomicsError> {
        let record = self
            .records
            .get_mut(slash_id)
            .ok_or_else(|| EconomicsError::SlashNotFound(slash_id.to_string()))?;
        if record.status != SlashStatus::Executed {
            return Err(EconomicsError::InvalidSlashState {
                id: slash_id.to_string(),
                message: format!("expected Executed, got {:?}", record.status),
            });
        }
        record.status = SlashStatus::Appealed;
        record.appeal = Some(AppealInfo::new(filed_by, evidence, now));
        Ok(record.clone())
    }

    /// Assign an arbiter to an appealed slash.
    pub fn assign_arbiter(
        &mut self,
        slash_id: &str,
        arbiter: &str,
    ) -> Result<SlashRecord, EconomicsError> {
        let record = self
            .records
            .get_mut(slash_id)
            .ok_or_else(|| EconomicsError::SlashNotFound(slash_id.to_string()))?;
        if record.status != SlashStatus::Appealed {
            return Err(EconomicsError::InvalidSlashState {
                id: slash_id.to_string(),
                message: format!("expected Appealed, got {:?}", record.status),
            });
        }
        if let Some(appeal) = &mut record.appeal {
            appeal.arbiter = arbiter.to_string();
        }
        Ok(record.clone())
    }

    /// Resolve an appealed slash. If `uphold` is `false`, the appeal is
    /// upheld and the slash is reversed (the debited amount is refunded to
    /// the agent's account). If `uphold` is `true`, the appeal is denied and
    /// the slash stands.
    pub fn resolve_appeal(
        &mut self,
        slash_id: &str,
        uphold: bool,
        note: &str,
    ) -> Result<SlashRecord, EconomicsError> {
        // We need to potentially mutate the account, so we handle the refund
        // after extracting the record info.
        let record = self
            .records
            .get_mut(slash_id)
            .ok_or_else(|| EconomicsError::SlashNotFound(slash_id.to_string()))?;
        if record.status != SlashStatus::Appealed {
            return Err(EconomicsError::InvalidSlashState {
                id: slash_id.to_string(),
                message: format!("expected Appealed, got {:?}", record.status),
            });
        }

        let agent_id = record.agent_id.clone();
        let refund_amount = record.executed_amount_milli;

        if uphold {
            record.status = SlashStatus::Upheld;
        } else {
            record.status = SlashStatus::Reversed;
        }
        if let Some(appeal) = &mut record.appeal {
            appeal.resolution_note = Some(note.to_string());
        }

        // If the appeal is upheld (reversed), refund the agent.
        if !uphold && refund_amount > 0 {
            if let Some(account) = &mut self.account {
                let credit_usage = ResourceUsage::new(0, 0, 0, 0, 0, refund_amount as u64);
                account.credit(&agent_id, &credit_usage);
            }
        }

        Ok(record.clone())
    }

    // -- Queries ------------------------------------------------------------

    /// Get a reference to a slash record by ID.
    pub fn get(&self, id: &str) -> Option<&SlashRecord> {
        self.records.get(id)
    }

    /// Get all slash records for a specific agent.
    pub fn for_agent(&self, agent_id: &str) -> Vec<&SlashRecord> {
        self.records
            .values()
            .filter(|r| r.agent_id == agent_id)
            .collect()
    }

    /// Get all slash records with a specific status.
    pub fn by_status(&self, status: SlashStatus) -> Vec<&SlashRecord> {
        self.records
            .values()
            .filter(|r| r.status == status)
            .collect()
    }

    /// Get all slash records for a specific condition.
    pub fn by_condition(&self, condition: SlashingCondition) -> Vec<&SlashRecord> {
        self.records
            .values()
            .filter(|r| r.penalty.condition == condition)
            .collect()
    }

    /// Total number of slash records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if there are no slash records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Total amount of all executed (non-reversed) slashes (milli-credits).
    pub fn total_slashed_milli(&self) -> i64 {
        self.records
            .values()
            .filter(|r| {
                r.status == SlashStatus::Executed
                    || r.status == SlashStatus::Appealed
                    || r.status == SlashStatus::Upheld
            })
            .map(|r| r.executed_amount_milli)
            .fold(0i64, |acc, a| acc.saturating_add(a))
    }

    /// Total amount of all reversed slashes (milli-credits).
    pub fn total_reversed_milli(&self) -> i64 {
        self.records
            .values()
            .filter(|r| r.status == SlashStatus::Reversed)
            .map(|r| r.executed_amount_milli)
            .fold(0i64, |acc, a| acc.saturating_add(a))
    }

    /// Number of slash records for an agent.
    pub fn agent_slash_count(&self, agent_id: &str) -> usize {
        self.records
            .values()
            .filter(|r| r.agent_id == agent_id)
            .count()
    }

    /// Remove a slash record. Returns the removed record, or `None`.
    pub fn remove(&mut self, id: &str) -> Option<SlashRecord> {
        self.records.remove(id)
    }

    /// Clear all slash records and slash timestamps (but not agent history).
    pub fn clear(&mut self) {
        self.records.clear();
        self.slash_timestamps.clear();
    }
}

impl Default for SlashingEngine {
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
    use crate::account::{ResourceAccount, ResourceUsage};

    // --- SlashingCondition tests ---

    #[test]
    fn test_condition_default_is_downtime() {
        assert_eq!(SlashingCondition::default(), SlashingCondition::Downtime);
    }

    #[test]
    fn test_condition_cbor_roundtrip() {
        for c in [
            SlashingCondition::Downtime,
            SlashingCondition::MissedTasks,
            SlashingCondition::MaliciousBehavior,
            SlashingCondition::ResourceMisuse,
            SlashingCondition::ContractViolation,
            SlashingCondition::RepeatedFailures,
        ] {
            let val = c.to_cbor();
            assert_eq!(SlashingCondition::from_cbor(&val).unwrap(), c);
        }
    }

    #[test]
    fn test_condition_cbor_invalid() {
        assert!(SlashingCondition::from_cbor(&Value::Unsigned(99)).is_err());
    }

    #[test]
    fn test_condition_name() {
        assert_eq!(SlashingCondition::Downtime.name(), "downtime");
        assert_eq!(SlashingCondition::MissedTasks.name(), "missed_tasks");
        assert_eq!(
            SlashingCondition::MaliciousBehavior.name(),
            "malicious_behavior"
        );
        assert_eq!(SlashingCondition::ResourceMisuse.name(), "resource_misuse");
        assert_eq!(
            SlashingCondition::ContractViolation.name(),
            "contract_violation"
        );
        assert_eq!(
            SlashingCondition::RepeatedFailures.name(),
            "repeated_failures"
        );
    }

    // --- Severity tests ---

    #[test]
    fn test_severity_default_is_minor() {
        assert_eq!(Severity::default(), Severity::Minor);
    }

    #[test]
    fn test_severity_multiplier() {
        assert_eq!(Severity::Minor.multiplier(), 1);
        assert_eq!(Severity::Major.multiplier(), 5);
        assert_eq!(Severity::Critical.multiplier(), 10);
    }

    #[test]
    fn test_severity_cbor_roundtrip() {
        for s in [Severity::Minor, Severity::Major, Severity::Critical] {
            let val = s.to_cbor();
            assert_eq!(Severity::from_cbor(&val).unwrap(), s);
        }
    }

    #[test]
    fn test_severity_cbor_invalid() {
        assert!(Severity::from_cbor(&Value::Unsigned(99)).is_err());
    }

    // --- SlashingPenalty tests ---

    #[test]
    fn test_penalty_new_computes_amount() {
        let p = SlashingPenalty::new(
            SlashingCondition::Downtime,
            Severity::Major,
            10_000,
            "offline too long",
        );
        assert_eq!(p.condition, SlashingCondition::Downtime);
        assert_eq!(p.severity, Severity::Major);
        assert_eq!(p.amount_milli, 50_000); // 10_000 * 5
        assert_eq!(p.evidence, "offline too long");
    }

    #[test]
    fn test_penalty_critical_multiplier() {
        let p = SlashingPenalty::new(
            SlashingCondition::MaliciousBehavior,
            Severity::Critical,
            10_000,
            "false results",
        );
        assert_eq!(p.amount_milli, 100_000); // 10_000 * 10
    }

    #[test]
    fn test_penalty_with_amount() {
        let p = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            42_000,
            "evidence",
        );
        assert_eq!(p.amount_milli, 42_000);
    }

    #[test]
    fn test_penalty_amount_credits() {
        let p = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            50_000,
            "evidence",
        );
        assert!((p.amount_credits() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_penalty_cbor_roundtrip() {
        let p = SlashingPenalty::new(
            SlashingCondition::ResourceMisuse,
            Severity::Critical,
            10_000,
            "over-consumed CPU",
        );
        let val = p.to_cbor();
        let p2 = SlashingPenalty::from_cbor(&val).unwrap();
        assert_eq!(p2.condition, p.condition);
        assert_eq!(p2.amount_milli, p.amount_milli);
        assert_eq!(p2.severity, p.severity);
        assert_eq!(p2.evidence, p.evidence);
    }

    #[test]
    fn test_penalty_compute_amount_saturates() {
        let amount = SlashingPenalty::compute_amount(i64::MAX, Severity::Critical);
        assert_eq!(amount, i64::MAX);
    }

    // --- SlashingConfig tests ---

    #[test]
    fn test_config_default() {
        let c = SlashingConfig::default();
        assert_eq!(c.downtime_threshold_ms, 3_600_000);
        assert_eq!(c.missed_tasks_threshold, 5);
        assert_eq!(c.malicious_behavior_threshold, 1);
        assert_eq!(c.resource_misuse_threshold, 3);
        assert_eq!(c.contract_violation_threshold, 1);
        assert_eq!(c.repeated_failures_threshold, 3);
        assert_eq!(c.max_slash_percentage, 50);
        assert_eq!(c.cooldown_period_ms, 3_600_000);
        assert_eq!(c.base_amount_milli, 10_000);
        assert_eq!(c.max_slashes_per_window, 5);
        assert_eq!(c.rate_limit_window_ms, 3_600_000);
    }

    #[test]
    fn test_config_builder() {
        let c = SlashingConfig::new()
            .with_downtime_threshold(600_000)
            .with_missed_tasks_threshold(3)
            .with_malicious_behavior_threshold(2)
            .with_resource_misuse_threshold(5)
            .with_contract_violation_threshold(3)
            .with_repeated_failures_threshold(2)
            .with_max_slash_percentage(25)
            .with_cooldown_period(1_800_000)
            .with_base_amount(5_000)
            .with_rate_limit(10, 900_000);
        assert_eq!(c.downtime_threshold_ms, 600_000);
        assert_eq!(c.missed_tasks_threshold, 3);
        assert_eq!(c.malicious_behavior_threshold, 2);
        assert_eq!(c.resource_misuse_threshold, 5);
        assert_eq!(c.contract_violation_threshold, 3);
        assert_eq!(c.repeated_failures_threshold, 2);
        assert_eq!(c.max_slash_percentage, 25);
        assert_eq!(c.cooldown_period_ms, 1_800_000);
        assert_eq!(c.base_amount_milli, 5_000);
        assert_eq!(c.max_slashes_per_window, 10);
        assert_eq!(c.rate_limit_window_ms, 900_000);
    }

    #[test]
    fn test_config_validate_ok() {
        let c = SlashingConfig::default();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_config_validate_percentage_over_100() {
        let c = SlashingConfig::new().with_max_slash_percentage(150);
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_validate_negative_base() {
        let c = SlashingConfig::new().with_base_amount(-1);
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_threshold_for() {
        let c = SlashingConfig::default();
        assert_eq!(
            c.threshold_for(SlashingCondition::Downtime),
            c.downtime_threshold_ms
        );
        assert_eq!(
            c.threshold_for(SlashingCondition::MissedTasks),
            c.missed_tasks_threshold as u64
        );
    }

    #[test]
    fn test_config_cbor_roundtrip() {
        let c = SlashingConfig::new()
            .with_downtime_threshold(500_000)
            .with_missed_tasks_threshold(7)
            .with_max_slash_percentage(30)
            .with_cooldown_period(2_000_000)
            .with_base_amount(8_000)
            .with_rate_limit(3, 500_000);
        let val = c.to_cbor();
        let c2 = SlashingConfig::from_cbor(&val).unwrap();
        assert_eq!(c2.downtime_threshold_ms, c.downtime_threshold_ms);
        assert_eq!(c2.missed_tasks_threshold, c.missed_tasks_threshold);
        assert_eq!(c2.max_slash_percentage, c.max_slash_percentage);
        assert_eq!(c2.cooldown_period_ms, c.cooldown_period_ms);
        assert_eq!(c2.base_amount_milli, c.base_amount_milli);
        assert_eq!(c2.max_slashes_per_window, c.max_slashes_per_window);
        assert_eq!(c2.rate_limit_window_ms, c.rate_limit_window_ms);
    }

    #[test]
    fn test_config_cbor_defaults_when_missing() {
        let val = int_map(vec![]);
        let c = SlashingConfig::from_cbor(&val).unwrap();
        assert_eq!(c.downtime_threshold_ms, 3_600_000);
        assert_eq!(c.base_amount_milli, 10_000);
    }

    // --- SlashStatus tests ---

    #[test]
    fn test_status_default_is_pending() {
        assert_eq!(SlashStatus::default(), SlashStatus::Pending);
    }

    #[test]
    fn test_status_cbor_roundtrip() {
        for s in [
            SlashStatus::Pending,
            SlashStatus::Executed,
            SlashStatus::Appealed,
            SlashStatus::Reversed,
            SlashStatus::Upheld,
        ] {
            let val = s.to_cbor();
            assert_eq!(SlashStatus::from_cbor(&val).unwrap(), s);
        }
    }

    #[test]
    fn test_status_cbor_invalid() {
        assert!(SlashStatus::from_cbor(&Value::Unsigned(99)).is_err());
    }

    #[test]
    fn test_status_is_terminal() {
        assert!(SlashStatus::Reversed.is_terminal());
        assert!(SlashStatus::Upheld.is_terminal());
        assert!(!SlashStatus::Pending.is_terminal());
        assert!(!SlashStatus::Executed.is_terminal());
        assert!(!SlashStatus::Appealed.is_terminal());
    }

    // --- AppealInfo tests ---

    #[test]
    fn test_appeal_info_new() {
        let a = AppealInfo::new("agent-1", "unfair slash", 1000);
        assert_eq!(a.filed_by, "agent-1");
        assert_eq!(a.evidence, "unfair slash");
        assert_eq!(a.filed_at, 1000);
        assert!(a.arbiter.is_empty());
        assert!(a.resolution_note.is_none());
    }

    #[test]
    fn test_appeal_info_with_arbiter_and_resolution() {
        let a = AppealInfo::new("agent-1", "evidence", 1000)
            .with_arbiter("arbiter-1")
            .with_resolution("appeal upheld");
        assert_eq!(a.arbiter, "arbiter-1");
        assert_eq!(a.resolution_note, Some("appeal upheld".to_string()));
    }

    #[test]
    fn test_appeal_info_cbor_roundtrip() {
        let a = AppealInfo::new("agent-1", "evidence text", 5000)
            .with_arbiter("arbiter-1")
            .with_resolution("resolved");
        let val = a.to_cbor();
        let a2 = AppealInfo::from_cbor(&val).unwrap();
        assert_eq!(a2.filed_by, a.filed_by);
        assert_eq!(a2.evidence, a.evidence);
        assert_eq!(a2.arbiter, a.arbiter);
        assert_eq!(a2.filed_at, a.filed_at);
        assert_eq!(a2.resolution_note, a.resolution_note);
    }

    // --- SlashRecord tests ---

    #[test]
    fn test_record_new() {
        let penalty = SlashingPenalty::new(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let r = SlashRecord::new("s1", "agent-1", penalty, 1000);
        assert_eq!(r.id, "s1");
        assert_eq!(r.agent_id, "agent-1");
        assert_eq!(r.timestamp, 1000);
        assert_eq!(r.status, SlashStatus::Pending);
        assert!(r.appeal.is_none());
        assert!(r.executed_at.is_none());
        assert_eq!(r.executed_amount_milli, 10_000);
    }

    #[test]
    fn test_record_executed_credits() {
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            50_000,
            "evidence",
        );
        let r = SlashRecord::new("s1", "a1", penalty, 1000);
        assert!((r.executed_credits() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_record_cbor_roundtrip() {
        let penalty = SlashingPenalty::new(
            SlashingCondition::MaliciousBehavior,
            Severity::Major,
            10_000,
            "false results",
        );
        let mut r = SlashRecord::new("s1", "agent-1", penalty, 2000);
        r.status = SlashStatus::Executed;
        r.executed_at = Some(3000);
        r.executed_amount_milli = 40_000;
        let val = r.to_cbor();
        let r2 = SlashRecord::from_cbor(&val).unwrap();
        assert_eq!(r2.id, r.id);
        assert_eq!(r2.agent_id, r.agent_id);
        assert_eq!(r2.penalty.condition, r.penalty.condition);
        assert_eq!(r2.penalty.amount_milli, r.penalty.amount_milli);
        assert_eq!(r2.penalty.severity, r.penalty.severity);
        assert_eq!(r2.timestamp, r.timestamp);
        assert_eq!(r2.status, r.status);
        assert_eq!(r2.executed_at, r.executed_at);
        assert_eq!(r2.executed_amount_milli, r.executed_amount_milli);
    }

    #[test]
    fn test_record_cbor_with_appeal() {
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let mut r = SlashRecord::new("s1", "a1", penalty, 1000);
        r.status = SlashStatus::Appealed;
        r.appeal = Some(AppealInfo::new("a1", "unfair", 2000).with_arbiter("arb-1"));
        let val = r.to_cbor();
        let r2 = SlashRecord::from_cbor(&val).unwrap();
        assert_eq!(r2.status, SlashStatus::Appealed);
        assert!(r2.appeal.is_some());
        assert_eq!(r2.appeal.unwrap().arbiter, "arb-1");
    }

    // --- AgentHistory tests ---

    #[test]
    fn test_agent_history_default() {
        let h = AgentHistory::default();
        assert_eq!(h.last_seen_ms, 0);
        assert_eq!(h.missed_task_count, 0);
        assert_eq!(h.consecutive_failures, 0);
    }

    #[test]
    fn test_agent_history_with_last_seen() {
        let h = AgentHistory::with_last_seen(5000);
        assert_eq!(h.last_seen_ms, 5000);
    }

    #[test]
    fn test_agent_history_cbor_roundtrip() {
        let h = AgentHistory {
            last_seen_ms: 1000,
            missed_task_count: 5,
            consecutive_failures: 3,
            resource_overuse_count: 2,
            contract_violations: 1,
            malicious_flags: 4,
        };
        let val = h.to_cbor();
        let h2 = AgentHistory::from_cbor(&val).unwrap();
        assert_eq!(h2.last_seen_ms, h.last_seen_ms);
        assert_eq!(h2.missed_task_count, h.missed_task_count);
        assert_eq!(h2.consecutive_failures, h.consecutive_failures);
        assert_eq!(h2.resource_overuse_count, h.resource_overuse_count);
        assert_eq!(h2.contract_violations, h.contract_violations);
        assert_eq!(h2.malicious_flags, h.malicious_flags);
    }

    // --- SlashingEngine: evaluate_condition ---

    #[test]
    fn test_evaluate_condition_downtime_met() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_agent_history("a1", AgentHistory::with_last_seen(1000));
        // now=5000, threshold=3_600_000, elapsed=4000 < threshold → not met
        assert!(!engine.evaluate_condition("a1", SlashingCondition::Downtime, 5000));
        // now=3_601_001, elapsed=3_600_001 > threshold → met
        assert!(engine.evaluate_condition("a1", SlashingCondition::Downtime, 3_601_001));
    }

    #[test]
    fn test_evaluate_condition_downtime_not_met() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_agent_history("a1", AgentHistory::with_last_seen(1000));
        assert!(!engine.evaluate_condition("a1", SlashingCondition::Downtime, 1000));
    }

    #[test]
    fn test_evaluate_condition_missed_tasks() {
        let mut engine = SlashingEngine::with_defaults();
        let h = AgentHistory {
            missed_task_count: 4,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(!engine.evaluate_condition("a1", SlashingCondition::MissedTasks, 0));
        let h = AgentHistory {
            missed_task_count: 5,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(engine.evaluate_condition("a1", SlashingCondition::MissedTasks, 0));
    }

    #[test]
    fn test_evaluate_condition_malicious_behavior() {
        let mut engine = SlashingEngine::with_defaults();
        let h = AgentHistory {
            malicious_flags: 0,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(!engine.evaluate_condition("a1", SlashingCondition::MaliciousBehavior, 0));
        let h = AgentHistory {
            malicious_flags: 1,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(engine.evaluate_condition("a1", SlashingCondition::MaliciousBehavior, 0));
    }

    #[test]
    fn test_evaluate_condition_resource_misuse() {
        let mut engine = SlashingEngine::with_defaults();
        let h = AgentHistory {
            resource_overuse_count: 2,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(!engine.evaluate_condition("a1", SlashingCondition::ResourceMisuse, 0));
        let h = AgentHistory {
            resource_overuse_count: 3,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(engine.evaluate_condition("a1", SlashingCondition::ResourceMisuse, 0));
    }

    #[test]
    fn test_evaluate_condition_contract_violation() {
        let mut engine = SlashingEngine::with_defaults();
        let h = AgentHistory {
            contract_violations: 0,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(!engine.evaluate_condition("a1", SlashingCondition::ContractViolation, 0));
        let h = AgentHistory {
            contract_violations: 1,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(engine.evaluate_condition("a1", SlashingCondition::ContractViolation, 0));
    }

    #[test]
    fn test_evaluate_condition_repeated_failures() {
        let mut engine = SlashingEngine::with_defaults();
        let h = AgentHistory {
            consecutive_failures: 2,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(!engine.evaluate_condition("a1", SlashingCondition::RepeatedFailures, 0));
        let h = AgentHistory {
            consecutive_failures: 3,
            ..AgentHistory::new()
        };
        engine.set_agent_history("a1", h);
        assert!(engine.evaluate_condition("a1", SlashingCondition::RepeatedFailures, 0));
    }

    #[test]
    fn test_evaluate_condition_no_history() {
        let engine = SlashingEngine::with_defaults();
        assert!(!engine.evaluate_condition("unknown", SlashingCondition::Downtime, 999_999_999));
    }

    #[test]
    fn test_evaluate_all_conditions() {
        let mut engine = SlashingEngine::with_defaults();
        let h = AgentHistory {
            last_seen_ms: 0,
            missed_task_count: 10,
            consecutive_failures: 0,
            resource_overuse_count: 0,
            contract_violations: 0,
            malicious_flags: 2,
        };
        engine.set_agent_history("a1", h);
        // now is very large → downtime met, missed_tasks met, malicious met
        let met = engine.evaluate_all_conditions("a1", 10_000_000);
        assert!(met.contains(&SlashingCondition::Downtime));
        assert!(met.contains(&SlashingCondition::MissedTasks));
        assert!(met.contains(&SlashingCondition::MaliciousBehavior));
        assert!(!met.contains(&SlashingCondition::RepeatedFailures));
    }

    // --- SlashingEngine: slash ---

    #[test]
    fn test_slash_basic() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::new(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "offline too long",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        assert_eq!(record.agent_id, "a1");
        assert_eq!(record.status, SlashStatus::Executed);
        assert_eq!(record.executed_at, Some(1000));
        assert_eq!(record.executed_amount_milli, 10_000);
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn test_slash_with_account_debits() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_account(ResourceAccount::with_defaults());

        // Give the agent some balance first.
        if let Some(acct) = engine.account_mut() {
            acct.debit("a1", &ResourceUsage::new(0, 0, 0, 0, 0, 100_000))
                .unwrap();
        }

        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        assert_eq!(record.status, SlashStatus::Executed);

        let balance = engine.account().unwrap().balance("a1");
        assert_eq!(balance.inference_tokens, 110_000); // 100_000 + 10_000 debited
    }

    #[test]
    fn test_slash_max_percentage_caps_amount() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_account(ResourceAccount::with_defaults());

        // Give the agent 100_000 tokens.
        if let Some(acct) = engine.account_mut() {
            acct.debit("a1", &ResourceUsage::new(0, 0, 0, 0, 0, 100_000))
                .unwrap();
        }

        // max_slash_percentage is 50% by default, so max slash = 50_000.
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Critical,
            200_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        assert_eq!(record.executed_amount_milli, 50_000); // capped at 50% of 100_000

        let balance = engine.account().unwrap().balance("a1");
        assert_eq!(balance.inference_tokens, 150_000); // 100_000 + 50_000
    }

    #[test]
    fn test_slash_without_account_no_cap() {
        let mut engine = SlashingEngine::with_defaults();
        // No account attached — amount is not capped.
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Critical,
            200_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        assert_eq!(record.executed_amount_milli, 200_000);
    }

    #[test]
    fn test_slash_rate_limited() {
        let config = SlashingConfig::new().with_rate_limit(2, 3_600_000);
        let mut engine = SlashingEngine::new(config);

        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            1_000,
            "e2",
        );
        let p3 = SlashingPenalty::with_amount(
            SlashingCondition::ResourceMisuse,
            Severity::Minor,
            1_000,
            "e3",
        );

        engine.slash("a1", p1, 1000).unwrap();
        engine.slash("a1", p2, 2000).unwrap();
        // Third slash should be rate-limited.
        let result = engine.slash("a1", p3, 3000);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EconomicsError::SlashRateLimited(_)
        ));
    }

    #[test]
    fn test_slash_cooldown_active() {
        let config = SlashingConfig::new().with_cooldown_period(10_000);
        let mut engine = SlashingEngine::new(config);

        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        engine.slash("a1", p1, 1000).unwrap();

        // Same condition within cooldown → error.
        let p2 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e2");
        let result = engine.slash("a1", p2, 5_000);
        assert!(result.is_err());
        match result.unwrap_err() {
            EconomicsError::SlashCooldownActive { remaining_ms, .. } => {
                assert_eq!(remaining_ms, 6_000); // 10_000 - (5_000 - 1_000)
            }
            e => panic!("expected SlashCooldownActive, got {e:?}"),
        }

        // After cooldown expires → ok.
        let p3 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e3");
        assert!(engine.slash("a1", p3, 11_001).is_ok());
    }

    #[test]
    fn test_slash_different_conditions_not_cooldown_limited() {
        let config = SlashingConfig::new().with_cooldown_period(10_000);
        let mut engine = SlashingEngine::new(config);

        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        engine.slash("a1", p1, 1000).unwrap();

        // Different condition — should not be cooldown-limited.
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            1_000,
            "e2",
        );
        assert!(engine.slash("a1", p2, 2_000).is_ok());
    }

    #[test]
    fn test_slash_with_id() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            5_000,
            "evidence",
        );
        let record = engine
            .slash_with_id("custom-id", "a1", penalty, 1000)
            .unwrap();
        assert_eq!(record.id, "custom-id");
        assert_eq!(engine.get("custom-id").unwrap().agent_id, "a1");
    }

    #[test]
    fn test_slash_with_id_duplicate() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            5_000,
            "evidence",
        );
        engine
            .slash_with_id("custom-id", "a1", penalty, 1000)
            .unwrap();
        let penalty2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            5_000,
            "evidence2",
        );
        let result = engine.slash_with_id("custom-id", "a1", penalty2, 2000);
        assert!(result.is_err());
    }

    // --- SlashingEngine: evaluate_and_slash ---

    #[test]
    fn test_evaluate_and_slash_condition_met() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_agent_history("a1", AgentHistory::with_last_seen(0));
        let record = engine
            .evaluate_and_slash(
                "a1",
                SlashingCondition::Downtime,
                Severity::Minor,
                "offline too long",
                5_000_000,
            )
            .unwrap();
        assert_eq!(record.status, SlashStatus::Executed);
        assert_eq!(record.penalty.condition, SlashingCondition::Downtime);
        assert_eq!(record.penalty.amount_milli, 10_000); // base * 1
    }

    #[test]
    fn test_evaluate_and_slash_condition_not_met() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_agent_history("a1", AgentHistory::with_last_seen(1_000_000));
        let result = engine.evaluate_and_slash(
            "a1",
            SlashingCondition::Downtime,
            Severity::Minor,
            "evidence",
            1_001_000, // elapsed = 1_000 < 3_600_000
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EconomicsError::SlashConditionNotMet { .. }
        ));
    }

    // --- SlashingEngine: appeal ---

    #[test]
    fn test_appeal_executed() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        let appealed = engine
            .appeal(&record.id, "a1", "unfair slash", 2000)
            .unwrap();
        assert_eq!(appealed.status, SlashStatus::Appealed);
        assert!(appealed.appeal.is_some());
        assert_eq!(appealed.appeal.as_ref().unwrap().filed_by, "a1");
    }

    #[test]
    fn test_appeal_not_found() {
        let mut engine = SlashingEngine::with_defaults();
        assert!(engine
            .appeal("nonexistent", "a1", "evidence", 1000)
            .is_err());
    }

    #[test]
    fn test_appeal_wrong_state() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        engine.appeal(&record.id, "a1", "evidence", 2000).unwrap();
        // Can't appeal again.
        assert!(engine.appeal(&record.id, "a1", "evidence", 3000).is_err());
    }

    // --- SlashingEngine: assign_arbiter ---

    #[test]
    fn test_assign_arbiter() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        engine.appeal(&record.id, "a1", "evidence", 2000).unwrap();
        let result = engine.assign_arbiter(&record.id, "arbiter-1").unwrap();
        assert_eq!(result.appeal.as_ref().unwrap().arbiter, "arbiter-1");
    }

    #[test]
    fn test_assign_arbiter_wrong_state() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        // Not appealed yet.
        assert!(engine.assign_arbiter(&record.id, "arb-1").is_err());
    }

    // --- SlashingEngine: resolve_appeal ---

    #[test]
    fn test_resolve_appeal_upheld() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        engine.appeal(&record.id, "a1", "evidence", 2000).unwrap();
        let resolved = engine
            .resolve_appeal(&record.id, true, "appeal denied")
            .unwrap();
        assert_eq!(resolved.status, SlashStatus::Upheld);
        assert_eq!(
            resolved.appeal.as_ref().unwrap().resolution_note,
            Some("appeal denied".to_string())
        );
    }

    #[test]
    fn test_resolve_appeal_reversed() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        engine.appeal(&record.id, "a1", "evidence", 2000).unwrap();
        let resolved = engine
            .resolve_appeal(&record.id, false, "appeal upheld")
            .unwrap();
        assert_eq!(resolved.status, SlashStatus::Reversed);
    }

    #[test]
    fn test_resolve_appeal_reversed_refunds_account() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_account(ResourceAccount::with_defaults());

        // Give the agent some balance.
        if let Some(acct) = engine.account_mut() {
            acct.debit("a1", &ResourceUsage::new(0, 0, 0, 0, 0, 100_000))
                .unwrap();
        }

        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();

        // Balance after slash: 100_000 + 10_000 = 110_000
        let balance_after_slash = engine.account().unwrap().balance("a1").inference_tokens;
        assert_eq!(balance_after_slash, 110_000);

        engine.appeal(&record.id, "a1", "unfair", 2000).unwrap();
        engine
            .resolve_appeal(&record.id, false, "appeal upheld")
            .unwrap();

        // Balance after reversal: 110_000 - 10_000 = 100_000
        let balance_after_reversal = engine.account().unwrap().balance("a1").inference_tokens;
        assert_eq!(balance_after_reversal, 100_000);
    }

    #[test]
    fn test_resolve_appeal_upheld_does_not_refund() {
        let mut engine = SlashingEngine::with_defaults();
        engine.set_account(ResourceAccount::with_defaults());

        if let Some(acct) = engine.account_mut() {
            acct.debit("a1", &ResourceUsage::new(0, 0, 0, 0, 0, 100_000))
                .unwrap();
        }

        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        engine.appeal(&record.id, "a1", "unfair", 2000).unwrap();
        engine.resolve_appeal(&record.id, true, "denied").unwrap();

        let balance = engine.account().unwrap().balance("a1").inference_tokens;
        assert_eq!(balance, 110_000); // unchanged from after slash
    }

    #[test]
    fn test_resolve_appeal_wrong_state() {
        let mut engine = SlashingEngine::with_defaults();
        let penalty = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "evidence",
        );
        let record = engine.slash("a1", penalty, 1000).unwrap();
        // Not appealed yet.
        assert!(engine.resolve_appeal(&record.id, true, "ok").is_err());
    }

    // --- SlashingEngine: queries ---

    #[test]
    fn test_for_agent() {
        let mut engine = SlashingEngine::with_defaults();
        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            1_000,
            "e2",
        );
        engine.slash("a1", p1, 1000).unwrap();
        engine.slash("a2", p2, 2000).unwrap();
        assert_eq!(engine.for_agent("a1").len(), 1);
        assert_eq!(engine.for_agent("a2").len(), 1);
        assert_eq!(engine.for_agent("a3").len(), 0);
    }

    #[test]
    fn test_by_status() {
        let mut engine = SlashingEngine::with_defaults();
        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            1_000,
            "e2",
        );
        let r1 = engine.slash("a1", p1, 1000).unwrap();
        engine.slash("a2", p2, 2000).unwrap();
        engine.appeal(&r1.id, "a1", "evidence", 3000).unwrap();
        assert_eq!(engine.by_status(SlashStatus::Appealed).len(), 1);
        assert_eq!(engine.by_status(SlashStatus::Executed).len(), 1);
        assert_eq!(engine.by_status(SlashStatus::Pending).len(), 0);
    }

    #[test]
    fn test_by_condition() {
        let mut engine = SlashingEngine::with_defaults();
        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            1_000,
            "e2",
        );
        let p3 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e3");
        engine.slash("a1", p1, 1000).unwrap();
        engine.slash("a2", p2, 2000).unwrap();
        engine.slash("a3", p3, 3000).unwrap();
        assert_eq!(engine.by_condition(SlashingCondition::Downtime).len(), 2);
        assert_eq!(engine.by_condition(SlashingCondition::MissedTasks).len(), 1);
    }

    #[test]
    fn test_total_slashed_milli() {
        let mut engine = SlashingEngine::with_defaults();
        let p1 = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "e1",
        );
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            5_000,
            "e2",
        );
        engine.slash("a1", p1, 1000).unwrap();
        engine.slash("a2", p2, 2000).unwrap();
        assert_eq!(engine.total_slashed_milli(), 15_000);
    }

    #[test]
    fn test_total_reversed_milli() {
        let mut engine = SlashingEngine::with_defaults();
        let p1 = SlashingPenalty::with_amount(
            SlashingCondition::Downtime,
            Severity::Minor,
            10_000,
            "e1",
        );
        let r1 = engine.slash("a1", p1, 1000).unwrap();
        engine.appeal(&r1.id, "a1", "evidence", 2000).unwrap();
        engine.resolve_appeal(&r1.id, false, "upheld").unwrap();
        assert_eq!(engine.total_reversed_milli(), 10_000);
        assert_eq!(engine.total_slashed_milli(), 0); // reversed slashes not counted
    }

    #[test]
    fn test_agent_slash_count() {
        let mut engine = SlashingEngine::with_defaults();
        let p1 =
            SlashingPenalty::with_amount(SlashingCondition::Downtime, Severity::Minor, 1_000, "e1");
        let p2 = SlashingPenalty::with_amount(
            SlashingCondition::MissedTasks,
            Severity::Minor,
            1_000,
            "e2",
        );
        engine.slash("a1", p1, 1000).unwrap();
        engine.slash("a1", p2, 2000).unwrap();
        engine
            .slash(
                "a2",
                SlashingPenalty::with_amount(
                    SlashingCondition::Downtime,
                    Severity::Minor,
                    1_000,
                    "e3",
                ),
                3000,
            )
            .unwrap();
        assert_eq!(engine.agent_slash_count("a1"), 2);
        assert_eq!(engine.agent_slash_count("a2"), 1);
        assert_eq!(engine.agent_slash_count("a3"), 0);
    }

    // --- SlashingEngine: rate limiting and cooldown queries ---

    #[test]
    fn test_is_rate_limited() {
        let config = SlashingConfig::new().with_rate_limit(2, 3_600_000);
        let mut engine = SlashingEngine::new(config);
        assert!(!engine.is_rate_limited("a1", 1000));
        engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::Downtime,
                    Severity::Minor,
                    1_000,
                    "e1",
                ),
                1000,
            )
            .unwrap();
        engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::MissedTasks,
                    Severity::Minor,
                    1_000,
                    "e2",
                ),
                2000,
            )
            .unwrap();
        assert!(engine.is_rate_limited("a1", 3000));
    }

    #[test]
    fn test_cooldown_remaining() {
        let config = SlashingConfig::new().with_cooldown_period(10_000);
        let mut engine = SlashingEngine::new(config);
        engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::Downtime,
                    Severity::Minor,
                    1_000,
                    "e1",
                ),
                1000,
            )
            .unwrap();
        assert_eq!(
            engine.cooldown_remaining("a1", SlashingCondition::Downtime, 5000),
            Some(6000)
        );
        assert_eq!(
            engine.cooldown_remaining("a1", SlashingCondition::Downtime, 11_000),
            None
        );
        assert_eq!(
            engine.cooldown_remaining("a1", SlashingCondition::MissedTasks, 5000),
            None
        );
    }

    // --- SlashingEngine: evict_expired ---

    #[test]
    fn test_evict_expired() {
        let config = SlashingConfig::new().with_rate_limit(100, 10_000);
        let mut engine = SlashingEngine::new(config);
        engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::Downtime,
                    Severity::Minor,
                    1_000,
                    "e1",
                ),
                1000,
            )
            .unwrap();
        engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::MissedTasks,
                    Severity::Minor,
                    1_000,
                    "e2",
                ),
                2000,
            )
            .unwrap();
        // Evict timestamps older than 10_000ms window.
        engine.evict_expired(20_000);
        // After eviction, the old slashes should not count toward rate limit.
        assert!(!engine.is_rate_limited("a1", 20_000));
    }

    // --- SlashingEngine: remove and clear ---

    #[test]
    fn test_remove() {
        let mut engine = SlashingEngine::with_defaults();
        let record = engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::Downtime,
                    Severity::Minor,
                    1_000,
                    "e1",
                ),
                1000,
            )
            .unwrap();
        assert!(engine.remove(&record.id).is_some());
        assert!(engine.get(&record.id).is_none());
        assert!(engine.remove(&record.id).is_none());
    }

    #[test]
    fn test_clear() {
        let mut engine = SlashingEngine::with_defaults();
        engine
            .slash(
                "a1",
                SlashingPenalty::with_amount(
                    SlashingCondition::Downtime,
                    Severity::Minor,
                    1_000,
                    "e1",
                ),
                1000,
            )
            .unwrap();
        assert_eq!(engine.len(), 1);
        engine.clear();
        assert_eq!(engine.len(), 0);
        assert!(engine.is_empty());
    }

    // --- SlashingEngine: agent_history_mut ---

    #[test]
    fn test_agent_history_mut() {
        let mut engine = SlashingEngine::with_defaults();
        let h = engine.agent_history_mut("a1");
        h.last_seen_ms = 5000;
        h.missed_task_count = 3;
        assert_eq!(engine.agent_history("a1").unwrap().last_seen_ms, 5000);
        assert_eq!(engine.agent_history("a1").unwrap().missed_task_count, 3);
    }

    // --- Default impl ---

    #[test]
    fn test_engine_default() {
        let engine = SlashingEngine::default();
        assert_eq!(engine.config().base_amount_milli, 10_000);
        assert!(engine.is_empty());
    }
}
