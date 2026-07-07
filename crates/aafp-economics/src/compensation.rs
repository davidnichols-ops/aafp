//! Compensation protocol for refunds and penalty payments (Track X4).
//!
//! [`CompensationProtocol`] manages the lifecycle of compensation requests —
//! refunds, partial refunds, and penalty payments — that arise when tasks
//! fail, time out, are overcharged, or when agents are slashed for bad
//! behavior.
//!
//! ## Lifecycle
//!
//! A compensation starts in [`CompensationStatus::Pending`]. From there it
//! can transition to:
//!
//! - [`CompensationStatus::Approved`] — auto-approved by policy or manually
//!   approved by an operator. Approved compensations are paid out via
//!   [`CompensationProtocol::process_payment`], which credits the agent's
//!   [`ResourceAccount`](crate::ResourceAccount) if one is attached.
//! - [`CompensationStatus::Rejected`] — manually rejected with a reason.
//! - [`CompensationStatus::Disputed`] — escalated to dispute resolution with
//!   evidence and an arbiter.
//!
//! A disputed compensation can later be resolved to `Approved` or `Rejected`
//! by the arbiter.
//!
//! ## Auto-approval
//!
//! [`CompensationPolicy`] defines thresholds for automatic approval:
//! compensations at or below `auto_approve_threshold_milli` are approved
//! immediately at request time, up to a per-agent rate limit. This avoids
//! the need for manual review of small, routine refunds.
//!
//! ## Batch processing
//!
//! [`CompensationProtocol::process_batch`] processes all pending
//! compensations in one pass, auto-approving those within policy and leaving
//! the rest for manual review.
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

// ---------------------------------------------------------------------------
// CompensationStatus
// ---------------------------------------------------------------------------

/// Lifecycle state of a compensation request.
///
/// Encoded as an unsigned integer: `Pending = 0`, `Approved = 1`,
/// `Rejected = 2`, `Paid = 3`, `Disputed = 4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CompensationStatus {
    /// Submitted, awaiting review or auto-approval.
    #[default]
    Pending = 0,
    /// Approved for payment (either automatically or by an operator).
    Approved = 1,
    /// Rejected with a reason.
    Rejected = 2,
    /// Payment has been processed and credited to the agent.
    Paid = 3,
    /// Escalated to dispute resolution.
    Disputed = 4,
}

impl CompensationStatus {
    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Pending),
            Value::Unsigned(1) => Ok(Self::Approved),
            Value::Unsigned(2) => Ok(Self::Rejected),
            Value::Unsigned(3) => Ok(Self::Paid),
            Value::Unsigned(4) => Ok(Self::Disputed),
            _ => Err(EconomicsError::InvalidField {
                field: "compensation_status",
                message: format!("expected 0/1/2/3/4, got {val:?}"),
            }),
        }
    }

    /// Returns `true` if the status is terminal (no further transitions
    /// expected).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Paid | Self::Rejected)
    }
}

// ---------------------------------------------------------------------------
// CompensationReason
// ---------------------------------------------------------------------------

/// The reason a compensation is being requested.
///
/// Encoded as an unsigned integer: `TaskFailure = 0`, `PartialCompletion = 1`,
/// `Timeout = 2`, `Overcharge = 3`, `Slashing = 4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CompensationReason {
    /// The task failed completely; a full refund is requested.
    #[default]
    TaskFailure = 0,
    /// The task completed partially; a proportional refund is requested.
    PartialCompletion = 1,
    /// The task timed out before completion.
    Timeout = 2,
    /// The agent was overcharged for the work performed.
    Overcharge = 3,
    /// A slashing penalty was applied (e.g. for bad behavior or SLA breach).
    Slashing = 4,
}

impl CompensationReason {
    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::TaskFailure),
            Value::Unsigned(1) => Ok(Self::PartialCompletion),
            Value::Unsigned(2) => Ok(Self::Timeout),
            Value::Unsigned(3) => Ok(Self::Overcharge),
            Value::Unsigned(4) => Ok(Self::Slashing),
            _ => Err(EconomicsError::InvalidField {
                field: "compensation_reason",
                message: format!("expected 0/1/2/3/4, got {val:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// CompensationPolicy
// ---------------------------------------------------------------------------

/// Policy governing auto-approval and limits for compensations.
///
/// Amounts are in milli-credits (1 credit = 1000 milli-credits).
#[derive(Clone, Debug)]
pub struct CompensationPolicy {
    /// Compensations at or below this amount (milli-credits) are
    /// auto-approved at request time. Default 10_000 (10 credits).
    pub auto_approve_threshold_milli: i64, // key 1
    /// Maximum compensation amount (milli-credits). Requests above this are
    /// rejected. Default 1_000_000 (1000 credits).
    pub max_amount_milli: i64, // key 2
    /// Maximum number of auto-approved compensations per agent within the
    /// rate-limit window. Default 10.
    pub auto_approve_rate_limit: u32, // key 3
    /// Rate-limit window in milliseconds. Default 3_600_000 (1 hour).
    pub rate_limit_window_ms: u64, // key 4
    /// Whether to auto-approve `Slashing` compensations. Default `false`
    /// (slashing always requires manual review).
    pub auto_approve_slashing: bool, // key 5
}

impl CompensationPolicy {
    /// Create a policy with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the auto-approval threshold (milli-credits).
    pub fn with_auto_approve_threshold(mut self, milli: i64) -> Self {
        self.auto_approve_threshold_milli = milli;
        self
    }

    /// Set the maximum compensation amount (milli-credits).
    pub fn with_max_amount(mut self, milli: i64) -> Self {
        self.max_amount_milli = milli;
        self
    }

    /// Set the auto-approval rate limit (count per window per agent).
    pub fn with_rate_limit(mut self, count: u32, window_ms: u64) -> Self {
        self.auto_approve_rate_limit = count;
        self.rate_limit_window_ms = window_ms;
        self
    }

    /// Set whether slashing compensations can be auto-approved.
    pub fn with_auto_approve_slashing(mut self, allow: bool) -> Self {
        self.auto_approve_slashing = allow;
        self
    }

    /// Check whether `amount_milli` is within the maximum.
    pub fn check_amount(&self, amount_milli: i64) -> Result<(), EconomicsError> {
        if amount_milli < 0 {
            return Err(EconomicsError::CompensationPolicyViolation(
                "amount must be non-negative".to_string(),
            ));
        }
        if amount_milli > self.max_amount_milli {
            return Err(EconomicsError::CompensationExceedsMaximum {
                amount: amount_milli,
                maximum: self.max_amount_milli,
            });
        }
        Ok(())
    }

    /// Determine whether a compensation with the given reason and amount
    /// should be auto-approved, given the agent's recent auto-approval count.
    pub fn should_auto_approve(
        &self,
        amount_milli: i64,
        reason: CompensationReason,
        recent_auto_approvals: u32,
    ) -> bool {
        if reason == CompensationReason::Slashing && !self.auto_approve_slashing {
            return false;
        }
        if amount_milli > self.auto_approve_threshold_milli {
            return false;
        }
        if recent_auto_approvals >= self.auto_approve_rate_limit {
            return false;
        }
        true
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_i64(self.auto_approve_threshold_milli)),
            (2, enc_i64(self.max_amount_milli)),
            (3, enc_u64(self.auto_approve_rate_limit as u64)),
            (4, enc_u64(self.rate_limit_window_ms)),
            (5, Value::Bool(self.auto_approve_slashing)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            auto_approve_threshold_milli: match opt(val, 1) {
                Some(v) => dec_i64(v, "auto_approve_threshold_milli")?,
                None => 10_000,
            },
            max_amount_milli: match opt(val, 2) {
                Some(v) => dec_i64(v, "max_amount_milli")?,
                None => 1_000_000,
            },
            auto_approve_rate_limit: match opt(val, 3) {
                Some(v) => dec_u64(v, "auto_approve_rate_limit")? as u32,
                None => 10,
            },
            rate_limit_window_ms: match opt(val, 4) {
                Some(v) => dec_u64(v, "rate_limit_window_ms")?,
                None => 3_600_000,
            },
            auto_approve_slashing: match opt(val, 5) {
                Some(Value::Bool(b)) => *b,
                Some(Value::Unsigned(0)) => false,
                Some(Value::Unsigned(1)) => true,
                None => false,
                Some(v) => {
                    return Err(EconomicsError::InvalidField {
                        field: "auto_approve_slashing",
                        message: format!("expected bool, got {v:?}"),
                    });
                }
            },
        })
    }
}

impl Default for CompensationPolicy {
    fn default() -> Self {
        Self {
            auto_approve_threshold_milli: 10_000,
            max_amount_milli: 1_000_000,
            auto_approve_rate_limit: 10,
            rate_limit_window_ms: 3_600_000,
            auto_approve_slashing: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DisputeInfo
// ---------------------------------------------------------------------------

/// Information attached to a disputed compensation.
#[derive(Clone, Debug)]
pub struct DisputeInfo {
    /// The agent or operator who filed the dispute.
    pub filed_by: String, // key 1
    /// Free-text evidence or justification.
    pub evidence: String, // key 2
    /// The arbiter assigned to resolve the dispute (empty if unassigned).
    pub arbiter: String, // key 3
    /// Timestamp when the dispute was filed (ms since epoch).
    pub filed_at: u64, // key 4
    /// Optional resolution note set by the arbiter.
    pub resolution_note: Option<String>, // key 5
}

impl DisputeInfo {
    /// Create new dispute info.
    pub fn new(filed_by: impl Into<String>, evidence: impl Into<String>, filed_at: u64) -> Self {
        Self {
            filed_by: filed_by.into(),
            evidence: evidence.into(),
            arbiter: String::new(),
            filed_at,
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
            (3, Value::TextString(self.arbiter.clone())),
            (4, enc_u64(self.filed_at)),
            (5, enc_opt_str(&self.resolution_note)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            filed_by: dec_str(req(val, 1, "filed_by")?, "filed_by")?,
            evidence: dec_str(req(val, 2, "evidence")?, "evidence")?,
            arbiter: match opt(val, 3) {
                Some(v) => dec_str(v, "arbiter")?,
                None => String::new(),
            },
            filed_at: dec_u64(req(val, 4, "filed_at")?, "filed_at")?,
            resolution_note: match opt(val, 5) {
                Some(v) => dec_opt_str(v, "resolution_note")?,
                None => None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Compensation
// ---------------------------------------------------------------------------

/// A single compensation request.
#[derive(Clone, Debug)]
pub struct Compensation {
    /// Unique compensation identifier.
    pub id: String, // key 1
    /// The task that triggered the compensation.
    pub task_id: String, // key 2
    /// The agent receiving (or paying) the compensation.
    pub agent_id: String, // key 3
    /// Amount in milli-credits. Positive = refund to agent; negative = charge
    /// to agent (e.g. slashing penalty).
    pub amount_milli: i64, // key 4
    /// Reason for the compensation.
    pub reason: CompensationReason, // key 5
    /// Timestamp when the request was submitted (ms since epoch).
    pub timestamp: u64, // key 6
    /// Current status.
    pub status: CompensationStatus, // key 7
    /// Optional reason for rejection.
    pub rejection_reason: Option<String>, // key 8
    /// Dispute information, if the compensation is disputed.
    pub dispute: Option<DisputeInfo>, // key 9
    /// Optional resource usage to credit to the agent when paid.
    /// If `None`, the compensation is purely a credit-value adjustment.
    pub resource_credit: Option<ResourceUsage>, // key 10
    /// Timestamp when payment was processed (ms since epoch), if paid.
    pub paid_at: Option<u64>, // key 11
    /// Whether this was auto-approved.
    pub auto_approved: bool, // key 12
}

impl Compensation {
    /// Create a new pending compensation.
    pub fn new(
        id: impl Into<String>,
        task_id: impl Into<String>,
        agent_id: impl Into<String>,
        amount_milli: i64,
        reason: CompensationReason,
        timestamp: u64,
    ) -> Self {
        Self {
            id: id.into(),
            task_id: task_id.into(),
            agent_id: agent_id.into(),
            amount_milli,
            reason,
            timestamp,
            status: CompensationStatus::Pending,
            rejection_reason: None,
            dispute: None,
            resource_credit: None,
            paid_at: None,
            auto_approved: false,
        }
    }

    /// Set the resource usage to credit when this compensation is paid.
    pub fn with_resource_credit(mut self, usage: ResourceUsage) -> Self {
        self.resource_credit = Some(usage);
        self
    }

    /// Amount in credits (as `f64`).
    pub fn amount_credits(&self) -> f64 {
        self.amount_milli as f64 / 1000.0
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.id.clone())),
            (2, Value::TextString(self.task_id.clone())),
            (3, Value::TextString(self.agent_id.clone())),
            (4, enc_i64(self.amount_milli)),
            (5, self.reason.to_cbor()),
            (6, enc_u64(self.timestamp)),
            (7, self.status.to_cbor()),
            (8, enc_opt_str(&self.rejection_reason)),
            (
                9,
                match &self.dispute {
                    Some(d) => d.to_cbor(),
                    None => Value::Null,
                },
            ),
            (
                10,
                match &self.resource_credit {
                    Some(u) => u.to_cbor(),
                    None => Value::Null,
                },
            ),
            (
                11,
                match self.paid_at {
                    Some(t) => enc_u64(t),
                    None => Value::Null,
                },
            ),
            (12, Value::Bool(self.auto_approved)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            id: dec_str(req(val, 1, "id")?, "id")?,
            task_id: dec_str(req(val, 2, "task_id")?, "task_id")?,
            agent_id: dec_str(req(val, 3, "agent_id")?, "agent_id")?,
            amount_milli: dec_i64(req(val, 4, "amount_milli")?, "amount_milli")?,
            reason: match opt(val, 5) {
                Some(v) => CompensationReason::from_cbor(v)?,
                None => CompensationReason::default(),
            },
            timestamp: dec_u64(req(val, 6, "timestamp")?, "timestamp")?,
            status: match opt(val, 7) {
                Some(v) => CompensationStatus::from_cbor(v)?,
                None => CompensationStatus::default(),
            },
            rejection_reason: match opt(val, 8) {
                Some(v) => dec_opt_str(v, "rejection_reason")?,
                None => None,
            },
            dispute: match opt(val, 9) {
                Some(Value::Null) | None => None,
                Some(v) => Some(DisputeInfo::from_cbor(v)?),
            },
            resource_credit: match opt(val, 10) {
                Some(Value::Null) | None => None,
                Some(v) => Some(ResourceUsage::from_cbor(v)?),
            },
            paid_at: match opt(val, 11) {
                Some(Value::Null) | None => None,
                Some(v) => Some(dec_u64(v, "paid_at")?),
            },
            auto_approved: match opt(val, 12) {
                Some(Value::Bool(b)) => *b,
                Some(Value::Unsigned(0)) => false,
                Some(Value::Unsigned(1)) => true,
                None => false,
                Some(v) => {
                    return Err(EconomicsError::InvalidField {
                        field: "auto_approved",
                        message: format!("expected bool, got {v:?}"),
                    });
                }
            },
        })
    }
}

// ---------------------------------------------------------------------------
// BatchResult
// ---------------------------------------------------------------------------

/// Result of [`CompensationProtocol::process_batch`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchResult {
    /// Number of compensations auto-approved.
    pub auto_approved: usize,
    /// Number of compensations left pending for manual review.
    pub left_pending: usize,
    /// Number of compensations rejected by policy (e.g. over max).
    pub rejected: usize,
    /// Number of compensations paid (previously approved, now processed).
    pub paid: usize,
}

// ---------------------------------------------------------------------------
// CompensationProtocol
// ---------------------------------------------------------------------------

/// Manages compensation requests with auto-approval, batch processing, and
/// optional integration with [`ResourceAccount`].
///
/// The protocol maintains a `HashMap` of all compensations keyed by their
/// unique `id`. An optional `ResourceAccount` can be attached via
/// [`CompensationProtocol::set_account`]; when a compensation is paid, the
/// agent's account is credited with the compensation's `resource_credit`
/// (if specified).
pub struct CompensationProtocol {
    policy: CompensationPolicy,
    compensations: HashMap<String, Compensation>,
    /// Optional resource account for crediting payments.
    account: Option<ResourceAccount>,
    /// Tracks auto-approval timestamps per agent for rate limiting.
    /// Maps agent_id → list of auto-approval timestamps.
    auto_approval_history: HashMap<String, Vec<u64>>,
    /// Counter for generating unique compensation IDs.
    id_counter: u64,
}

impl CompensationProtocol {
    /// Create a new protocol with the given policy.
    pub fn new(policy: CompensationPolicy) -> Self {
        Self {
            policy,
            compensations: HashMap::new(),
            account: None,
            auto_approval_history: HashMap::new(),
            id_counter: 0,
        }
    }

    /// Create a new protocol with default policy.
    pub fn with_defaults() -> Self {
        Self::new(CompensationPolicy::default())
    }

    /// Return a reference to the policy.
    pub fn policy(&self) -> &CompensationPolicy {
        &self.policy
    }

    /// Return a mutable reference to the policy.
    pub fn policy_mut(&mut self) -> &mut CompensationPolicy {
        &mut self.policy
    }

    /// Attach a [`ResourceAccount`] for crediting payments.
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

    /// Generate a unique compensation ID.
    fn next_id(&mut self) -> String {
        self.id_counter += 1;
        format!("comp-{}", self.id_counter)
    }

    /// Count auto-approvals for `agent` within the rate-limit window ending
    /// at `now`.
    fn count_recent_auto_approvals(&self, agent: &str, now: u64) -> u32 {
        let window = self.policy.rate_limit_window_ms;
        match self.auto_approval_history.get(agent) {
            Some(timestamps) => timestamps
                .iter()
                .filter(|&&t| now.saturating_sub(t) <= window)
                .count() as u32,
            None => 0,
        }
    }

    /// Record an auto-approval timestamp for `agent`.
    fn record_auto_approval(&mut self, agent: &str, now: u64) {
        self.auto_approval_history
            .entry(agent.to_string())
            .or_default()
            .push(now);
    }

    /// Evict expired auto-approval timestamps older than the rate-limit
    /// window. This prevents unbounded growth of the history.
    pub fn evict_expired(&mut self, now: u64) {
        let window = self.policy.rate_limit_window_ms;
        for timestamps in self.auto_approval_history.values_mut() {
            timestamps.retain(|&t| now.saturating_sub(t) <= window);
        }
    }

    /// Submit a compensation request. If the amount is within the
    /// auto-approval threshold and the agent is within its rate limit, the
    /// compensation is auto-approved immediately.
    ///
    /// Returns the created compensation, or an error if the amount exceeds
    /// the policy maximum.
    pub fn request_compensation(
        &mut self,
        task_id: &str,
        agent_id: &str,
        amount_milli: i64,
        reason: CompensationReason,
        now: u64,
    ) -> Result<Compensation, EconomicsError> {
        self.policy.check_amount(amount_milli)?;

        let id = self.next_id();
        let mut comp = Compensation::new(id, task_id, agent_id, amount_milli, reason, now);

        // Check auto-approval.
        let recent = self.count_recent_auto_approvals(agent_id, now);
        if self
            .policy
            .should_auto_approve(amount_milli, reason, recent)
        {
            comp.status = CompensationStatus::Approved;
            comp.auto_approved = true;
            self.record_auto_approval(agent_id, now);
        }

        self.compensations.insert(comp.id.clone(), comp.clone());
        Ok(comp)
    }

    /// Submit a compensation request with a specific ID (useful for
    /// deterministic testing or external ID assignment).
    pub fn request_compensation_with_id(
        &mut self,
        id: &str,
        task_id: &str,
        agent_id: &str,
        amount_milli: i64,
        reason: CompensationReason,
        now: u64,
    ) -> Result<Compensation, EconomicsError> {
        self.policy.check_amount(amount_milli)?;

        if self.compensations.contains_key(id) {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: "compensation ID already exists".to_string(),
            });
        }

        let mut comp = Compensation::new(id, task_id, agent_id, amount_milli, reason, now);

        let recent = self.count_recent_auto_approvals(agent_id, now);
        if self
            .policy
            .should_auto_approve(amount_milli, reason, recent)
        {
            comp.status = CompensationStatus::Approved;
            comp.auto_approved = true;
            self.record_auto_approval(agent_id, now);
        }

        self.compensations.insert(comp.id.clone(), comp.clone());
        Ok(comp)
    }

    /// Approve a pending compensation. Returns an error if the compensation
    /// is not in the `Pending` state.
    pub fn approve_compensation(&mut self, id: &str) -> Result<Compensation, EconomicsError> {
        let comp = self
            .compensations
            .get_mut(id)
            .ok_or_else(|| EconomicsError::CompensationNotFound(id.to_string()))?;
        if comp.status != CompensationStatus::Pending {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: format!("expected Pending, got {:?}", comp.status),
            });
        }
        comp.status = CompensationStatus::Approved;
        Ok(comp.clone())
    }

    /// Reject a pending compensation with a reason. Returns an error if the
    /// compensation is not in the `Pending` state.
    pub fn reject_compensation(
        &mut self,
        id: &str,
        reason: &str,
    ) -> Result<Compensation, EconomicsError> {
        let comp = self
            .compensations
            .get_mut(id)
            .ok_or_else(|| EconomicsError::CompensationNotFound(id.to_string()))?;
        if comp.status != CompensationStatus::Pending {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: format!("expected Pending, got {:?}", comp.status),
            });
        }
        comp.status = CompensationStatus::Rejected;
        comp.rejection_reason = Some(reason.to_string());
        Ok(comp.clone())
    }

    /// Escalate a compensation to dispute resolution. The compensation must
    /// be in `Pending` or `Approved` state.
    pub fn dispute_compensation(
        &mut self,
        id: &str,
        filed_by: &str,
        evidence: &str,
        now: u64,
    ) -> Result<Compensation, EconomicsError> {
        let comp = self
            .compensations
            .get_mut(id)
            .ok_or_else(|| EconomicsError::CompensationNotFound(id.to_string()))?;
        if comp.status != CompensationStatus::Pending && comp.status != CompensationStatus::Approved
        {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: format!("expected Pending or Approved, got {:?}", comp.status),
            });
        }
        comp.status = CompensationStatus::Disputed;
        comp.dispute = Some(DisputeInfo::new(filed_by, evidence, now));
        Ok(comp.clone())
    }

    /// Assign an arbiter to a disputed compensation.
    pub fn assign_arbiter(
        &mut self,
        id: &str,
        arbiter: &str,
    ) -> Result<Compensation, EconomicsError> {
        let comp = self
            .compensations
            .get_mut(id)
            .ok_or_else(|| EconomicsError::CompensationNotFound(id.to_string()))?;
        if comp.status != CompensationStatus::Disputed {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: format!("expected Disputed, got {:?}", comp.status),
            });
        }
        if let Some(dispute) = &mut comp.dispute {
            dispute.arbiter = arbiter.to_string();
        }
        Ok(comp.clone())
    }

    /// Resolve a disputed compensation. The arbiter can approve or reject it.
    pub fn resolve_dispute(
        &mut self,
        id: &str,
        approve: bool,
        note: &str,
    ) -> Result<Compensation, EconomicsError> {
        let comp = self
            .compensations
            .get_mut(id)
            .ok_or_else(|| EconomicsError::CompensationNotFound(id.to_string()))?;
        if comp.status != CompensationStatus::Disputed {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: format!("expected Disputed, got {:?}", comp.status),
            });
        }
        if approve {
            comp.status = CompensationStatus::Approved;
        } else {
            comp.status = CompensationStatus::Rejected;
            comp.rejection_reason = Some(note.to_string());
        }
        if let Some(dispute) = &mut comp.dispute {
            dispute.resolution_note = Some(note.to_string());
        }
        Ok(comp.clone())
    }

    /// Process payment for an approved compensation. If a `ResourceAccount`
    /// is attached and the compensation has a `resource_credit`, the agent's
    /// account is credited. The compensation transitions to `Paid`.
    pub fn process_payment(&mut self, id: &str, now: u64) -> Result<Compensation, EconomicsError> {
        // We need to potentially mutate the account, so we take out the comp
        // first, process it, then put it back.
        let comp = self
            .compensations
            .get_mut(id)
            .ok_or_else(|| EconomicsError::CompensationNotFound(id.to_string()))?;
        if comp.status != CompensationStatus::Approved {
            return Err(EconomicsError::InvalidCompensationState {
                id: id.to_string(),
                message: format!("expected Approved, got {:?}", comp.status),
            });
        }

        // Credit the resource account if attached and resource_credit is set.
        if let Some(account) = &mut self.account {
            if let Some(usage) = &comp.resource_credit {
                account.credit(&comp.agent_id, usage);
            }
        }

        comp.status = CompensationStatus::Paid;
        comp.paid_at = Some(now);
        Ok(comp.clone())
    }

    /// Batch process all pending compensations. Auto-approves those within
    /// policy, rejects those over the maximum, and pays out any previously
    /// approved compensations.
    ///
    /// Returns a [`BatchResult`] summarizing the actions taken.
    pub fn process_batch(&mut self, now: u64) -> BatchResult {
        let mut result = BatchResult::default();

        // Collect IDs to avoid borrowing issues during iteration.
        let ids: Vec<String> = self.compensations.keys().cloned().collect();

        for id in ids {
            let status = self.compensations[&id].status;
            match status {
                CompensationStatus::Pending => {
                    let comp = &self.compensations[&id];
                    let amount = comp.amount_milli;
                    let reason = comp.reason;
                    let agent = comp.agent_id.clone();

                    // Check if over max (shouldn't happen, but be safe).
                    if amount > self.policy.max_amount_milli {
                        let _ = self.reject_compensation(&id, "exceeds maximum");
                        result.rejected += 1;
                        continue;
                    }

                    let recent = self.count_recent_auto_approvals(&agent, now);
                    if self.policy.should_auto_approve(amount, reason, recent) {
                        // Auto-approve.
                        if let Ok(mut comp) = self.approve_compensation(&id) {
                            comp.auto_approved = true;
                            // Update the stored copy.
                            if let Some(stored) = self.compensations.get_mut(&id) {
                                stored.auto_approved = true;
                            }
                            self.record_auto_approval(&agent, now);
                            // Pay it out.
                            if self.process_payment(&id, now).is_ok() {
                                result.paid += 1;
                            }
                            result.auto_approved += 1;
                        }
                    } else {
                        result.left_pending += 1;
                    }
                }
                CompensationStatus::Approved
                    // Pay out previously approved compensations.
                    if self.process_payment(&id, now).is_ok() =>
                {
                    result.paid += 1;
                }
                _ => {}
            }
        }

        result
    }

    /// Get a reference to a compensation by ID.
    pub fn get(&self, id: &str) -> Option<&Compensation> {
        self.compensations.get(id)
    }

    /// Get all compensations for a specific agent.
    pub fn for_agent(&self, agent_id: &str) -> Vec<&Compensation> {
        self.compensations
            .values()
            .filter(|c| c.agent_id == agent_id)
            .collect()
    }

    /// Get all compensations for a specific task.
    pub fn for_task(&self, task_id: &str) -> Vec<&Compensation> {
        self.compensations
            .values()
            .filter(|c| c.task_id == task_id)
            .collect()
    }

    /// Get all compensations with a specific status.
    pub fn by_status(&self, status: CompensationStatus) -> Vec<&Compensation> {
        self.compensations
            .values()
            .filter(|c| c.status == status)
            .collect()
    }

    /// Total number of compensations.
    pub fn len(&self) -> usize {
        self.compensations.len()
    }

    /// Returns `true` if there are no compensations.
    pub fn is_empty(&self) -> bool {
        self.compensations.is_empty()
    }

    /// Total amount of all paid compensations (milli-credits).
    pub fn total_paid_milli(&self) -> i64 {
        self.compensations
            .values()
            .filter(|c| c.status == CompensationStatus::Paid)
            .map(|c| c.amount_milli)
            .fold(0i64, |acc, a| acc.saturating_add(a))
    }

    /// Total amount of all pending compensations (milli-credits).
    pub fn total_pending_milli(&self) -> i64 {
        self.compensations
            .values()
            .filter(|c| c.status == CompensationStatus::Pending)
            .map(|c| c.amount_milli)
            .fold(0i64, |acc, a| acc.saturating_add(a))
    }

    /// Remove a compensation. Returns the removed compensation, or `None`.
    pub fn remove(&mut self, id: &str) -> Option<Compensation> {
        self.compensations.remove(id)
    }

    /// Clear all compensations.
    pub fn clear(&mut self) {
        self.compensations.clear();
        self.auto_approval_history.clear();
    }
}

impl Default for CompensationProtocol {
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
    use crate::account::{AccountConfig, ResourceAccount, ResourceUsage};

    fn usage(cpu: u64, mem: u64, stor: u64, net: u64, api: u64, tok: u64) -> ResourceUsage {
        ResourceUsage::new(cpu, mem, stor, net, api, tok)
    }

    // --- CompensationStatus tests ---

    #[test]
    fn test_status_default_is_pending() {
        assert_eq!(CompensationStatus::default(), CompensationStatus::Pending);
    }

    #[test]
    fn test_status_cbor_roundtrip() {
        for s in [
            CompensationStatus::Pending,
            CompensationStatus::Approved,
            CompensationStatus::Rejected,
            CompensationStatus::Paid,
            CompensationStatus::Disputed,
        ] {
            let val = s.to_cbor();
            assert_eq!(CompensationStatus::from_cbor(&val).unwrap(), s);
        }
    }

    #[test]
    fn test_status_cbor_invalid() {
        assert!(CompensationStatus::from_cbor(&Value::Unsigned(99)).is_err());
    }

    #[test]
    fn test_status_is_terminal() {
        assert!(CompensationStatus::Paid.is_terminal());
        assert!(CompensationStatus::Rejected.is_terminal());
        assert!(!CompensationStatus::Pending.is_terminal());
        assert!(!CompensationStatus::Approved.is_terminal());
        assert!(!CompensationStatus::Disputed.is_terminal());
    }

    // --- CompensationReason tests ---

    #[test]
    fn test_reason_default_is_task_failure() {
        assert_eq!(
            CompensationReason::default(),
            CompensationReason::TaskFailure
        );
    }

    #[test]
    fn test_reason_cbor_roundtrip() {
        for r in [
            CompensationReason::TaskFailure,
            CompensationReason::PartialCompletion,
            CompensationReason::Timeout,
            CompensationReason::Overcharge,
            CompensationReason::Slashing,
        ] {
            let val = r.to_cbor();
            assert_eq!(CompensationReason::from_cbor(&val).unwrap(), r);
        }
    }

    #[test]
    fn test_reason_cbor_invalid() {
        assert!(CompensationReason::from_cbor(&Value::Unsigned(99)).is_err());
    }

    // --- CompensationPolicy tests ---

    #[test]
    fn test_policy_default() {
        let p = CompensationPolicy::default();
        assert_eq!(p.auto_approve_threshold_milli, 10_000);
        assert_eq!(p.max_amount_milli, 1_000_000);
        assert_eq!(p.auto_approve_rate_limit, 10);
        assert_eq!(p.rate_limit_window_ms, 3_600_000);
        assert!(!p.auto_approve_slashing);
    }

    #[test]
    fn test_policy_builder() {
        let p = CompensationPolicy::new()
            .with_auto_approve_threshold(50_000)
            .with_max_amount(500_000)
            .with_rate_limit(5, 1_800_000)
            .with_auto_approve_slashing(true);
        assert_eq!(p.auto_approve_threshold_milli, 50_000);
        assert_eq!(p.max_amount_milli, 500_000);
        assert_eq!(p.auto_approve_rate_limit, 5);
        assert_eq!(p.rate_limit_window_ms, 1_800_000);
        assert!(p.auto_approve_slashing);
    }

    #[test]
    fn test_policy_check_amount_ok() {
        let p = CompensationPolicy::default();
        assert!(p.check_amount(0).is_ok());
        assert!(p.check_amount(500_000).is_ok());
        assert!(p.check_amount(p.max_amount_milli).is_ok());
    }

    #[test]
    fn test_policy_check_amount_negative() {
        let p = CompensationPolicy::default();
        assert!(p.check_amount(-1).is_err());
    }

    #[test]
    fn test_policy_check_amount_over_max() {
        let p = CompensationPolicy::default();
        let result = p.check_amount(p.max_amount_milli + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_should_auto_approve_small_amount() {
        let p = CompensationPolicy::default();
        assert!(p.should_auto_approve(5_000, CompensationReason::TaskFailure, 0));
    }

    #[test]
    fn test_policy_should_not_auto_approve_large_amount() {
        let p = CompensationPolicy::default();
        assert!(!p.should_auto_approve(50_000, CompensationReason::TaskFailure, 0));
    }

    #[test]
    fn test_policy_should_not_auto_approve_slashing_by_default() {
        let p = CompensationPolicy::default();
        assert!(!p.should_auto_approve(1_000, CompensationReason::Slashing, 0));
    }

    #[test]
    fn test_policy_auto_approve_slashing_when_enabled() {
        let p = CompensationPolicy::default().with_auto_approve_slashing(true);
        assert!(p.should_auto_approve(1_000, CompensationReason::Slashing, 0));
    }

    #[test]
    fn test_policy_rate_limit_exceeded() {
        let p = CompensationPolicy::default();
        assert!(!p.should_auto_approve(1_000, CompensationReason::TaskFailure, 10));
    }

    #[test]
    fn test_policy_cbor_roundtrip() {
        let p = CompensationPolicy::new()
            .with_auto_approve_threshold(25_000)
            .with_max_amount(750_000)
            .with_rate_limit(20, 900_000)
            .with_auto_approve_slashing(true);
        let val = p.to_cbor();
        let p2 = CompensationPolicy::from_cbor(&val).unwrap();
        assert_eq!(
            p2.auto_approve_threshold_milli,
            p.auto_approve_threshold_milli
        );
        assert_eq!(p2.max_amount_milli, p.max_amount_milli);
        assert_eq!(p2.auto_approve_rate_limit, p.auto_approve_rate_limit);
        assert_eq!(p2.rate_limit_window_ms, p.rate_limit_window_ms);
        assert_eq!(p2.auto_approve_slashing, p.auto_approve_slashing);
    }

    #[test]
    fn test_policy_cbor_defaults_when_missing() {
        let val = int_map(vec![]);
        let p = CompensationPolicy::from_cbor(&val).unwrap();
        assert_eq!(p.auto_approve_threshold_milli, 10_000);
        assert_eq!(p.max_amount_milli, 1_000_000);
    }

    // --- DisputeInfo tests ---

    #[test]
    fn test_dispute_info_new() {
        let d = DisputeInfo::new("agent-1", "task failed due to timeout", 1000);
        assert_eq!(d.filed_by, "agent-1");
        assert_eq!(d.evidence, "task failed due to timeout");
        assert_eq!(d.filed_at, 1000);
        assert!(d.arbiter.is_empty());
        assert!(d.resolution_note.is_none());
    }

    #[test]
    fn test_dispute_info_with_arbiter_and_resolution() {
        let d = DisputeInfo::new("agent-1", "evidence", 1000)
            .with_arbiter("arbiter-1")
            .with_resolution("approved with note");
        assert_eq!(d.arbiter, "arbiter-1");
        assert_eq!(d.resolution_note, Some("approved with note".to_string()));
    }

    #[test]
    fn test_dispute_info_cbor_roundtrip() {
        let d = DisputeInfo::new("agent-1", "evidence text", 5000)
            .with_arbiter("arbiter-1")
            .with_resolution("resolved");
        let val = d.to_cbor();
        let d2 = DisputeInfo::from_cbor(&val).unwrap();
        assert_eq!(d2.filed_by, d.filed_by);
        assert_eq!(d2.evidence, d.evidence);
        assert_eq!(d2.arbiter, d.arbiter);
        assert_eq!(d2.filed_at, d.filed_at);
        assert_eq!(d2.resolution_note, d.resolution_note);
    }

    // --- Compensation struct tests ---

    #[test]
    fn test_compensation_new() {
        let c = Compensation::new(
            "c1",
            "task-1",
            "agent-1",
            50_000,
            CompensationReason::Timeout,
            1000,
        );
        assert_eq!(c.id, "c1");
        assert_eq!(c.task_id, "task-1");
        assert_eq!(c.agent_id, "agent-1");
        assert_eq!(c.amount_milli, 50_000);
        assert_eq!(c.reason, CompensationReason::Timeout);
        assert_eq!(c.status, CompensationStatus::Pending);
        assert!(!c.auto_approved);
    }

    #[test]
    fn test_compensation_amount_credits() {
        let c = Compensation::new("c1", "t1", "a1", 50_000, CompensationReason::TaskFailure, 0);
        assert!((c.amount_credits() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_compensation_with_resource_credit() {
        let c = Compensation::new("c1", "t1", "a1", 50_000, CompensationReason::TaskFailure, 0)
            .with_resource_credit(usage(100, 0, 0, 0, 0, 0));
        assert!(c.resource_credit.is_some());
        assert_eq!(c.resource_credit.unwrap().cpu_ms, 100);
    }

    #[test]
    fn test_compensation_cbor_roundtrip() {
        let mut c = Compensation::new(
            "c1",
            "task-1",
            "agent-1",
            75_000,
            CompensationReason::PartialCompletion,
            2000,
        );
        c.status = CompensationStatus::Approved;
        c.auto_approved = true;
        c.resource_credit = Some(usage(50, 10, 0, 0, 0, 0));
        let val = c.to_cbor();
        let c2 = Compensation::from_cbor(&val).unwrap();
        assert_eq!(c2.id, c.id);
        assert_eq!(c2.task_id, c.task_id);
        assert_eq!(c2.agent_id, c.agent_id);
        assert_eq!(c2.amount_milli, c.amount_milli);
        assert_eq!(c2.reason, c.reason);
        assert_eq!(c2.status, c.status);
        assert_eq!(c2.auto_approved, c.auto_approved);
        assert_eq!(c2.resource_credit, c.resource_credit);
    }

    #[test]
    fn test_compensation_cbor_with_dispute() {
        let mut c = Compensation::new(
            "c1",
            "t1",
            "a1",
            100_000,
            CompensationReason::Overcharge,
            1000,
        );
        c.status = CompensationStatus::Disputed;
        c.dispute = Some(DisputeInfo::new("agent-1", "overcharged", 2000).with_arbiter("arb-1"));
        let val = c.to_cbor();
        let c2 = Compensation::from_cbor(&val).unwrap();
        assert_eq!(c2.status, CompensationStatus::Disputed);
        assert!(c2.dispute.is_some());
        assert_eq!(c2.dispute.unwrap().arbiter, "arb-1");
    }

    #[test]
    fn test_compensation_cbor_with_rejection_and_paid() {
        let mut c = Compensation::new("c1", "t1", "a1", 50_000, CompensationReason::Timeout, 1000);
        c.status = CompensationStatus::Paid;
        c.paid_at = Some(3000);
        let val = c.to_cbor();
        let c2 = Compensation::from_cbor(&val).unwrap();
        assert_eq!(c2.status, CompensationStatus::Paid);
        assert_eq!(c2.paid_at, Some(3000));
    }

    // --- CompensationProtocol: request_compensation ---

    #[test]
    fn test_protocol_request_basic() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation(
                "task-1",
                "agent-1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert_eq!(comp.task_id, "task-1");
        assert_eq!(comp.agent_id, "agent-1");
        assert_eq!(comp.amount_milli, 50_000);
        assert_eq!(comp.status, CompensationStatus::Pending); // over threshold
        assert!(!comp.auto_approved);
    }

    #[test]
    fn test_protocol_request_auto_approved() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation(
                "task-1",
                "agent-1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert_eq!(comp.status, CompensationStatus::Approved);
        assert!(comp.auto_approved);
    }

    #[test]
    fn test_protocol_request_over_max_rejected() {
        let mut proto = CompensationProtocol::with_defaults();
        let result = proto.request_compensation(
            "task-1",
            "agent-1",
            2_000_000,
            CompensationReason::TaskFailure,
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_request_negative_amount_rejected() {
        let mut proto = CompensationProtocol::with_defaults();
        let result = proto.request_compensation(
            "task-1",
            "agent-1",
            -1,
            CompensationReason::TaskFailure,
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_request_slashing_not_auto_approved() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation(
                "task-1",
                "agent-1",
                1_000,
                CompensationReason::Slashing,
                1000,
            )
            .unwrap();
        assert_eq!(comp.status, CompensationStatus::Pending);
        assert!(!comp.auto_approved);
    }

    // --- CompensationProtocol: approve / reject ---

    #[test]
    fn test_protocol_approve_pending() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        let approved = proto.approve_compensation(&comp.id).unwrap();
        assert_eq!(approved.status, CompensationStatus::Approved);
    }

    #[test]
    fn test_protocol_approve_not_found() {
        let mut proto = CompensationProtocol::with_defaults();
        assert!(proto.approve_compensation("nonexistent").is_err());
    }

    #[test]
    fn test_protocol_approve_wrong_state() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto.approve_compensation(&comp.id).unwrap();
        // Can't approve again.
        assert!(proto.approve_compensation(&comp.id).is_err());
    }

    #[test]
    fn test_protocol_reject_pending() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        let rejected = proto
            .reject_compensation(&comp.id, "invalid claim")
            .unwrap();
        assert_eq!(rejected.status, CompensationStatus::Rejected);
        assert_eq!(rejected.rejection_reason, Some("invalid claim".to_string()));
    }

    #[test]
    fn test_protocol_reject_wrong_state() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto.reject_compensation(&comp.id, "no").unwrap();
        // Can't reject again.
        assert!(proto.reject_compensation(&comp.id, "no").is_err());
    }

    // --- CompensationProtocol: dispute ---

    #[test]
    fn test_protocol_dispute_pending() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        let disputed = proto
            .dispute_compensation(&comp.id, "agent-1", "evidence", 2000)
            .unwrap();
        assert_eq!(disputed.status, CompensationStatus::Disputed);
        assert!(disputed.dispute.is_some());
    }

    #[test]
    fn test_protocol_dispute_approved() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto.approve_compensation(&comp.id).unwrap();
        let disputed = proto
            .dispute_compensation(&comp.id, "agent-1", "evidence", 2000)
            .unwrap();
        assert_eq!(disputed.status, CompensationStatus::Disputed);
    }

    #[test]
    fn test_protocol_dispute_wrong_state() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto.reject_compensation(&comp.id, "no").unwrap();
        assert!(proto
            .dispute_compensation(&comp.id, "a1", "e", 2000)
            .is_err());
    }

    #[test]
    fn test_protocol_assign_arbiter() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto
            .dispute_compensation(&comp.id, "a1", "evidence", 2000)
            .unwrap();
        let result = proto.assign_arbiter(&comp.id, "arbiter-1").unwrap();
        assert_eq!(result.dispute.as_ref().unwrap().arbiter, "arbiter-1");
    }

    #[test]
    fn test_protocol_assign_arbiter_wrong_state() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        // Not disputed yet.
        assert!(proto.assign_arbiter(&comp.id, "arb-1").is_err());
    }

    #[test]
    fn test_protocol_resolve_dispute_approve() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto
            .dispute_compensation(&comp.id, "a1", "evidence", 2000)
            .unwrap();
        let resolved = proto
            .resolve_dispute(&comp.id, true, "approved by arbiter")
            .unwrap();
        assert_eq!(resolved.status, CompensationStatus::Approved);
        assert_eq!(
            resolved.dispute.as_ref().unwrap().resolution_note,
            Some("approved by arbiter".to_string())
        );
    }

    #[test]
    fn test_protocol_resolve_dispute_reject() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto
            .dispute_compensation(&comp.id, "a1", "evidence", 2000)
            .unwrap();
        let resolved = proto
            .resolve_dispute(&comp.id, false, "insufficient evidence")
            .unwrap();
        assert_eq!(resolved.status, CompensationStatus::Rejected);
        assert_eq!(
            resolved.rejection_reason,
            Some("insufficient evidence".to_string())
        );
    }

    #[test]
    fn test_protocol_resolve_dispute_wrong_state() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        // Not disputed.
        assert!(proto.resolve_dispute(&comp.id, true, "ok").is_err());
    }

    // --- CompensationProtocol: process_payment ---

    #[test]
    fn test_protocol_process_payment_approved() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto.approve_compensation(&comp.id).unwrap();
        let paid = proto.process_payment(&comp.id, 3000).unwrap();
        assert_eq!(paid.status, CompensationStatus::Paid);
        assert_eq!(paid.paid_at, Some(3000));
    }

    #[test]
    fn test_protocol_process_payment_wrong_state() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        // Still pending.
        assert!(proto.process_payment(&comp.id, 3000).is_err());
    }

    // --- CompensationProtocol: ResourceAccount integration ---

    #[test]
    fn test_protocol_payment_credits_account() {
        let mut proto = CompensationProtocol::with_defaults();
        proto.set_account(ResourceAccount::with_defaults());

        // Debit the agent first so there's something to credit.
        if let Some(acct) = proto.account_mut() {
            acct.debit("a1", &usage(200, 0, 0, 0, 0, 0)).unwrap();
        }

        let comp = proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap()
            .with_resource_credit(usage(100, 0, 0, 0, 0, 0));
        // Update the stored compensation with resource_credit.
        if let Some(stored) = proto.compensations.get_mut("c1") {
            stored.resource_credit = Some(usage(100, 0, 0, 0, 0, 0));
        }

        proto.approve_compensation("c1").unwrap();
        proto.process_payment("c1", 3000).unwrap();

        let balance = proto.account().unwrap().balance("a1");
        assert_eq!(balance.cpu_ms, 100); // 200 debited - 100 credited
    }

    #[test]
    fn test_protocol_payment_without_account() {
        let mut proto = CompensationProtocol::with_defaults();
        // No account attached.
        let comp = proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto.approve_compensation(&comp.id).unwrap();
        // Should still work, just no account credit.
        let paid = proto.process_payment(&comp.id, 3000).unwrap();
        assert_eq!(paid.status, CompensationStatus::Paid);
    }

    #[test]
    fn test_protocol_payment_without_resource_credit() {
        let mut proto = CompensationProtocol::with_defaults();
        proto.set_account(ResourceAccount::with_defaults());

        if let Some(acct) = proto.account_mut() {
            acct.debit("a1", &usage(200, 0, 0, 0, 0, 0)).unwrap();
        }

        let comp = proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        // No resource_credit set.
        proto.approve_compensation(&comp.id).unwrap();
        proto.process_payment(&comp.id, 3000).unwrap();

        // Balance unchanged (no resource_credit).
        let balance = proto.account().unwrap().balance("a1");
        assert_eq!(balance.cpu_ms, 200);
    }

    // --- CompensationProtocol: process_batch ---

    #[test]
    fn test_protocol_process_batch_auto_approves_small() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a1",
                3_000,
                CompensationReason::Timeout,
                1000,
            )
            .unwrap();

        let result = proto.process_batch(2000);
        // Both were auto-approved at request time, so they enter the batch as
        // Approved and are paid out (not counted as auto_approved in the batch).
        assert_eq!(result.auto_approved, 0);
        assert_eq!(result.paid, 2);
        assert_eq!(result.left_pending, 0);
        assert_eq!(proto.get("c1").unwrap().status, CompensationStatus::Paid);
        assert_eq!(proto.get("c2").unwrap().status, CompensationStatus::Paid);
    }

    #[test]
    fn test_protocol_process_batch_leaves_large_pending() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();

        let result = proto.process_batch(2000);
        assert_eq!(result.auto_approved, 0);
        assert_eq!(result.left_pending, 1);
        assert_eq!(proto.get("c1").unwrap().status, CompensationStatus::Pending);
    }

    #[test]
    fn test_protocol_process_batch_auto_approves_after_policy_change() {
        let mut proto = CompensationProtocol::with_defaults();
        // Request with a large amount that won't auto-approve at request time.
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert_eq!(proto.get("c1").unwrap().status, CompensationStatus::Pending);

        // Raise the auto-approval threshold so the batch will auto-approve it.
        proto.policy_mut().auto_approve_threshold_milli = 100_000;

        let result = proto.process_batch(2000);
        assert_eq!(result.auto_approved, 1);
        assert_eq!(result.paid, 1);
        assert_eq!(proto.get("c1").unwrap().status, CompensationStatus::Paid);
    }

    #[test]
    fn test_protocol_process_batch_pays_approved() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        // Manually approve.
        proto.approve_compensation("c1").unwrap();

        let result = proto.process_batch(2000);
        assert_eq!(result.paid, 1);
        assert_eq!(result.left_pending, 0);
        assert_eq!(proto.get("c1").unwrap().status, CompensationStatus::Paid);
    }

    #[test]
    fn test_protocol_process_batch_mixed() {
        let mut proto = CompensationProtocol::with_defaults();
        // Small — auto-approved.
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        // Large — stays pending.
        proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a2",
                50_000,
                CompensationReason::Timeout,
                1000,
            )
            .unwrap();
        // Large — manually approved.
        proto
            .request_compensation_with_id(
                "c3",
                "t3",
                "a3",
                80_000,
                CompensationReason::Overcharge,
                1000,
            )
            .unwrap();
        proto.approve_compensation("c3").unwrap();

        let result = proto.process_batch(2000);
        // c1 was auto-approved at request time → paid via Approved branch.
        // c3 was manually approved → paid via Approved branch.
        // c2 is pending and over threshold → left pending.
        assert_eq!(result.auto_approved, 0);
        assert_eq!(result.paid, 2); // c1 and c3
        assert_eq!(result.left_pending, 1); // c2
    }

    // --- CompensationProtocol: rate limiting ---

    #[test]
    fn test_protocol_rate_limit_blocks_auto_approve() {
        let policy = CompensationPolicy::default().with_rate_limit(2, 3_600_000);
        let mut proto = CompensationProtocol::new(policy);

        // First two should auto-approve.
        let c1 = proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert!(c1.auto_approved);
        let c2 = proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert!(c2.auto_approved);
        // Third should be rate-limited.
        let c3 = proto
            .request_compensation_with_id(
                "c3",
                "t3",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert!(!c3.auto_approved);
        assert_eq!(c3.status, CompensationStatus::Pending);
    }

    #[test]
    fn test_protocol_rate_limit_window_expires() {
        let policy = CompensationPolicy::default().with_rate_limit(1, 1000);
        let mut proto = CompensationProtocol::new(policy);

        let c1 = proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert!(c1.auto_approved);
        // Within window — blocked.
        let c2 = proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                1500,
            )
            .unwrap();
        assert!(!c2.auto_approved);
        // Outside window — allowed.
        let c3 = proto
            .request_compensation_with_id(
                "c3",
                "t3",
                "a1",
                5_000,
                CompensationReason::TaskFailure,
                3000,
            )
            .unwrap();
        assert!(c3.auto_approved);
    }

    // --- CompensationProtocol: queries ---

    #[test]
    fn test_protocol_for_agent() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a1",
                30_000,
                CompensationReason::Timeout,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c3",
                "t3",
                "a2",
                20_000,
                CompensationReason::Overcharge,
                1000,
            )
            .unwrap();

        let a1_comps = proto.for_agent("a1");
        assert_eq!(a1_comps.len(), 2);
        let a2_comps = proto.for_agent("a2");
        assert_eq!(a2_comps.len(), 1);
    }

    #[test]
    fn test_protocol_for_task() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "task-1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c2",
                "task-1",
                "a2",
                30_000,
                CompensationReason::Timeout,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c3",
                "task-2",
                "a3",
                20_000,
                CompensationReason::Overcharge,
                1000,
            )
            .unwrap();

        let task1_comps = proto.for_task("task-1");
        assert_eq!(task1_comps.len(), 2);
    }

    #[test]
    fn test_protocol_by_status() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a2",
                5_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap(); // auto-approved
        proto.reject_compensation("c1", "no").unwrap();

        assert_eq!(proto.by_status(CompensationStatus::Rejected).len(), 1);
        assert_eq!(proto.by_status(CompensationStatus::Approved).len(), 1);
        assert_eq!(proto.by_status(CompensationStatus::Pending).len(), 0);
    }

    #[test]
    fn test_protocol_total_paid() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto
            .request_compensation_with_id(
                "c2",
                "t2",
                "a2",
                30_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        proto.approve_compensation("c1").unwrap();
        proto.process_payment("c1", 2000).unwrap();

        assert_eq!(proto.total_paid_milli(), 50_000);
        assert_eq!(proto.total_pending_milli(), 30_000);
    }

    // --- CompensationProtocol: misc ---

    #[test]
    fn test_protocol_len_and_is_empty() {
        let mut proto = CompensationProtocol::with_defaults();
        assert!(proto.is_empty());
        proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        assert_eq!(proto.len(), 1);
        assert!(!proto.is_empty());
    }

    #[test]
    fn test_protocol_remove() {
        let mut proto = CompensationProtocol::with_defaults();
        let comp = proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        assert!(proto.remove(&comp.id).is_some());
        assert!(proto.get(&comp.id).is_none());
        assert!(proto.is_empty());
    }

    #[test]
    fn test_protocol_clear() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation("t1", "a1", 50_000, CompensationReason::TaskFailure, 1000)
            .unwrap();
        proto
            .request_compensation("t2", "a2", 30_000, CompensationReason::Timeout, 1000)
            .unwrap();
        proto.clear();
        assert!(proto.is_empty());
    }

    #[test]
    fn test_protocol_evict_expired() {
        let policy = CompensationPolicy::default().with_rate_limit(100, 1000);
        let mut proto = CompensationProtocol::new(policy);

        // Generate some auto-approvals.
        for i in 0..5 {
            proto
                .request_compensation_with_id(
                    &format!("c{i}"),
                    "t1",
                    "a1",
                    5_000,
                    CompensationReason::TaskFailure,
                    1000,
                )
                .unwrap();
        }
        // Evict timestamps older than 1000ms window.
        proto.evict_expired(3000);
        // History should be empty (all timestamps at 1000, window ends at 2000).
        assert_eq!(proto.count_recent_auto_approvals("a1", 3000), 0);
    }

    #[test]
    fn test_protocol_request_with_id_duplicate() {
        let mut proto = CompensationProtocol::with_defaults();
        proto
            .request_compensation_with_id(
                "c1",
                "t1",
                "a1",
                50_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap();
        assert!(proto
            .request_compensation_with_id(
                "c1",
                "t2",
                "a2",
                30_000,
                CompensationReason::Timeout,
                1000
            )
            .is_err());
    }

    // --- Full lifecycle integration test ---

    #[test]
    fn test_protocol_full_lifecycle() {
        let mut proto = CompensationProtocol::with_defaults();
        proto.set_account(ResourceAccount::with_defaults());

        // Debit agent.
        if let Some(acct) = proto.account_mut() {
            acct.debit("a1", &usage(500, 50, 10, 5, 2, 100)).unwrap();
        }

        // Request compensation (over threshold → pending).
        let comp = proto
            .request_compensation_with_id(
                "c1",
                "task-1",
                "a1",
                100_000,
                CompensationReason::TaskFailure,
                1000,
            )
            .unwrap()
            .with_resource_credit(usage(500, 50, 10, 5, 2, 100));
        // Update stored copy with resource_credit.
        if let Some(stored) = proto.compensations.get_mut("c1") {
            stored.resource_credit = Some(usage(500, 50, 10, 5, 2, 100));
        }
        assert_eq!(comp.status, CompensationStatus::Pending);

        // Dispute it.
        proto
            .dispute_compensation("c1", "a1", "task failed completely", 2000)
            .unwrap();
        assert_eq!(
            proto.get("c1").unwrap().status,
            CompensationStatus::Disputed
        );

        // Assign arbiter.
        proto.assign_arbiter("c1", "arbiter-1").unwrap();

        // Arbiter approves.
        proto
            .resolve_dispute("c1", true, "evidence supports full refund")
            .unwrap();
        assert_eq!(
            proto.get("c1").unwrap().status,
            CompensationStatus::Approved
        );

        // Process payment.
        proto.process_payment("c1", 3000).unwrap();
        assert_eq!(proto.get("c1").unwrap().status, CompensationStatus::Paid);

        // Verify account was credited.
        let balance = proto.account().unwrap().balance("a1");
        assert_eq!(balance.cpu_ms, 0); // fully refunded
        assert_eq!(balance.inference_tokens, 0);
    }
}
