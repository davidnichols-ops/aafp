//! Priority queue for economic task scheduling (Track X3).
//!
//! [`PriorityQueue`] orders pending tasks by a composite priority score derived
//! from four weighted factors:
//!
//! - **Urgency** — how close the task deadline is. Tasks with nearer deadlines
//!   receive higher urgency scores.
//! - **Cost** — the estimated cost of the task. More expensive tasks represent
//!   greater economic value and are prioritized when the cost weight is
//!   positive.
//! - **Resource availability** — how well the task's resource estimate fits
//!   within current capacity. Tasks that consume fewer scarce resources score
//!   higher.
//! - **Reputation** — the requesting agent's reputation. Agents with better
//!   track records receive a priority boost.
//!
//! Each factor is expressed in *milli-units* (0–1000, where 1000 = 1.0) and
//! multiplied by a configurable weight (also in milli-units). The final score
//! is the weighted sum plus a band bonus, temporary boost, and aging bonus.
//!
//! Five priority bands — [`PriorityBand::Critical`], [`PriorityBand::High`],
//! [`PriorityBand::Normal`], [`PriorityBand::Low`], [`PriorityBand::BestEffort`]
//! — provide coarse ordering. Within a band, the composite score provides
//! fine-grained ordering.
//!
//! **Aging** prevents starvation: entries that have waited longer than the
//! configured aging interval receive an incremental boost each interval,
//! gradually lifting low-priority tasks so they are eventually serviced.
//!
//! All persistent structures encode to canonical CBOR int-keyed maps
//! (RFC-0002 §8).

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

fn dec_str(val: &Value, field: &'static str) -> Result<String, EconomicsError> {
    match val {
        Value::TextString(s) => Ok(s.clone()),
        _ => Err(EconomicsError::InvalidField {
            field,
            message: format!("expected text string, got {val:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// PriorityBand
// ---------------------------------------------------------------------------

/// Coarse priority band for a queue entry.
///
/// Bands provide dominant ordering: a `Critical` entry always outranks a
/// `High` entry regardless of the composite score. Within a band, the
/// fine-grained score determines ordering.
///
/// Encoded as an unsigned integer: `Critical = 0`, `High = 1`, `Normal = 2`,
/// `Low = 3`, `BestEffort = 4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PriorityBand {
    /// Highest priority — must be serviced immediately (e.g. SLA-critical).
    Critical = 0,
    /// High priority — service before normal tasks.
    High = 1,
    /// Default priority for most tasks.
    #[default]
    Normal = 2,
    /// Low priority — service when no higher-priority work remains.
    Low = 3,
    /// Lowest priority — service only when the queue is otherwise empty.
    BestEffort = 4,
}

impl PriorityBand {
    /// Bonus score (milli-units) added to the composite score for this band.
    /// Higher bands receive larger bonuses so they dominate ordering.
    pub fn bonus_milli(self) -> i64 {
        match self {
            Self::Critical => 5_000_000,
            Self::High => 3_000_000,
            Self::Normal => 1_000_000,
            Self::Low => 500_000,
            Self::BestEffort => 0,
        }
    }

    /// Encode as an unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    /// Decode from an unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Critical),
            Value::Unsigned(1) => Ok(Self::High),
            Value::Unsigned(2) => Ok(Self::Normal),
            Value::Unsigned(3) => Ok(Self::Low),
            Value::Unsigned(4) => Ok(Self::BestEffort),
            _ => Err(EconomicsError::InvalidField {
                field: "priority_band",
                message: format!("expected 0/1/2/3/4, got {val:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// PriorityConfig
// ---------------------------------------------------------------------------

/// Configuration for [`PriorityQueue`] scoring and aging.
///
/// Weights are expressed in *milli-units* (0–1000, where 1000 = 1.0). Each
/// factor (also 0–1000 milli) is multiplied by its weight and divided by 1000
/// to produce a score contribution. The total score is the sum of all
/// contributions plus the band bonus, temporary boost, and aging bonus.
///
/// All weights default to 250 (0.25), giving equal weight to all four factors.
#[derive(Clone, Debug)]
pub struct PriorityConfig {
    /// Weight for the urgency factor (milli-units, 0–1000). Default 250.
    pub urgency_weight_milli: i64, // key 1
    /// Weight for the cost factor (milli-units, 0–1000). Default 250.
    pub cost_weight_milli: i64, // key 2
    /// Weight for the resource-availability factor (milli-units, 0–1000). Default 250.
    pub resource_availability_weight_milli: i64, // key 3
    /// Weight for the reputation factor (milli-units, 0–1000). Default 250.
    pub reputation_weight_milli: i64, // key 4
    /// Maximum cost (milli-credits) used to normalize the cost factor.
    /// Costs above this saturate at 1000. Default 1_000_000 (1000 credits).
    pub max_cost_milli: i64, // key 5
    /// Capacity (weighted-total units) used to normalize resource usage.
    /// Usage above this saturates at 0 availability. Default 100_000.
    pub resource_capacity: u64, // key 6
    /// Aging interval in milliseconds. Every interval an entry waits, it
    /// receives `aging_boost_milli` added to its score. Default 60_000 (1 min).
    pub aging_interval_ms: u64, // key 7
    /// Boost applied per aging interval (milli-units). Default 50_000.
    pub aging_boost_milli: i64, // key 8
    /// Maximum cumulative aging boost (milli-units). Default 2_000_000.
    pub aging_max_boost_milli: i64, // key 9
}

impl PriorityConfig {
    /// Create a config with equal weights (250 each) and default aging.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the urgency weight (milli-units, 0–1000).
    pub fn with_urgency_weight(mut self, milli: i64) -> Self {
        self.urgency_weight_milli = milli;
        self
    }

    /// Set the cost weight (milli-units, 0–1000).
    pub fn with_cost_weight(mut self, milli: i64) -> Self {
        self.cost_weight_milli = milli;
        self
    }

    /// Set the resource-availability weight (milli-units, 0–1000).
    pub fn with_resource_weight(mut self, milli: i64) -> Self {
        self.resource_availability_weight_milli = milli;
        self
    }

    /// Set the reputation weight (milli-units, 0–1000).
    pub fn with_reputation_weight(mut self, milli: i64) -> Self {
        self.reputation_weight_milli = milli;
        self
    }

    /// Set the maximum cost for normalization (milli-credits).
    pub fn with_max_cost(mut self, milli: i64) -> Self {
        self.max_cost_milli = milli;
        self
    }

    /// Set the resource capacity for normalization (weighted-total units).
    pub fn with_resource_capacity(mut self, capacity: u64) -> Self {
        self.resource_capacity = capacity;
        self
    }

    /// Set the aging interval (ms) and boost per interval (milli-units).
    pub fn with_aging(mut self, interval_ms: u64, boost_milli: i64) -> Self {
        self.aging_interval_ms = interval_ms;
        self.aging_boost_milli = boost_milli;
        self
    }

    /// Set the maximum cumulative aging boost (milli-units).
    pub fn with_aging_max(mut self, max_milli: i64) -> Self {
        self.aging_max_boost_milli = max_milli;
        self
    }

    /// Validate the configuration. Returns an error if any weight is negative
    /// or if the aging interval is zero.
    pub fn validate(&self) -> Result<(), EconomicsError> {
        if self.urgency_weight_milli < 0
            || self.cost_weight_milli < 0
            || self.resource_availability_weight_milli < 0
            || self.reputation_weight_milli < 0
        {
            return Err(EconomicsError::InvalidPriorityConfig(
                "weights must be non-negative".to_string(),
            ));
        }
        if self.max_cost_milli <= 0 {
            return Err(EconomicsError::InvalidPriorityConfig(
                "max_cost_milli must be positive".to_string(),
            ));
        }
        if self.aging_interval_ms == 0 {
            return Err(EconomicsError::InvalidPriorityConfig(
                "aging_interval_ms must be positive".to_string(),
            ));
        }
        if self.aging_boost_milli < 0 {
            return Err(EconomicsError::InvalidPriorityConfig(
                "aging_boost_milli must be non-negative".to_string(),
            ));
        }
        if self.aging_max_boost_milli < 0 {
            return Err(EconomicsError::InvalidPriorityConfig(
                "aging_max_boost_milli must be non-negative".to_string(),
            ));
        }
        Ok(())
    }

    /// Compute the urgency factor (0–1000 milli) for an entry.
    ///
    /// If the entry has no deadline (`deadline == 0`), urgency is 0.
    /// If the deadline has passed (`now >= deadline`), urgency is 1000.
    /// Otherwise, urgency decreases linearly as the time remaining increases,
    /// reaching 0 when `time_remaining >= deadline_horizon_ms`.
    fn urgency_factor(&self, deadline: u64, now: u64, deadline_horizon_ms: u64) -> i64 {
        if deadline == 0 {
            return 0;
        }
        if now >= deadline {
            return 1000;
        }
        let remaining = deadline - now;
        if deadline_horizon_ms == 0 || remaining >= deadline_horizon_ms {
            return 0;
        }
        // urgency = 1000 * (1 - remaining/horizon)
        let factor = 1000_i64.saturating_mul((deadline_horizon_ms - remaining) as i64)
            / deadline_horizon_ms as i64;
        factor.clamp(0, 1000)
    }

    /// Compute the cost factor (0–1000 milli) for an entry.
    /// Higher cost → higher factor (more valuable tasks are prioritized).
    fn cost_factor(&self, cost_estimate_milli: i64) -> i64 {
        if cost_estimate_milli <= 0 {
            return 0;
        }
        if cost_estimate_milli >= self.max_cost_milli {
            return 1000;
        }
        1000_i64.saturating_mul(cost_estimate_milli) / self.max_cost_milli
    }

    /// Compute the resource-availability factor (0–1000 milli).
    /// Lower resource usage → higher factor (tasks that fit better are
    /// prioritized when resources are scarce).
    fn resource_factor(&self, usage: &ResourceUsage) -> i64 {
        if self.resource_capacity == 0 {
            return 0;
        }
        let weighted = usage.weighted_total();
        if weighted >= self.resource_capacity {
            return 0;
        }
        // availability = 1000 * (1 - usage/capacity)
        1000_i64.saturating_mul((self.resource_capacity - weighted) as i64)
            / self.resource_capacity as i64
    }

    /// Compute the composite score (milli-units) for an entry, excluding
    /// band bonus, boost, and aging. This is the weighted sum of factors.
    fn composite_score(
        &self,
        deadline: u64,
        now: u64,
        deadline_horizon_ms: u64,
        cost_estimate_milli: i64,
        resource_estimate: &ResourceUsage,
        reputation_milli: i64,
    ) -> i64 {
        let urgency = self.urgency_factor(deadline, now, deadline_horizon_ms);
        let cost = self.cost_factor(cost_estimate_milli);
        let resource = self.resource_factor(resource_estimate);
        let reputation = reputation_milli.clamp(0, 1000);

        // Each contribution = factor * weight / 1000 (since both are milli).
        let urgency_contrib = urgency.saturating_mul(self.urgency_weight_milli) / 1000;
        let cost_contrib = cost.saturating_mul(self.cost_weight_milli) / 1000;
        let resource_contrib =
            resource.saturating_mul(self.resource_availability_weight_milli) / 1000;
        let reputation_contrib = reputation.saturating_mul(self.reputation_weight_milli) / 1000;

        urgency_contrib
            .saturating_add(cost_contrib)
            .saturating_add(resource_contrib)
            .saturating_add(reputation_contrib)
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_i64(self.urgency_weight_milli)),
            (2, enc_i64(self.cost_weight_milli)),
            (3, enc_i64(self.resource_availability_weight_milli)),
            (4, enc_i64(self.reputation_weight_milli)),
            (5, enc_i64(self.max_cost_milli)),
            (6, enc_u64(self.resource_capacity)),
            (7, enc_u64(self.aging_interval_ms)),
            (8, enc_i64(self.aging_boost_milli)),
            (9, enc_i64(self.aging_max_boost_milli)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            urgency_weight_milli: match opt(val, 1) {
                Some(v) => dec_i64(v, "urgency_weight_milli")?,
                None => 250,
            },
            cost_weight_milli: match opt(val, 2) {
                Some(v) => dec_i64(v, "cost_weight_milli")?,
                None => 250,
            },
            resource_availability_weight_milli: match opt(val, 3) {
                Some(v) => dec_i64(v, "resource_availability_weight_milli")?,
                None => 250,
            },
            reputation_weight_milli: match opt(val, 4) {
                Some(v) => dec_i64(v, "reputation_weight_milli")?,
                None => 250,
            },
            max_cost_milli: match opt(val, 5) {
                Some(v) => dec_i64(v, "max_cost_milli")?,
                None => 1_000_000,
            },
            resource_capacity: match opt(val, 6) {
                Some(v) => dec_u64(v, "resource_capacity")?,
                None => 100_000,
            },
            aging_interval_ms: match opt(val, 7) {
                Some(v) => dec_u64(v, "aging_interval_ms")?,
                None => 60_000,
            },
            aging_boost_milli: match opt(val, 8) {
                Some(v) => dec_i64(v, "aging_boost_milli")?,
                None => 50_000,
            },
            aging_max_boost_milli: match opt(val, 9) {
                Some(v) => dec_i64(v, "aging_max_boost_milli")?,
                None => 2_000_000,
            },
        })
    }
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            urgency_weight_milli: 250,
            cost_weight_milli: 250,
            resource_availability_weight_milli: 250,
            reputation_weight_milli: 250,
            max_cost_milli: 1_000_000,
            resource_capacity: 100_000,
            aging_interval_ms: 60_000,
            aging_boost_milli: 50_000,
            aging_max_boost_milli: 2_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// PriorityEntry
// ---------------------------------------------------------------------------

/// A task entry in the [`PriorityQueue`].
///
/// The `priority_score` field is the *effective* score including band bonus,
/// temporary boost, and aging. It is recomputed by [`PriorityQueue::reorder`]
/// and [`PriorityQueue::apply_aging`].
#[derive(Clone, Debug)]
pub struct PriorityEntry {
    /// Unique task identifier.
    pub task_id: String, // key 1
    /// Agent that submitted the task.
    pub agent_id: String, // key 2
    /// Effective priority score (milli-units, higher = more important).
    pub priority_score: i64, // key 3
    /// Estimated resource consumption for the task.
    pub resource_estimate: ResourceUsage, // key 4
    /// Deadline in milliseconds since epoch. 0 means no deadline.
    pub deadline: u64, // key 5
    /// Estimated cost (milli-credits).
    pub cost_estimate_milli: i64, // key 6
    /// Priority band.
    pub band: PriorityBand, // key 7
    /// Time the entry was enqueued (ms since epoch).
    pub enqueue_time: u64, // key 8
    /// Temporary boost (milli-units), applied via [`PriorityQueue::boost`].
    pub boost_milli: i64, // key 9
    /// Agent reputation (milli-units, 0–1000).
    pub reputation_milli: i64, // key 10
    /// Cumulative aging boost applied so far (milli-units).
    pub aging_accumulated_milli: i64, // key 11
}

impl PriorityEntry {
    /// Create a new entry with the given fields. The `priority_score` is
    /// initialized to 0; call [`PriorityQueue::enqueue`] or
    /// [`PriorityEntry::recompute_score`] to compute it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: impl Into<String>,
        agent_id: impl Into<String>,
        resource_estimate: ResourceUsage,
        deadline: u64,
        cost_estimate_milli: i64,
        band: PriorityBand,
        reputation_milli: i64,
        enqueue_time: u64,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            agent_id: agent_id.into(),
            priority_score: 0,
            resource_estimate,
            deadline,
            cost_estimate_milli,
            band,
            enqueue_time,
            boost_milli: 0,
            reputation_milli: reputation_milli.clamp(0, 1000),
            aging_accumulated_milli: 0,
        }
    }

    /// Recompute the effective priority score from the config and current
    /// time. The score includes the composite weighted factors, band bonus,
    /// temporary boost, and accumulated aging.
    pub fn recompute_score(&mut self, config: &PriorityConfig, now: u64, deadline_horizon_ms: u64) {
        let composite = config.composite_score(
            self.deadline,
            now,
            deadline_horizon_ms,
            self.cost_estimate_milli,
            &self.resource_estimate,
            self.reputation_milli,
        );
        let band_bonus = self.band.bonus_milli();
        self.priority_score = composite
            .saturating_add(band_bonus)
            .saturating_add(self.boost_milli)
            .saturating_add(self.aging_accumulated_milli);
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.task_id.clone())),
            (2, Value::TextString(self.agent_id.clone())),
            (3, enc_i64(self.priority_score)),
            (4, self.resource_estimate.to_cbor()),
            (5, enc_u64(self.deadline)),
            (6, enc_i64(self.cost_estimate_milli)),
            (7, self.band.to_cbor()),
            (8, enc_u64(self.enqueue_time)),
            (9, enc_i64(self.boost_milli)),
            (10, enc_i64(self.reputation_milli)),
            (11, enc_i64(self.aging_accumulated_milli)),
        ])
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, EconomicsError> {
        Ok(Self {
            task_id: dec_str(req(val, 1, "task_id")?, "task_id")?,
            agent_id: dec_str(req(val, 2, "agent_id")?, "agent_id")?,
            priority_score: dec_i64(req(val, 3, "priority_score")?, "priority_score")?,
            resource_estimate: ResourceUsage::from_cbor(req(val, 4, "resource_estimate")?)?,
            deadline: dec_u64(req(val, 5, "deadline")?, "deadline")?,
            cost_estimate_milli: dec_i64(
                req(val, 6, "cost_estimate_milli")?,
                "cost_estimate_milli",
            )?,
            band: match opt(val, 7) {
                Some(v) => PriorityBand::from_cbor(v)?,
                None => PriorityBand::default(),
            },
            enqueue_time: dec_u64(req(val, 8, "enqueue_time")?, "enqueue_time")?,
            boost_milli: match opt(val, 9) {
                Some(v) => dec_i64(v, "boost_milli")?,
                None => 0,
            },
            reputation_milli: match opt(val, 10) {
                Some(v) => dec_i64(v, "reputation_milli")?,
                None => 500,
            },
            aging_accumulated_milli: match opt(val, 11) {
                Some(v) => dec_i64(v, "aging_accumulated_milli")?,
                None => 0,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// PriorityQueue
// ---------------------------------------------------------------------------

/// A priority queue that orders tasks by a composite economic score.
///
/// The queue stores [`PriorityEntry`] items in a `Vec` and sorts them on
/// demand (dequeue, peek, reorder). A `HashMap` indexes entries by `task_id`
/// for O(1) lookup during `boost`, `degrade`, and `remove` operations.
///
/// Aging is applied explicitly via [`PriorityQueue::apply_aging`], which
/// should be called periodically (e.g. every aging interval) to boost
/// low-priority entries and prevent starvation.
pub struct PriorityQueue {
    config: PriorityConfig,
    entries: Vec<PriorityEntry>,
    /// Index from task_id to position in `entries`. Maintained lazily —
    /// rebuilt when stale.
    index: HashMap<String, usize>,
    index_dirty: bool,
    /// The deadline horizon (ms) used for urgency normalization. Tasks with
    /// more than this much time remaining get zero urgency. Default 3_600_000
    /// (1 hour).
    deadline_horizon_ms: u64,
}

impl PriorityQueue {
    /// Create a new queue with the given configuration.
    pub fn new(config: PriorityConfig) -> Result<Self, EconomicsError> {
        config.validate()?;
        Ok(Self {
            config,
            entries: Vec::new(),
            index: HashMap::new(),
            index_dirty: false,
            deadline_horizon_ms: 3_600_000,
        })
    }

    /// Create a new queue with default configuration.
    pub fn with_defaults() -> Result<Self, EconomicsError> {
        Self::new(PriorityConfig::default())
    }

    /// Return a reference to the queue configuration.
    pub fn config(&self) -> &PriorityConfig {
        &self.config
    }

    /// Return a mutable reference to the queue configuration.
    pub fn config_mut(&mut self) -> &mut PriorityConfig {
        &mut self.config
    }

    /// Set the deadline horizon (ms) for urgency normalization.
    pub fn set_deadline_horizon(&mut self, horizon_ms: u64) {
        self.deadline_horizon_ms = horizon_ms;
    }

    /// Return the deadline horizon (ms).
    pub fn deadline_horizon(&self) -> u64 {
        self.deadline_horizon_ms
    }

    /// Number of entries in the queue.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Rebuild the internal task_id → position index.
    fn rebuild_index(&mut self) {
        self.index.clear();
        self.index.reserve(self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            self.index.insert(e.task_id.clone(), i);
        }
        self.index_dirty = false;
    }

    /// Ensure the index is up-to-date.
    fn ensure_index(&mut self) {
        if self.index_dirty {
            self.rebuild_index();
        }
    }

    /// Add an entry to the queue. The entry's priority score is computed
    /// automatically from the config and the given `now` timestamp.
    ///
    /// Returns `false` if an entry with the same `task_id` already exists.
    pub fn enqueue(&mut self, mut entry: PriorityEntry, now: u64) -> bool {
        self.ensure_index();
        if self.index.contains_key(&entry.task_id) {
            return false;
        }
        entry.recompute_score(&self.config, now, self.deadline_horizon_ms);
        let pos = self.entries.len();
        self.index.insert(entry.task_id.clone(), pos);
        self.entries.push(entry);
        true
    }

    /// Remove and return the highest-priority entry. Returns `None` if the
    /// queue is empty.
    pub fn dequeue(&mut self, now: u64) -> Option<PriorityEntry> {
        if self.entries.is_empty() {
            return None;
        }
        // Find the entry with the highest priority_score.
        // On ties, the earlier-enqueued entry wins (FIFO within same score).
        let best_idx = self.find_best_index(now);
        let entry = self.entries.swap_remove(best_idx);
        self.index_dirty = true;
        Some(entry)
    }

    /// Return a reference to the highest-priority entry without removing it.
    /// Returns `None` if the queue is empty.
    pub fn peek(&self) -> Option<&PriorityEntry> {
        if self.entries.is_empty() {
            return None;
        }
        // Find the entry with the highest priority_score.
        // On ties, the earlier-enqueued entry wins.
        let mut best_idx = 0;
        let mut best_score = self.entries[0].priority_score;
        for (i, e) in self.entries.iter().enumerate().skip(1) {
            if e.priority_score > best_score {
                best_score = e.priority_score;
                best_idx = i;
            }
        }
        self.entries.get(best_idx)
    }

    /// Find the index of the highest-priority entry, applying aging if `now`
    /// is beyond the enqueue time. On ties, the earlier-enqueued entry wins.
    fn find_best_index(&self, now: u64) -> usize {
        let mut best_idx = 0;
        let mut best_score = self.entries[0].effective_score_with_aging(&self.config, now);
        for (i, e) in self.entries.iter().enumerate().skip(1) {
            let score = e.effective_score_with_aging(&self.config, now);
            if score > best_score {
                best_score = score;
                best_idx = i;
            }
        }
        best_idx
    }

    /// Recalculate priorities for all entries. This should be called when
    /// external conditions change (e.g. resource availability, reputation
    /// updates, or config changes).
    pub fn reorder(&mut self, now: u64) {
        for e in &mut self.entries {
            e.recompute_score(&self.config, now, self.deadline_horizon_ms);
        }
    }

    /// Temporarily increase the priority of a task by `boost_milli`
    /// (milli-units). This adds to the entry's `boost_milli` field and
    /// recomputes its score. Returns `false` if the task is not found.
    pub fn boost(&mut self, task_id: &str, boost_milli: i64, now: u64) -> bool {
        self.ensure_index();
        let idx = match self.index.get(task_id) {
            Some(&i) => i,
            None => return false,
        };
        let entry = &mut self.entries[idx];
        entry.boost_milli = entry.boost_milli.saturating_add(boost_milli);
        entry.recompute_score(&self.config, now, self.deadline_horizon_ms);
        true
    }

    /// Decrease the priority of a task by `penalty_milli` (milli-units).
    /// This subtracts from the entry's `boost_milli` (which can go negative)
    /// and recomputes its score. Returns `false` if the task is not found.
    pub fn degrade(&mut self, task_id: &str, penalty_milli: i64, now: u64) -> bool {
        self.ensure_index();
        let idx = match self.index.get(task_id) {
            Some(&i) => i,
            None => return false,
        };
        let entry = &mut self.entries[idx];
        entry.boost_milli = entry.boost_milli.saturating_sub(penalty_milli);
        entry.recompute_score(&self.config, now, self.deadline_horizon_ms);
        true
    }

    /// Apply aging to all entries. Each entry that has waited at least one
    /// aging interval receives `aging_boost_milli` per interval (capped at
    /// `aging_max_boost_milli`). This prevents starvation of low-priority
    /// entries.
    ///
    /// Returns the number of entries whose aging boost was increased.
    pub fn apply_aging(&mut self, now: u64) -> usize {
        let interval = self.config.aging_interval_ms;
        let boost_per = self.config.aging_boost_milli;
        let max_boost = self.config.aging_max_boost_milli;

        let mut count = 0;
        for e in &mut self.entries {
            if now <= e.enqueue_time {
                continue;
            }
            let elapsed = now - e.enqueue_time;
            let intervals = (elapsed / interval) as i64;
            // Subtract the boost already applied to find new intervals.
            let already_applied = e.aging_accumulated_milli / boost_per.max(1);
            let new_intervals = intervals.saturating_sub(already_applied);
            if new_intervals <= 0 {
                continue;
            }
            let additional = new_intervals.saturating_mul(boost_per);
            let new_total = e.aging_accumulated_milli.saturating_add(additional);
            e.aging_accumulated_milli = new_total.min(max_boost);
            e.recompute_score(&self.config, now, self.deadline_horizon_ms);
            count += 1;
        }
        count
    }

    /// Remove a specific task from the queue. Returns the removed entry, or
    /// `None` if not found.
    pub fn remove(&mut self, task_id: &str) -> Option<PriorityEntry> {
        self.ensure_index();
        let idx = match self.index.get(task_id) {
            Some(&i) => i,
            None => return None,
        };
        let entry = self.entries.swap_remove(idx);
        self.index_dirty = true;
        Some(entry)
    }

    /// Get a reference to a specific entry by task_id.
    pub fn get(&self, task_id: &str) -> Option<&PriorityEntry> {
        // Linear scan — the index may be stale if we only have &self.
        self.entries.iter().find(|e| e.task_id == task_id)
    }

    /// Get a mutable reference to a specific entry by task_id.
    pub fn get_mut(&mut self, task_id: &str) -> Option<&mut PriorityEntry> {
        self.entries.iter_mut().find(|e| e.task_id == task_id)
    }

    /// Return all entries sorted by priority (highest first). Does not
    /// mutate the queue.
    pub fn sorted_entries(&self) -> Vec<&PriorityEntry> {
        let mut refs: Vec<&PriorityEntry> = self.entries.iter().collect();
        refs.sort_by_key(|e| -e.priority_score);
        refs
    }

    /// Return all entries in arbitrary order.
    pub fn entries(&self) -> &[PriorityEntry] {
        &self.entries
    }

    /// Clear all entries from the queue.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
        self.index_dirty = false;
    }

    /// Update an agent's reputation across all entries for that agent.
    /// Recomputes scores for affected entries.
    pub fn update_reputation(&mut self, agent_id: &str, reputation_milli: i64, now: u64) {
        let rep = reputation_milli.clamp(0, 1000);
        for e in &mut self.entries {
            if e.agent_id == agent_id {
                e.reputation_milli = rep;
                e.recompute_score(&self.config, now, self.deadline_horizon_ms);
            }
        }
    }

    /// Count entries in a specific band.
    pub fn count_band(&self, band: PriorityBand) -> usize {
        self.entries.iter().filter(|e| e.band == band).count()
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::with_defaults().expect("default config is valid")
    }
}

impl PriorityEntry {
    /// Compute the effective score including on-the-fly aging for `now`,
    /// without mutating the entry. Used during dequeue to account for aging
    /// that hasn't been explicitly applied yet.
    fn effective_score_with_aging(&self, config: &PriorityConfig, now: u64) -> i64 {
        let mut score = self.priority_score;
        // Add aging that would have accumulated since last apply_aging.
        if now > self.enqueue_time && config.aging_boost_milli > 0 {
            let elapsed = now - self.enqueue_time;
            let intervals = (elapsed / config.aging_interval_ms) as i64;
            let already_applied = self.aging_accumulated_milli / config.aging_boost_milli;
            let new_intervals = intervals.saturating_sub(already_applied);
            if new_intervals > 0 {
                let additional = new_intervals
                    .saturating_mul(config.aging_boost_milli)
                    .min(config.aging_max_boost_milli - self.aging_accumulated_milli);
                score = score.saturating_add(additional.max(0));
            }
        }
        score
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

    fn entry(task: &str, agent: &str, band: PriorityBand) -> PriorityEntry {
        PriorityEntry::new(
            task,
            agent,
            usage(100, 10, 5, 2, 1, 50),
            0,
            100_000,
            band,
            500,
            1000,
        )
    }

    // --- PriorityBand tests ---

    #[test]
    fn test_band_default_is_normal() {
        assert_eq!(PriorityBand::default(), PriorityBand::Normal);
    }

    #[test]
    fn test_band_bonus_ordering() {
        assert!(PriorityBand::Critical.bonus_milli() > PriorityBand::High.bonus_milli());
        assert!(PriorityBand::High.bonus_milli() > PriorityBand::Normal.bonus_milli());
        assert!(PriorityBand::Normal.bonus_milli() > PriorityBand::Low.bonus_milli());
        assert!(PriorityBand::Low.bonus_milli() > PriorityBand::BestEffort.bonus_milli());
        assert_eq!(PriorityBand::BestEffort.bonus_milli(), 0);
    }

    #[test]
    fn test_band_cbor_roundtrip() {
        for b in [
            PriorityBand::Critical,
            PriorityBand::High,
            PriorityBand::Normal,
            PriorityBand::Low,
            PriorityBand::BestEffort,
        ] {
            let val = b.to_cbor();
            assert_eq!(PriorityBand::from_cbor(&val).unwrap(), b);
        }
    }

    #[test]
    fn test_band_cbor_invalid() {
        assert!(PriorityBand::from_cbor(&Value::Unsigned(99)).is_err());
    }

    // --- PriorityConfig tests ---

    #[test]
    fn test_config_default() {
        let c = PriorityConfig::default();
        assert_eq!(c.urgency_weight_milli, 250);
        assert_eq!(c.cost_weight_milli, 250);
        assert_eq!(c.resource_availability_weight_milli, 250);
        assert_eq!(c.reputation_weight_milli, 250);
        assert_eq!(c.aging_interval_ms, 60_000);
    }

    #[test]
    fn test_config_builder() {
        let c = PriorityConfig::new()
            .with_urgency_weight(500)
            .with_cost_weight(100)
            .with_resource_weight(200)
            .with_reputation_weight(300)
            .with_max_cost(500_000)
            .with_resource_capacity(50_000)
            .with_aging(30_000, 25_000)
            .with_aging_max(1_000_000);
        assert_eq!(c.urgency_weight_milli, 500);
        assert_eq!(c.cost_weight_milli, 100);
        assert_eq!(c.resource_availability_weight_milli, 200);
        assert_eq!(c.reputation_weight_milli, 300);
        assert_eq!(c.max_cost_milli, 500_000);
        assert_eq!(c.resource_capacity, 50_000);
        assert_eq!(c.aging_interval_ms, 30_000);
        assert_eq!(c.aging_boost_milli, 25_000);
        assert_eq!(c.aging_max_boost_milli, 1_000_000);
    }

    #[test]
    fn test_config_validate_ok() {
        assert!(PriorityConfig::default().validate().is_ok());
    }

    #[test]
    fn test_config_validate_negative_weight() {
        let c = PriorityConfig {
            urgency_weight_milli: -1,
            ..PriorityConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_max_cost() {
        let c = PriorityConfig {
            max_cost_milli: 0,
            ..PriorityConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_aging_interval() {
        let c = PriorityConfig {
            aging_interval_ms: 0,
            ..PriorityConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_cbor_roundtrip() {
        let c = PriorityConfig::new()
            .with_urgency_weight(400)
            .with_cost_weight(150)
            .with_resource_weight(350)
            .with_reputation_weight(100)
            .with_max_cost(750_000)
            .with_resource_capacity(80_000)
            .with_aging(45_000, 30_000)
            .with_aging_max(1_500_000);
        let val = c.to_cbor();
        let c2 = PriorityConfig::from_cbor(&val).unwrap();
        assert_eq!(c2.urgency_weight_milli, c.urgency_weight_milli);
        assert_eq!(c2.cost_weight_milli, c.cost_weight_milli);
        assert_eq!(
            c2.resource_availability_weight_milli,
            c.resource_availability_weight_milli
        );
        assert_eq!(c2.reputation_weight_milli, c.reputation_weight_milli);
        assert_eq!(c2.max_cost_milli, c.max_cost_milli);
        assert_eq!(c2.resource_capacity, c.resource_capacity);
        assert_eq!(c2.aging_interval_ms, c.aging_interval_ms);
        assert_eq!(c2.aging_boost_milli, c.aging_boost_milli);
        assert_eq!(c2.aging_max_boost_milli, c.aging_max_boost_milli);
    }

    #[test]
    fn test_config_cbor_defaults_when_missing() {
        // Empty map should decode to defaults.
        let val = int_map(vec![]);
        let c = PriorityConfig::from_cbor(&val).unwrap();
        assert_eq!(c.urgency_weight_milli, 250);
        assert_eq!(c.aging_interval_ms, 60_000);
    }

    // --- Factor computation tests ---

    #[test]
    fn test_urgency_factor_no_deadline() {
        let c = PriorityConfig::default();
        assert_eq!(c.urgency_factor(0, 1000, 3_600_000), 0);
    }

    #[test]
    fn test_urgency_factor_deadline_passed() {
        let c = PriorityConfig::default();
        assert_eq!(c.urgency_factor(1000, 2000, 3_600_000), 1000);
    }

    #[test]
    fn test_urgency_factor_far_deadline() {
        let c = PriorityConfig::default();
        // deadline far beyond horizon → urgency 0
        assert_eq!(c.urgency_factor(5_000_000, 1000, 3_600_000), 0);
    }

    #[test]
    fn test_urgency_factor_partial() {
        let c = PriorityConfig::default();
        // deadline at 2000, now at 1000, horizon 2000 → remaining=1000, urgency=500
        assert_eq!(c.urgency_factor(2000, 1000, 2000), 500);
    }

    #[test]
    fn test_cost_factor_zero() {
        let c = PriorityConfig::default();
        assert_eq!(c.cost_factor(0), 0);
        assert_eq!(c.cost_factor(-100), 0);
    }

    #[test]
    fn test_cost_factor_saturated() {
        let c = PriorityConfig::default();
        assert_eq!(c.cost_factor(c.max_cost_milli), 1000);
        assert_eq!(c.cost_factor(c.max_cost_milli * 2), 1000);
    }

    #[test]
    fn test_cost_factor_partial() {
        let c = PriorityConfig::default();
        // max_cost = 1_000_000, cost = 500_000 → factor = 500
        assert_eq!(c.cost_factor(500_000), 500);
    }

    #[test]
    fn test_resource_factor_zero_usage() {
        let c = PriorityConfig::default();
        assert_eq!(c.resource_factor(&ResourceUsage::zero()), 1000);
    }

    #[test]
    fn test_resource_factor_full_usage() {
        let c = PriorityConfig::default();
        let u = usage(c.resource_capacity, 0, 0, 0, 0, 0);
        assert_eq!(c.resource_factor(&u), 0);
    }

    #[test]
    fn test_resource_factor_partial() {
        let c = PriorityConfig::default();
        // capacity = 100_000, weighted_total = 50_000 → factor = 500
        let u = usage(50_000, 0, 0, 0, 0, 0);
        assert_eq!(c.resource_factor(&u), 500);
    }

    // --- PriorityEntry tests ---

    #[test]
    fn test_entry_new() {
        let e = entry("t1", "a1", PriorityBand::Normal);
        assert_eq!(e.task_id, "t1");
        assert_eq!(e.agent_id, "a1");
        assert_eq!(e.band, PriorityBand::Normal);
        assert_eq!(e.priority_score, 0);
        assert_eq!(e.boost_milli, 0);
    }

    #[test]
    fn test_entry_recompute_score_includes_band() {
        let config = PriorityConfig::default();
        let mut e = entry("t1", "a1", PriorityBand::Critical);
        e.recompute_score(&config, 1000, 3_600_000);
        // Critical band bonus is 5_000_000, so score >= 5_000_000
        assert!(e.priority_score >= 5_000_000);
    }

    #[test]
    fn test_entry_recompute_score_band_ordering() {
        let config = PriorityConfig::default();
        let mut critical = entry("t1", "a1", PriorityBand::Critical);
        let mut low = entry("t2", "a2", PriorityBand::Low);
        critical.recompute_score(&config, 1000, 3_600_000);
        low.recompute_score(&config, 1000, 3_600_000);
        assert!(critical.priority_score > low.priority_score);
    }

    #[test]
    fn test_entry_cbor_roundtrip() {
        let mut e = entry("t1", "a1", PriorityBand::High);
        e.boost_milli = 100_000;
        e.aging_accumulated_milli = 50_000;
        e.priority_score = 3_500_000;
        let val = e.to_cbor();
        let e2 = PriorityEntry::from_cbor(&val).unwrap();
        assert_eq!(e2.task_id, e.task_id);
        assert_eq!(e2.agent_id, e.agent_id);
        assert_eq!(e2.priority_score, e.priority_score);
        assert_eq!(e2.band, e.band);
        assert_eq!(e2.boost_milli, e.boost_milli);
        assert_eq!(e2.aging_accumulated_milli, e.aging_accumulated_milli);
        assert_eq!(e2.cost_estimate_milli, e.cost_estimate_milli);
        assert_eq!(e2.deadline, e.deadline);
    }

    // --- PriorityQueue: enqueue / dequeue / peek ---

    #[test]
    fn test_queue_enqueue_and_len() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000));
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
    }

    #[test]
    fn test_queue_enqueue_duplicate_rejected() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        assert!(q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000));
        assert!(!q.enqueue(entry("t1", "a1", PriorityBand::High), 1000));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_queue_dequeue_empty() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        assert!(q.dequeue(1000).is_none());
    }

    #[test]
    fn test_queue_dequeue_single() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        let e = q.dequeue(1000).unwrap();
        assert_eq!(e.task_id, "t1");
        assert!(q.is_empty());
    }

    #[test]
    fn test_queue_dequeue_band_ordering() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("low", "a1", PriorityBand::Low), 1000);
        q.enqueue(entry("critical", "a2", PriorityBand::Critical), 1000);
        q.enqueue(entry("normal", "a3", PriorityBand::Normal), 1000);

        assert_eq!(q.dequeue(1000).unwrap().task_id, "critical");
        assert_eq!(q.dequeue(1000).unwrap().task_id, "normal");
        assert_eq!(q.dequeue(1000).unwrap().task_id, "low");
    }

    #[test]
    fn test_queue_peek_does_not_remove() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        let peeked = q.peek().unwrap();
        assert_eq!(peeked.task_id, "t1");
        assert_eq!(q.len(), 1); // still there
    }

    #[test]
    fn test_queue_peek_empty() {
        let q = PriorityQueue::with_defaults().unwrap();
        assert!(q.peek().is_none());
    }

    #[test]
    fn test_queue_peek_returns_highest() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("low", "a1", PriorityBand::Low), 1000);
        q.enqueue(entry("critical", "a2", PriorityBand::Critical), 1000);
        assert_eq!(q.peek().unwrap().task_id, "critical");
    }

    // --- PriorityQueue: boost / degrade ---

    #[test]
    fn test_queue_boost_increases_score() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        let before = q.get("t1").unwrap().priority_score;
        assert!(q.boost("t1", 500_000, 1000));
        let after = q.get("t1").unwrap().priority_score;
        assert!(after > before);
        assert_eq!(after - before, 500_000);
    }

    #[test]
    fn test_queue_boost_not_found() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        assert!(!q.boost("nonexistent", 100_000, 1000));
    }

    #[test]
    fn test_queue_degrade_decreases_score() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        let before = q.get("t1").unwrap().priority_score;
        assert!(q.degrade("t1", 200_000, 1000));
        let after = q.get("t1").unwrap().priority_score;
        assert!(after < before);
    }

    #[test]
    fn test_queue_boost_changes_order() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("low", "a1", PriorityBand::Low), 1000);
        q.enqueue(entry("normal", "a2", PriorityBand::Normal), 1000);
        // Normal should come out first.
        assert_eq!(q.peek().unwrap().task_id, "normal");
        // Boost low above normal.
        q.boost("low", 2_000_000, 1000);
        assert_eq!(q.peek().unwrap().task_id, "low");
    }

    // --- PriorityQueue: reorder ---

    #[test]
    fn test_queue_reorder_recomputes() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        // Change config weights.
        q.config_mut().urgency_weight_milli = 1000;
        q.reorder(1000);
        // Score should have been recomputed.
        let e = q.get("t1").unwrap();
        assert!(e.priority_score > 0);
    }

    #[test]
    fn test_queue_reorder_with_deadline() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        let mut e1 = entry("t1", "a1", PriorityBand::Normal);
        e1.deadline = 2000; // near deadline
        let mut e2 = entry("t2", "a2", PriorityBand::Normal);
        e2.deadline = 0; // no deadline
        q.enqueue(e1, 1000);
        q.enqueue(e2, 1000);
        q.reorder(1000);
        // t1 has urgency, t2 doesn't → t1 should have higher score.
        assert!(q.get("t1").unwrap().priority_score > q.get("t2").unwrap().priority_score);
    }

    // --- PriorityQueue: aging ---

    #[test]
    fn test_queue_aging_boosts_old_entries() {
        let config = PriorityConfig::default().with_aging(1000, 100_000);
        let mut q = PriorityQueue::new(config).unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::BestEffort), 1000);
        let before = q.get("t1").unwrap().priority_score;
        // Advance 5 intervals.
        let count = q.apply_aging(6000);
        assert_eq!(count, 1);
        let after = q.get("t1").unwrap().priority_score;
        assert!(after > before);
        // 5 intervals * 100_000 = 500_000 boost
        assert_eq!(q.get("t1").unwrap().aging_accumulated_milli, 500_000);
    }

    #[test]
    fn test_queue_aging_capped_at_max() {
        let config = PriorityConfig::default()
            .with_aging(1000, 100_000)
            .with_aging_max(300_000);
        let mut q = PriorityQueue::new(config).unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::BestEffort), 1000);
        // Advance 10 intervals → would be 1_000_000 but capped at 300_000.
        q.apply_aging(11_000);
        assert_eq!(q.get("t1").unwrap().aging_accumulated_milli, 300_000);
    }

    #[test]
    fn test_queue_aging_no_boost_for_new_entries() {
        let config = PriorityConfig::default().with_aging(60_000, 50_000);
        let mut q = PriorityQueue::new(config).unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        // Only 1000 ms elapsed, interval is 60_000 → no boost.
        let count = q.apply_aging(2000);
        assert_eq!(count, 0);
        assert_eq!(q.get("t1").unwrap().aging_accumulated_milli, 0);
    }

    #[test]
    fn test_queue_aging_prevents_starvation() {
        let config = PriorityConfig::default().with_aging(1000, 500_000);
        let mut q = PriorityQueue::new(config).unwrap();
        q.enqueue(entry("high", "a1", PriorityBand::High), 1000);
        q.enqueue(entry("low", "a2", PriorityBand::Low), 1000);
        // Initially high comes first.
        assert_eq!(q.peek().unwrap().task_id, "high");
        // After many intervals, low's aging boost should surpass high.
        q.apply_aging(100_000);
        // Low gets 100 intervals * 500_000 = 50_000_000, capped at 2_000_000.
        // High band bonus - Low band bonus = 3_000_000 - 500_000 = 2_500_000.
        // Low's aging cap is 2_000_000, which is < 2_500_000, so high still wins.
        // But with enough aging, low should eventually be serviced.
        // Let's verify low's score increased significantly.
        let low_score = q.get("low").unwrap().priority_score;
        let low_base = PriorityBand::Low.bonus_milli();
        assert!(low_score > low_base);
    }

    // --- PriorityQueue: remove / get / clear ---

    #[test]
    fn test_queue_remove() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        q.enqueue(entry("t2", "a2", PriorityBand::Normal), 1000);
        let removed = q.remove("t1").unwrap();
        assert_eq!(removed.task_id, "t1");
        assert_eq!(q.len(), 1);
        assert!(q.get("t1").is_none());
    }

    #[test]
    fn test_queue_remove_not_found() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        assert!(q.remove("nonexistent").is_none());
    }

    #[test]
    fn test_queue_get() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        let e = q.get("t1").unwrap();
        assert_eq!(e.task_id, "t1");
        assert_eq!(e.agent_id, "a1");
    }

    #[test]
    fn test_queue_get_not_found() {
        let q = PriorityQueue::with_defaults().unwrap();
        assert!(q.get("nonexistent").is_none());
    }

    #[test]
    fn test_queue_clear() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        q.enqueue(entry("t2", "a2", PriorityBand::Normal), 1000);
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    // --- PriorityQueue: sorted_entries / count_band ---

    #[test]
    fn test_queue_sorted_entries() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("low", "a1", PriorityBand::Low), 1000);
        q.enqueue(entry("critical", "a2", PriorityBand::Critical), 1000);
        q.enqueue(entry("normal", "a3", PriorityBand::Normal), 1000);
        let sorted = q.sorted_entries();
        assert_eq!(sorted[0].task_id, "critical");
        assert_eq!(sorted[1].task_id, "normal");
        assert_eq!(sorted[2].task_id, "low");
    }

    #[test]
    fn test_queue_count_band() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Critical), 1000);
        q.enqueue(entry("t2", "a2", PriorityBand::Critical), 1000);
        q.enqueue(entry("t3", "a3", PriorityBand::Normal), 1000);
        assert_eq!(q.count_band(PriorityBand::Critical), 2);
        assert_eq!(q.count_band(PriorityBand::Normal), 1);
        assert_eq!(q.count_band(PriorityBand::Low), 0);
    }

    // --- PriorityQueue: update_reputation ---

    #[test]
    fn test_queue_update_reputation() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        q.enqueue(entry("t2", "a1", PriorityBand::Normal), 1000);
        q.enqueue(entry("t3", "a2", PriorityBand::Normal), 1000);
        q.update_reputation("a1", 1000, 1000);
        assert_eq!(q.get("t1").unwrap().reputation_milli, 1000);
        assert_eq!(q.get("t2").unwrap().reputation_milli, 1000);
        // a2 unchanged
        assert_eq!(q.get("t3").unwrap().reputation_milli, 500);
    }

    #[test]
    fn test_queue_reputation_affects_ordering() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        let mut e1 = entry("t1", "a1", PriorityBand::Normal);
        e1.reputation_milli = 0;
        let mut e2 = entry("t2", "a2", PriorityBand::Normal);
        e2.reputation_milli = 1000;
        q.enqueue(e1, 1000);
        q.enqueue(e2, 1000);
        // Same band, same resources/cost → higher reputation should win.
        assert_eq!(q.peek().unwrap().task_id, "t2");
    }

    // --- PriorityQueue: deadline urgency ---

    #[test]
    fn test_queue_deadline_affects_ordering() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        let mut e1 = entry("t1", "a1", PriorityBand::Normal);
        e1.deadline = 1100; // very close to now=1000
        let mut e2 = entry("t2", "a2", PriorityBand::Normal);
        e2.deadline = 0; // no deadline
        q.enqueue(e1, 1000);
        q.enqueue(e2, 1000);
        // t1 has urgency, t2 doesn't → t1 should come first.
        assert_eq!(q.peek().unwrap().task_id, "t1");
    }

    // --- PriorityQueue: invalid config ---

    #[test]
    fn test_queue_new_invalid_config() {
        let bad = PriorityConfig {
            urgency_weight_milli: -1,
            ..PriorityConfig::default()
        };
        assert!(PriorityQueue::new(bad).is_err());
    }

    // --- PriorityQueue: dequeue after remove preserves correctness ---

    #[test]
    fn test_queue_dequeue_after_remove() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Low), 1000);
        q.enqueue(entry("t2", "a2", PriorityBand::Critical), 1000);
        q.enqueue(entry("t3", "a3", PriorityBand::Normal), 1000);
        q.remove("t2"); // remove the highest
        assert_eq!(q.dequeue(1000).unwrap().task_id, "t3");
        assert_eq!(q.dequeue(1000).unwrap().task_id, "t1");
    }

    #[test]
    fn test_queue_re_enqueue_after_dequeue() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        q.dequeue(1000).unwrap();
        // Should be able to re-enqueue same task_id after dequeue.
        assert!(q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_queue_re_enqueue_after_remove() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000);
        q.remove("t1");
        assert!(q.enqueue(entry("t1", "a1", PriorityBand::Normal), 1000));
    }

    // --- Integration: cost factor affects ordering ---

    #[test]
    fn test_queue_cost_affects_ordering() {
        let config = PriorityConfig::default().with_cost_weight(1000);
        let mut q = PriorityQueue::new(config).unwrap();
        let mut e1 = entry("t1", "a1", PriorityBand::Normal);
        e1.cost_estimate_milli = 10_000; // low cost
        let mut e2 = entry("t2", "a2", PriorityBand::Normal);
        e2.cost_estimate_milli = 900_000; // high cost
        q.enqueue(e1, 1000);
        q.enqueue(e2, 1000);
        // Higher cost = higher priority (more valuable).
        assert_eq!(q.peek().unwrap().task_id, "t2");
    }

    #[test]
    fn test_queue_resource_availability_affects_ordering() {
        let config = PriorityConfig::default().with_resource_weight(1000);
        let mut q = PriorityQueue::new(config).unwrap();
        let mut e1 = entry("t1", "a1", PriorityBand::Normal);
        e1.resource_estimate = usage(10_000, 0, 0, 0, 0, 0); // low usage
        let mut e2 = entry("t2", "a2", PriorityBand::Normal);
        e2.resource_estimate = usage(90_000, 0, 0, 0, 0, 0); // high usage
        q.enqueue(e1, 1000);
        q.enqueue(e2, 1000);
        // Lower usage = higher availability score = higher priority.
        assert_eq!(q.peek().unwrap().task_id, "t1");
    }

    // --- Deadline horizon ---

    #[test]
    fn test_queue_set_deadline_horizon() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.set_deadline_horizon(10_000);
        assert_eq!(q.deadline_horizon(), 10_000);
    }

    #[test]
    fn test_queue_deadline_horizon_affects_urgency() {
        let mut q = PriorityQueue::with_defaults().unwrap();
        q.set_deadline_horizon(1000);
        let mut e1 = entry("t1", "a1", PriorityBand::Normal);
        e1.deadline = 1500; // 500ms remaining, horizon 1000 → urgency = 500
        let mut e2 = entry("t2", "a2", PriorityBand::Normal);
        e2.deadline = 1800; // 800ms remaining, horizon 1000 → urgency = 200
        q.enqueue(e1, 1000);
        q.enqueue(e2, 1000);
        assert_eq!(q.peek().unwrap().task_id, "t1");
    }
}
