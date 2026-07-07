//! Failure recovery — handles task execution failures with configurable
//! retry, fallback, skip, abort, and escalation strategies.
//!
//! The [`FailureRecovery`] manager tracks failure history per task and per
//! agent, applies [`RecoveryStrategy`] policies, and integrates a circuit
//! breaker to skip agents that have repeated failures.
//!
//! # Strategies
//!
//! - [`RecoveryStrategy::Retry`] — retry the task on the same (or a
//!   different) agent, subject to the retry policy (max retries + backoff).
//! - [`RecoveryStrategy::Fallback`] — try a chain of fallback
//!   agents/capabilities in order until one succeeds.
//! - [`RecoveryStrategy::Skip`] — skip the failed task and continue with
//!   the rest of the plan.
//! - [`RecoveryStrategy::Abort`] — abort the entire plan immediately.
//! - [`RecoveryStrategy::Escalate`] — notify a higher-level coordinator
//!   and wait for guidance.
//!
//! # Circuit Breaker
//!
//! The circuit breaker tracks consecutive failures per agent. When an
//! agent exceeds the configured threshold, the breaker opens and
//! [`is_agent_available`](FailureRecovery::is_agent_available) returns
//! `false` for that agent until the reset timeout elapses.

use crate::execution::plan::TaskId;
use aafp_identity::identity_v1::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────
// FailureRecord
// ──────────────────────────────────────────────────────────────────────

/// A record of a single task execution failure.
#[derive(Clone, Debug)]
pub struct FailureRecord {
    /// The task that failed.
    pub task_id: TaskId,
    /// The agent that was executing the task.
    pub agent_id: AgentId,
    /// The error message describing the failure.
    pub error: String,
    /// Which attempt number this was (1-based).
    pub attempt: u32,
    /// Unix timestamp (millis) when the failure occurred.
    pub timestamp: u64,
}

impl FailureRecord {
    /// Create a new failure record.
    pub fn new(task_id: TaskId, agent_id: AgentId, error: &str, attempt: u32) -> Self {
        Self {
            task_id,
            agent_id,
            error: error.to_string(),
            attempt,
            timestamp: now_millis(),
        }
    }
}

/// Current Unix timestamp in milliseconds.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ──────────────────────────────────────────────────────────────────────
// RecoveryStrategy
// ──────────────────────────────────────────────────────────────────────

/// Strategy for recovering from a task execution failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryStrategy {
    /// Retry the task, subject to the retry policy (max retries + backoff).
    Retry,
    /// Try a chain of fallback agents/capabilities in order.
    Fallback,
    /// Skip the failed task and continue with the rest of the plan.
    Skip,
    /// Abort the entire plan immediately.
    Abort,
    /// Escalate to a higher-level coordinator for guidance.
    Escalate,
}

impl Default for RecoveryStrategy {
    fn default() -> Self {
        Self::Retry
    }
}

// ──────────────────────────────────────────────────────────────────────
// RetryPolicy
// ──────────────────────────────────────────────────────────────────────

/// Configuration for retry behavior with exponential backoff.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (not counting the initial attempt).
    pub max_retries: u32,
    /// Initial delay before the first retry, in milliseconds.
    pub initial_delay_ms: u64,
    /// Multiplier applied to the delay after each retry (exponential backoff).
    pub backoff_multiplier: f64,
    /// Maximum delay between retries, in milliseconds (caps the backoff).
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            backoff_multiplier: 2.0,
            max_delay_ms: 10_000,
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy with the given max retries and initial delay.
    pub fn new(max_retries: u32, initial_delay_ms: u64) -> Self {
        Self {
            max_retries,
            initial_delay_ms,
            ..Self::default()
        }
    }

    /// Set the backoff multiplier.
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Set the maximum delay.
    pub fn with_max_delay_ms(mut self, ms: u64) -> Self {
        self.max_delay_ms = ms;
        self
    }

    /// Compute the delay before the next retry, given the current retry
    /// count (0-based: 0 = before first retry).
    ///
    /// Uses exponential backoff: `initial_delay * multiplier^retry_count`,
    /// capped at `max_delay_ms`.
    pub fn delay_for_retry(&self, retry_count: u32) -> Duration {
        if retry_count == 0 {
            return Duration::from_millis(self.initial_delay_ms);
        }
        let multiplier = self.backoff_multiplier.powi(retry_count as i32);
        let delay = (self.initial_delay_ms as f64 * multiplier) as u64;
        Duration::from_millis(delay.min(self.max_delay_ms))
    }

    /// Check if more retries are allowed given the current retry count.
    pub fn can_retry(&self, current_retries: u32) -> bool {
        current_retries < self.max_retries
    }
}

// ──────────────────────────────────────────────────────────────────────
// CircuitBreaker
// ──────────────────────────────────────────────────────────────────────

/// Circuit breaker state for a single agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerState {
    /// The breaker is closed — the agent is available.
    Closed,
    /// The breaker is open — the agent is temporarily unavailable.
    Open,
    /// The breaker is half-open — the agent is being tested.
    HalfOpen,
}

/// Per-agent circuit breaker tracking.
#[derive(Clone, Debug)]
struct AgentBreaker {
    /// Current state of the breaker.
    state: BreakerState,
    /// Number of consecutive failures.
    consecutive_failures: u32,
    /// When the breaker opened (for reset timeout calculation).
    opened_at: Option<Instant>,
}

impl AgentBreaker {
    fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            opened_at: None,
        }
    }
}

/// Configuration for the circuit breaker.
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the breaker opens.
    pub failure_threshold: u32,
    /// How long to keep the breaker open before transitioning to half-open,
    /// in milliseconds.
    pub reset_timeout_ms: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout_ms: 30_000,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// RecoveryConfig
// ──────────────────────────────────────────────────────────────────────

/// Configuration for the [`FailureRecovery`] manager.
#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    /// The default recovery strategy.
    pub default_strategy: RecoveryStrategy,
    /// Retry policy for [`RecoveryStrategy::Retry`].
    pub retry_policy: RetryPolicy,
    /// Circuit breaker configuration.
    pub breaker_config: CircuitBreakerConfig,
    /// Fallback chain: list of (agent_id, capability) pairs to try in order.
    pub fallback_chain: Vec<(AgentId, String)>,
    /// Per-task strategy overrides (task_id → strategy).
    pub task_strategies: HashMap<TaskId, RecoveryStrategy>,
    /// Whether to escalate to a higher-level coordinator on unrecoverable
    /// failures.
    pub escalate_on_exhausted: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            default_strategy: RecoveryStrategy::Retry,
            retry_policy: RetryPolicy::default(),
            breaker_config: CircuitBreakerConfig::default(),
            fallback_chain: Vec::new(),
            task_strategies: HashMap::new(),
            escalate_on_exhausted: false,
        }
    }
}

impl RecoveryConfig {
    /// Create a new config with the given default strategy.
    pub fn new(strategy: RecoveryStrategy) -> Self {
        Self {
            default_strategy: strategy,
            ..Self::default()
        }
    }

    /// Set the retry policy.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Set the circuit breaker config.
    pub fn with_breaker_config(mut self, config: CircuitBreakerConfig) -> Self {
        self.breaker_config = config;
        self
    }

    /// Set the fallback chain.
    pub fn with_fallback_chain(mut self, chain: Vec<(AgentId, String)>) -> Self {
        self.fallback_chain = chain;
        self
    }

    /// Add a per-task strategy override.
    pub fn with_task_strategy(mut self, task_id: TaskId, strategy: RecoveryStrategy) -> Self {
        self.task_strategies.insert(task_id, strategy);
        self
    }

    /// Enable escalation on exhausted retries.
    pub fn with_escalate_on_exhausted(mut self, escalate: bool) -> Self {
        self.escalate_on_exhausted = escalate;
        self
    }
}

// ──────────────────────────────────────────────────────────────────────
// RecoveryAction
// ──────────────────────────────────────────────────────────────────────

/// The action to take in response to a failure.
#[derive(Clone, Debug)]
pub enum RecoveryAction {
    /// Retry the task, optionally on a different agent. The delay before
    /// the retry is included.
    Retry {
        /// The agent to retry on (may differ from the original).
        agent_id: AgentId,
        /// The attempt number for the retry.
        attempt: u32,
        /// Delay before the retry.
        delay: Duration,
    },
    /// Fall back to a different agent/capability.
    Fallback {
        /// The fallback agent to try.
        agent_id: AgentId,
        /// The fallback capability to invoke.
        capability: String,
    },
    /// Skip the task and continue.
    Skip,
    /// Abort the entire plan.
    Abort,
    /// Escalate to a higher-level coordinator.
    Escalate {
        /// Human-readable reason for escalation.
        reason: String,
    },
}

// ──────────────────────────────────────────────────────────────────────
// EscalationCallback
// ──────────────────────────────────────────────────────────────────────

/// A callback invoked when a failure is escalated to a higher-level coordinator.
///
/// The callback receives the [`FailureRecord`] and returns a [`RecoveryAction`]
/// indicating how to proceed.
pub type EscalationCallback = Arc<dyn Fn(&FailureRecord) -> RecoveryAction + Send + Sync>;

// ──────────────────────────────────────────────────────────────────────
// FailureRecovery
// ──────────────────────────────────────────────────────────────────────

/// Manages task execution failures with configurable recovery strategies.
///
/// Tracks failure history per task and per agent, applies recovery
/// strategies, and integrates a circuit breaker to skip agents with
/// repeated failures.
///
/// # Thread Safety
///
/// All internal state is protected by `RwLock`, making the manager safe
/// to share across threads.
pub struct FailureRecovery {
    /// Configuration for this recovery manager.
    config: RecoveryConfig,
    /// Failure history per task (task_id → list of failure records).
    task_failures: RwLock<HashMap<TaskId, Vec<FailureRecord>>>,
    /// Failure history per agent (agent_id → list of failure records).
    agent_failures: RwLock<HashMap<AgentId, Vec<FailureRecord>>>,
    /// Circuit breaker state per agent.
    breakers: RwLock<HashMap<AgentId, AgentBreaker>>,
    /// Optional escalation callback.
    escalation_callback: RwLock<Option<EscalationCallback>>,
    /// Count of total escalations.
    escalation_count: RwLock<u64>,
}

impl std::fmt::Debug for FailureRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let task_count = self
            .task_failures
            .read()
            .expect("task_failures lock poisoned")
            .len();
        let agent_count = self
            .agent_failures
            .read()
            .expect("agent_failures lock poisoned")
            .len();
        f.debug_struct("FailureRecovery")
            .field("config", &self.config)
            .field("task_failure_entries", &task_count)
            .field("agent_failure_entries", &agent_count)
            .finish()
    }
}

impl FailureRecovery {
    /// Create a new failure recovery manager with the given configuration.
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            task_failures: RwLock::new(HashMap::new()),
            agent_failures: RwLock::new(HashMap::new()),
            breakers: RwLock::new(HashMap::new()),
            escalation_callback: RwLock::new(None),
            escalation_count: RwLock::new(0),
        }
    }

    /// Create a new failure recovery manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RecoveryConfig::default())
    }

    /// Get a reference to the recovery configuration.
    pub fn config(&self) -> &RecoveryConfig {
        &self.config
    }

    /// Set the escalation callback.
    pub fn set_escalation_callback(&self, callback: EscalationCallback) {
        let mut cb = self
            .escalation_callback
            .write()
            .expect("escalation lock poisoned");
        *cb = Some(callback);
    }

    // ── Failure tracking ──

    /// Record a failure and return the appropriate recovery action.
    ///
    /// This is the primary entry point for handling a task failure. It:
    /// 1. Records the failure in the task and agent failure histories.
    /// 2. Updates the circuit breaker for the agent.
    /// 3. Determines the recovery strategy (per-task override or default).
    /// 4. Returns the appropriate [`RecoveryAction`].
    pub fn handle_failure(
        &self,
        task_id: &TaskId,
        agent_id: &AgentId,
        error: &str,
        current_retry_count: u32,
    ) -> RecoveryAction {
        let attempt = current_retry_count + 1;
        let record = FailureRecord::new(task_id.clone(), agent_id.clone(), error, attempt);

        // Record the failure.
        self.record_failure(record.clone());

        // Update the circuit breaker.
        self.record_agent_failure(agent_id);

        // Determine the strategy.
        let strategy = self.strategy_for_task(task_id);

        match strategy {
            RecoveryStrategy::Retry => self.handle_retry(task_id, agent_id, current_retry_count),
            RecoveryStrategy::Fallback => self.handle_fallback(task_id, agent_id, error),
            RecoveryStrategy::Skip => RecoveryAction::Skip,
            RecoveryStrategy::Abort => RecoveryAction::Abort,
            RecoveryStrategy::Escalate => self.escalate(&record),
        }
    }

    /// Record a failure in the task and agent failure histories.
    fn record_failure(&self, record: FailureRecord) {
        // Task failure history.
        {
            let mut task_failures = self
                .task_failures
                .write()
                .expect("task_failures lock poisoned");
            task_failures
                .entry(record.task_id.clone())
                .or_default()
                .push(record.clone());
        }
        // Agent failure history.
        {
            let mut agent_failures = self
                .agent_failures
                .write()
                .expect("agent_failures lock poisoned");
            agent_failures
                .entry(record.agent_id.clone())
                .or_default()
                .push(record);
        }
    }

    /// Update the circuit breaker for an agent after a failure.
    fn record_agent_failure(&self, agent_id: &AgentId) {
        let mut breakers = self.breakers.write().expect("breakers lock poisoned");
        let breaker = breakers
            .entry(agent_id.clone())
            .or_insert_with(AgentBreaker::new);
        breaker.consecutive_failures += 1;
        if breaker.consecutive_failures >= self.config.breaker_config.failure_threshold {
            breaker.state = BreakerState::Open;
            breaker.opened_at = Some(Instant::now());
        }
    }

    /// Record a success for an agent, resetting the circuit breaker.
    pub fn record_success(&self, agent_id: &AgentId) {
        let mut breakers = self.breakers.write().expect("breakers lock poisoned");
        if let Some(breaker) = breakers.get_mut(agent_id) {
            breaker.consecutive_failures = 0;
            breaker.state = BreakerState::Closed;
            breaker.opened_at = None;
        }
    }

    /// Determine the recovery strategy for a task (per-task override or default).
    fn strategy_for_task(&self, task_id: &TaskId) -> RecoveryStrategy {
        // Check for a per-task strategy override first.
        if let Some(strategy) = self.config.task_strategies.get(task_id) {
            return strategy.clone();
        }
        self.config.default_strategy.clone()
    }

    // ── Retry handling ──

    /// Handle a retry: check if retries are allowed, compute the delay,
    /// and determine the agent to retry on.
    fn handle_retry(
        &self,
        task_id: &TaskId,
        agent_id: &AgentId,
        current_retry_count: u32,
    ) -> RecoveryAction {
        let policy = &self.config.retry_policy;

        if !policy.can_retry(current_retry_count) {
            // Retries exhausted.
            if self.config.escalate_on_exhausted {
                let record = FailureRecord::new(
                    task_id.clone(),
                    agent_id.clone(),
                    "retries_exhausted",
                    current_retry_count + 1,
                );
                return self.escalate(&record);
            }
            return RecoveryAction::Abort;
        }

        let delay = policy.delay_for_retry(current_retry_count);

        // If the agent's circuit breaker is open, we still retry but on
        // a different agent (if available in the fallback chain).
        if !self.is_agent_available(agent_id) {
            // Try to find an alternative agent from the fallback chain.
            if let Some((alt_agent, _)) = self.find_available_fallback() {
                return RecoveryAction::Retry {
                    agent_id: alt_agent,
                    attempt: current_retry_count + 1,
                    delay,
                };
            }
            // No alternative — escalate or abort.
            if self.config.escalate_on_exhausted {
                let record = FailureRecord::new(
                    task_id.clone(),
                    agent_id.clone(),
                    "agent_circuit_open_no_fallback",
                    current_retry_count + 1,
                );
                return self.escalate(&record);
            }
            return RecoveryAction::Abort;
        }

        RecoveryAction::Retry {
            agent_id: agent_id.clone(),
            attempt: current_retry_count + 1,
            delay,
        }
    }

    /// Get the retry policy.
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.config.retry_policy
    }

    // ── Fallback handling ──

    /// Handle a fallback: try the next available agent/capability in the
    /// fallback chain.
    fn handle_fallback(
        &self,
        task_id: &TaskId,
        agent_id: &AgentId,
        _error: &str,
    ) -> RecoveryAction {
        if let Some((fb_agent, capability)) = self.find_available_fallback() {
            return RecoveryAction::Fallback {
                agent_id: fb_agent,
                capability,
            };
        }
        // No fallback available — escalate or abort.
        if self.config.escalate_on_exhausted {
            let record = FailureRecord::new(
                task_id.clone(),
                agent_id.clone(),
                "no_fallback_available",
                1,
            );
            return self.escalate(&record);
        }
        RecoveryAction::Abort
    }

    /// Get the fallback chain.
    pub fn fallback_chain(&self) -> &[(AgentId, String)] {
        &self.config.fallback_chain
    }

    /// Find the first available agent in the fallback chain (circuit
    /// breaker not open).
    fn find_available_fallback(&self) -> Option<(AgentId, String)> {
        for (agent_id, capability) in &self.config.fallback_chain {
            if self.is_agent_available(agent_id) {
                return Some((agent_id.clone(), capability.clone()));
            }
        }
        None
    }

    // ── Escalation ──

    /// Escalate a failure to a higher-level coordinator.
    ///
    /// If an escalation callback is set, it is invoked to determine the
    /// recovery action. Otherwise, a default `Escalate` action is returned.
    pub fn escalate(&self, record: &FailureRecord) -> RecoveryAction {
        {
            let mut count = self
                .escalation_count
                .write()
                .expect("escalation_count lock poisoned");
            *count += 1;
        }
        let cb = self
            .escalation_callback
            .read()
            .expect("escalation lock poisoned");
        match &*cb {
            Some(callback) => callback(record),
            None => RecoveryAction::Escalate {
                reason: format!(
                    "unrecoverable failure: task={:?} agent={:?} error={}",
                    record.task_id, record.agent_id, record.error
                ),
            },
        }
    }

    /// Get the total number of escalations.
    pub fn escalation_count(&self) -> u64 {
        *self
            .escalation_count
            .read()
            .expect("escalation_count lock poisoned")
    }

    // ── Circuit breaker ──

    /// Check if an agent is available (circuit breaker not open).
    ///
    /// If the breaker is open but the reset timeout has elapsed, the
    /// breaker transitions to half-open and the agent is considered
    /// available (for a trial request).
    pub fn is_agent_available(&self, agent_id: &AgentId) -> bool {
        let mut breakers = self.breakers.write().expect("breakers lock poisoned");
        let breaker = match breakers.get_mut(agent_id) {
            Some(b) => b,
            None => return true, // No breaker → available.
        };

        match breaker.state {
            BreakerState::Closed | BreakerState::HalfOpen => true,
            BreakerState::Open => {
                // Check if reset timeout has elapsed.
                if let Some(opened_at) = breaker.opened_at {
                    let elapsed = opened_at.elapsed();
                    let reset_timeout =
                        Duration::from_millis(self.config.breaker_config.reset_timeout_ms);
                    if elapsed >= reset_timeout {
                        // Transition to half-open.
                        breaker.state = BreakerState::HalfOpen;
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Get the circuit breaker state for an agent.
    pub fn breaker_state(&self, agent_id: &AgentId) -> BreakerState {
        let breakers = self.breakers.read().expect("breakers lock poisoned");
        breakers
            .get(agent_id)
            .map(|b| b.state.clone())
            .unwrap_or(BreakerState::Closed)
    }

    /// Get the number of consecutive failures for an agent.
    pub fn agent_failure_count(&self, agent_id: &AgentId) -> u32 {
        let breakers = self.breakers.read().expect("breakers lock poisoned");
        breakers
            .get(agent_id)
            .map(|b| b.consecutive_failures)
            .unwrap_or(0)
    }

    /// Reset the circuit breaker for an agent (e.g., for testing).
    pub fn reset_breaker(&self, agent_id: &AgentId) {
        let mut breakers = self.breakers.write().expect("breakers lock poisoned");
        if let Some(breaker) = breakers.get_mut(agent_id) {
            breaker.state = BreakerState::Closed;
            breaker.consecutive_failures = 0;
            breaker.opened_at = None;
        }
    }

    // ── History queries ──

    /// Get the failure history for a task.
    pub fn task_failures(&self, task_id: &TaskId) -> Vec<FailureRecord> {
        let task_failures = self
            .task_failures
            .read()
            .expect("task_failures lock poisoned");
        task_failures.get(task_id).cloned().unwrap_or_default()
    }

    /// Get the failure history for an agent.
    pub fn agent_failures(&self, agent_id: &AgentId) -> Vec<FailureRecord> {
        let agent_failures = self
            .agent_failures
            .read()
            .expect("agent_failures lock poisoned");
        agent_failures.get(agent_id).cloned().unwrap_or_default()
    }

    /// Get the total number of failures recorded.
    pub fn total_failures(&self) -> usize {
        let task_failures = self
            .task_failures
            .read()
            .expect("task_failures lock poisoned");
        task_failures.values().map(|v| v.len()).sum()
    }

    /// Get the number of tasks that have at least one failure.
    pub fn failed_task_count(&self) -> usize {
        let task_failures = self
            .task_failures
            .read()
            .expect("task_failures lock poisoned");
        task_failures.len()
    }

    /// Clear all failure history and reset all circuit breakers.
    pub fn clear(&self) {
        {
            let mut tf = self
                .task_failures
                .write()
                .expect("task_failures lock poisoned");
            tf.clear();
        }
        {
            let mut af = self
                .agent_failures
                .write()
                .expect("agent_failures lock poisoned");
            af.clear();
        }
        {
            let mut b = self.breakers.write().expect("breakers lock poisoned");
            b.clear();
        }
        {
            let mut c = self
                .escalation_count
                .write()
                .expect("escalation_count lock poisoned");
            *c = 0;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──

    fn make_task_id(seed: &[u8]) -> TaskId {
        TaskId::from_seed(seed)
    }

    fn make_agent_id(byte: u8) -> AgentId {
        AgentId([byte; 32])
    }

    fn make_config_with_threshold(threshold: u32) -> RecoveryConfig {
        RecoveryConfig::new(RecoveryStrategy::Retry)
            .with_breaker_config(CircuitBreakerConfig {
                failure_threshold: threshold,
                reset_timeout_ms: 100,
            })
            .with_retry_policy(RetryPolicy::new(3, 10))
    }

    fn make_escalation_callback() -> EscalationCallback {
        Arc::new(|_record: &FailureRecord| RecoveryAction::Abort)
    }

    // ── 1. FailureRecord construction ──

    #[test]
    fn test_failure_record_construction() {
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);
        let record = FailureRecord::new(task_id.clone(), agent_id.clone(), "timeout", 2);
        assert_eq!(record.task_id, task_id);
        assert_eq!(record.agent_id, agent_id);
        assert_eq!(record.error, "timeout");
        assert_eq!(record.attempt, 2);
        assert!(record.timestamp > 0);
    }

    // ── 2. RecoveryStrategy default ──

    #[test]
    fn test_recovery_strategy_default() {
        assert_eq!(RecoveryStrategy::default(), RecoveryStrategy::Retry);
    }

    // ── 3. RetryPolicy default ──

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.initial_delay_ms, 100);
        assert_eq!(policy.backoff_multiplier, 2.0);
        assert_eq!(policy.max_delay_ms, 10_000);
    }

    // ── 4. RetryPolicy::delay_for_retry exponential backoff ──

    #[test]
    fn test_delay_for_retry_exponential_backoff() {
        let policy = RetryPolicy::new(3, 100).with_backoff_multiplier(2.0);
        assert_eq!(policy.delay_for_retry(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for_retry(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for_retry(2), Duration::from_millis(400));
        assert_eq!(policy.delay_for_retry(3), Duration::from_millis(800));
    }

    // ── 5. RetryPolicy::delay_for_retry capped at max_delay ──

    #[test]
    fn test_delay_for_retry_capped() {
        let policy = RetryPolicy::new(10, 100)
            .with_backoff_multiplier(10.0)
            .with_max_delay_ms(500);
        // 100 * 10^3 = 10000, capped at 500.
        assert_eq!(policy.delay_for_retry(3), Duration::from_millis(500));
    }

    // ── 6. RetryPolicy::can_retry ──

    #[test]
    fn test_can_retry() {
        let policy = RetryPolicy::new(3, 100);
        assert!(policy.can_retry(0));
        assert!(policy.can_retry(1));
        assert!(policy.can_retry(2));
        assert!(!policy.can_retry(3));
        assert!(!policy.can_retry(4));
    }

    // ── 7. handle_failure with Retry strategy ──

    #[test]
    fn test_handle_failure_retry() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_retry_policy(RetryPolicy::new(3, 100)),
        );
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        match action {
            RecoveryAction::Retry {
                agent_id: a,
                attempt,
                delay,
            } => {
                assert_eq!(a, agent_id);
                assert_eq!(attempt, 1);
                assert_eq!(delay, Duration::from_millis(100));
            }
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    // ── 8. handle_failure Retry exhausted → Abort ──

    #[test]
    fn test_handle_failure_retry_exhausted_abort() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry).with_retry_policy(RetryPolicy::new(2, 10)),
        );
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        // retry_count = 2, max_retries = 2 → cannot retry.
        let action = recovery.handle_failure(&task_id, &agent_id, "error", 2);
        assert!(matches!(action, RecoveryAction::Abort));
    }

    // ── 9. handle_failure Retry exhausted → Escalate ──

    #[test]
    fn test_handle_failure_retry_exhausted_escalate() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_retry_policy(RetryPolicy::new(2, 10))
                .with_escalate_on_exhausted(true),
        );
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 2);
        match action {
            RecoveryAction::Escalate { reason } => {
                assert!(reason.contains("retries_exhausted"));
            }
            other => panic!("expected Escalate, got {other:?}"),
        }
    }

    // ── 10. handle_failure with Skip strategy ──

    #[test]
    fn test_handle_failure_skip() {
        let recovery = FailureRecovery::new(RecoveryConfig::new(RecoveryStrategy::Skip));
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        assert!(matches!(action, RecoveryAction::Skip));
    }

    // ── 11. handle_failure with Abort strategy ──

    #[test]
    fn test_handle_failure_abort() {
        let recovery = FailureRecovery::new(RecoveryConfig::new(RecoveryStrategy::Abort));
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        assert!(matches!(action, RecoveryAction::Abort));
    }

    // ── 12. handle_failure with Fallback strategy ──

    #[test]
    fn test_handle_failure_fallback() {
        let fallback_agent = make_agent_id(9);
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Fallback)
                .with_fallback_chain(vec![(fallback_agent.clone(), "backup_cap".to_string())]),
        );
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        match action {
            RecoveryAction::Fallback {
                agent_id,
                capability,
            } => {
                assert_eq!(agent_id, fallback_agent);
                assert_eq!(capability, "backup_cap");
            }
            other => panic!("expected Fallback, got {other:?}"),
        }
    }

    // ── 13. handle_failure Fallback with no available fallback → Abort ──

    #[test]
    fn test_handle_failure_fallback_none_available() {
        let recovery = FailureRecovery::new(RecoveryConfig::new(RecoveryStrategy::Fallback));
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        assert!(matches!(action, RecoveryAction::Abort));
    }

    // ── 14. handle_failure with Escalate strategy ──

    #[test]
    fn test_handle_failure_escalate() {
        let recovery = FailureRecovery::new(RecoveryConfig::new(RecoveryStrategy::Escalate));
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        match action {
            RecoveryAction::Escalate { reason } => {
                assert!(reason.contains("unrecoverable failure"));
            }
            other => panic!("expected Escalate, got {other:?}"),
        }
    }

    // ── 15. Per-task strategy override ──

    #[test]
    fn test_per_task_strategy_override() {
        let task_id = make_task_id(b"task1");
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_task_strategy(task_id.clone(), RecoveryStrategy::Skip),
        );
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        assert!(matches!(action, RecoveryAction::Skip));
    }

    // ── 16. Circuit breaker opens after threshold ──

    #[test]
    fn test_circuit_breaker_opens() {
        let recovery = FailureRecovery::new(make_config_with_threshold(3));
        let agent_id = make_agent_id(1);
        let task_id = make_task_id(b"task1");

        // First two failures — breaker stays closed.
        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 1);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Closed);
        assert!(recovery.is_agent_available(&agent_id));

        // Third failure — breaker opens.
        recovery.handle_failure(&task_id, &agent_id, "e", 2);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Open);
        assert!(!recovery.is_agent_available(&agent_id));
    }

    // ── 17. Circuit breaker resets on success ──

    #[test]
    fn test_circuit_breaker_resets_on_success() {
        let recovery = FailureRecovery::new(make_config_with_threshold(3));
        let agent_id = make_agent_id(1);
        let task_id = make_task_id(b"task1");

        // Two failures.
        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 1);
        assert_eq!(recovery.agent_failure_count(&agent_id), 2);

        // Success resets the breaker.
        recovery.record_success(&agent_id);
        assert_eq!(recovery.agent_failure_count(&agent_id), 0);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Closed);
    }

    // ── 18. Circuit breaker transitions to half-open after timeout ──

    #[test]
    fn test_circuit_breaker_half_open_after_timeout() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_breaker_config(CircuitBreakerConfig {
                    failure_threshold: 2,
                    reset_timeout_ms: 10,
                })
                .with_retry_policy(RetryPolicy::new(10, 1)),
        );
        let agent_id = make_agent_id(1);
        let task_id = make_task_id(b"task1");

        // Open the breaker.
        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 1);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Open);

        // Wait for reset timeout.
        std::thread::sleep(Duration::from_millis(20));

        // Now the agent should be available (half-open).
        assert!(recovery.is_agent_available(&agent_id));
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::HalfOpen);
    }

    // ── 19. Retry with open circuit breaker uses fallback ──

    #[test]
    fn test_retry_with_open_breaker_uses_fallback() {
        let fallback_agent = make_agent_id(9);
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_breaker_config(CircuitBreakerConfig {
                    failure_threshold: 2,
                    reset_timeout_ms: 10_000,
                })
                .with_retry_policy(RetryPolicy::new(10, 10))
                .with_fallback_chain(vec![(fallback_agent.clone(), "cap".to_string())]),
        );
        let agent_id = make_agent_id(1);
        let task_id = make_task_id(b"task1");

        // Open the breaker.
        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 1);

        // Next failure with retry should use the fallback agent.
        let action = recovery.handle_failure(&task_id, &agent_id, "e", 2);
        match action {
            RecoveryAction::Retry {
                agent_id: a,
                attempt,
                ..
            } => {
                assert_eq!(a, fallback_agent);
                assert_eq!(attempt, 3);
            }
            other => panic!("expected Retry on fallback, got {other:?}"),
        }
    }

    // ── 20. Task failure history is tracked ──

    #[test]
    fn test_task_failure_history() {
        let recovery = FailureRecovery::with_defaults();
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        recovery.handle_failure(&task_id, &agent_id, "error1", 0);
        recovery.handle_failure(&task_id, &agent_id, "error2", 1);

        let history = recovery.task_failures(&task_id);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].error, "error1");
        assert_eq!(history[1].error, "error2");
        assert_eq!(history[0].attempt, 1);
        assert_eq!(history[1].attempt, 2);
    }

    // ── 21. Agent failure history is tracked ──

    #[test]
    fn test_agent_failure_history() {
        let recovery = FailureRecovery::with_defaults();
        let task1 = make_task_id(b"task1");
        let task2 = make_task_id(b"task2");
        let agent_id = make_agent_id(1);

        recovery.handle_failure(&task1, &agent_id, "error1", 0);
        recovery.handle_failure(&task2, &agent_id, "error2", 0);

        let history = recovery.agent_failures(&agent_id);
        assert_eq!(history.len(), 2);
    }

    // ── 22. total_failures counts all failures ──

    #[test]
    fn test_total_failures() {
        let recovery = FailureRecovery::with_defaults();
        let task1 = make_task_id(b"task1");
        let task2 = make_task_id(b"task2");
        let agent1 = make_agent_id(1);
        let agent2 = make_agent_id(2);

        recovery.handle_failure(&task1, &agent1, "e", 0);
        recovery.handle_failure(&task1, &agent1, "e", 1);
        recovery.handle_failure(&task2, &agent2, "e", 0);

        assert_eq!(recovery.total_failures(), 3);
        assert_eq!(recovery.failed_task_count(), 2);
    }

    // ── 23. Escalation callback is invoked ──

    #[test]
    fn test_escalation_callback_invoked() {
        let recovery = FailureRecovery::new(RecoveryConfig::new(RecoveryStrategy::Escalate));
        recovery.set_escalation_callback(Arc::new(|_r: &FailureRecord| RecoveryAction::Skip));

        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "error", 0);
        assert!(matches!(action, RecoveryAction::Skip));
        assert_eq!(recovery.escalation_count(), 1);
    }

    // ── 24. escalation_count tracks escalations ──

    #[test]
    fn test_escalation_count() {
        let recovery = FailureRecovery::new(RecoveryConfig::new(RecoveryStrategy::Escalate));
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        assert_eq!(recovery.escalation_count(), 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 1);
        assert_eq!(recovery.escalation_count(), 2);
    }

    // ── 25. clear resets all state ──

    #[test]
    fn test_clear_resets_state() {
        let recovery = FailureRecovery::with_defaults();
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        assert_eq!(recovery.total_failures(), 1);

        recovery.clear();
        assert_eq!(recovery.total_failures(), 0);
        assert_eq!(recovery.escalation_count(), 0);
        assert!(recovery.task_failures(&task_id).is_empty());
        assert!(recovery.agent_failures(&agent_id).is_empty());
    }

    // ── 26. reset_breaker resets a specific agent ──

    #[test]
    fn test_reset_breaker() {
        let recovery = FailureRecovery::new(make_config_with_threshold(2));
        let agent_id = make_agent_id(1);
        let task_id = make_task_id(b"task1");

        recovery.handle_failure(&task_id, &agent_id, "e", 0);
        recovery.handle_failure(&task_id, &agent_id, "e", 1);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Open);

        recovery.reset_breaker(&agent_id);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Closed);
        assert_eq!(recovery.agent_failure_count(&agent_id), 0);
    }

    // ── 27. is_agent_available returns true for unknown agent ──

    #[test]
    fn test_is_agent_available_unknown() {
        let recovery = FailureRecovery::with_defaults();
        let agent_id = make_agent_id(1);
        assert!(recovery.is_agent_available(&agent_id));
    }

    // ── 28. fallback_chain returns configured chain ──

    #[test]
    fn test_fallback_chain() {
        let agent1 = make_agent_id(1);
        let agent2 = make_agent_id(2);
        let chain = vec![
            (agent1.clone(), "cap1".to_string()),
            (agent2.clone(), "cap2".to_string()),
        ];
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Fallback).with_fallback_chain(chain.clone()),
        );

        assert_eq!(recovery.fallback_chain(), &chain[..]);
    }

    // ── 29. Fallback skips agents with open breakers ──

    #[test]
    fn test_fallback_skips_open_breakers() {
        let agent1 = make_agent_id(1);
        let agent2 = make_agent_id(2);
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Fallback)
                .with_fallback_chain(vec![
                    (agent1.clone(), "cap1".to_string()),
                    (agent2.clone(), "cap2".to_string()),
                ])
                .with_breaker_config(CircuitBreakerConfig {
                    failure_threshold: 1,
                    reset_timeout_ms: 10_000,
                }),
        );
        let task_id = make_task_id(b"task1");

        // Open the breaker for agent1.
        recovery.handle_failure(&task_id, &agent1, "e", 0);

        // Fallback should skip agent1 and use agent2.
        let action = recovery.handle_failure(&task_id, &agent1, "e", 1);
        match action {
            RecoveryAction::Fallback {
                agent_id,
                capability,
            } => {
                assert_eq!(agent_id, agent2);
                assert_eq!(capability, "cap2");
            }
            other => panic!("expected Fallback to agent2, got {other:?}"),
        }
    }

    // ── 30. RecoveryConfig builder methods ──

    #[test]
    fn test_recovery_config_builder() {
        let task_id = make_task_id(b"task1");
        let agent = make_agent_id(1);
        let config = RecoveryConfig::new(RecoveryStrategy::Fallback)
            .with_retry_policy(RetryPolicy::new(5, 200))
            .with_breaker_config(CircuitBreakerConfig {
                failure_threshold: 10,
                reset_timeout_ms: 5000,
            })
            .with_fallback_chain(vec![(agent.clone(), "cap".to_string())])
            .with_task_strategy(task_id.clone(), RecoveryStrategy::Abort)
            .with_escalate_on_exhausted(true);

        assert_eq!(config.default_strategy, RecoveryStrategy::Fallback);
        assert_eq!(config.retry_policy.max_retries, 5);
        assert_eq!(config.breaker_config.failure_threshold, 10);
        assert_eq!(config.fallback_chain.len(), 1);
        assert_eq!(
            config.task_strategies.get(&task_id),
            Some(&RecoveryStrategy::Abort)
        );
        assert!(config.escalate_on_exhausted);
    }

    // ── 31. Debug formatting does not panic ──

    #[test]
    fn test_debug_formatting() {
        let recovery = FailureRecovery::with_defaults();
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);
        recovery.handle_failure(&task_id, &agent_id, "e", 0);

        let debug_str = format!("{recovery:?}");
        assert!(debug_str.contains("FailureRecovery"));
        assert!(debug_str.contains("task_failure_entries: 1"));
    }

    // ── 32. RetryPolicy::new ──

    #[test]
    fn test_retry_policy_new() {
        let policy = RetryPolicy::new(5, 500);
        assert_eq!(policy.max_retries, 5);
        assert_eq!(policy.initial_delay_ms, 500);
        // Defaults preserved.
        assert_eq!(policy.backoff_multiplier, 2.0);
        assert_eq!(policy.max_delay_ms, 10_000);
    }

    // ── 33. BreakerState default is Closed ──

    #[test]
    fn test_breaker_state_default() {
        let recovery = FailureRecovery::with_defaults();
        let agent_id = make_agent_id(1);
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Closed);
    }

    // ── 34. Multiple tasks on same agent share breaker ──

    #[test]
    fn test_multiple_tasks_share_breaker() {
        let recovery = FailureRecovery::new(make_config_with_threshold(3));
        let agent_id = make_agent_id(1);
        let task1 = make_task_id(b"task1");
        let task2 = make_task_id(b"task2");

        // Failures from different tasks on the same agent.
        recovery.handle_failure(&task1, &agent_id, "e", 0);
        recovery.handle_failure(&task2, &agent_id, "e", 0);
        recovery.handle_failure(&task1, &agent_id, "e", 1);

        // Breaker should be open (3 total failures).
        assert_eq!(recovery.breaker_state(&agent_id), BreakerState::Open);
        assert_eq!(recovery.agent_failure_count(&agent_id), 3);
    }

    // ── 35. agent_failure_count for unknown agent is 0 ──

    #[test]
    fn test_agent_failure_count_unknown() {
        let recovery = FailureRecovery::with_defaults();
        assert_eq!(recovery.agent_failure_count(&make_agent_id(1)), 0);
    }

    // ── 36. task_failures for unknown task is empty ──

    #[test]
    fn test_task_failures_unknown() {
        let recovery = FailureRecovery::with_defaults();
        let task_id = make_task_id(b"unknown");
        assert!(recovery.task_failures(&task_id).is_empty());
    }

    // ── 37. Retry with backoff delay increases ──

    #[test]
    fn test_retry_delay_increases() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_retry_policy(RetryPolicy::new(5, 50).with_backoff_multiplier(2.0)),
        );
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        // retry_count=0 → delay=50ms
        let action1 = recovery.handle_failure(&task_id, &agent_id, "e", 0);
        let delay1 = match action1 {
            RecoveryAction::Retry { delay, .. } => delay,
            _ => panic!("expected Retry"),
        };
        assert_eq!(delay1, Duration::from_millis(50));

        // retry_count=1 → delay=100ms
        let action2 = recovery.handle_failure(&task_id, &agent_id, "e", 1);
        let delay2 = match action2 {
            RecoveryAction::Retry { delay, .. } => delay,
            _ => panic!("expected Retry"),
        };
        assert_eq!(delay2, Duration::from_millis(100));
    }

    // ── 38. Escalate with callback returns custom action ──

    #[test]
    fn test_escalate_with_callback() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry)
                .with_retry_policy(RetryPolicy::new(1, 10))
                .with_escalate_on_exhausted(true),
        );
        recovery.set_escalation_callback(Arc::new(|r: &FailureRecord| RecoveryAction::Escalate {
            reason: format!("custom: {}", r.error),
        }));

        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        // retry_count=1, max_retries=1 → cannot retry → escalate.
        let action = recovery.handle_failure(&task_id, &agent_id, "my_error", 1);
        match action {
            RecoveryAction::Escalate { reason } => {
                assert_eq!(reason, "custom: retries_exhausted");
            }
            other => panic!("expected Escalate, got {other:?}"),
        }
    }

    // ── 39. RecoveryAction::Retry carries correct attempt ──

    #[test]
    fn test_retry_attempt_number() {
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry).with_retry_policy(RetryPolicy::new(10, 1)),
        );
        let task_id = make_task_id(b"task1");
        let agent_id = make_agent_id(1);

        let action = recovery.handle_failure(&task_id, &agent_id, "e", 4);
        match action {
            RecoveryAction::Retry { attempt, .. } => assert_eq!(attempt, 5),
            _ => panic!("expected Retry"),
        }
    }

    // ── 40. CircuitBreakerConfig default ──

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.reset_timeout_ms, 30_000);
    }

    // ── 41. config() returns reference ──

    #[test]
    fn test_config_accessor() {
        let config = RecoveryConfig::new(RecoveryStrategy::Abort);
        let recovery = FailureRecovery::new(config.clone());
        assert_eq!(recovery.config().default_strategy, RecoveryStrategy::Abort);
    }

    // ── 42. retry_policy() returns reference ──

    #[test]
    fn test_retry_policy_accessor() {
        let policy = RetryPolicy::new(7, 300);
        let recovery = FailureRecovery::new(
            RecoveryConfig::new(RecoveryStrategy::Retry).with_retry_policy(policy.clone()),
        );
        assert_eq!(recovery.retry_policy().max_retries, 7);
        assert_eq!(recovery.retry_policy().initial_delay_ms, 300);
    }
}
