//! Result aggregator — collects and combines results from parallel task
//! executions using configurable aggregation strategies.
//!
//! The [`ResultAggregator`] collects [`TaskResult`]s from multiple agents
//! that executed the same (or related) tasks in parallel. Depending on the
//! [`AggregationStrategy`], it selects the best result, merges results, or
//! requires a quorum of agreeing results before returning.
//!
//! # Strategies
//!
//! - [`AggregationStrategy::FirstSuccess`] — return the first successful
//!   result (fastest agent wins).
//! - [`AggregationStrategy::AllRequired`] — all results must succeed; the
//!   outputs are merged.
//! - [`AggregationStrategy::BestOfN`] — wait for N results, pick the one
//!   with the highest verification score.
//! - [`AggregationStrategy::Quorum`] — wait until a quorum of results agree
//!   (by output hash), then return one of the agreeing results.
//!
//! # Verification
//!
//! An optional verification callback ([`ResultVerifier`]) can be plugged in
//! to validate or score each result. The verifier returns a `f64` score in
//! `[0.0, 1.0]`; results with a score of `0.0` are considered invalid.

use crate::execution::plan::TaskId;
use aafp_identity::identity_v1::AgentId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────
// TaskResult
// ──────────────────────────────────────────────────────────────────────

/// The outcome of a single task execution by one agent.
///
/// Carries the output bytes, optional metadata, a timestamp, and a
/// success/failure flag. Failed results carry an error message in
/// `metadata["error"]` instead of output bytes.
#[derive(Clone, Debug)]
pub struct TaskResult {
    /// The task that was executed.
    pub task_id: TaskId,
    /// The agent that produced this result.
    pub agent_id: AgentId,
    /// Output bytes (empty if the task failed).
    pub output: Vec<u8>,
    /// Arbitrary metadata key-value pairs (e.g., timing, error messages).
    pub metadata: HashMap<String, String>,
    /// Unix timestamp (millis) when the result was produced.
    pub timestamp: u64,
    /// Whether the task succeeded.
    pub success: bool,
}

impl TaskResult {
    /// Create a successful result.
    pub fn success(task_id: TaskId, agent_id: AgentId, output: Vec<u8>) -> Self {
        Self {
            task_id,
            agent_id,
            output,
            metadata: HashMap::new(),
            timestamp: now_millis(),
            success: true,
        }
    }

    /// Create a failed result with an error message.
    pub fn failure(task_id: TaskId, agent_id: AgentId, error: &str) -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("error".to_string(), error.to_string());
        Self {
            task_id,
            agent_id,
            output: Vec::new(),
            metadata,
            timestamp: now_millis(),
            success: false,
        }
    }

    /// Add a metadata key-value pair.
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Compute the SHA-256 hash of the output bytes.
    ///
    /// Returns `[0u8; 32]` for empty output (failed tasks).
    pub fn output_hash(&self) -> [u8; 32] {
        let hash = Sha256::digest(&self.output);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        arr
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
// AggregationStrategy
// ──────────────────────────────────────────────────────────────────────

/// Strategy for aggregating results from parallel task executions.
#[derive(Clone, Debug)]
pub enum AggregationStrategy {
    /// Return the first successful result. If no results succeed, return
    /// an error.
    FirstSuccess,
    /// All results must succeed. The outputs are merged using the
    /// configured merge function (or concatenation if none is set).
    AllRequired,
    /// Wait for at least `n` results, then pick the one with the highest
    /// verifier score (or the first if no verifier is set).
    BestOfN(usize),
    /// Wait until at least `n` results agree on the output hash, then
    /// return one of the agreeing results.
    Quorum(usize),
}

impl Default for AggregationStrategy {
    fn default() -> Self {
        Self::FirstSuccess
    }
}

// ──────────────────────────────────────────────────────────────────────
// ResultVerifier
// ──────────────────────────────────────────────────────────────────────

/// A pluggable callback that validates or scores a [`TaskResult`].
///
/// The verifier returns a `f64` score in `[0.0, 1.0]`:
/// - `0.0` — the result is invalid and should be discarded.
/// - `1.0` — the result is perfect.
/// - Values in between indicate partial validity.
pub type ResultVerifier = Arc<dyn Fn(&TaskResult) -> f64 + Send + Sync>;

/// A function that merges multiple output byte vectors into one.
pub type MergeFn = Arc<dyn Fn(&[Vec<u8>]) -> Vec<u8> + Send + Sync>;

/// Concatenate all output byte vectors in order.
fn default_merge(outputs: &[Vec<u8>]) -> Vec<u8> {
    let total_len = outputs.iter().map(|o| o.len()).sum();
    let mut merged = Vec::with_capacity(total_len);
    for o in outputs {
        merged.extend_from_slice(o);
    }
    merged
}

// ──────────────────────────────────────────────────────────────────────
// AggregationConfig
// ──────────────────────────────────────────────────────────────────────

/// Configuration for the [`ResultAggregator`].
#[derive(Clone)]
pub struct AggregationConfig {
    /// The aggregation strategy to use.
    pub strategy: AggregationStrategy,
    /// Timeout for collecting results (in milliseconds). Zero means no
    /// timeout.
    pub timeout_ms: u64,
    /// Minimum number of results required before aggregation can proceed.
    pub min_results: usize,
    /// Optional verification callback. If set, results with a score of
    /// `0.0` are discarded.
    pub verifier: Option<ResultVerifier>,
    /// Optional merge function for combining outputs. Defaults to
    /// concatenation.
    pub merge_fn: Option<MergeFn>,
}

impl std::fmt::Debug for AggregationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregationConfig")
            .field("strategy", &self.strategy)
            .field("timeout_ms", &self.timeout_ms)
            .field("min_results", &self.min_results)
            .field("verifier", &self.verifier.is_some())
            .field("merge_fn", &self.merge_fn.is_some())
            .finish()
    }
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            strategy: AggregationStrategy::FirstSuccess,
            timeout_ms: 30_000,
            min_results: 1,
            verifier: None,
            merge_fn: None,
        }
    }
}

impl AggregationConfig {
    /// Create a config with the given strategy.
    pub fn new(strategy: AggregationStrategy) -> Self {
        Self {
            strategy,
            ..Self::default()
        }
    }

    /// Set the timeout in milliseconds.
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set the minimum number of results.
    pub fn with_min_results(mut self, n: usize) -> Self {
        self.min_results = n;
        self
    }

    /// Set the verification callback.
    pub fn with_verifier(mut self, verifier: ResultVerifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Set the merge function.
    pub fn with_merge_fn(mut self, merge_fn: MergeFn) -> Self {
        self.merge_fn = Some(merge_fn);
        self
    }
}

// ──────────────────────────────────────────────────────────────────────
// AggregationOutcome
// ──────────────────────────────────────────────────────────────────────

/// The outcome of an aggregation operation.
#[derive(Clone, Debug)]
pub struct AggregationOutcome {
    /// The aggregated output bytes (empty if aggregation failed).
    pub output: Vec<u8>,
    /// All results that were collected (both successful and failed).
    pub results: Vec<TaskResult>,
    /// Whether the aggregation succeeded.
    pub success: bool,
    /// Human-readable description of the outcome (e.g., "first_success",
    /// "quorum_reached", "all_required_failed").
    pub reason: String,
    /// The agent that produced the selected output (if any).
    pub selected_agent: Option<AgentId>,
}

impl AggregationOutcome {
    /// Create a successful outcome.
    pub fn success(output: Vec<u8>, results: Vec<TaskResult>, reason: &str) -> Self {
        let selected_agent = results
            .iter()
            .find(|r| r.success && r.output == output)
            .map(|r| r.agent_id.clone());
        Self {
            output,
            results,
            success: true,
            reason: reason.to_string(),
            selected_agent,
        }
    }

    /// Create a failed outcome.
    pub fn failure(results: Vec<TaskResult>, reason: &str) -> Self {
        Self {
            output: Vec::new(),
            results,
            success: false,
            reason: reason.to_string(),
            selected_agent: None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// ResultAggregator
// ──────────────────────────────────────────────────────────────────────

/// Collects and aggregates results from parallel task executions.
///
/// The aggregator is parameterized by an [`AggregationConfig`] that
/// specifies the strategy, timeout, minimum results, optional verifier,
/// and optional merge function.
///
/// # Thread Safety
///
/// The aggregator uses an internal `RwLock` for the collected results,
/// making it safe to share across threads (e.g., multiple agents reporting
/// results concurrently).
pub struct ResultAggregator {
    /// Configuration for this aggregator.
    config: AggregationConfig,
    /// Collected results in insertion order. If a result from the same
    /// agent already exists, it is replaced in-place.
    results: RwLock<Vec<TaskResult>>,
    /// When aggregation started (for timeout enforcement).
    start_time: RwLock<Option<Instant>>,
}

impl std::fmt::Debug for ResultAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let results_count = self
            .results
            .read()
            .expect("results read lock poisoned")
            .len();
        f.debug_struct("ResultAggregator")
            .field("config", &self.config)
            .field("results_count", &results_count)
            .finish()
    }
}

impl ResultAggregator {
    /// Create a new aggregator with the given configuration.
    pub fn new(config: AggregationConfig) -> Self {
        Self {
            config,
            results: RwLock::new(Vec::new()),
            start_time: RwLock::new(None),
        }
    }

    /// Create a new aggregator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AggregationConfig::default())
    }

    /// Get a reference to the aggregator's configuration.
    pub fn config(&self) -> &AggregationConfig {
        &self.config
    }

    /// Submit a result to the aggregator.
    ///
    /// If a result from the same agent already exists, it is replaced.
    /// Starts the timeout clock on the first submission if not already
    /// started.
    pub fn submit(&self, result: TaskResult) {
        // Start the timeout clock on first submission.
        {
            let mut start = self.start_time.write().expect("start_time lock poisoned");
            if start.is_none() {
                *start = Some(Instant::now());
            }
        }
        let mut results = self.results.write().expect("results write lock poisoned");
        // Replace existing result from the same agent, or append.
        if let Some(existing) = results.iter_mut().find(|r| r.agent_id == result.agent_id) {
            *existing = result;
        } else {
            results.push(result);
        }
    }

    /// Submit a result, but only if the verifier accepts it (score > 0.0).
    ///
    /// If no verifier is configured, this is equivalent to [`submit`](Self::submit).
    /// Returns `true` if the result was accepted, `false` if it was rejected
    /// by the verifier.
    pub fn submit_verified(&self, result: TaskResult) -> bool {
        if let Some(ref verifier) = self.config.verifier {
            if verifier(&result) <= 0.0 {
                return false;
            }
        }
        self.submit(result);
        true
    }

    /// Get a snapshot of all collected results.
    pub fn results(&self) -> Vec<TaskResult> {
        let results = self.results.read().expect("results read lock poisoned");
        results.clone()
    }

    /// Get the number of results collected so far.
    pub fn count(&self) -> usize {
        self.results
            .read()
            .expect("results read lock poisoned")
            .len()
    }

    /// Get the number of successful results collected so far.
    pub fn success_count(&self) -> usize {
        self.results
            .read()
            .expect("results read lock poisoned")
            .iter()
            .filter(|r| r.success)
            .count()
    }

    /// Check if the timeout has been exceeded.
    ///
    /// Returns `false` if no results have been submitted yet (the clock
    /// hasn't started) or if `timeout_ms` is zero.
    pub fn is_timed_out(&self) -> bool {
        if self.config.timeout_ms == 0 {
            return false;
        }
        let start = self.start_time.read().expect("start_time lock poisoned");
        match *start {
            Some(start_time) => {
                start_time.elapsed() >= Duration::from_millis(self.config.timeout_ms)
            }
            None => false,
        }
    }

    /// Clear all collected results and reset the timeout clock.
    pub fn clear(&self) {
        let mut results = self.results.write().expect("results write lock poisoned");
        results.clear();
        let mut start = self.start_time.write().expect("start_time lock poisoned");
        *start = None;
    }

    // ── Aggregation ──

    /// Aggregate the collected results according to the configured strategy.
    ///
    /// This is a synchronous, non-blocking call — it aggregates whatever
    /// results have been collected so far. If the minimum number of results
    /// has not been reached and the timeout has not expired, this returns
    /// a failure outcome with reason `"insufficient_results"`.
    pub fn aggregate(&self) -> AggregationOutcome {
        let results = self.results();

        // Check for empty results first.
        if results.is_empty() {
            return AggregationOutcome::failure(results, "no_results");
        }

        // Check minimum results.
        if results.len() < self.config.min_results && !self.is_timed_out() {
            return AggregationOutcome::failure(results, "insufficient_results");
        }

        match self.config.strategy {
            AggregationStrategy::FirstSuccess => self.aggregate_first_success(results),
            AggregationStrategy::AllRequired => self.aggregate_all_required(results),
            AggregationStrategy::BestOfN(n) => self.aggregate_best_of_n(results, n),
            AggregationStrategy::Quorum(n) => self.aggregate_quorum(results, n),
        }
    }

    /// FirstSuccess: return the first successful result.
    fn aggregate_first_success(&self, results: Vec<TaskResult>) -> AggregationOutcome {
        // Sort by timestamp to get the earliest successful result.
        let mut sorted = results.clone();
        sorted.sort_by_key(|r| r.timestamp);

        for r in &sorted {
            if r.success && self.verify_passes(r) {
                return AggregationOutcome::success(r.output.clone(), results, "first_success");
            }
        }
        AggregationOutcome::failure(results, "no_successful_results")
    }

    /// AllRequired: all results must succeed; merge outputs.
    fn aggregate_all_required(&self, results: Vec<TaskResult>) -> AggregationOutcome {
        let successful: Vec<&TaskResult> = results
            .iter()
            .filter(|r| r.success && self.verify_passes(r))
            .collect();

        if successful.len() < results.len() {
            let failed_count = results.len() - successful.len();
            let reason = format!("all_required_failed ({failed_count} failures)");
            return AggregationOutcome::failure(results, &reason);
        }

        let merged = self.merge_outputs(&successful);
        AggregationOutcome::success(merged, results, "all_required_merged")
    }

    /// BestOfN: wait for N results, pick the one with the highest score.
    fn aggregate_best_of_n(&self, results: Vec<TaskResult>, n: usize) -> AggregationOutcome {
        let successful: Vec<&TaskResult> = results
            .iter()
            .filter(|r| r.success && self.verify_passes(r))
            .collect();

        if successful.is_empty() {
            return AggregationOutcome::failure(results, "best_of_n_no_success");
        }

        if successful.len() < n && !self.is_timed_out() {
            return AggregationOutcome::failure(results, "best_of_n_insufficient");
        }

        // Score each result and pick the best.
        let best = if let Some(ref verifier) = self.config.verifier {
            let mut scored: Vec<(f64, &TaskResult)> =
                successful.iter().map(|r| (verifier(r), *r)).collect();
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            scored[0].1
        } else {
            // No verifier — pick the first successful result.
            successful[0]
        };

        AggregationOutcome::success(best.output.clone(), results, "best_of_n_selected")
    }

    /// Quorum: wait until N results agree on the output hash.
    fn aggregate_quorum(&self, results: Vec<TaskResult>, n: usize) -> AggregationOutcome {
        let successful: Vec<&TaskResult> = results
            .iter()
            .filter(|r| r.success && self.verify_passes(r))
            .collect();

        if successful.is_empty() {
            return AggregationOutcome::failure(results, "quorum_no_success");
        }

        // Group by output hash.
        let mut groups: HashMap<[u8; 32], Vec<&TaskResult>> = HashMap::new();
        for r in &successful {
            groups.entry(r.output_hash()).or_default().push(*r);
        }

        // Find the largest group (sort by group size descending).
        let mut groups_vec: Vec<Vec<&TaskResult>> = groups.into_values().collect();
        groups_vec.sort_by_key(|v| std::cmp::Reverse(v.len()));

        let best_group = &groups_vec[0];

        if best_group.len() >= n {
            return AggregationOutcome::success(
                best_group[0].output.clone(),
                results,
                "quorum_reached",
            );
        }

        if self.is_timed_out() {
            // Timeout — return the largest group if it has at least one
            // result (partial result support).
            if !best_group.is_empty() {
                return AggregationOutcome::success(
                    best_group[0].output.clone(),
                    results,
                    "quorum_partial_timeout",
                );
            }
            return AggregationOutcome::failure(results, "quorum_timeout_no_agreement");
        }

        AggregationOutcome::failure(results, "quorum_not_reached")
    }

    // ── Merge ──

    /// Merge multiple task outputs into one using the configured merge
    /// function, or concatenation if none is set.
    pub fn merge_outputs(&self, results: &[&TaskResult]) -> Vec<u8> {
        let outputs: Vec<Vec<u8>> = results.iter().map(|r| r.output.clone()).collect();
        self.merge_byte_outputs(&outputs)
    }

    /// Merge raw byte vectors using the configured merge function.
    fn merge_byte_outputs(&self, outputs: &[Vec<u8>]) -> Vec<u8> {
        if outputs.is_empty() {
            return Vec::new();
        }
        if outputs.len() == 1 {
            return outputs[0].clone();
        }
        match &self.config.merge_fn {
            Some(f) => f(outputs),
            None => default_merge(outputs),
        }
    }

    /// Check if a result passes the verifier (or returns true if no
    /// verifier is configured).
    fn verify_passes(&self, result: &TaskResult) -> bool {
        match &self.config.verifier {
            Some(verifier) => verifier(result) > 0.0,
            None => true,
        }
    }

    /// Verify a single result using the configured verifier.
    ///
    /// Returns `0.0` if no verifier is configured (meaning "no score
    /// available", not "invalid").
    pub fn verify(&self, result: &TaskResult) -> f64 {
        match &self.config.verifier {
            Some(verifier) => verifier(result),
            None => 0.0,
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

    fn make_success_result(task_seed: &[u8], agent_byte: u8, output: Vec<u8>) -> TaskResult {
        TaskResult::success(make_task_id(task_seed), make_agent_id(agent_byte), output)
    }

    fn make_failure_result(task_seed: &[u8], agent_byte: u8, error: &str) -> TaskResult {
        TaskResult::failure(make_task_id(task_seed), make_agent_id(agent_byte), error)
    }

    fn make_verifier(min_len: usize) -> ResultVerifier {
        Arc::new(move |r: &TaskResult| {
            if !r.success {
                return 0.0;
            }
            if r.output.len() < min_len {
                return 0.0;
            }
            1.0
        })
    }

    fn make_scoring_verifier() -> ResultVerifier {
        Arc::new(|r: &TaskResult| {
            if !r.success {
                return 0.0;
            }
            // Score = output length as fraction of 100.
            (r.output.len() as f64 / 100.0).min(1.0)
        })
    }

    fn make_merge_fn() -> MergeFn {
        Arc::new(|outputs: &[Vec<u8>]| {
            let mut merged = Vec::new();
            for (i, o) in outputs.iter().enumerate() {
                if i > 0 {
                    merged.push(b',');
                }
                merged.extend_from_slice(o);
            }
            merged
        })
    }

    // ── 1. TaskResult::success construction ──

    #[test]
    fn test_task_result_success_construction() {
        let result = make_success_result(b"task1", 1, vec![1, 2, 3]);
        assert!(result.success);
        assert_eq!(result.output, vec![1, 2, 3]);
        assert!(result.metadata.is_empty());
        assert_eq!(result.agent_id, make_agent_id(1));
    }

    // ── 2. TaskResult::failure construction ──

    #[test]
    fn test_task_result_failure_construction() {
        let result = make_failure_result(b"task1", 1, "timeout");
        assert!(!result.success);
        assert!(result.output.is_empty());
        assert_eq!(result.metadata.get("error"), Some(&"timeout".to_string()));
    }

    // ── 3. TaskResult::with_metadata ──

    #[test]
    fn test_task_result_with_metadata() {
        let result = make_success_result(b"task1", 1, vec![1])
            .with_metadata("latency_ms", "42")
            .with_metadata("model", "gpt-4");
        assert_eq!(result.metadata.get("latency_ms"), Some(&"42".to_string()));
        assert_eq!(result.metadata.get("model"), Some(&"gpt-4".to_string()));
    }

    // ── 4. TaskResult::output_hash consistency ──

    #[test]
    fn test_task_result_output_hash_consistency() {
        let r1 = make_success_result(b"task1", 1, vec![1, 2, 3]);
        let r2 = make_success_result(b"task1", 2, vec![1, 2, 3]);
        assert_eq!(r1.output_hash(), r2.output_hash());
    }

    // ── 5. TaskResult::output_hash differs for different outputs ──

    #[test]
    fn test_task_result_output_hash_differs() {
        let r1 = make_success_result(b"task1", 1, vec![1, 2, 3]);
        let r2 = make_success_result(b"task1", 2, vec![4, 5, 6]);
        assert_ne!(r1.output_hash(), r2.output_hash());
    }

    // ── 6. FirstSuccess strategy — returns first successful ──

    #[test]
    fn test_first_success_returns_first_successful() {
        let agg = ResultAggregator::new(AggregationConfig::new(AggregationStrategy::FirstSuccess));
        agg.submit(make_failure_result(b"task1", 1, "error"));
        agg.submit(make_success_result(b"task1", 2, vec![10, 20]));
        agg.submit(make_success_result(b"task1", 3, vec![30, 40]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![10, 20]);
        assert_eq!(outcome.reason, "first_success");
    }

    // ── 7. FirstSuccess strategy — no successful results ──

    #[test]
    fn test_first_success_no_successful_results() {
        let agg = ResultAggregator::new(AggregationConfig::new(AggregationStrategy::FirstSuccess));
        agg.submit(make_failure_result(b"task1", 1, "error1"));
        agg.submit(make_failure_result(b"task1", 2, "error2"));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "no_successful_results");
    }

    // ── 8. FirstSuccess strategy — empty results ──

    #[test]
    fn test_first_success_empty_results() {
        let agg = ResultAggregator::new(AggregationConfig::new(AggregationStrategy::FirstSuccess));
        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "no_results");
    }

    // ── 9. AllRequired strategy — all succeed, outputs merged ──

    #[test]
    fn test_all_required_all_succeed_merged() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::AllRequired).with_min_results(2),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 2, vec![3, 4]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1, 2, 3, 4]);
        assert_eq!(outcome.reason, "all_required_merged");
    }

    // ── 10. AllRequired strategy — some fail ──

    #[test]
    fn test_all_required_some_fail() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::AllRequired).with_min_results(2),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_failure_result(b"task1", 2, "error"));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert!(outcome.reason.contains("all_required_failed"));
    }

    // ── 11. AllRequired strategy — custom merge function ──

    #[test]
    fn test_all_required_custom_merge() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::AllRequired)
                .with_min_results(2)
                .with_merge_fn(make_merge_fn()),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 2, vec![3, 4]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1, 2, b',', 3, 4]);
    }

    // ── 12. BestOfN strategy — picks highest score ──

    #[test]
    fn test_best_of_n_picks_highest_score() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::BestOfN(2))
                .with_verifier(make_scoring_verifier()),
        );
        // Agent 1: output of length 50 → score 0.5
        agg.submit(make_success_result(b"task1", 1, vec![0u8; 50]));
        // Agent 2: output of length 80 → score 0.8
        agg.submit(make_success_result(b"task1", 2, vec![0u8; 80]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output.len(), 80);
        assert_eq!(outcome.reason, "best_of_n_selected");
    }

    // ── 13. BestOfN strategy — insufficient results ──

    #[test]
    fn test_best_of_n_insufficient_results() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::BestOfN(3)).with_timeout_ms(0), // no timeout so it won't time out
        );
        agg.submit(make_success_result(b"task1", 1, vec![1]));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "best_of_n_insufficient");
    }

    // ── 14. BestOfN strategy — no successful results ──

    #[test]
    fn test_best_of_n_no_success() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::BestOfN(2)).with_timeout_ms(0),
        );
        agg.submit(make_failure_result(b"task1", 1, "error"));
        agg.submit(make_failure_result(b"task1", 2, "error"));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "best_of_n_no_success");
    }

    // ── 15. Quorum strategy — quorum reached ──

    #[test]
    fn test_quorum_reached() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::Quorum(2)).with_min_results(3),
        );
        // Three agents, two agree on output [1,2,3].
        agg.submit(make_success_result(b"task1", 1, vec![1, 2, 3]));
        agg.submit(make_success_result(b"task1", 2, vec![1, 2, 3]));
        agg.submit(make_success_result(b"task1", 3, vec![9, 9, 9]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1, 2, 3]);
        assert_eq!(outcome.reason, "quorum_reached");
    }

    // ── 16. Quorum strategy — quorum not reached ──

    #[test]
    fn test_quorum_not_reached() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::Quorum(3))
                .with_min_results(3)
                .with_timeout_ms(0),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 2, vec![3, 4]));
        agg.submit(make_success_result(b"task1", 3, vec![5, 6]));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "quorum_not_reached");
    }

    // ── 17. Quorum strategy — no successful results ──

    #[test]
    fn test_quorum_no_success() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::Quorum(2)).with_min_results(2),
        );
        agg.submit(make_failure_result(b"task1", 1, "error"));
        agg.submit(make_failure_result(b"task1", 2, "error"));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "quorum_no_success");
    }

    // ── 18. Verifier rejects invalid results ──

    #[test]
    fn test_verifier_rejects_invalid_results() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess)
                .with_verifier(make_verifier(10)),
        );
        // Output too short — verifier returns 0.0.
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        // Output long enough — verifier returns 1.0.
        agg.submit(make_success_result(b"task1", 2, vec![0u8; 20]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output.len(), 20);
    }

    // ── 19. submit_verified rejects invalid results ──

    #[test]
    fn test_submit_verified_rejects_invalid() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess)
                .with_verifier(make_verifier(10)),
        );
        // This should be rejected (output too short).
        let accepted = agg.submit_verified(make_success_result(b"task1", 1, vec![1, 2]));
        assert!(!accepted);
        assert_eq!(agg.count(), 0);

        // This should be accepted.
        let accepted = agg.submit_verified(make_success_result(b"task1", 2, vec![0u8; 20]));
        assert!(accepted);
        assert_eq!(agg.count(), 1);
    }

    // ── 20. Insufficient results (below min_results) ──

    #[test]
    fn test_insufficient_results() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess)
                .with_min_results(3)
                .with_timeout_ms(0),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1]));

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "insufficient_results");
    }

    // ── 21. Timeout enforcement ──

    #[test]
    fn test_timeout_enforcement() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess)
                .with_min_results(5)
                .with_timeout_ms(1), // 1ms timeout
        );
        agg.submit(make_success_result(b"task1", 1, vec![1]));

        // Wait for timeout to elapse.
        std::thread::sleep(Duration::from_millis(10));

        // Now aggregation should proceed despite insufficient results
        // (because we've timed out).
        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1]);
    }

    // ── 22. is_timed_out returns false before any submission ──

    #[test]
    fn test_is_timed_out_before_submission() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess).with_timeout_ms(100),
        );
        assert!(!agg.is_timed_out());
    }

    // ── 23. is_timed_out returns false when timeout_ms is zero ──

    #[test]
    fn test_is_timed_out_zero_timeout() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess).with_timeout_ms(0),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1]));
        assert!(!agg.is_timed_out());
    }

    // ── 24. clear resets the aggregator ──

    #[test]
    fn test_clear_resets_aggregator() {
        let agg = ResultAggregator::with_defaults();
        agg.submit(make_success_result(b"task1", 1, vec![1]));
        agg.submit(make_success_result(b"task1", 2, vec![2]));
        assert_eq!(agg.count(), 2);

        agg.clear();
        assert_eq!(agg.count(), 0);

        let outcome = agg.aggregate();
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "no_results");
    }

    // ── 25. success_count tracks successful results ──

    #[test]
    fn test_success_count() {
        let agg = ResultAggregator::with_defaults();
        agg.submit(make_success_result(b"task1", 1, vec![1]));
        agg.submit(make_failure_result(b"task1", 2, "error"));
        agg.submit(make_success_result(b"task1", 3, vec![3]));
        assert_eq!(agg.count(), 3);
        assert_eq!(agg.success_count(), 2);
    }

    // ── 26. Quorum partial result on timeout ──

    #[test]
    fn test_quorum_partial_timeout() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::Quorum(3))
                .with_min_results(2)
                .with_timeout_ms(1),
        );
        // Two agents agree, but quorum is 3.
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 2, vec![1, 2]));

        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(10));

        let outcome = agg.aggregate();
        // Timeout — should return partial result from the largest group.
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1, 2]);
        assert_eq!(outcome.reason, "quorum_partial_timeout");
    }

    // ── 27. merge_outputs with single result ──

    #[test]
    fn test_merge_outputs_single() {
        let agg = ResultAggregator::with_defaults();
        let r = make_success_result(b"task1", 1, vec![1, 2, 3]);
        let merged = agg.merge_outputs(&[&r]);
        assert_eq!(merged, vec![1, 2, 3]);
    }

    // ── 28. merge_outputs with empty slice ──

    #[test]
    fn test_merge_outputs_empty() {
        let agg = ResultAggregator::with_defaults();
        let merged = agg.merge_outputs(&[]);
        assert!(merged.is_empty());
    }

    // ── 29. AggregationOutcome::success sets selected_agent ──

    #[test]
    fn test_outcome_success_sets_selected_agent() {
        let agent = make_agent_id(5);
        let result = TaskResult::success(make_task_id(b"t"), agent.clone(), vec![1, 2]);
        let outcome = AggregationOutcome::success(vec![1, 2], vec![result], "first_success");
        assert_eq!(outcome.selected_agent, Some(agent));
    }

    // ── 30. AggregationOutcome::failure has no selected_agent ──

    #[test]
    fn test_outcome_failure_no_selected_agent() {
        let outcome = AggregationOutcome::failure(vec![], "test_failure");
        assert!(outcome.selected_agent.is_none());
        assert!(!outcome.success);
    }

    // ── 31. Config builder methods ──

    #[test]
    fn test_config_builder_methods() {
        let config = AggregationConfig::new(AggregationStrategy::BestOfN(3))
            .with_timeout_ms(5000)
            .with_min_results(2)
            .with_verifier(make_verifier(1))
            .with_merge_fn(make_merge_fn());

        assert!(matches!(config.strategy, AggregationStrategy::BestOfN(3)));
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.min_results, 2);
        assert!(config.verifier.is_some());
        assert!(config.merge_fn.is_some());
    }

    // ── 32. Default merge concatenates in order ──

    #[test]
    fn test_default_merge_concatenates() {
        let outputs = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let merged = default_merge(&outputs);
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 6]);
    }

    // ── 33. verify returns 0.0 without verifier ──

    #[test]
    fn test_verify_without_verifier() {
        let agg = ResultAggregator::with_defaults();
        let r = make_success_result(b"task1", 1, vec![1]);
        assert_eq!(agg.verify(&r), 0.0);
    }

    // ── 34. verify returns score with verifier ──

    #[test]
    fn test_verify_with_verifier() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::FirstSuccess)
                .with_verifier(make_scoring_verifier()),
        );
        let r = make_success_result(b"task1", 1, vec![0u8; 50]);
        assert!((agg.verify(&r) - 0.5).abs() < 0.001);
    }

    // ── 35. Debug formatting does not panic ──

    #[test]
    fn test_debug_formatting() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::Quorum(2)).with_verifier(make_verifier(1)),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1]));
        let debug_str = format!("{agg:?}");
        assert!(debug_str.contains("ResultAggregator"));
        assert!(debug_str.contains("results_count: 1"));
    }

    // ── 36. Submit replaces existing result from same agent ──

    #[test]
    fn test_submit_replaces_existing() {
        let agg = ResultAggregator::with_defaults();
        let agent = make_agent_id(1);
        agg.submit(make_success_result(b"task1", 1, vec![1]));
        agg.submit(make_success_result(b"task1", 1, vec![2, 3]));
        assert_eq!(agg.count(), 1);

        let outcome = agg.aggregate();
        assert_eq!(outcome.output, vec![2, 3]);
    }

    // ── 37. Quorum with all agents agreeing ──

    #[test]
    fn test_quorum_all_agree() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::Quorum(3)).with_min_results(3),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 2, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 3, vec![1, 2]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1, 2]);
        assert_eq!(outcome.reason, "quorum_reached");
    }

    // ── 38. BestOfN without verifier picks first successful ──

    #[test]
    fn test_best_of_n_without_verifier() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::BestOfN(2)).with_min_results(2),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));
        agg.submit(make_success_result(b"task1", 2, vec![3, 4]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        // Without verifier, picks the first successful result.
        assert!(!outcome.output.is_empty());
        assert_eq!(outcome.reason, "best_of_n_selected");
    }

    // ── 39. AggregationConfig default values ──

    #[test]
    fn test_config_defaults() {
        let config = AggregationConfig::default();
        assert!(matches!(config.strategy, AggregationStrategy::FirstSuccess));
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.min_results, 1);
        assert!(config.verifier.is_none());
        assert!(config.merge_fn.is_none());
    }

    // ── 40. AggregationStrategy default ──

    #[test]
    fn test_strategy_default() {
        let strategy = AggregationStrategy::default();
        assert!(matches!(strategy, AggregationStrategy::FirstSuccess));
    }

    // ── 41. results() returns snapshot ──

    #[test]
    fn test_results_snapshot() {
        let agg = ResultAggregator::with_defaults();
        agg.submit(make_success_result(b"task1", 1, vec![1]));
        agg.submit(make_success_result(b"task1", 2, vec![2]));

        let snapshot = agg.results();
        assert_eq!(snapshot.len(), 2);

        // Modifying the snapshot should not affect the aggregator.
        let _ = agg.count();
        assert_eq!(agg.count(), 2);
    }

    // ── 42. AllRequired with single result ──

    #[test]
    fn test_all_required_single_result() {
        let agg = ResultAggregator::new(
            AggregationConfig::new(AggregationStrategy::AllRequired).with_min_results(1),
        );
        agg.submit(make_success_result(b"task1", 1, vec![1, 2]));

        let outcome = agg.aggregate();
        assert!(outcome.success);
        assert_eq!(outcome.output, vec![1, 2]);
    }
}
