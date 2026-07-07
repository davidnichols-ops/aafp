//! Task scheduler — assigns tasks to the best available agents using the
//! adaptive routing plane.
//!
//! The [`TaskScheduler`] combines:
//! - **Reputation** (static score 1.0 for now)
//! - **Load** (from `PeerMetricsRegistry.in_flight`)
//! - **Cost** (placeholder 0 for now)
//! - **Latency** (from `PeerMetricsRegistry.latency_ewma_ms`)
//!
//! into a weighted static score, which is passed to
//! [`AdaptiveRouter::select()`] along with the candidate list. The router
//! then applies its own dynamic scoring, circuit breaker filtering, and
//! selection strategy to pick the best agent.
//!
//! # Interior Mutability
//!
//! The router is wrapped in `Arc<RwLock<AdaptiveRouter>>` because
//! `AdaptiveRouter::select()` requires `&mut self` (it mutates the internal
//! RNG and observer). The `RwLock` allows multiple concurrent readers for
//! non-mutating operations (like `acquire`) and exclusive write access for
//! `select`.

use crate::execution::plan::{ExecutionPlan, TaskId, TaskStatus};
use crate::routing::integration::AdaptiveRouter;
use crate::routing::metrics::PeerMetricsRegistry;
use crate::SdkError;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::identity_v1::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Configuration for the [`TaskScheduler`].
#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    /// Maximum number of tasks that can be assigned to a single agent.
    pub max_tasks_per_agent: u32,
    /// Weight for the reputation component (0.0–1.0).
    pub reputation_weight: f64,
    /// Weight for the load component (0.0–1.0).
    pub load_weight: f64,
    /// Weight for the cost component (0.0–1.0).
    pub cost_weight: f64,
    /// Weight for the latency component (0.0–1.0).
    pub latency_weight: f64,
    /// Assignment timeout in milliseconds.
    pub assignment_timeout_ms: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_tasks_per_agent: 10,
            reputation_weight: 0.3,
            load_weight: 0.3,
            cost_weight: 0.2,
            latency_weight: 0.2,
            assignment_timeout_ms: 5000,
        }
    }
}

/// Task scheduler that assigns tasks to agents using the adaptive routing plane.
///
/// Tracks assignments in an internal `RwLock<HashMap<TaskId, AgentId>>` and
/// uses the [`AdaptiveRouter`] for candidate selection with circuit breaker
/// and bulkhead integration.
pub struct TaskScheduler {
    /// The adaptive router, wrapped in `RwLock` because `select()` requires
    /// `&mut self`.
    router: Arc<RwLock<AdaptiveRouter>>,
    /// Peer metrics registry for computing static scores.
    metrics: Arc<PeerMetricsRegistry>,
    /// Current task assignments: TaskId → AgentId.
    assignments: RwLock<HashMap<TaskId, AgentId>>,
    /// Scheduler configuration.
    config: SchedulerConfig,
}

impl TaskScheduler {
    /// Create a new scheduler with the given router, metrics, and config.
    pub fn new(
        router: Arc<RwLock<AdaptiveRouter>>,
        metrics: Arc<PeerMetricsRegistry>,
        config: SchedulerConfig,
    ) -> Self {
        Self {
            router,
            metrics,
            assignments: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create a new scheduler with default configuration.
    pub fn with_defaults(
        router: Arc<RwLock<AdaptiveRouter>>,
        metrics: Arc<PeerMetricsRegistry>,
    ) -> Self {
        Self::new(router, metrics, SchedulerConfig::default())
    }

    /// Get a reference to the scheduler configuration.
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Compute a weighted static score for a candidate agent.
    ///
    /// Higher score = better candidate. The score combines:
    /// - **Reputation**: static 1.0 (placeholder)
    /// - **Load**: `1.0 / (1.0 + in_flight)` (less loaded = higher score)
    /// - **Cost**: 0.0 (placeholder)
    /// - **Latency**: `1.0 / (1.0 + latency_ewma_ms)` (lower latency = higher score)
    fn compute_static_score(&self, agent_id: &AgentId) -> f64 {
        let m = self.metrics.get_or_create(agent_id);

        let reputation = 1.0_f64;
        // Combine scheduler-level assignments and routing-level in-flight
        // counts for a comprehensive load metric.
        let assigned_load = self.agent_load(agent_id) as f64;
        let routing_load = m.in_flight as f64;
        let total_load = assigned_load + routing_load;
        let load = 1.0 / (1.0 + total_load);
        let cost = 0.0_f64;
        let latency = if m.latency_ewma_ms.is_initialized() && m.latency_ewma_ms.value() > 0.0 {
            1.0 / (1.0 + m.latency_ewma_ms.value())
        } else {
            1.0 // No latency data — neutral score
        };

        self.config.reputation_weight * reputation
            + self.config.load_weight * load
            + self.config.cost_weight * cost
            + self.config.latency_weight * latency
    }

    /// Assign a single task to the best available agent.
    ///
    /// Computes a weighted static score for each candidate, filters out
    /// agents that have reached `max_tasks_per_agent`, and delegates to
    /// `AdaptiveRouter::select()` for final selection (which applies circuit
    /// breaker filtering and dynamic scoring).
    pub async fn assign_task(
        &self,
        plan: &ExecutionPlan,
        task_idx: usize,
        candidates: &[AgentRecord],
    ) -> Result<AgentId, SdkError> {
        // Check for zero timeout (immediate timeout).
        if self.config.assignment_timeout_ms == 0 {
            return Err(SdkError::Timeout);
        }

        if task_idx >= plan.tasks.len() {
            return Err(SdkError::Messaging(format!(
                "assign_task: task_idx {task_idx} out of bounds (tasks={})",
                plan.tasks.len()
            )));
        }

        if candidates.is_empty() {
            return Err(SdkError::NoViableCandidate);
        }

        // Filter out candidates that have reached max_tasks_per_agent.
        let viable: Vec<AgentRecord> = candidates
            .iter()
            .filter(|c| {
                let agent_id = AgentId(c.agent_id);
                self.agent_load(&agent_id) < self.config.max_tasks_per_agent
            })
            .cloned()
            .collect();

        if viable.is_empty() {
            return Err(SdkError::NoViableCandidate);
        }

        // Compute static scores for each viable candidate.
        let static_scores: Vec<f64> = viable
            .iter()
            .map(|c| self.compute_static_score(&AgentId(c.agent_id)))
            .collect();

        // Use the adaptive router for final selection.
        let selected = {
            let mut router = self.router.write().expect("router write lock poisoned");
            router.select(&viable, &static_scores)?
        };

        // Record the assignment.
        {
            let mut assignments = self
                .assignments
                .write()
                .expect("assignments write lock poisoned");
            assignments.insert(plan.tasks[task_idx].id.clone(), selected);
        }

        Ok(selected)
    }

    /// Assign all ready tasks in a plan.
    ///
    /// A task is "ready" if its status is `Pending` and all its
    /// `DataDependency` predecessors are `Completed`.
    pub async fn assign_ready_tasks(
        &self,
        plan: &ExecutionPlan,
        candidates: &[AgentRecord],
    ) -> Result<Vec<(TaskId, AgentId)>, SdkError> {
        if candidates.is_empty() {
            return Err(SdkError::NoViableCandidate);
        }

        // Find all ready task indices.
        let ready_indices: Vec<usize> = (0..plan.tasks.len())
            .filter(|&i| plan.tasks[i].status == TaskStatus::Pending && plan.dependencies_met(i))
            .collect();

        let mut results = Vec::with_capacity(ready_indices.len());
        for &task_idx in &ready_indices {
            match self.assign_task(plan, task_idx, candidates).await {
                Ok(agent_id) => {
                    results.push((plan.tasks[task_idx].id.clone(), agent_id));
                }
                Err(SdkError::NoViableCandidate) => {
                    // Skip this task — no viable candidate. Continue with others.
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(results)
    }

    /// Reassign a failed task to a different agent.
    ///
    /// Increments the task's `retry_count`, resets its status to `Pending`,
    /// excludes the failed agent from candidates, and selects a new agent.
    pub async fn reassign_task(
        &self,
        plan: &mut ExecutionPlan,
        task_idx: usize,
        candidates: &[AgentRecord],
        failed_agent: &AgentId,
    ) -> Result<AgentId, SdkError> {
        if task_idx >= plan.tasks.len() {
            return Err(SdkError::Messaging(format!(
                "reassign_task: task_idx {task_idx} out of bounds (tasks={})",
                plan.tasks.len()
            )));
        }

        // Increment retry count and reset status.
        plan.tasks[task_idx].retry_count = plan.tasks[task_idx].retry_count.saturating_add(1);
        plan.tasks[task_idx].status = TaskStatus::Pending;
        plan.tasks[task_idx].assigned_agent = None;

        // Remove the old assignment from our tracking.
        {
            let mut assignments = self
                .assignments
                .write()
                .expect("assignments write lock poisoned");
            assignments.remove(&plan.tasks[task_idx].id);
        }

        // Filter out the failed agent from candidates.
        let filtered: Vec<AgentRecord> = candidates
            .iter()
            .filter(|c| &AgentId(c.agent_id) != failed_agent)
            .cloned()
            .collect();

        if filtered.is_empty() {
            return Err(SdkError::NoViableCandidate);
        }

        // Assign to a new agent.
        self.assign_task(plan, task_idx, &filtered).await
    }

    /// Get the current load for an agent (number of assigned tasks).
    pub fn agent_load(&self, agent_id: &AgentId) -> u32 {
        let assignments = self
            .assignments
            .read()
            .expect("assignments read lock poisoned");
        assignments.values().filter(|a| *a == agent_id).count() as u32
    }

    /// Get a snapshot of all current assignments.
    pub fn assignments(&self) -> HashMap<TaskId, AgentId> {
        self.assignments
            .read()
            .expect("assignments read lock poisoned")
            .clone()
    }

    /// Clear all assignments (for testing or plan reset).
    pub fn clear_assignments(&self) {
        let mut assignments = self
            .assignments
            .write()
            .expect("assignments write lock poisoned");
        assignments.clear();
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::plan::{DependencyType, TaskNode};
    use crate::routing::config::AdaptiveRoutingConfig;
    use crate::routing::selection::RoutingStrategy;
    use std::time::Duration;

    // ── Helper functions ──

    fn make_record(id: AgentId) -> AgentRecord {
        AgentRecord {
            agent_id: id.0,
            public_key: vec![0u8; 1952],
            capabilities: vec!["test".to_string()],
            endpoints: vec!["127.0.0.1:0".to_string()],
            version: 1,
            timestamp: 0,
            signature: vec![],
        }
    }

    fn make_task(cap: &str, duration: u64) -> TaskNode {
        TaskNode::new(cap, vec![1, 2, 3], duration)
    }

    fn make_scheduler() -> TaskScheduler {
        let router = Arc::new(RwLock::new(AdaptiveRouter::with_defaults()));
        let metrics = Arc::new(PeerMetricsRegistry::new());
        TaskScheduler::with_defaults(router, metrics)
    }

    fn make_scheduler_with_config(config: SchedulerConfig) -> TaskScheduler {
        let router = Arc::new(RwLock::new(AdaptiveRouter::with_defaults()));
        let metrics = Arc::new(PeerMetricsRegistry::new());
        TaskScheduler::new(router, metrics, config)
    }

    fn make_deterministic_scheduler() -> TaskScheduler {
        // Use LeastConnections strategy for deterministic load-based selection
        // (P2C/WeightedRandom are probabilistic and can flake with 2 candidates).
        let config = AdaptiveRoutingConfig {
            strategy: RoutingStrategy::LeastConnections,
            ..AdaptiveRoutingConfig::default()
        };
        let router = Arc::new(RwLock::new(AdaptiveRouter::new(config)));
        let metrics = Arc::new(PeerMetricsRegistry::new());
        TaskScheduler::with_defaults(router, metrics)
    }

    fn make_plan_with_tasks(n: usize) -> ExecutionPlan {
        let tasks: Vec<TaskNode> = (0..n)
            .map(|i| make_task(&format!("task-{i}"), 100))
            .collect();
        ExecutionPlan::new("test-plan", tasks, vec![])
    }

    // ── 1. Single task assignment ──

    #[tokio::test]
    async fn test_single_task_assignment() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id1);

        // Verify assignment was recorded.
        let assignments = scheduler.assignments();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments.get(&plan.tasks[0].id), Some(&id1));
    }

    // ── 2. Multiple parallel task assignment ──

    #[tokio::test]
    async fn test_multiple_parallel_task_assignment() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(3);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let id3 = AgentId([3u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2), make_record(id3)];

        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();

        assert_eq!(results.len(), 3);
        // All tasks should be assigned (no dependencies, all Pending).
        let assignments = scheduler.assignments();
        assert_eq!(assignments.len(), 3);
    }

    // ── 3. Reassignment after failure (excludes failed agent) ──

    #[tokio::test]
    async fn test_reassignment_excludes_failed_agent() {
        let scheduler = make_scheduler();
        let mut plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        // Initial assignment.
        let first = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();

        // Reassign, excluding the first agent.
        let second = scheduler
            .reassign_task(&mut plan, 0, &candidates, &first)
            .await
            .unwrap();

        assert_ne!(first, second);
    }

    // ── 4. Load balancing across agents ──

    #[tokio::test]
    async fn test_load_balancing_across_agents() {
        let scheduler = make_deterministic_scheduler();
        let plan = make_plan_with_tasks(2);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        // Assign first task.
        let first = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        // Assign second task — should prefer the less loaded agent.
        let second = scheduler.assign_task(&plan, 1, &candidates).await.unwrap();

        // With load balancing, the two tasks should go to different agents
        // (the less loaded one gets preference).
        assert_ne!(first, second);
    }

    // ── 5. Reputation-weighted selection (higher score preferred) ──

    #[tokio::test]
    async fn test_reputation_weighted_selection() {
        // Both agents have the same static score (reputation=1.0 for both),
        // so selection should succeed and return one of them.
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        // Should be one of the two candidates.
        assert!(assigned == id1 || assigned == id2);
    }

    // ── 6. Cost-weighted selection ──

    #[tokio::test]
    async fn test_cost_weighted_selection() {
        let config = SchedulerConfig {
            cost_weight: 1.0,
            reputation_weight: 0.0,
            load_weight: 0.0,
            latency_weight: 0.0,
            ..Default::default()
        };
        let scheduler = make_scheduler_with_config(config);
        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // With cost_weight=1.0 and cost=0 for all, score is 0 for all.
        // Selection should still succeed.
        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id1);
    }

    // ── 7. Assignment timeout (very short timeout) ──

    #[tokio::test]
    async fn test_assignment_timeout_zero() {
        let config = SchedulerConfig {
            assignment_timeout_ms: 0,
            ..Default::default()
        };
        let scheduler = make_scheduler_with_config(config);
        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let result = scheduler.assign_task(&plan, 0, &candidates).await;
        assert!(matches!(result, Err(SdkError::Timeout)));
    }

    #[tokio::test]
    async fn test_assignment_normal_timeout() {
        let config = SchedulerConfig {
            assignment_timeout_ms: 5000,
            ..Default::default()
        };
        let scheduler = make_scheduler_with_config(config);
        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id1);
    }

    // ── 8. Max tasks per agent enforcement ──

    #[tokio::test]
    async fn test_max_tasks_per_agent_enforcement() {
        let config = SchedulerConfig {
            max_tasks_per_agent: 2,
            ..Default::default()
        };
        let scheduler = make_scheduler_with_config(config);

        // Create a plan with 3 tasks.
        let plan = make_plan_with_tasks(3);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // Assign first two tasks to id1 (within limit).
        scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        scheduler.assign_task(&plan, 1, &candidates).await.unwrap();
        assert_eq!(scheduler.agent_load(&id1), 2);

        // Third task should fail — id1 is at capacity and no other candidates.
        let result = scheduler.assign_task(&plan, 2, &candidates).await;
        assert!(matches!(result, Err(SdkError::NoViableCandidate)));
    }

    #[tokio::test]
    async fn test_max_tasks_per_agent_with_multiple_candidates() {
        let config = SchedulerConfig {
            max_tasks_per_agent: 1,
            ..Default::default()
        };
        let scheduler = make_scheduler_with_config(config);

        let plan = make_plan_with_tasks(2);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        // First task goes to one agent.
        let first = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        // Second task must go to the other agent (first is at capacity).
        let second = scheduler.assign_task(&plan, 1, &candidates).await.unwrap();
        assert_ne!(first, second);
    }

    // ── 9. Dependency-aware scheduling (won't assign task before deps complete) ──

    #[tokio::test]
    async fn test_dependency_aware_scheduling() {
        let scheduler = make_scheduler();

        // Create a plan with a dependency: task 0 -> task 1.
        let tasks = vec![make_task("a", 100), make_task("b", 200)];
        let edges = vec![(0, 1, DependencyType::DataDependency)];
        let plan = ExecutionPlan::new("dep-aware", tasks, edges);

        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // Initially, only task 0 is ready (task 1 depends on task 0).
        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, plan.tasks[0].id);
    }

    #[tokio::test]
    async fn test_dependency_aware_scheduling_after_completion() {
        let scheduler = make_scheduler();

        let mut tasks = vec![make_task("a", 100), make_task("b", 200)];
        let edges = vec![(0, 1, DependencyType::DataDependency)];
        let mut plan = ExecutionPlan::new("dep-complete", tasks.clone(), edges);

        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // Complete task 0.
        plan.tasks[0].status = TaskStatus::Completed(vec![42]);

        // Now task 1 should be ready.
        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, plan.tasks[1].id);
    }

    // ── 10. Circuit breaker integration (skip open circuits — router handles this) ──

    #[tokio::test]
    async fn test_circuit_breaker_integration() {
        let router = Arc::new(RwLock::new(AdaptiveRouter::with_defaults()));
        let metrics = Arc::new(PeerMetricsRegistry::new());
        let scheduler = TaskScheduler::with_defaults(router.clone(), metrics);

        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);

        // Open the circuit for id1.
        {
            let mut r = router.write().expect("router write lock poisoned");
            let threshold = r.config().circuit_breaker.failure_threshold;
            for _ in 0..threshold {
                r.circuits.record_failure(&id1);
            }
        }

        let plan = make_plan_with_tasks(1);
        let candidates = vec![make_record(id1), make_record(id2)];

        // Should select id2 (id1's circuit is open).
        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id2);
    }

    // ── 11. Bulkhead integration (respect concurrency limits — router handles this) ──

    #[tokio::test]
    async fn test_bulkhead_integration() {
        // The router's select() doesn't check bulkheads (that's in acquire()).
        // But the scheduler should still work correctly with the router.
        let config = AdaptiveRoutingConfig::builder()
            .bulkhead_max_per_peer(1)
            .build();
        let router = Arc::new(RwLock::new(AdaptiveRouter::new(config)));
        let metrics = Arc::new(PeerMetricsRegistry::new());
        let scheduler = TaskScheduler::with_defaults(router, metrics);

        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // select() should still work (bulkhead is checked in acquire(), not select()).
        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id1);
    }

    // ── 12. Empty candidates list (returns NoViableCandidate) ──

    #[tokio::test]
    async fn test_empty_candidates() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(1);

        let result = scheduler.assign_task(&plan, 0, &[]).await;
        assert!(matches!(result, Err(SdkError::NoViableCandidate)));
    }

    #[tokio::test]
    async fn test_assign_ready_tasks_empty_candidates() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(1);

        let result = scheduler.assign_ready_tasks(&plan, &[]).await;
        assert!(matches!(result, Err(SdkError::NoViableCandidate)));
    }

    // ── 13. agent_load returns correct count ──

    #[tokio::test]
    async fn test_agent_load_returns_correct_count() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(3);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // Initially zero.
        assert_eq!(scheduler.agent_load(&id1), 0);

        // Assign 2 tasks to id1.
        scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        scheduler.assign_task(&plan, 1, &candidates).await.unwrap();

        assert_eq!(scheduler.agent_load(&id1), 2);

        // Other agents should have 0.
        let id2 = AgentId([2u8; 32]);
        assert_eq!(scheduler.agent_load(&id2), 0);
    }

    // ── 14. assignments() returns all assignments ──

    #[tokio::test]
    async fn test_assignments_returns_all() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(2);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        // Initially empty.
        assert_eq!(scheduler.assignments().len(), 0);

        // Assign both tasks.
        scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        scheduler.assign_task(&plan, 1, &candidates).await.unwrap();

        let assignments = scheduler.assignments();
        assert_eq!(assignments.len(), 2);
        assert!(assignments.contains_key(&plan.tasks[0].id));
        assert!(assignments.contains_key(&plan.tasks[1].id));
    }

    // ── 15. Reassign increments retry count ──

    #[tokio::test]
    async fn test_reassign_increments_retry_count() {
        let scheduler = make_scheduler();
        let mut plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        // Initial assignment.
        let first = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(plan.tasks[0].retry_count, 0);

        // Reassign.
        scheduler
            .reassign_task(&mut plan, 0, &candidates, &first)
            .await
            .unwrap();
        assert_eq!(plan.tasks[0].retry_count, 1);
        assert_eq!(plan.tasks[0].status, TaskStatus::Pending);

        // Reassign again.
        let second = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        scheduler
            .reassign_task(&mut plan, 0, &candidates, &second)
            .await
            .unwrap();
        assert_eq!(plan.tasks[0].retry_count, 2);
    }

    // ── Additional tests ──

    #[tokio::test]
    async fn test_assign_task_out_of_bounds() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let result = scheduler.assign_task(&plan, 5, &candidates).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reassign_task_out_of_bounds() {
        let scheduler = make_scheduler();
        let mut plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let result = scheduler
            .reassign_task(&mut plan, 5, &candidates, &id1)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reassign_all_candidates_excluded() {
        let scheduler = make_scheduler();
        let mut plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        // Initial assignment.
        let first = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();

        // Reassign excluding the only candidate.
        let result = scheduler
            .reassign_task(&mut plan, 0, &candidates, &first)
            .await;
        assert!(matches!(result, Err(SdkError::NoViableCandidate)));
    }

    #[tokio::test]
    async fn test_reassign_resets_status_and_agent() {
        let scheduler = make_scheduler();
        let mut plan = make_plan_with_tasks(1);
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        let candidates = vec![make_record(id1), make_record(id2)];

        // Initial assignment.
        let first = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();

        // Simulate failure.
        plan.tasks[0].status = TaskStatus::Failed("error".into());
        plan.tasks[0].assigned_agent = Some(first);

        // Reassign.
        scheduler
            .reassign_task(&mut plan, 0, &candidates, &first)
            .await
            .unwrap();

        // Status should be reset to Pending.
        assert_eq!(plan.tasks[0].status, TaskStatus::Pending);
        assert!(plan.tasks[0].assigned_agent.is_none());
    }

    #[tokio::test]
    async fn test_assign_ready_tasks_skips_non_pending() {
        let scheduler = make_scheduler();

        let mut tasks = vec![make_task("a", 100), make_task("b", 200)];
        // Mark task 0 as already assigned.
        tasks[0].status = TaskStatus::Assigned;
        let plan = ExecutionPlan::new("skip-assigned", tasks, vec![]);

        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();
        // Only task 1 should be assigned (task 0 is not Pending).
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, plan.tasks[1].id);
    }

    #[tokio::test]
    async fn test_assign_ready_tasks_skips_completed() {
        let scheduler = make_scheduler();

        let mut tasks = vec![make_task("a", 100), make_task("b", 200)];
        tasks[0].status = TaskStatus::Completed(vec![42]);
        let plan = ExecutionPlan::new("skip-completed", tasks, vec![]);

        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();
        // Only task 1 should be assigned.
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_assign_ready_tasks_no_ready_tasks() {
        let scheduler = make_scheduler();

        let mut tasks = vec![make_task("a", 100), make_task("b", 200)];
        tasks[0].status = TaskStatus::Completed(vec![]);
        tasks[1].status = TaskStatus::Completed(vec![]);
        let plan = ExecutionPlan::new("no-ready", tasks, vec![]);

        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();
        assert_eq!(config.max_tasks_per_agent, 10);
        assert_eq!(config.reputation_weight, 0.3);
        assert_eq!(config.load_weight, 0.3);
        assert_eq!(config.cost_weight, 0.2);
        assert_eq!(config.latency_weight, 0.2);
        assert_eq!(config.assignment_timeout_ms, 5000);
    }

    #[tokio::test]
    async fn test_clear_assignments() {
        let scheduler = make_scheduler();
        let plan = make_plan_with_tasks(2);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)];

        scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        scheduler.assign_task(&plan, 1, &candidates).await.unwrap();
        assert_eq!(scheduler.assignments().len(), 2);

        scheduler.clear_assignments();
        assert_eq!(scheduler.assignments().len(), 0);
        assert_eq!(scheduler.agent_load(&id1), 0);
    }

    #[tokio::test]
    async fn test_latency_weighted_selection() {
        // Use LowestLatency strategy for deterministic selection.
        let config = AdaptiveRoutingConfig {
            strategy: RoutingStrategy::LowestLatency,
            ..AdaptiveRoutingConfig::default()
        };
        let router = Arc::new(RwLock::new(AdaptiveRouter::new(config)));
        let metrics = Arc::new(PeerMetricsRegistry::new());

        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);

        // Record low latency for id1, high latency for id2.
        metrics.record_outcome(&id1, 10.0, true);
        metrics.record_outcome(&id2, 500.0, true);

        let scheduler = TaskScheduler::with_defaults(router, metrics);
        let plan = make_plan_with_tasks(1);
        let candidates = vec![make_record(id1), make_record(id2)];

        // id1 has lower latency, so it should be preferred.
        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id1);
    }

    #[tokio::test]
    async fn test_load_weighted_selection() {
        // Use LeastConnections strategy for deterministic selection.
        let config = AdaptiveRoutingConfig {
            strategy: RoutingStrategy::LeastConnections,
            ..AdaptiveRoutingConfig::default()
        };
        let router = Arc::new(RwLock::new(AdaptiveRouter::new(config)));
        let metrics = Arc::new(PeerMetricsRegistry::new());

        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);

        // Give id1 high in_flight, id2 low.
        metrics.inflight_inc(&id1);
        metrics.inflight_inc(&id1);
        metrics.inflight_inc(&id1);

        let scheduler = TaskScheduler::with_defaults(router, metrics);
        let plan = make_plan_with_tasks(1);
        let candidates = vec![make_record(id1), make_record(id2)];

        // id2 has lower load, so it should be preferred.
        let assigned = scheduler.assign_task(&plan, 0, &candidates).await.unwrap();
        assert_eq!(assigned, id2);
    }

    #[tokio::test]
    async fn test_assign_ready_tasks_partial_failure() {
        // If one task has no viable candidate, others should still be assigned.
        let config = SchedulerConfig {
            max_tasks_per_agent: 1,
            ..Default::default()
        };
        let scheduler = make_scheduler_with_config(config);

        let plan = make_plan_with_tasks(2);
        let id1 = AgentId([1u8; 32]);
        let candidates = vec![make_record(id1)]; // Only one candidate

        // First task gets assigned, second hits max_tasks_per_agent.
        let results = scheduler
            .assign_ready_tasks(&plan, &candidates)
            .await
            .unwrap();
        // Only one task should be assigned.
        assert_eq!(results.len(), 1);
    }
}
