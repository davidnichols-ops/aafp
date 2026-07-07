//! Migration manager — migrates execution plan state between schema versions.
//!
//! The [`MigrationManager`] transforms [`ExecutionPlan`]s and [`Checkpoint`]s
//! from older schema versions to the current version. Migrations are
//! registered as a chain of [`PlanMigration`] steps (e.g., v1→v2→v3), and
//! the manager automatically chains multiple steps when migrating across
//! several versions.
//!
//! # Registration
//!
//! Each migration is registered via
//! [`register_migration`](MigrationManager::register_migration) with a
//! `from_version`, `to_version`, and a transform function. The transform
//! takes an `ExecutionPlan` at `from_version` and returns one at
//! `to_version`.
//!
//! # Version Chains
//!
//! If a direct migration path doesn't exist (e.g., v1→v3), the manager
//! searches for an intermediate chain (v1→v2→v3) using BFS over the
//! registered migration graph.
//!
//! # CBOR Encoding
//!
//! Migrations operate on the in-memory [`ExecutionPlan`] struct. The
//! [`migrate_checkpoint`](MigrationManager::migrate_checkpoint) method
//! handles deserializing a checkpoint, migrating its underlying plan, and
//! re-serializing.

use crate::execution::checkpoint::{Checkpoint, CHECKPOINT_VERSION};
use crate::execution::plan::ExecutionPlan;
use crate::SdkError;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

// ──────────────────────────────────────────────────────────────────────
// PlanMigration
// ──────────────────────────────────────────────────────────────────────

/// A function that transforms an [`ExecutionPlan`] from one version to another.
pub type MigrationFn = Box<dyn Fn(ExecutionPlan) -> ExecutionPlan + Send + Sync>;

/// A single migration step from one plan version to another.
///
/// The `transform` function takes an [`ExecutionPlan`] at `from_version`
/// and returns a new [`ExecutionPlan`] at `to_version`.
#[derive(Clone)]
pub struct PlanMigration {
    /// The source version.
    pub from_version: u32,
    /// The target version.
    pub to_version: u32,
    /// The transform function.
    pub transform: Arc<MigrationFn>,
}

impl std::fmt::Debug for PlanMigration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanMigration")
            .field("from_version", &self.from_version)
            .field("to_version", &self.to_version)
            .finish()
    }
}

impl PlanMigration {
    /// Create a new migration step.
    pub fn new<F>(from_version: u32, to_version: u32, transform: F) -> Self
    where
        F: Fn(ExecutionPlan) -> ExecutionPlan + Send + Sync + 'static,
    {
        Self {
            from_version,
            to_version,
            transform: Arc::new(Box::new(transform)),
        }
    }

    /// Apply this migration to a plan.
    ///
    /// Returns an error if the plan's version does not match `from_version`.
    pub fn apply(&self, plan: ExecutionPlan) -> Result<ExecutionPlan, SdkError> {
        if plan.version != self.from_version {
            return Err(SdkError::Messaging(format!(
                "PlanMigration: expected version {}, got {}",
                self.from_version, plan.version
            )));
        }
        let mut result = (self.transform)(plan);
        result.version = self.to_version;
        Ok(result)
    }
}

// ──────────────────────────────────────────────────────────────────────
// MigrationManager
// ──────────────────────────────────────────────────────────────────────

/// Manages migration of execution plans and checkpoints between schema versions.
///
/// Migrations are registered as a directed graph of version transitions.
/// When migrating from version A to version B, the manager searches for a
/// path through the graph (using BFS) and applies each step in sequence.
///
/// # Thread Safety
///
/// [`MigrationManager`] is thread-safe via an internal [`RwLock`] on the
/// migration registry. It can be shared across threads by wrapping in `Arc`.
pub struct MigrationManager {
    /// Registered migrations, keyed by (from_version, to_version).
    migrations: RwLock<HashMap<(u32, u32), PlanMigration>>,
    /// The current (latest) target version.
    current_version: u32,
}

impl MigrationManager {
    /// Create a new migration manager targeting `current_version`.
    pub fn new(current_version: u32) -> Self {
        Self {
            migrations: RwLock::new(HashMap::new()),
            current_version,
        }
    }

    /// Create a shared (`Arc`) migration manager.
    pub fn shared(current_version: u32) -> Arc<Self> {
        Arc::new(Self::new(current_version))
    }

    /// Get the current target version.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Register a migration path from `from_version` to `to_version`.
    ///
    /// If a migration for the same version pair already exists, it is
    /// replaced.
    pub fn register_migration(&self, migration: PlanMigration) {
        let mut guard = self
            .migrations
            .write()
            .expect("migrations write lock poisoned");
        guard.insert((migration.from_version, migration.to_version), migration);
    }

    /// Register a migration function directly.
    pub fn register<F>(&self, from_version: u32, to_version: u32, transform: F)
    where
        F: Fn(ExecutionPlan) -> ExecutionPlan + Send + Sync + 'static,
    {
        self.register_migration(PlanMigration::new(from_version, to_version, transform));
    }

    /// Find a chain of migrations from `from_version` to `to_version`.
    ///
    /// Uses BFS over the registered migration graph. Returns the ordered
    /// list of version steps (e.g., [1, 2, 3] for v1→v2→v3).
    fn find_path(&self, from_version: u32, to_version: u32) -> Result<Vec<u32>, SdkError> {
        if from_version == to_version {
            return Ok(vec![from_version]);
        }

        let guard = self
            .migrations
            .read()
            .expect("migrations read lock poisoned");

        // BFS: queue of (current_version, path_so_far).
        let mut queue: VecDeque<(u32, Vec<u32>)> = VecDeque::new();
        queue.push_back((from_version, vec![from_version]));
        let mut visited: HashSet<u32> = HashSet::new();
        visited.insert(from_version);

        while let Some((current, path)) = queue.pop_front() {
            // Find all migrations starting from `current`.
            for (&(from, to), _) in guard.iter() {
                if from == current && !visited.contains(&to) {
                    let mut new_path = path.clone();
                    new_path.push(to);
                    if to == to_version {
                        return Ok(new_path);
                    }
                    visited.insert(to);
                    queue.push_back((to, new_path));
                }
            }
        }

        Err(SdkError::Messaging(format!(
            "MigrationManager: no migration path from v{from_version} to v{to_version}"
        )))
    }

    /// Get the ordered list of migrations for a path.
    fn get_migrations_for_path(&self, path: &[u32]) -> Result<Vec<PlanMigration>, SdkError> {
        let guard = self
            .migrations
            .read()
            .expect("migrations read lock poisoned");
        let mut result = Vec::with_capacity(path.len().saturating_sub(1));
        for i in 0..path.len().saturating_sub(1) {
            let key = (path[i], path[i + 1]);
            let migration = guard.get(&key).ok_or_else(|| {
                SdkError::Messaging(format!(
                    "MigrationManager: missing migration v{}→v{}",
                    path[i],
                    path[i + 1]
                ))
            })?;
            result.push(migration.clone());
        }
        Ok(result)
    }

    /// Migrate an execution plan to the current version.
    ///
    /// If the plan is already at the current version, it is returned
    /// unchanged. Otherwise, the manager finds a chain of migrations
    /// and applies them in sequence.
    pub fn migrate_plan(&self, plan: ExecutionPlan) -> Result<ExecutionPlan, SdkError> {
        self.migrate_plan_to(plan, self.current_version)
    }

    /// Migrate an execution plan to a specific target version.
    pub fn migrate_plan_to(
        &self,
        plan: ExecutionPlan,
        target_version: u32,
    ) -> Result<ExecutionPlan, SdkError> {
        if plan.version == target_version {
            return Ok(plan);
        }

        let path = self.find_path(plan.version, target_version)?;
        let migrations = self.get_migrations_for_path(&path)?;

        let mut current = plan;
        for migration in migrations {
            current = migration.apply(current)?;
        }
        Ok(current)
    }

    /// Migrate a checkpoint to the current checkpoint version.
    ///
    /// This updates the checkpoint's `version` field. The checkpoint's
    /// task statuses are version-independent (they use the same CBOR
    /// encoding across versions), so no task-level transformation is
    /// needed for checkpoint schema migrations.
    pub fn migrate_checkpoint(
        &self,
        mut checkpoint: Checkpoint,
        target_version: u32,
    ) -> Result<Checkpoint, SdkError> {
        if checkpoint.version == target_version {
            return Ok(checkpoint);
        }
        // Checkpoint migrations are simple version bumps for now.
        // In the future, this could transform task status encoding.
        if checkpoint.version < target_version {
            checkpoint.version = target_version;
            Ok(checkpoint)
        } else {
            Err(SdkError::Messaging(format!(
                "MigrationManager: cannot downgrade checkpoint v{} to v{}",
                checkpoint.version, target_version
            )))
        }
    }

    /// Migrate a checkpoint to the current checkpoint version.
    pub fn migrate_checkpoint_to_current(
        &self,
        checkpoint: Checkpoint,
    ) -> Result<Checkpoint, SdkError> {
        self.migrate_checkpoint(checkpoint, CHECKPOINT_VERSION)
    }

    /// List all registered migration paths.
    pub fn registered_paths(&self) -> Vec<(u32, u32)> {
        let guard = self
            .migrations
            .read()
            .expect("migrations read lock poisoned");
        let mut paths: Vec<(u32, u32)> = guard.keys().copied().collect();
        paths.sort_by_key(|(from, to)| (*from, *to));
        paths
    }

    /// Check if a migration path exists between two versions.
    pub fn has_path(&self, from_version: u32, to_version: u32) -> bool {
        self.find_path(from_version, to_version).is_ok()
    }
}

impl Default for MigrationManager {
    fn default() -> Self {
        Self::new(CHECKPOINT_VERSION)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Built-in migration helpers
// ──────────────────────────────────────────────────────────────────────

/// Example migration: v1 → v2 (adds a default resource requirement if missing).
///
/// This is a no-op transform that just bumps the version. Real migrations
/// would modify task fields, add/remove tasks, or adjust edges.
pub fn v1_to_v2_transform(mut plan: ExecutionPlan) -> ExecutionPlan {
    // Example: ensure all tasks have at least 1 CPU core.
    for task in &mut plan.tasks {
        if task.resources.cpu_cores.is_none() {
            task.resources.cpu_cores = Some(1);
        }
    }
    plan
}

/// Example migration: v2 → v3 (ensures network flag is set for inference tasks).
pub fn v2_to_v3_transform(mut plan: ExecutionPlan) -> ExecutionPlan {
    for task in &mut plan.tasks {
        if task.capability == "inference" {
            task.resources.network = true;
        }
    }
    plan
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::plan::{DependencyType, PlanId, TaskNode, TaskStatus};

    // ── Helpers ──

    fn make_task(cap: &str, duration: u64) -> TaskNode {
        TaskNode::new(cap, vec![1, 2, 3], duration)
    }

    fn make_plan_v1(n: usize) -> ExecutionPlan {
        let tasks: Vec<TaskNode> = (0..n)
            .map(|i| make_task(&format!("task-{i}"), 100))
            .collect();
        let mut plan = ExecutionPlan::new("test-plan", tasks, vec![]);
        plan.version = 1;
        plan
    }

    fn make_plan_with_inference() -> ExecutionPlan {
        let tasks = vec![make_task("search", 100), make_task("inference", 200)];
        let mut plan = ExecutionPlan::new("inference-plan", tasks, vec![]);
        plan.version = 1;
        plan
    }

    // ── 1. Single-step migration (v1→v2) ──

    #[test]
    fn test_single_step_migration() {
        let mgr = MigrationManager::new(2);
        mgr.register(1, 2, v1_to_v2_transform);

        let plan = make_plan_v1(2);
        assert_eq!(plan.version, 1);

        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.version, 2);
        // v1_to_v2 adds default cpu_cores.
        assert_eq!(migrated.tasks[0].resources.cpu_cores, Some(1));
    }

    // ── 2. Multi-step chain (v1→v2→v3) ──

    #[test]
    fn test_multi_step_chain() {
        let mgr = MigrationManager::new(3);
        mgr.register(1, 2, v1_to_v2_transform);
        mgr.register(2, 3, v2_to_v3_transform);

        let plan = make_plan_with_inference();
        assert_eq!(plan.version, 1);

        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.version, 3);
        // v1_to_v2: cpu_cores set.
        assert_eq!(migrated.tasks[0].resources.cpu_cores, Some(1));
        // v2_to_v3: inference task has network=true.
        assert!(migrated.tasks[1].resources.network);
        assert_eq!(migrated.tasks[1].capability, "inference");
    }

    // ── 3. Missing migration path returns error ──

    #[test]
    fn test_missing_migration_path() {
        let mgr = MigrationManager::new(3);
        // Only register v1→v2, no v2→v3.
        mgr.register(1, 2, v1_to_v2_transform);

        let plan = make_plan_v1(2);
        let result = mgr.migrate_plan(plan);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no migration path"));
    }

    // ── 4. No migration needed (already at target) ──

    #[test]
    fn test_no_migration_needed() {
        let mgr = MigrationManager::new(3);
        mgr.register(1, 2, v1_to_v2_transform);
        mgr.register(2, 3, v2_to_v3_transform);

        let mut plan = make_plan_v1(2);
        plan.version = 3;

        let migrated = mgr.migrate_plan(plan.clone()).unwrap();
        assert_eq!(migrated.version, 3);
        // Should be unchanged.
        assert_eq!(migrated.tasks, plan.tasks);
    }

    // ── 5. Idempotent migration (migrating twice is a no-op) ──

    #[test]
    fn test_idempotent_migration() {
        let mgr = MigrationManager::new(2);
        mgr.register(1, 2, v1_to_v2_transform);

        let plan = make_plan_v1(2);
        let migrated1 = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated1.version, 2);

        // Migrate again — should be a no-op.
        let migrated2 = mgr.migrate_plan(migrated1.clone()).unwrap();
        assert_eq!(migrated2.version, 2);
        assert_eq!(migrated2.tasks, migrated1.tasks);
    }

    // ── 6. Migration applies version bump correctly ──

    #[test]
    fn test_migration_version_bump() {
        let mgr = MigrationManager::new(5);
        // Register a chain v1→v2→v3→v4→v5 with identity transforms.
        for v in 1..5 {
            mgr.register(v, v + 1, |p| p);
        }

        let plan = make_plan_v1(1);
        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.version, 5);
    }

    // ── 7. PlanMigration apply checks version ──

    #[test]
    fn test_plan_migration_apply_checks_version() {
        let migration = PlanMigration::new(1, 2, v1_to_v2_transform);

        let mut plan = make_plan_v1(2);
        plan.version = 5; // Wrong version.

        let result = migration.apply(plan);
        assert!(result.is_err());
    }

    // ── 8. PlanMigration apply sets target version ──

    #[test]
    fn test_plan_migration_apply_sets_version() {
        let migration = PlanMigration::new(1, 2, v1_to_v2_transform);

        let plan = make_plan_v1(2);
        let result = migration.apply(plan).unwrap();
        assert_eq!(result.version, 2);
    }

    // ── 9. Checkpoint migration (version bump) ──

    #[test]
    fn test_checkpoint_migration() {
        let mgr = MigrationManager::new(CHECKPOINT_VERSION);

        let checkpoint = Checkpoint {
            plan_id: PlanId([1u8; 32]),
            completed_tasks: vec![],
            created_at: 1000,
            version: 0, // Old version
        };

        let migrated = mgr.migrate_checkpoint_to_current(checkpoint).unwrap();
        assert_eq!(migrated.version, CHECKPOINT_VERSION);
    }

    // ── 10. Checkpoint already at current version ──

    #[test]
    fn test_checkpoint_already_current() {
        let mgr = MigrationManager::new(CHECKPOINT_VERSION);

        let checkpoint = Checkpoint {
            plan_id: PlanId([1u8; 32]),
            completed_tasks: vec![],
            created_at: 1000,
            version: CHECKPOINT_VERSION,
        };

        let migrated = mgr
            .migrate_checkpoint_to_current(checkpoint.clone())
            .unwrap();
        assert_eq!(migrated.version, checkpoint.version);
    }

    // ── 11. Checkpoint downgrade fails ──

    #[test]
    fn test_checkpoint_downgrade_fails() {
        let mgr = MigrationManager::new(CHECKPOINT_VERSION);

        let checkpoint = Checkpoint {
            plan_id: PlanId([1u8; 32]),
            completed_tasks: vec![],
            created_at: 1000,
            version: 100, // Future version
        };

        let result = mgr.migrate_checkpoint(checkpoint, 1);
        assert!(result.is_err());
    }

    // ── 12. has_path returns true for registered path ──

    #[test]
    fn test_has_path_true() {
        let mgr = MigrationManager::new(3);
        mgr.register(1, 2, v1_to_v2_transform);
        mgr.register(2, 3, v2_to_v3_transform);

        assert!(mgr.has_path(1, 3));
        assert!(mgr.has_path(1, 2));
        assert!(mgr.has_path(2, 3));
    }

    // ── 13. has_path returns false for missing path ──

    #[test]
    fn test_has_path_false() {
        let mgr = MigrationManager::new(3);
        mgr.register(1, 2, v1_to_v2_transform);
        // No v2→v3.

        assert!(!mgr.has_path(1, 3));
        assert!(!mgr.has_path(2, 3));
    }

    // ── 14. has_path same version is true ──

    #[test]
    fn test_has_path_same_version() {
        let mgr = MigrationManager::new(3);
        assert!(mgr.has_path(1, 1));
        assert!(mgr.has_path(3, 3));
    }

    // ── 15. registered_paths lists all ──

    #[test]
    fn test_registered_paths() {
        let mgr = MigrationManager::new(3);
        mgr.register(1, 2, v1_to_v2_transform);
        mgr.register(2, 3, v2_to_v3_transform);

        let paths = mgr.registered_paths();
        assert_eq!(paths, vec![(1, 2), (2, 3)]);
    }

    // ── 16. BFS finds shortest path ──

    #[test]
    fn test_bfs_shortest_path() {
        let mgr = MigrationManager::new(4);
        // Direct path v1→v4 and indirect v1→v2→v3→v4.
        mgr.register(1, 4, |p| p);
        mgr.register(1, 2, |p| p);
        mgr.register(2, 3, |p| p);
        mgr.register(3, 4, |p| p);

        let path = mgr.find_path(1, 4).unwrap();
        // BFS should find the direct path (length 2: [1, 4]).
        assert_eq!(path, vec![1, 4]);
    }

    // ── 17. Migration preserves plan ID ──

    #[test]
    fn test_migration_preserves_plan_id() {
        let mgr = MigrationManager::new(2);
        mgr.register(1, 2, v1_to_v2_transform);

        let plan = make_plan_v1(2);
        let original_id = plan.id.clone();
        let migrated = mgr.migrate_plan(plan).unwrap();

        assert_eq!(migrated.id, original_id);
    }

    // ── 18. Migration preserves task count ──

    #[test]
    fn test_migration_preserves_task_count() {
        let mgr = MigrationManager::new(3);
        mgr.register(1, 2, v1_to_v2_transform);
        mgr.register(2, 3, v2_to_v3_transform);

        let plan = make_plan_v1(5);
        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.tasks.len(), 5);
    }

    // ── 19. Migration with dependency edges preserved ──

    #[test]
    fn test_migration_preserves_edges() {
        let mgr = MigrationManager::new(2);
        mgr.register(1, 2, v1_to_v2_transform);

        let tasks = vec![make_task("a", 100), make_task("b", 200)];
        let edges = vec![(0, 1, DependencyType::DataDependency)];
        let mut plan = ExecutionPlan::new("edge-plan", tasks, edges);
        plan.version = 1;

        let migrated = mgr.migrate_plan(plan.clone()).unwrap();
        assert_eq!(migrated.edges.len(), 1);
        assert_eq!(migrated.edges[0].2, DependencyType::DataDependency);
    }

    // ── 20. Concurrent registration and migration ──

    #[test]
    fn test_concurrent_registration() {
        use std::thread;

        let mgr = Arc::new(MigrationManager::new(3));
        let mgr1 = Arc::clone(&mgr);
        let mgr2 = Arc::clone(&mgr);

        let h1 = thread::spawn(move || {
            mgr1.register(1, 2, v1_to_v2_transform);
        });
        let h2 = thread::spawn(move || {
            mgr2.register(2, 3, v2_to_v3_transform);
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let plan = make_plan_v1(2);
        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.version, 3);
    }

    // ── 21. Default MigrationManager ──

    #[test]
    fn test_default_migration_manager() {
        let mgr = MigrationManager::default();
        assert_eq!(mgr.current_version(), CHECKPOINT_VERSION);
    }

    // ── 22. Migration to specific target version ──

    #[test]
    fn test_migrate_to_specific_target() {
        let mgr = MigrationManager::new(5);
        mgr.register(1, 2, v1_to_v2_transform);
        mgr.register(2, 3, v2_to_v3_transform);

        let plan = make_plan_v1(2);
        // Migrate only to v3, not v5.
        let migrated = mgr.migrate_plan_to(plan, 3).unwrap();
        assert_eq!(migrated.version, 3);
    }

    // ── 23. Re-registering migration replaces old one ──

    #[test]
    fn test_reregister_migration() {
        let mgr = MigrationManager::new(2);
        mgr.register(1, 2, |mut p| {
            p.tasks[0].capability = "first".to_string();
            p
        });
        mgr.register(1, 2, |mut p| {
            p.tasks[0].capability = "second".to_string();
            p
        });

        let plan = make_plan_v1(2);
        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.tasks[0].capability, "second");
    }

    // ── 24. Migration with completed tasks preserves status ──

    #[test]
    fn test_migration_preserves_task_status() {
        let mgr = MigrationManager::new(2);
        mgr.register(1, 2, v1_to_v2_transform);

        let mut plan = make_plan_v1(2);
        plan.tasks[0].status = TaskStatus::Completed(vec![42]);

        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.tasks[0].status, TaskStatus::Completed(vec![42]));
    }

    // ── 25. Empty migration registry ──

    #[test]
    fn test_empty_registry() {
        let mgr = MigrationManager::new(3);
        assert!(mgr.registered_paths().is_empty());
        assert!(!mgr.has_path(1, 2));

        let plan = make_plan_v1(2);
        let result = mgr.migrate_plan(plan);
        assert!(result.is_err());
    }

    // ── 26. Shared (Arc) manager works ──

    #[test]
    fn test_shared_manager() {
        let mgr = MigrationManager::shared(2);
        mgr.register(1, 2, v1_to_v2_transform);

        let plan = make_plan_v1(2);
        let migrated = mgr.migrate_plan(plan).unwrap();
        assert_eq!(migrated.version, 2);
    }
}
