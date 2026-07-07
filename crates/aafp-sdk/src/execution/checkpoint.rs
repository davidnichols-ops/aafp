//! Checkpoint manager — saves and restores execution plan state for
//! crash recovery and resumption.
//!
//! The [`CheckpointManager`] persists [`Checkpoint`]s to disk as CBOR-encoded
//! files. Each checkpoint captures the plan ID, the set of completed tasks
//! with their results, and a timestamp. On restart, a checkpoint can be
//! restored into a fresh [`ExecutionPlan`] to resume execution from where
//! it left off.
//!
//! # Retention Policy
//!
//! A [`RetentionConfig`] controls how many checkpoints are kept and how long
//! they live. Calling [`apply_retention`](CheckpointManager::apply_retention)
//! prunes checkpoints that exceed either limit.
//!
//! # CBOR Encoding
//!
//! Checkpoints use integer-keyed CBOR maps (RFC 8949 deterministic encoding)
//! for on-disk persistence, consistent with the rest of the execution fabric.

use crate::execution::plan::{ExecutionPlan, PlanId, TaskId, TaskStatus};
use crate::SdkError;
use aafp_cbor::{decode, encode, int_map, int_map_get, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

// ──────────────────────────────────────────────────────────────────────
// Checkpoint
// ──────────────────────────────────────────────────────────────────────

/// A snapshot of execution plan state at a point in time.
///
/// Captures the plan ID and the set of completed tasks (with their output
/// bytes) so that execution can be resumed after a crash or restart.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    /// The plan this checkpoint belongs to.
    pub plan_id: PlanId,
    /// Completed task IDs with their final status (output bytes or failure).
    pub completed_tasks: Vec<(TaskId, TaskStatus)>,
    /// Unix timestamp (seconds) when the checkpoint was created.
    pub created_at: u64,
    /// Checkpoint schema version (for migration support).
    pub version: u32,
}

impl Checkpoint {
    /// Create a new checkpoint from an execution plan, capturing all
    /// tasks that are in a terminal state.
    ///
    /// Only `Completed`, `Failed`, and `Cancelled` tasks are captured —
    /// in-flight tasks are not checkpointed because they may need to be
    /// re-executed.
    pub fn from_plan(plan: &ExecutionPlan) -> Self {
        let completed_tasks: Vec<(TaskId, TaskStatus)> = plan
            .tasks
            .iter()
            .filter(|t| t.status.is_terminal())
            .map(|t| (t.id.clone(), t.status.clone()))
            .collect();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            plan_id: plan.id.clone(),
            completed_tasks,
            created_at,
            version: CHECKPOINT_VERSION,
        }
    }

    /// Apply this checkpoint's completed-task state to an execution plan.
    ///
    /// For each task in the plan that matches a captured task ID, the
    /// task's status is overwritten with the checkpointed status. Tasks
    /// not present in the checkpoint are left unchanged.
    ///
    /// Returns the number of tasks that were updated.
    pub fn apply_to_plan(&self, plan: &mut ExecutionPlan) -> usize {
        let mut status_map: HashMap<&TaskId, &TaskStatus> = HashMap::new();
        for (id, status) in &self.completed_tasks {
            status_map.insert(id, status);
        }
        let mut updated = 0usize;
        for task in &mut plan.tasks {
            if let Some(status) = status_map.get(&task.id) {
                task.status = (*status).clone();
                updated += 1;
            }
        }
        updated
    }

    /// Returns `true` if the checkpoint has no completed tasks.
    pub fn is_empty(&self) -> bool {
        self.completed_tasks.is_empty()
    }

    /// Returns the number of completed tasks in the checkpoint.
    pub fn len(&self) -> usize {
        self.completed_tasks.len()
    }

    /// Encode the checkpoint to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let entries: Vec<(i64, Value)> = vec![
            (1, Value::ByteString(self.plan_id.0.to_vec())),
            (
                2,
                Value::Array(
                    self.completed_tasks
                        .iter()
                        .map(|(id, status)| {
                            int_map(vec![
                                (1, Value::ByteString(id.0.to_vec())),
                                (2, status.to_cbor()),
                            ])
                        })
                        .collect(),
                ),
            ),
            (3, Value::Unsigned(self.created_at)),
            (4, Value::Unsigned(self.version as u64)),
        ];
        int_map(entries)
    }

    /// Decode a checkpoint from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let plan_id = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) => {
                if b.len() != 32 {
                    return Err(SdkError::Messaging(format!(
                        "Checkpoint: plan_id must be 32 bytes, got {}",
                        b.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                PlanId(arr)
            }
            _ => return Err(SdkError::Messaging("Checkpoint: missing plan_id".into())),
        };
        let completed_tasks = match int_map_get(val, 2) {
            Some(Value::Array(arr)) => {
                let mut tasks = Vec::with_capacity(arr.len());
                for item in arr {
                    let id = match int_map_get(item, 1) {
                        Some(Value::ByteString(b)) => {
                            if b.len() != 32 {
                                return Err(SdkError::Messaging(format!(
                                    "Checkpoint: task id must be 32 bytes, got {}",
                                    b.len()
                                )));
                            }
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(b);
                            TaskId(arr)
                        }
                        _ => return Err(SdkError::Messaging("Checkpoint: missing task id".into())),
                    };
                    let status = match int_map_get(item, 2) {
                        Some(v) => TaskStatus::from_cbor(v)?,
                        _ => {
                            return Err(SdkError::Messaging(
                                "Checkpoint: missing task status".into(),
                            ))
                        }
                    };
                    tasks.push((id, status));
                }
                tasks
            }
            _ => {
                return Err(SdkError::Messaging(
                    "Checkpoint: missing completed_tasks".into(),
                ))
            }
        };
        let created_at = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n,
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "Checkpoint: created_at not uint".into(),
                ))
            }
        };
        let version = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => {
                if *n > u32::MAX as u64 {
                    return Err(SdkError::Messaging("Checkpoint: version overflow".into()));
                }
                *n as u32
            }
            None => CHECKPOINT_VERSION,
            _ => return Err(SdkError::Messaging("Checkpoint: version not uint".into())),
        };
        Ok(Self {
            plan_id,
            completed_tasks,
            created_at,
            version,
        })
    }

    /// Serialize the checkpoint to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError> {
        encode(&self.to_cbor()).map_err(|e| SdkError::Messaging(format!("cbor encode: {e}")))
    }

    /// Deserialize a checkpoint from CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError> {
        let (val, consumed) =
            decode(data).map_err(|e| SdkError::Messaging(format!("cbor decode: {e}")))?;
        if consumed != data.len() {
            return Err(SdkError::Messaging(format!(
                "Checkpoint: {} trailing bytes after decode",
                data.len() - consumed
            )));
        }
        Self::from_cbor(&val)
    }
}

/// Current checkpoint schema version.
pub const CHECKPOINT_VERSION: u32 = 1;

// ──────────────────────────────────────────────────────────────────────
// RetentionConfig
// ──────────────────────────────────────────────────────────────────────

/// Retention policy for checkpoints.
///
/// Controls how many checkpoints are kept per plan and how long they
/// survive before being pruned by [`CheckpointManager::apply_retention`].
#[derive(Clone, Debug)]
pub struct RetentionConfig {
    /// Maximum number of checkpoints to retain (per plan). Older
    /// checkpoints beyond this count are deleted. `0` means unlimited.
    pub max_checkpoints: u32,
    /// Maximum age in seconds. Checkpoints older than this are deleted.
    /// `0` means no age-based expiry.
    pub max_age_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            max_checkpoints: 10,
            max_age_secs: 0,
        }
    }
}

impl RetentionConfig {
    /// Create a retention config with unlimited checkpoints and no age limit.
    pub fn unlimited() -> Self {
        Self {
            max_checkpoints: 0,
            max_age_secs: 0,
        }
    }

    /// Create a retention config that keeps only the most recent `n` checkpoints.
    pub fn keep_last(n: u32) -> Self {
        Self {
            max_checkpoints: n,
            max_age_secs: 0,
        }
    }

    /// Create a retention config that expires checkpoints after `secs` seconds.
    pub fn max_age(secs: u64) -> Self {
        Self {
            max_checkpoints: 0,
            max_age_secs: secs,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// CheckpointManager
// ──────────────────────────────────────────────────────────────────────

/// Manages saving and restoring execution plan checkpoints to disk.
///
/// Each checkpoint is stored as a CBOR file in a configurable directory,
/// named by the plan ID (hex-encoded) and a timestamp. The manager
/// supports listing, deleting, and applying retention policies.
///
/// # Thread Safety
///
/// [`CheckpointManager`] is thread-safe via an internal [`RwLock`] on the
/// retention config and a [`Mutex`] on directory operations. It can be
/// shared across threads by wrapping in `Arc`.
pub struct CheckpointManager {
    /// Directory where checkpoint files are stored.
    storage_dir: PathBuf,
    /// Retention policy (mutable at runtime).
    retention: RwLock<RetentionConfig>,
    /// Mutex to serialize file operations within the directory.
    file_lock: Mutex<()>,
    /// Monotonic counter to ensure unique filenames for concurrent saves.
    save_counter: AtomicU64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager that stores files in `storage_dir`.
    ///
    /// The directory is created if it does not exist.
    pub fn new(
        storage_dir: impl AsRef<Path>,
        retention: RetentionConfig,
    ) -> Result<Self, SdkError> {
        let storage_dir = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&storage_dir).map_err(SdkError::Io)?;
        Ok(Self {
            storage_dir,
            retention: RwLock::new(retention),
            file_lock: Mutex::new(()),
            save_counter: AtomicU64::new(0),
        })
    }

    /// Create a new checkpoint manager with default retention policy.
    pub fn with_defaults(storage_dir: impl AsRef<Path>) -> Result<Self, SdkError> {
        Self::new(storage_dir, RetentionConfig::default())
    }

    /// Create a shared (`Arc`) checkpoint manager.
    pub fn shared(
        storage_dir: impl AsRef<Path>,
        retention: RetentionConfig,
    ) -> Result<Arc<Self>, SdkError> {
        Ok(Arc::new(Self::new(storage_dir, retention)?))
    }

    /// Get a clone of the current retention config.
    pub fn retention(&self) -> RetentionConfig {
        self.retention
            .read()
            .expect("retention read lock poisoned")
            .clone()
    }

    /// Update the retention policy.
    pub fn set_retention(&self, config: RetentionConfig) {
        let mut guard = self
            .retention
            .write()
            .expect("retention write lock poisoned");
        *guard = config;
    }

    /// Save a checkpoint of the given execution plan to disk.
    ///
    /// Captures all terminal (completed/failed/cancelled) tasks and writes
    /// a CBOR file named `<plan_id_hex>_<timestamp>.ckpt`. Returns the
    /// plan ID.
    pub fn save_checkpoint(&self, plan: &ExecutionPlan) -> Result<PlanId, SdkError> {
        let checkpoint = Checkpoint::from_plan(plan);
        self.save_raw(&checkpoint)?;
        Ok(checkpoint.plan_id)
    }

    /// Save a pre-built checkpoint to disk.
    pub fn save_raw(&self, checkpoint: &Checkpoint) -> Result<(), SdkError> {
        let _lock = self.file_lock.lock().expect("file lock poisoned");
        let seq = self.save_counter.fetch_add(1, Ordering::SeqCst);
        let path = self.checkpoint_path(&checkpoint.plan_id, checkpoint.created_at, seq);
        let bytes = checkpoint.to_bytes()?;
        // Write atomically: write to temp file then rename.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &bytes).map_err(SdkError::Io)?;
        fs::rename(&tmp, &path).map_err(SdkError::Io)?;
        Ok(())
    }

    /// Restore the most recent checkpoint for a given plan ID.
    ///
    /// Returns `None` if no checkpoint exists for the plan.
    pub fn restore_checkpoint(&self, plan_id: &PlanId) -> Result<Option<Checkpoint>, SdkError> {
        let _lock = self.file_lock.lock().expect("file lock poisoned");
        let entries = self.list_checkpoints_for_plan(plan_id)?;
        if entries.is_empty() {
            return Ok(None);
        }
        // Most recent = highest timestamp.
        let (timestamp, _) = entries
            .into_iter()
            .max_by_key(|(ts, _)| *ts)
            .expect("entries is non-empty");
        let path = self
            .find_checkpoint_path(plan_id, timestamp)
            .ok_or_else(|| SdkError::Messaging("checkpoint file not found".into()))?;
        let data = fs::read(&path).map_err(SdkError::Io)?;
        let checkpoint = Checkpoint::from_bytes(&data)?;
        Ok(Some(checkpoint))
    }

    /// Restore a checkpoint and apply it to an execution plan in one step.
    ///
    /// If no checkpoint exists, the plan is returned unchanged.
    /// Returns `(checkpoint, num_tasks_updated)`.
    pub fn restore_into_plan(
        &self,
        plan_id: &PlanId,
        plan: &mut ExecutionPlan,
    ) -> Result<Option<(Checkpoint, usize)>, SdkError> {
        match self.restore_checkpoint(plan_id)? {
            Some(cp) => {
                let updated = cp.apply_to_plan(plan);
                Ok(Some((cp, updated)))
            }
            None => Ok(None),
        }
    }

    /// List all available checkpoints across all plans.
    ///
    /// Returns a vector of `(plan_id, timestamp)` pairs, sorted by
    /// timestamp ascending.
    pub fn list_checkpoints(&self) -> Result<Vec<(PlanId, u64)>, SdkError> {
        let _lock = self.file_lock.lock().expect("file lock poisoned");
        let mut results = Vec::new();
        let entries = match fs::read_dir(&self.storage_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SdkError::Io(e)),
        };
        for entry in entries {
            let entry = entry.map_err(SdkError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ckpt") {
                continue;
            }
            if let Some((plan_id, timestamp)) = self.parse_checkpoint_filename(&path) {
                results.push((plan_id, timestamp));
            }
        }
        results.sort_by_key(|(_, ts)| *ts);
        Ok(results)
    }

    /// List checkpoints for a specific plan ID.
    ///
    /// Returns `(timestamp, path)` pairs sorted by timestamp ascending.
    fn list_checkpoints_for_plan(&self, plan_id: &PlanId) -> Result<Vec<(u64, PathBuf)>, SdkError> {
        let prefix = hex::encode(plan_id.0);
        let mut results = Vec::new();
        let entries = match fs::read_dir(&self.storage_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SdkError::Io(e)),
        };
        for entry in entries {
            let entry = entry.map_err(SdkError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ckpt") {
                continue;
            }
            let fname = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            // Filename format: <plan_id_hex>_<timestamp>_<16-hex-seq>
            if let Some(rest) = fname.strip_prefix(format!("{prefix}_").as_str()) {
                // rest = "<timestamp>_<seq>" — extract the timestamp part.
                if let Some((ts_str, _)) = rest.split_once('_') {
                    if let Ok(timestamp) = ts_str.parse::<u64>() {
                        results.push((timestamp, path));
                    }
                }
            }
        }
        results.sort_by_key(|(ts, _)| *ts);
        Ok(results)
    }

    /// Delete a specific checkpoint identified by plan ID and timestamp.
    pub fn delete_checkpoint(&self, plan_id: &PlanId, timestamp: u64) -> Result<(), SdkError> {
        let _lock = self.file_lock.lock().expect("file lock poisoned");
        // There may be multiple files with the same plan_id+timestamp (from
        // concurrent saves). Delete all matching files.
        let prefix = format!("{}_{}", hex::encode(plan_id.0), timestamp);
        if let Ok(entries) = fs::read_dir(&self.storage_dir) {
            for entry in entries.flatten() {
                if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    if stem.starts_with(&prefix) {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    }

    /// Delete all checkpoints for a given plan ID.
    ///
    /// Returns the number of checkpoints deleted.
    pub fn delete_all_for_plan(&self, plan_id: &PlanId) -> Result<usize, SdkError> {
        let _lock = self.file_lock.lock().expect("file lock poisoned");
        let entries = self.list_checkpoints_for_plan(plan_id)?;
        let mut count = 0usize;
        for (_, path) in entries {
            match fs::remove_file(&path) {
                Ok(()) => count += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(SdkError::Io(e)),
            }
        }
        Ok(count)
    }

    /// Apply the retention policy, deleting checkpoints that exceed limits.
    ///
    /// - If `max_checkpoints > 0`, keeps only the most recent N checkpoints
    ///   per plan.
    /// - If `max_age_secs > 0`, deletes checkpoints older than the cutoff.
    ///
    /// Returns the total number of checkpoints deleted.
    pub fn apply_retention(&self) -> Result<usize, SdkError> {
        let config = self.retention();
        if config.max_checkpoints == 0 && config.max_age_secs == 0 {
            return Ok(0);
        }
        let _lock = self.file_lock.lock().expect("file lock poisoned");

        // Group checkpoints by plan ID.
        let all = self.list_checkpoints_unlocked()?;
        let mut by_plan: HashMap<PlanId, Vec<(u64, PathBuf)>> = HashMap::new();
        for (plan_id, timestamp) in all {
            if let Some(path) = self.find_checkpoint_path(&plan_id, timestamp) {
                by_plan.entry(plan_id).or_default().push((timestamp, path));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age_cutoff = now.saturating_sub(config.max_age_secs);

        let mut deleted = 0usize;
        for (_plan_id, mut entries) in by_plan {
            // Sort by timestamp descending (newest first).
            entries.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));

            for (i, (timestamp, path)) in entries.iter().enumerate() {
                let should_delete =
                    if config.max_checkpoints > 0 && i >= config.max_checkpoints as usize {
                        true
                    } else { config.max_age_secs > 0 && *timestamp < age_cutoff };

                if should_delete {
                    match fs::remove_file(path) {
                        Ok(()) => deleted += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(SdkError::Io(e)),
                    }
                }
            }
        }
        Ok(deleted)
    }

    /// Count the total number of checkpoints across all plans.
    pub fn count(&self) -> Result<usize, SdkError> {
        Ok(self.list_checkpoints()?.len())
    }

    // ── Internal helpers (no locking) ──

    /// Build the file path for a checkpoint.
    fn checkpoint_path(&self, plan_id: &PlanId, timestamp: u64, seq: u64) -> PathBuf {
        let filename = format!("{}_{}_{:016x}.ckpt", hex::encode(plan_id.0), timestamp, seq);
        self.storage_dir.join(filename)
    }

    /// Find the file path for a checkpoint by plan_id and timestamp.
    /// Since multiple files can share the same plan_id+timestamp (concurrent
    /// saves), this returns the first match.
    fn find_checkpoint_path(&self, plan_id: &PlanId, timestamp: u64) -> Option<PathBuf> {
        let prefix = format!("{}_{}", hex::encode(plan_id.0), timestamp);
        if let Ok(entries) = fs::read_dir(&self.storage_dir) {
            for entry in entries.flatten() {
                if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    if stem.starts_with(&prefix) && entry.path().extension().is_some() {
                        return Some(entry.path());
                    }
                }
            }
        }
        None
    }

    /// Parse a checkpoint filename into (plan_id, timestamp).
    fn parse_checkpoint_filename(&self, path: &Path) -> Option<(PlanId, u64)> {
        let stem = path.file_stem()?.to_str()?;
        // Format: <64-hex-chars>_<timestamp>_<16-hex-seq>
        // Split from the right to get seq, then from the right again for timestamp.
        let (rest, _seq) = stem.rsplit_once('_')?;
        let (hex_part, ts_part) = rest.rsplit_once('_')?;
        if hex_part.len() != 64 {
            return None;
        }
        let bytes = hex::decode(hex_part).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let timestamp = ts_part.parse::<u64>().ok()?;
        Some((PlanId(arr), timestamp))
    }

    /// List all checkpoints without acquiring the file lock.
    fn list_checkpoints_unlocked(&self) -> Result<Vec<(PlanId, u64)>, SdkError> {
        let mut results = Vec::new();
        let entries = match fs::read_dir(&self.storage_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SdkError::Io(e)),
        };
        for entry in entries {
            let entry = entry.map_err(SdkError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ckpt") {
                continue;
            }
            if let Some((plan_id, timestamp)) = self.parse_checkpoint_filename(&path) {
                results.push((plan_id, timestamp));
            }
        }
        results.sort_by_key(|(_, ts)| *ts);
        Ok(results)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::plan::{DependencyType, TaskNode};
    use std::thread;

    // ── Helpers ──

    fn make_task(cap: &str, duration: u64) -> TaskNode {
        TaskNode::new(cap, vec![1, 2, 3], duration)
    }

    fn make_plan(n: usize) -> ExecutionPlan {
        let tasks: Vec<TaskNode> = (0..n)
            .map(|i| make_task(&format!("task-{i}"), 100))
            .collect();
        ExecutionPlan::new("test-plan", tasks, vec![])
    }

    fn make_plan_with_deps() -> ExecutionPlan {
        let tasks = vec![
            make_task("a", 100),
            make_task("b", 200),
            make_task("c", 300),
        ];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (1, 2, DependencyType::DataDependency),
        ];
        ExecutionPlan::new("dep-plan", tasks, edges)
    }

    /// Create a unique temp directory for this test run.
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aafp_checkpoint_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ── 1. Basic save/restore roundtrip ──

    #[test]
    fn test_save_restore_roundtrip() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let mut plan = make_plan(3);
        plan.tasks[0].status = TaskStatus::Completed(vec![10]);
        plan.tasks[1].status = TaskStatus::Completed(vec![20]);

        let plan_id = mgr.save_checkpoint(&plan).unwrap();
        let restored = mgr.restore_checkpoint(&plan_id).unwrap().unwrap();

        assert_eq!(restored.plan_id, plan.id);
        assert_eq!(restored.completed_tasks.len(), 2);
        assert_eq!(restored.version, CHECKPOINT_VERSION);
    }

    // ── 2. Restore into a fresh plan updates task statuses ──

    #[test]
    fn test_restore_into_plan_updates_statuses() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let mut plan = make_plan(3);
        plan.tasks[0].status = TaskStatus::Completed(vec![10]);
        plan.tasks[1].status = TaskStatus::Completed(vec![20]);

        mgr.save_checkpoint(&plan).unwrap();

        // Create a fresh plan with same tasks (all Pending).
        let mut fresh = make_plan(3);
        // The fresh plan has the same IDs because TaskNode::new is deterministic.
        assert_eq!(fresh.tasks[0].id, plan.tasks[0].id);

        let result = mgr.restore_into_plan(&plan.id, &mut fresh).unwrap();
        assert!(result.is_some());
        let (_cp, updated) = result.unwrap();
        assert_eq!(updated, 2);
        assert_eq!(fresh.tasks[0].status, TaskStatus::Completed(vec![10]));
        assert_eq!(fresh.tasks[1].status, TaskStatus::Completed(vec![20]));
        // Task 2 should still be Pending.
        assert_eq!(fresh.tasks[2].status, TaskStatus::Pending);
    }

    // ── 3. Partial completion checkpoint ──

    #[test]
    fn test_partial_completion_checkpoint() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let mut plan = make_plan_with_deps();
        // Complete only task 0.
        plan.tasks[0].status = TaskStatus::Completed(vec![42]);

        let checkpoint = Checkpoint::from_plan(&plan);
        assert_eq!(checkpoint.len(), 1);
        assert!(!checkpoint.is_empty());

        mgr.save_raw(&checkpoint).unwrap();
        let restored = mgr.restore_checkpoint(&plan.id).unwrap().unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.completed_tasks[0].0, plan.tasks[0].id);
    }

    // ── 4. Empty checkpoint (no completed tasks) ──

    #[test]
    fn test_empty_checkpoint() {
        let plan = make_plan(3);
        let checkpoint = Checkpoint::from_plan(&plan);
        assert!(checkpoint.is_empty());
        assert_eq!(checkpoint.len(), 0);
    }

    // ── 5. CBOR roundtrip for Checkpoint ──

    #[test]
    fn test_checkpoint_cbor_roundtrip() {
        let mut plan = make_plan(2);
        plan.tasks[0].status = TaskStatus::Completed(vec![1, 2, 3]);
        plan.tasks[1].status = TaskStatus::Failed("error".into());

        let checkpoint = Checkpoint::from_plan(&plan);
        let bytes = checkpoint.to_bytes().unwrap();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();

        assert_eq!(restored.plan_id, checkpoint.plan_id);
        assert_eq!(restored.completed_tasks.len(), 2);
        assert_eq!(restored.created_at, checkpoint.created_at);
        assert_eq!(restored.version, checkpoint.version);
        assert_eq!(
            restored.completed_tasks[0].1,
            TaskStatus::Completed(vec![1, 2, 3])
        );
        assert_eq!(
            restored.completed_tasks[1].1,
            TaskStatus::Failed("error".into())
        );
    }

    // ── 6. CBOR roundtrip with all task status variants ──

    #[test]
    fn test_checkpoint_all_status_variants() {
        let mut plan = make_plan(4);
        plan.tasks[0].status = TaskStatus::Completed(vec![0xAA]);
        plan.tasks[1].status = TaskStatus::Failed("boom".into());
        plan.tasks[2].status = TaskStatus::Cancelled;
        // task 3 stays Pending (not terminal, won't be captured)

        let checkpoint = Checkpoint::from_plan(&plan);
        assert_eq!(checkpoint.len(), 3); // Pending is not terminal

        let bytes = checkpoint.to_bytes().unwrap();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 3);
    }

    // ── 7. Restore non-existent checkpoint returns None ──

    #[test]
    fn test_restore_nonexistent_returns_none() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let fake_id = PlanId([0xFF; 32]);
        let result = mgr.restore_checkpoint(&fake_id).unwrap();
        assert!(result.is_none());
    }

    // ── 8. List checkpoints ──

    #[test]
    fn test_list_checkpoints() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let plan1 = make_plan(2);
        let plan2 = make_plan_with_deps();

        // Save multiple checkpoints.
        mgr.save_checkpoint(&plan1).unwrap();
        // Small delay to ensure different timestamps.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        mgr.save_checkpoint(&plan2).unwrap();

        let list = mgr.list_checkpoints().unwrap();
        assert!(list.len() >= 2);
        // Should be sorted by timestamp.
        for i in 1..list.len() {
            assert!(list[i - 1].1 <= list[i].1);
        }
    }

    // ── 9. List checkpoints for specific plan ──

    #[test]
    fn test_list_checkpoints_for_plan() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let plan = make_plan(2);
        mgr.save_checkpoint(&plan).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        mgr.save_checkpoint(&plan).unwrap();

        let entries = mgr.list_checkpoints_for_plan(&plan.id).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted ascending.
        assert!(entries[0].0 <= entries[1].0);
    }

    // ── 10. Delete a specific checkpoint ──

    #[test]
    fn test_delete_checkpoint() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let mut plan = make_plan(2);
        plan.tasks[0].status = TaskStatus::Completed(vec![1]);
        mgr.save_checkpoint(&plan).unwrap();

        let entries = mgr.list_checkpoints_for_plan(&plan.id).unwrap();
        assert_eq!(entries.len(), 1);
        let timestamp = entries[0].0;

        mgr.delete_checkpoint(&plan.id, timestamp).unwrap();
        let entries2 = mgr.list_checkpoints_for_plan(&plan.id).unwrap();
        assert_eq!(entries2.len(), 0);
    }

    // ── 11. Delete non-existent checkpoint is a no-op ──

    #[test]
    fn test_delete_nonexistent_checkpoint_noop() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();
        // Should not error.
        mgr.delete_checkpoint(&PlanId([1u8; 32]), 99999).unwrap();
    }

    // ── 12. Delete all checkpoints for a plan ──

    #[test]
    fn test_delete_all_for_plan() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let plan = make_plan(2);
        mgr.save_checkpoint(&plan).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        mgr.save_checkpoint(&plan).unwrap();

        let deleted = mgr.delete_all_for_plan(&plan.id).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(mgr.list_checkpoints_for_plan(&plan.id).unwrap().len(), 0);
    }

    // ── 13. Retention: max_checkpoints ──

    #[test]
    fn test_retention_max_checkpoints() {
        let dir = temp_dir();
        let mgr = CheckpointManager::new(&dir, RetentionConfig::keep_last(2)).unwrap();

        let plan = make_plan(2);
        // Save 3 checkpoints with distinct timestamps.
        let cp1 = Checkpoint {
            plan_id: plan.id.clone(),
            completed_tasks: vec![],
            created_at: 1000,
            version: CHECKPOINT_VERSION,
        };
        mgr.save_raw(&cp1).unwrap();
        let cp2 = Checkpoint {
            plan_id: plan.id.clone(),
            completed_tasks: vec![],
            created_at: 2000,
            version: CHECKPOINT_VERSION,
        };
        mgr.save_raw(&cp2).unwrap();
        let cp3 = Checkpoint {
            plan_id: plan.id.clone(),
            completed_tasks: vec![],
            created_at: 3000,
            version: CHECKPOINT_VERSION,
        };
        mgr.save_raw(&cp3).unwrap();

        assert_eq!(mgr.list_checkpoints_for_plan(&plan.id).unwrap().len(), 3);

        let deleted = mgr.apply_retention().unwrap();
        assert_eq!(deleted, 1);
        // Only the 2 most recent should remain.
        let remaining = mgr.list_checkpoints_for_plan(&plan.id).unwrap();
        assert_eq!(remaining.len(), 2);
        // The oldest (1000) should be deleted.
        assert!(remaining.iter().all(|(ts, _)| *ts > 1000));
    }

    // ── 14. Retention: max_age ──

    #[test]
    fn test_retention_max_age() {
        let dir = temp_dir();
        let mgr = CheckpointManager::new(&dir, RetentionConfig::max_age(3600)).unwrap();

        let plan = make_plan(2);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Old checkpoint (should be deleted).
        let old = Checkpoint {
            plan_id: plan.id.clone(),
            completed_tasks: vec![],
            created_at: now.saturating_sub(7200),
            version: CHECKPOINT_VERSION,
        };
        mgr.save_raw(&old).unwrap();
        // Recent checkpoint (should survive).
        let recent = Checkpoint {
            plan_id: plan.id.clone(),
            completed_tasks: vec![],
            created_at: now,
            version: CHECKPOINT_VERSION,
        };
        mgr.save_raw(&recent).unwrap();

        let deleted = mgr.apply_retention().unwrap();
        assert_eq!(deleted, 1);
        let remaining = mgr.list_checkpoints_for_plan(&plan.id).unwrap();
        assert_eq!(remaining.len(), 1);
    }

    // ── 15. Retention: unlimited (no deletion) ──

    #[test]
    fn test_retention_unlimited() {
        let dir = temp_dir();
        let mgr = CheckpointManager::new(&dir, RetentionConfig::unlimited()).unwrap();

        let plan = make_plan(2);
        for i in 0..5 {
            let cp = Checkpoint {
                plan_id: plan.id.clone(),
                completed_tasks: vec![],
                created_at: 1000 + i,
                version: CHECKPOINT_VERSION,
            };
            mgr.save_raw(&cp).unwrap();
        }

        let deleted = mgr.apply_retention().unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(mgr.list_checkpoints_for_plan(&plan.id).unwrap().len(), 5);
    }

    // ── 16. Corruption recovery: invalid CBOR ──

    #[test]
    fn test_corruption_recovery_invalid_cbor() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let plan = make_plan(2);
        let path = mgr.checkpoint_path(&plan.id, 5000, 0);
        // Write garbage bytes.
        fs::write(&path, b"not valid cbor at all").unwrap();

        let result = mgr.restore_checkpoint(&plan.id);
        assert!(result.is_err());
    }

    // ── 17. Corruption recovery: truncated CBOR ──

    #[test]
    fn test_corruption_recovery_truncated() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let mut plan = make_plan(2);
        plan.tasks[0].status = TaskStatus::Completed(vec![1]);
        let cp = Checkpoint::from_plan(&plan);
        let full_bytes = cp.to_bytes().unwrap();
        // Truncate to half.
        let truncated = &full_bytes[..full_bytes.len() / 2];

        let path = mgr.checkpoint_path(&plan.id, cp.created_at, 0);
        fs::write(&path, truncated).unwrap();

        let result = mgr.restore_checkpoint(&plan.id);
        assert!(result.is_err());
    }

    // ── 18. Corruption recovery: valid CBOR but wrong structure ──

    #[test]
    fn test_corruption_recovery_wrong_structure() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let plan = make_plan(2);
        let path = mgr.checkpoint_path(&plan.id, 7000, 0);
        // Write a valid CBOR value that's not a checkpoint (just an unsigned int).
        let bad_val = Value::Unsigned(42);
        let bad_bytes = encode(&bad_val).unwrap();
        fs::write(&path, &bad_bytes).unwrap();

        let result = mgr.restore_checkpoint(&plan.id);
        assert!(result.is_err());
    }

    // ── 19. Concurrent access: multiple threads saving ──

    #[test]
    fn test_concurrent_save_access() {
        let dir = temp_dir();
        let mgr = Arc::new(CheckpointManager::with_defaults(&dir).unwrap());

        let plan = make_plan(2);
        let plan_id = plan.id.clone();

        let mut handles = Vec::new();
        for i in 0..4 {
            let mgr_clone = Arc::clone(&mgr);
            let plan_clone = plan.clone();
            let handle = thread::spawn(move || {
                let mut p = plan_clone;
                p.tasks[0].status = TaskStatus::Completed(vec![i as u8]);
                mgr_clone.save_checkpoint(&p)
            });
            handles.push(handle);
        }

        for h in handles {
            let result = h.join().unwrap();
            assert!(result.is_ok());
        }

        // All saves should have produced checkpoint files.
        let entries = mgr.list_checkpoints_for_plan(&plan_id).unwrap();
        assert_eq!(entries.len(), 4);
    }

    // ── 20. Concurrent access: save + list simultaneously ──

    #[test]
    fn test_concurrent_save_and_list() {
        let dir = temp_dir();
        let mgr = Arc::new(CheckpointManager::with_defaults(&dir).unwrap());

        let plan = make_plan(2);

        let mgr1 = Arc::clone(&mgr);
        let plan1 = plan.clone();
        let writer = thread::spawn(move || {
            for i in 0..3 {
                let mut p = plan1.clone();
                p.tasks[0].status = TaskStatus::Completed(vec![i as u8]);
                mgr1.save_checkpoint(&p).unwrap();
            }
        });

        let mgr2 = Arc::clone(&mgr);
        let reader = thread::spawn(move || {
            for _ in 0..5 {
                let _ = mgr2.list_checkpoints().unwrap();
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();

        // After both threads finish, we should have 3 checkpoints.
        let entries = mgr.list_checkpoints_for_plan(&plan.id).unwrap();
        assert_eq!(entries.len(), 3);
    }

    // ── 21. Count checkpoints ──

    #[test]
    fn test_count_checkpoints() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        assert_eq!(mgr.count().unwrap(), 0);

        let plan = make_plan(2);
        mgr.save_checkpoint(&plan).unwrap();

        assert_eq!(mgr.count().unwrap(), 1);
    }

    // ── 22. Retention config update at runtime ──

    #[test]
    fn test_retention_config_update() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        assert_eq!(mgr.retention().max_checkpoints, 10);

        mgr.set_retention(RetentionConfig::keep_last(3));
        assert_eq!(mgr.retention().max_checkpoints, 3);

        mgr.set_retention(RetentionConfig::unlimited());
        assert_eq!(mgr.retention().max_checkpoints, 0);
    }

    // ── 23. Multiple plans don't interfere ──

    #[test]
    fn test_multiple_plans_no_interference() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let plan1 = make_plan(2);
        let plan2 = make_plan_with_deps();

        mgr.save_checkpoint(&plan1).unwrap();
        mgr.save_checkpoint(&plan2).unwrap();

        let restored1 = mgr.restore_checkpoint(&plan1.id).unwrap().unwrap();
        let restored2 = mgr.restore_checkpoint(&plan2.id).unwrap().unwrap();

        assert_eq!(restored1.plan_id, plan1.id);
        assert_eq!(restored2.plan_id, plan2.id);
        assert_ne!(restored1.plan_id, restored2.plan_id);
    }

    // ── 24. Retention applies per-plan ──

    #[test]
    fn test_retention_per_plan() {
        let dir = temp_dir();
        let mgr = CheckpointManager::new(&dir, RetentionConfig::keep_last(1)).unwrap();

        let plan1 = make_plan(2);
        let plan2 = make_plan_with_deps();

        // 2 checkpoints for each plan.
        for i in 0..2 {
            let cp1 = Checkpoint {
                plan_id: plan1.id.clone(),
                completed_tasks: vec![],
                created_at: 1000 + i,
                version: CHECKPOINT_VERSION,
            };
            mgr.save_raw(&cp1).unwrap();
            let cp2 = Checkpoint {
                plan_id: plan2.id.clone(),
                completed_tasks: vec![],
                created_at: 1000 + i,
                version: CHECKPOINT_VERSION,
            };
            mgr.save_raw(&cp2).unwrap();
        }

        let deleted = mgr.apply_retention().unwrap();
        assert_eq!(deleted, 2); // one from each plan

        // Each plan should have 1 remaining.
        assert_eq!(mgr.list_checkpoints_for_plan(&plan1.id).unwrap().len(), 1);
        assert_eq!(mgr.list_checkpoints_for_plan(&plan2.id).unwrap().len(), 1);
    }

    // ── 25. Checkpoint with failed and cancelled tasks ──

    #[test]
    fn test_checkpoint_with_failed_and_cancelled() {
        let dir = temp_dir();
        let mgr = CheckpointManager::with_defaults(&dir).unwrap();

        let mut plan = make_plan(3);
        plan.tasks[0].status = TaskStatus::Failed("timeout".into());
        plan.tasks[1].status = TaskStatus::Cancelled;

        let cp = Checkpoint::from_plan(&plan);
        assert_eq!(cp.len(), 2);

        mgr.save_raw(&cp).unwrap();
        let restored = mgr.restore_checkpoint(&plan.id).unwrap().unwrap();

        // Verify statuses are preserved.
        let status_map: HashMap<_, _> = restored
            .completed_tasks
            .iter()
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        assert_eq!(
            status_map.get(&plan.tasks[0].id),
            Some(&TaskStatus::Failed("timeout".into()))
        );
        assert_eq!(
            status_map.get(&plan.tasks[1].id),
            Some(&TaskStatus::Cancelled)
        );
    }

    // ── 26. Directory creation ──

    #[test]
    fn test_directory_creation() {
        let dir = temp_dir().join("nested/deep/path");
        assert!(!dir.exists());

        let _mgr = CheckpointManager::with_defaults(&dir).unwrap();
        assert!(dir.exists());
    }

    // ── 27. Apply to plan with no matching tasks ──

    #[test]
    fn test_apply_to_plan_no_matching_tasks() {
        let plan = make_plan(2);
        let cp = Checkpoint {
            plan_id: plan.id.clone(),
            completed_tasks: vec![(TaskId([0xAA; 32]), TaskStatus::Completed(vec![1]))],
            created_at: 1000,
            version: CHECKPOINT_VERSION,
        };

        let mut fresh = make_plan(2);
        let updated = cp.apply_to_plan(&mut fresh);
        assert_eq!(updated, 0); // No matching task IDs.
    }

    // ── 28. Shared (Arc) manager works ──

    #[test]
    fn test_shared_manager() {
        let dir = temp_dir();
        let mgr = CheckpointManager::shared(&dir, RetentionConfig::default()).unwrap();

        let plan = make_plan(2);
        mgr.save_checkpoint(&plan).unwrap();
        let restored = mgr.restore_checkpoint(&plan.id).unwrap().unwrap();
        assert_eq!(restored.plan_id, plan.id);
    }
}
