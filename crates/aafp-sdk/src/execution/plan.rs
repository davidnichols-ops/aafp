//! Execution Fabric plan — a DAG of tasks with scheduling metadata.
//!
//! This is the execution fabric's [`ExecutionPlan`], distinct from
//! `aafp_discovery::semantic::planner::ExecutionPlan` (the SCG planning
//! domain). The fabric's plan carries:
//! - Resource requirements per task
//! - Assignment state (which agent is running each task)
//! - Retry counts and task status
//! - Estimated cost and latency
//! - CBOR serialization for checkpointing and recovery
//!
//! # CBOR Encoding
//!
//! All structures use integer-keyed CBOR maps (RFC 8949 deterministic
//! encoding) for wire serialization and checkpoint persistence.

use crate::SdkError;
use aafp_cbor::{int_map, int_map_get, Value};
use aafp_discovery::semantic::planner::PlannedStep;
use aafp_identity::identity_v1::AgentId;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

// ──────────────────────────────────────────────────────────────────────
// PlanId / TaskId
// ──────────────────────────────────────────────────────────────────────

/// Unique identifier for an [`ExecutionPlan`] (SHA-256 of plan content).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlanId(pub [u8; 32]);

impl PlanId {
    /// The all-zeros placeholder ID used during hash computation.
    fn zero() -> Self {
        Self([0u8; 32])
    }
}

/// Unique identifier for a [`TaskNode`] within a plan.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaskId(pub [u8; 32]);

impl TaskId {
    /// Derive a `TaskId` from arbitrary seed bytes (SHA-256).
    pub fn from_seed(seed: &[u8]) -> Self {
        let hash = Sha256::digest(seed);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        Self(id)
    }
}

// ──────────────────────────────────────────────────────────────────────
// TaskStatus
// ──────────────────────────────────────────────────────────────────────

/// Status of a task in the execution fabric.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum TaskStatus {
    /// Task has not yet been assigned to an agent.
    #[default]
    Pending,
    /// Task has been assigned to an agent but has not started running.
    Assigned,
    /// Task is currently running on an agent.
    Running,
    /// Task completed successfully; carries the output bytes.
    Completed(Vec<u8>),
    /// Task failed; carries the error message.
    Failed(String),
    /// Task was cancelled.
    Cancelled,
}

impl TaskStatus {
    /// Returns `true` if the task is in a terminal state (Completed, Failed, or Cancelled).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed(_) | Self::Failed(_) | Self::Cancelled)
    }

    /// CBOR variant tag: 0=Pending, 1=Assigned, 2=Running, 3=Completed, 4=Failed, 5=Cancelled.
    fn variant_tag(&self) -> u64 {
        match self {
            Self::Pending => 0,
            Self::Assigned => 1,
            Self::Running => 2,
            Self::Completed(_) => 3,
            Self::Failed(_) => 4,
            Self::Cancelled => 5,
        }
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        entries.push((1, Value::Unsigned(self.variant_tag())));
        match self {
            Self::Completed(data) => {
                entries.push((2, Value::ByteString(data.clone())));
            }
            Self::Failed(msg) => {
                entries.push((2, Value::TextString(msg.clone())));
            }
            _ => {}
        }
        int_map(entries)
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let tag = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => {
                return Err(SdkError::Messaging(
                    "TaskStatus: missing variant tag".into(),
                ))
            }
        };
        match tag {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Assigned),
            2 => Ok(Self::Running),
            3 => {
                let data = match int_map_get(val, 2) {
                    Some(Value::ByteString(b)) => b.clone(),
                    _ => {
                        return Err(SdkError::Messaging(
                            "TaskStatus::Completed: missing output".into(),
                        ))
                    }
                };
                Ok(Self::Completed(data))
            }
            4 => {
                let msg = match int_map_get(val, 2) {
                    Some(Value::TextString(s)) => s.clone(),
                    _ => {
                        return Err(SdkError::Messaging(
                            "TaskStatus::Failed: missing message".into(),
                        ))
                    }
                };
                Ok(Self::Failed(msg))
            }
            5 => Ok(Self::Cancelled),
            _ => Err(SdkError::Messaging(format!(
                "TaskStatus: unknown variant {tag}"
            ))),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// DependencyType
// ──────────────────────────────────────────────────────────────────────

/// Type of dependency between two tasks in the DAG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DependencyType {
    /// The downstream task consumes the output of the upstream task.
    DataDependency,
    /// The downstream task may only start after the upstream task completes
    /// (ordering constraint, no data flow).
    ControlDependency,
    /// The downstream task requires a resource held by the upstream task.
    ResourceDependency,
}

impl DependencyType {
    /// CBOR variant tag: 0=Data, 1=Control, 2=Resource.
    fn variant_tag(&self) -> u64 {
        match self {
            Self::DataDependency => 0,
            Self::ControlDependency => 1,
            Self::ResourceDependency => 2,
        }
    }

    /// Encode as a CBOR unsigned integer.
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(self.variant_tag())
    }

    /// Decode from a CBOR unsigned integer.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        match val {
            Value::Unsigned(0) => Ok(Self::DataDependency),
            Value::Unsigned(1) => Ok(Self::ControlDependency),
            Value::Unsigned(2) => Ok(Self::ResourceDependency),
            _ => Err(SdkError::Messaging(format!(
                "DependencyType: unknown variant {val:?}"
            ))),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// GpuRequirement
// ──────────────────────────────────────────────────────────────────────

/// GPU resource requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuRequirement {
    /// Minimum VRAM in megabytes.
    pub min_vram_mb: u32,
    /// Optional minimum compute capability (e.g., "8.6").
    pub compute_capability: Option<String>,
}

impl GpuRequirement {
    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        entries.push((1, Value::Unsigned(self.min_vram_mb as u64)));
        if let Some(ref cc) = self.compute_capability {
            entries.push((2, Value::TextString(cc.clone())));
        }
        int_map(entries)
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let min_vram_mb = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => {
                if *n > u32::MAX as u64 {
                    return Err(SdkError::Messaging(
                        "GpuRequirement: min_vram_mb overflow".into(),
                    ));
                }
                *n as u32
            }
            _ => {
                return Err(SdkError::Messaging(
                    "GpuRequirement: missing min_vram_mb".into(),
                ))
            }
        };
        let compute_capability = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => Some(s.clone()),
            _ => None,
        };
        Ok(Self {
            min_vram_mb,
            compute_capability,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────
// ResourceRequirements
// ──────────────────────────────────────────────────────────────────────

/// Resource requirements for a task or plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceRequirements {
    /// Minimum CPU cores.
    pub cpu_cores: Option<u32>,
    /// Minimum memory in megabytes.
    pub memory_mb: Option<u32>,
    /// GPU requirement (if any).
    pub gpu: Option<GpuRequirement>,
    /// Minimum disk space in megabytes.
    pub disk_mb: Option<u64>,
    /// Whether network access is required.
    pub network: bool,
}

impl ResourceRequirements {
    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = Vec::new();
        if let Some(cpu) = self.cpu_cores {
            entries.push((1, Value::Unsigned(cpu as u64)));
        }
        if let Some(mem) = self.memory_mb {
            entries.push((2, Value::Unsigned(mem as u64)));
        }
        if let Some(ref gpu) = self.gpu {
            entries.push((3, gpu.to_cbor()));
        }
        if let Some(disk) = self.disk_mb {
            entries.push((4, Value::Unsigned(disk)));
        }
        if self.network {
            entries.push((5, Value::Bool(true)));
        }
        int_map(entries)
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let cpu_cores = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => {
                if *n > u32::MAX as u64 {
                    return Err(SdkError::Messaging(
                        "ResourceRequirements: cpu_cores overflow".into(),
                    ));
                }
                Some(*n as u32)
            }
            _ => None,
        };
        let memory_mb = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => {
                if *n > u32::MAX as u64 {
                    return Err(SdkError::Messaging(
                        "ResourceRequirements: memory_mb overflow".into(),
                    ));
                }
                Some(*n as u32)
            }
            _ => None,
        };
        let gpu = match int_map_get(val, 3) {
            Some(v) => Some(GpuRequirement::from_cbor(v)?),
            None => None,
        };
        let disk_mb = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => Some(*n),
            _ => None,
        };
        let network = matches!(int_map_get(val, 5), Some(Value::Bool(true)));
        Ok(Self {
            cpu_cores,
            memory_mb,
            gpu,
            disk_mb,
            network,
        })
    }

    /// Aggregate a set of resource requirements into a single requirement
    /// that satisfies all inputs (max of each dimension).
    pub fn aggregate(requirements: &[&ResourceRequirements]) -> Self {
        let mut result = Self::default();
        for req in requirements {
            result.cpu_cores = result
                .cpu_cores
                .map_or(req.cpu_cores, |existing| {
                    Some(existing.max(req.cpu_cores.unwrap_or(0)))
                })
                .or(req.cpu_cores);
            result.memory_mb = result
                .memory_mb
                .map_or(req.memory_mb, |existing| {
                    Some(existing.max(req.memory_mb.unwrap_or(0)))
                })
                .or(req.memory_mb);
            // GPU: take the one with higher min_vram_mb
            match (&result.gpu, &req.gpu) {
                (Some(a), Some(b)) => {
                    if b.min_vram_mb > a.min_vram_mb {
                        result.gpu = Some(b.clone());
                    }
                }
                (None, Some(b)) => result.gpu = Some(b.clone()),
                _ => {}
            }
            result.disk_mb = result
                .disk_mb
                .map_or(req.disk_mb, |existing| {
                    Some(existing.max(req.disk_mb.unwrap_or(0)))
                })
                .or(req.disk_mb);
            result.network = result.network || req.network;
        }
        result
    }
}

// ──────────────────────────────────────────────────────────────────────
// TaskNode
// ──────────────────────────────────────────────────────────────────────

/// A single task node in the execution fabric DAG.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskNode {
    /// Unique task identifier (SHA-256 of task content).
    pub id: TaskId,
    /// The capability to invoke (e.g., "inference", "translation").
    pub capability: String,
    /// Serialized input data for the task.
    pub input: Vec<u8>,
    /// Estimated execution duration in milliseconds.
    pub estimated_duration_ms: u64,
    /// Resource requirements for this task.
    pub resources: ResourceRequirements,
    /// The agent assigned to execute this task (if any).
    pub assigned_agent: Option<AgentId>,
    /// Current status of the task.
    pub status: TaskStatus,
    /// Number of times this task has been retried.
    pub retry_count: u32,
}

impl TaskNode {
    /// Create a new task node with `Pending` status and no assignment.
    pub fn new(capability: &str, input: Vec<u8>, estimated_duration_ms: u64) -> Self {
        let mut seed = Vec::new();
        seed.extend_from_slice(capability.as_bytes());
        seed.extend_from_slice(&input);
        seed.extend_from_slice(&estimated_duration_ms.to_be_bytes());
        Self {
            id: TaskId::from_seed(&seed),
            capability: capability.to_string(),
            input,
            estimated_duration_ms,
            resources: ResourceRequirements::default(),
            assigned_agent: None,
            status: TaskStatus::Pending,
            retry_count: 0,
        }
    }

    /// Encode to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        let entries: Vec<(i64, Value)> = vec![
            (1, Value::ByteString(self.id.0.to_vec())),
            (2, Value::TextString(self.capability.clone())),
            (3, Value::ByteString(self.input.clone())),
            (4, Value::Unsigned(self.estimated_duration_ms)),
            (5, self.resources.to_cbor()),
            (
                6,
                match &self.assigned_agent {
                    Some(agent) => Value::ByteString(agent.0.to_vec()),
                    None => Value::Null,
                },
            ),
            (7, self.status.to_cbor()),
            (8, Value::Unsigned(self.retry_count as u64)),
        ];
        int_map(entries)
    }

    /// Decode from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let id = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) => {
                if b.len() != 32 {
                    return Err(SdkError::Messaging(format!(
                        "TaskNode: id must be 32 bytes, got {}",
                        b.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                TaskId(arr)
            }
            _ => return Err(SdkError::Messaging("TaskNode: missing id".into())),
        };
        let capability = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SdkError::Messaging("TaskNode: missing capability".into())),
        };
        let input = match int_map_get(val, 3) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(SdkError::Messaging("TaskNode: missing input".into())),
        };
        let estimated_duration_ms = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => *n,
            _ => {
                return Err(SdkError::Messaging(
                    "TaskNode: missing estimated_duration_ms".into(),
                ))
            }
        };
        let resources = match int_map_get(val, 5) {
            Some(v) => ResourceRequirements::from_cbor(v)?,
            None => ResourceRequirements::default(),
        };
        let assigned_agent = match int_map_get(val, 6) {
            Some(Value::ByteString(b)) => {
                if b.len() != 32 {
                    return Err(SdkError::Messaging(format!(
                        "TaskNode: assigned_agent must be 32 bytes, got {}",
                        b.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Some(AgentId(arr))
            }
            _ => None,
        };
        let status = match int_map_get(val, 7) {
            Some(v) => TaskStatus::from_cbor(v)?,
            None => TaskStatus::Pending,
        };
        let retry_count = match int_map_get(val, 8) {
            Some(Value::Unsigned(n)) => {
                if *n > u32::MAX as u64 {
                    return Err(SdkError::Messaging("TaskNode: retry_count overflow".into()));
                }
                *n as u32
            }
            _ => 0,
        };
        Ok(Self {
            id,
            capability,
            input,
            estimated_duration_ms,
            resources,
            assigned_agent,
            status,
            retry_count,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────
// ExecutionPlan
// ──────────────────────────────────────────────────────────────────────

/// A DAG of tasks to be executed by the agent network.
///
/// This is the execution fabric's plan, carrying scheduling metadata,
/// resource requirements, and assignment state. It is distinct from
/// `aafp_discovery::semantic::planner::ExecutionPlan` (the SCG planning
/// domain), which represents a capability chain without scheduling metadata.
#[derive(Clone, Debug)]
pub struct ExecutionPlan {
    /// Unique plan identifier (SHA-256 of plan content).
    pub id: PlanId,
    /// Human-readable goal description.
    pub goal: String,
    /// Task nodes in the DAG.
    pub tasks: Vec<TaskNode>,
    /// Edges: (from_index, to_index, dependency_type).
    pub edges: Vec<(usize, usize, DependencyType)>,
    /// Estimated total cost (arbitrary units, sum of task durations).
    pub estimated_cost: u64,
    /// Estimated wall-clock latency in ms (critical path duration).
    pub estimated_latency_ms: u64,
    /// Aggregated resource requirements (max across all tasks).
    pub resource_requirements: ResourceRequirements,
    /// Unix timestamp when the plan was created.
    pub created_at: u64,
    /// Plan version (for schema evolution).
    pub version: u32,
}

impl ExecutionPlan {
    /// Create a new execution plan.
    ///
    /// Auto-computes:
    /// - `id`: SHA-256 of the plan content (excluding `id` and `created_at`)
    /// - `estimated_cost`: sum of all task `estimated_duration_ms`
    /// - `estimated_latency_ms`: critical path duration
    /// - `resource_requirements`: max across all tasks
    /// - `created_at`: current Unix timestamp
    pub fn new(
        goal: &str,
        tasks: Vec<TaskNode>,
        edges: Vec<(usize, usize, DependencyType)>,
    ) -> Self {
        let estimated_cost = tasks
            .iter()
            .map(|t| t.estimated_duration_ms)
            .fold(0u64, |acc, d| acc.saturating_add(d));
        let estimated_latency_ms = Self::compute_critical_path_duration(&tasks, &edges);
        let resource_requirements = Self::aggregate_resources(&tasks);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Compute PlanId from content (excluding id and created_at for determinism).
        let temp = ExecutionPlan {
            id: PlanId::zero(),
            goal: goal.to_string(),
            tasks: tasks.clone(),
            edges: edges.clone(),
            estimated_cost,
            estimated_latency_ms,
            resource_requirements: resource_requirements.clone(),
            created_at: 0,
            version: 1,
        };
        let content_cbor = temp.content_cbor();
        let bytes = aafp_cbor::encode(&content_cbor).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);

        ExecutionPlan {
            id: PlanId(id),
            goal: goal.to_string(),
            tasks,
            edges,
            estimated_cost,
            estimated_latency_ms,
            resource_requirements,
            created_at,
            version: 1,
        }
    }

    /// Convert SCG planner steps to an execution plan.
    ///
    /// Each `PlannedStep` becomes a [`TaskNode`]. Dependencies from
    /// `depends_on` become [`DependencyType::DataDependency`] edges.
    /// The `estimated_duration_ms` is derived from the step's
    /// `estimated_latency_ms` (with `is_finite()` guard).
    pub fn from_capability_graph(steps: &[PlannedStep], goal: &str) -> Self {
        let mut tasks = Vec::with_capacity(steps.len());
        let mut edges = Vec::new();

        for (i, step) in steps.iter().enumerate() {
            // Derive a deterministic TaskId from goal + capability name + index.
            let mut seed = Vec::new();
            seed.extend_from_slice(goal.as_bytes());
            seed.extend_from_slice(step.capability.name.as_bytes());
            seed.extend_from_slice(&(i as u64).to_be_bytes());

            // Convert estimated_latency_ms (f64) to u64 with is_finite() guard.
            let estimated_duration_ms =
                if step.estimated_latency_ms.is_finite() && step.estimated_latency_ms >= 0.0 {
                    step.estimated_latency_ms as u64
                } else {
                    0
                };

            // Only set assigned_agent if the step's agent_id is non-zero.
            let assigned_agent = if step.agent_id.iter().any(|&b| b != 0) {
                Some(AgentId(step.agent_id))
            } else {
                None
            };

            let task = TaskNode {
                id: TaskId::from_seed(&seed),
                capability: step.capability.name.clone(),
                input: Vec::new(),
                estimated_duration_ms,
                resources: ResourceRequirements::default(),
                assigned_agent,
                status: TaskStatus::Pending,
                retry_count: 0,
            };
            tasks.push(task);

            // Convert depends_on to DataDependency edges.
            for &dep in &step.depends_on {
                if dep < i {
                    edges.push((dep, i, DependencyType::DataDependency));
                }
            }
        }

        Self::new(goal, tasks, edges)
    }

    /// Encode only the content fields (excluding `id` and `created_at`)
    /// for deterministic PlanId computation.
    fn content_cbor(&self) -> Value {
        int_map(vec![
            (2, Value::TextString(self.goal.clone())),
            (
                3,
                Value::Array(self.tasks.iter().map(|t| t.to_cbor()).collect()),
            ),
            (
                4,
                Value::Array(
                    self.edges
                        .iter()
                        .map(|(from, to, dep)| {
                            Value::Array(vec![
                                Value::Unsigned(*from as u64),
                                Value::Unsigned(*to as u64),
                                dep.to_cbor(),
                            ])
                        })
                        .collect(),
                ),
            ),
            (5, Value::Unsigned(self.estimated_cost)),
            (6, Value::Unsigned(self.estimated_latency_ms)),
            (7, self.resource_requirements.to_cbor()),
            (9, Value::Unsigned(self.version as u64)),
        ])
    }

    /// Encode the full plan to a CBOR int-keyed map.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::ByteString(self.id.0.to_vec())),
            (2, Value::TextString(self.goal.clone())),
            (
                3,
                Value::Array(self.tasks.iter().map(|t| t.to_cbor()).collect()),
            ),
            (
                4,
                Value::Array(
                    self.edges
                        .iter()
                        .map(|(from, to, dep)| {
                            Value::Array(vec![
                                Value::Unsigned(*from as u64),
                                Value::Unsigned(*to as u64),
                                dep.to_cbor(),
                            ])
                        })
                        .collect(),
                ),
            ),
            (5, Value::Unsigned(self.estimated_cost)),
            (6, Value::Unsigned(self.estimated_latency_ms)),
            (7, self.resource_requirements.to_cbor()),
            (8, Value::Unsigned(self.created_at)),
            (9, Value::Unsigned(self.version as u64)),
        ])
    }

    /// Decode a plan from a CBOR int-keyed map.
    pub fn from_cbor(val: &Value) -> Result<Self, SdkError> {
        let id = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) => {
                if b.len() != 32 {
                    return Err(SdkError::Messaging(format!(
                        "ExecutionPlan: id must be 32 bytes, got {}",
                        b.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                PlanId(arr)
            }
            _ => return Err(SdkError::Messaging("ExecutionPlan: missing id".into())),
        };
        let goal = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SdkError::Messaging("ExecutionPlan: missing goal".into())),
        };
        let tasks = match int_map_get(val, 3) {
            Some(Value::Array(arr)) => {
                let mut tasks = Vec::with_capacity(arr.len());
                for item in arr {
                    tasks.push(TaskNode::from_cbor(item)?);
                }
                tasks
            }
            _ => return Err(SdkError::Messaging("ExecutionPlan: missing tasks".into())),
        };
        let edges = match int_map_get(val, 4) {
            Some(Value::Array(arr)) => {
                let mut edges = Vec::with_capacity(arr.len());
                for item in arr {
                    let edge_arr = match item {
                        Value::Array(e) if e.len() == 3 => e,
                        _ => return Err(SdkError::Messaging("ExecutionPlan: invalid edge".into())),
                    };
                    let from = match &edge_arr[0] {
                        Value::Unsigned(n) => *n as usize,
                        _ => {
                            return Err(SdkError::Messaging(
                                "ExecutionPlan: edge from not uint".into(),
                            ))
                        }
                    };
                    let to = match &edge_arr[1] {
                        Value::Unsigned(n) => *n as usize,
                        _ => {
                            return Err(SdkError::Messaging(
                                "ExecutionPlan: edge to not uint".into(),
                            ))
                        }
                    };
                    let dep = DependencyType::from_cbor(&edge_arr[2])?;
                    edges.push((from, to, dep));
                }
                edges
            }
            _ => return Err(SdkError::Messaging("ExecutionPlan: missing edges".into())),
        };
        let estimated_cost = match int_map_get(val, 5) {
            Some(Value::Unsigned(n)) => *n,
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "ExecutionPlan: estimated_cost not uint".into(),
                ))
            }
        };
        let estimated_latency_ms = match int_map_get(val, 6) {
            Some(Value::Unsigned(n)) => *n,
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "ExecutionPlan: estimated_latency_ms not uint".into(),
                ))
            }
        };
        let resource_requirements = match int_map_get(val, 7) {
            Some(v) => ResourceRequirements::from_cbor(v)?,
            None => ResourceRequirements::default(),
        };
        let created_at = match int_map_get(val, 8) {
            Some(Value::Unsigned(n)) => *n,
            None => 0,
            _ => {
                return Err(SdkError::Messaging(
                    "ExecutionPlan: created_at not uint".into(),
                ))
            }
        };
        let version = match int_map_get(val, 9) {
            Some(Value::Unsigned(n)) => {
                if *n > u32::MAX as u64 {
                    return Err(SdkError::Messaging(
                        "ExecutionPlan: version overflow".into(),
                    ));
                }
                *n as u32
            }
            None => 1,
            _ => {
                return Err(SdkError::Messaging(
                    "ExecutionPlan: version not uint".into(),
                ))
            }
        };
        Ok(Self {
            id,
            goal,
            tasks,
            edges,
            estimated_cost,
            estimated_latency_ms,
            resource_requirements,
            created_at,
            version,
        })
    }

    /// Return task indices in topological order (Kahn's algorithm).
    ///
    /// If the DAG contains a cycle, the returned vector will be shorter
    /// than `tasks.len()`. Use [`validate`](Self::validate) to detect cycles.
    pub fn topological_sort(&self) -> Vec<usize> {
        let n = self.tasks.len();
        let mut in_degree = vec![0usize; n];

        // Build adjacency list and in-degree counts.
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(from, to, _) in &self.edges {
            if from < n && to < n {
                adj.entry(from).or_default().push(to);
                in_degree[to] = in_degree[to].saturating_add(1);
            }
        }

        // Start with all nodes that have no incoming edges.
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(i);
            }
        }

        let mut order = Vec::with_capacity(n);
        while let Some(node) = queue.pop_front() {
            order.push(node);
            if let Some(successors) = adj.get(&node) {
                for &succ in successors {
                    in_degree[succ] = in_degree[succ].saturating_sub(1);
                    if in_degree[succ] == 0 {
                        queue.push_back(succ);
                    }
                }
            }
        }
        order
    }

    /// Return the critical path: the longest dependency chain by estimated duration.
    ///
    /// The critical path is the chain of tasks that determines the minimum
    /// wall-clock time to complete the plan (assuming unlimited parallelism).
    pub fn critical_path(&self) -> Vec<usize> {
        let n = self.tasks.len();
        if n == 0 {
            return Vec::new();
        }

        let topo = self.topological_sort();
        if topo.len() < n {
            // Cycle detected — return the partial order.
            return topo;
        }

        // earliest_finish[i] = max(earliest_finish[pred]) + duration[i]
        let mut earliest_finish = vec![0u64; n];
        let mut predecessor: Vec<Option<usize>> = vec![None; n];

        // Build predecessor map from edges.
        let mut successors: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(from, to, _) in &self.edges {
            if from < n && to < n {
                successors.entry(from).or_default().push(to);
            }
        }

        for &node in &topo {
            let duration = self.tasks[node].estimated_duration_ms;
            earliest_finish[node] = earliest_finish[node].saturating_add(duration);
            if let Some(succs) = successors.get(&node) {
                for &succ in succs {
                    if earliest_finish[node] > earliest_finish[succ] {
                        earliest_finish[succ] = earliest_finish[node];
                        predecessor[succ] = Some(node);
                    }
                }
            }
        }

        // Find the node with the maximum earliest_finish.
        let end_node = (0..n).max_by_key(|&i| earliest_finish[i]).unwrap_or(0);

        // Backtrack from end_node to find the path.
        let mut path = Vec::new();
        let mut current = Some(end_node);
        while let Some(node) = current {
            path.push(node);
            current = predecessor[node];
        }
        path.reverse();
        path
    }

    /// Group tasks that can run in parallel (same topological level).
    ///
    /// Tasks in the same group have no dependencies on each other and
    /// can be dispatched simultaneously.
    pub fn parallel_groups(&self) -> Vec<Vec<usize>> {
        let n = self.tasks.len();
        if n == 0 {
            return Vec::new();
        }

        // Compute level[i] = 0 for nodes with no predecessors,
        // max(level[pred]) + 1 otherwise.
        let mut level = vec![0usize; n];
        let mut in_degree = vec![0usize; n];
        let mut successors: HashMap<usize, Vec<usize>> = HashMap::new();

        for &(from, to, _) in &self.edges {
            if from < n && to < n {
                successors.entry(from).or_default().push(to);
                in_degree[to] = in_degree[to].saturating_add(1);
            }
        }

        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(i);
            }
        }

        let mut max_level = 0;
        while let Some(node) = queue.pop_front() {
            if level[node] > max_level {
                max_level = level[node];
            }
            if let Some(succs) = successors.get(&node) {
                for &succ in succs {
                    level[succ] = level[succ].max(level[node] + 1);
                    in_degree[succ] = in_degree[succ].saturating_sub(1);
                    if in_degree[succ] == 0 {
                        queue.push_back(succ);
                    }
                }
            }
        }

        // Group by level.
        let mut groups: Vec<Vec<usize>> = vec![Vec::new(); max_level + 1];
        for i in 0..n {
            if level[i] <= max_level {
                groups[level[i]].push(i);
            }
        }
        // Remove empty groups (in case of cycles).
        groups.into_iter().filter(|g| !g.is_empty()).collect()
    }

    /// Validate the plan: no cycles, all edges reference valid task indices.
    pub fn validate(&self) -> Result<(), SdkError> {
        let n = self.tasks.len();

        // Check all edge indices are within bounds.
        for &(from, to, _) in &self.edges {
            if from >= n {
                return Err(SdkError::Messaging(format!(
                    "ExecutionPlan: edge from index {from} out of bounds (tasks={n})"
                )));
            }
            if to >= n {
                return Err(SdkError::Messaging(format!(
                    "ExecutionPlan: edge to index {to} out of bounds (tasks={n})"
                )));
            }
        }

        // Check for cycles using Kahn's algorithm.
        let topo = self.topological_sort();
        if topo.len() != n {
            return Err(SdkError::Messaging(format!(
                "ExecutionPlan: cycle detected ({} of {} tasks in topological order)",
                topo.len(),
                n
            )));
        }

        Ok(())
    }

    /// Compute the critical path duration (sum of durations along the longest path).
    fn compute_critical_path_duration(
        tasks: &[TaskNode],
        edges: &[(usize, usize, DependencyType)],
    ) -> u64 {
        let n = tasks.len();
        if n == 0 {
            return 0;
        }

        // Build in-degree and adjacency.
        let mut in_degree = vec![0usize; n];
        let mut successors: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(from, to, _) in edges {
            if from < n && to < n {
                successors.entry(from).or_default().push(to);
                in_degree[to] = in_degree[to].saturating_add(1);
            }
        }

        // Topological order via Kahn's.
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(i);
            }
        }

        let mut earliest_finish = vec![0u64; n];
        let mut processed = 0usize;
        while let Some(node) = queue.pop_front() {
            processed += 1;
            let duration = tasks[node].estimated_duration_ms;
            earliest_finish[node] = earliest_finish[node].saturating_add(duration);
            if let Some(succs) = successors.get(&node) {
                for &succ in succs {
                    if earliest_finish[node] > earliest_finish[succ] {
                        earliest_finish[succ] = earliest_finish[node];
                    }
                    in_degree[succ] = in_degree[succ].saturating_sub(1);
                    if in_degree[succ] == 0 {
                        queue.push_back(succ);
                    }
                }
            }
        }

        if processed < n {
            // Cycle — return sum of all durations as fallback.
            return tasks
                .iter()
                .map(|t| t.estimated_duration_ms)
                .fold(0u64, |acc, d| acc.saturating_add(d));
        }

        earliest_finish.into_iter().max().unwrap_or(0)
    }

    /// Aggregate resource requirements across all tasks (max of each dimension).
    fn aggregate_resources(tasks: &[TaskNode]) -> ResourceRequirements {
        let refs: Vec<&ResourceRequirements> = tasks.iter().map(|t| &t.resources).collect();
        ResourceRequirements::aggregate(&refs)
    }

    /// Get the indices of all DataDependency predecessors of a task.
    pub fn data_dependencies(&self, task_idx: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter(|&&(_, to, ref dep)| to == task_idx && *dep == DependencyType::DataDependency)
            .map(|&(from, _, _)| from)
            .collect()
    }

    /// Check if all DataDependency predecessors of a task are Completed.
    pub fn dependencies_met(&self, task_idx: usize) -> bool {
        let deps = self.data_dependencies(task_idx);
        deps.iter()
            .all(|&dep| matches!(self.tasks[dep].status, TaskStatus::Completed(_)))
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};
    use aafp_discovery::semantic::capability::SemanticCapability;

    // ── Helper functions ──

    fn make_task(cap: &str, duration: u64) -> TaskNode {
        TaskNode::new(cap, vec![1, 2, 3], duration)
    }

    fn make_task_with_resources(
        cap: &str,
        duration: u64,
        resources: ResourceRequirements,
    ) -> TaskNode {
        let mut task = make_task(cap, duration);
        task.resources = resources;
        task
    }

    fn make_planned_step(
        index: usize,
        cap_name: &str,
        depends_on: Vec<usize>,
        latency_ms: f64,
        cost_micro_usd: u64,
    ) -> PlannedStep {
        PlannedStep {
            index,
            capability: SemanticCapability::new(cap_name),
            agent_id: [0u8; 32],
            depends_on,
            preconditions: Vec::new(),
            effects: Vec::new(),
            estimated_latency_ms: latency_ms,
            estimated_cost_micro_usd: cost_micro_usd,
        }
    }

    // ── 1. CBOR round-trip for ExecutionPlan ──

    #[test]
    fn test_cbor_roundtrip_execution_plan() {
        let t0 = make_task("search", 100);
        let t1 = make_task("inference", 200);
        let plan = ExecutionPlan::new(
            "answer user query",
            vec![t0, t1],
            vec![(0, 1, DependencyType::DataDependency)],
        );
        let cbor = plan.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, consumed) = decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len(), "no trailing bytes");
        let plan2 = ExecutionPlan::from_cbor(&decoded).unwrap();
        assert_eq!(plan.id, plan2.id);
        assert_eq!(plan.goal, plan2.goal);
        assert_eq!(plan.estimated_cost, plan2.estimated_cost);
        assert_eq!(plan.estimated_latency_ms, plan2.estimated_latency_ms);
        assert_eq!(plan.resource_requirements, plan2.resource_requirements);
        assert_eq!(plan.version, plan2.version);
        assert_eq!(plan.tasks.len(), plan2.tasks.len());
        assert_eq!(plan.edges.len(), plan2.edges.len());
        // Verify edge content
        assert_eq!(plan2.edges[0].0, 0);
        assert_eq!(plan2.edges[0].1, 1);
        assert_eq!(plan2.edges[0].2, DependencyType::DataDependency);
    }

    // ── 2. CBOR round-trip for TaskNode ──

    #[test]
    fn test_cbor_roundtrip_task_node() {
        let task = TaskNode {
            id: TaskId([0xAB; 32]),
            capability: "inference".into(),
            input: vec![0xDE, 0xAD, 0xBE, 0xEF],
            estimated_duration_ms: 500,
            resources: ResourceRequirements {
                cpu_cores: Some(4),
                memory_mb: Some(2048),
                gpu: None,
                disk_mb: Some(100),
                network: true,
            },
            assigned_agent: Some(AgentId([0x11; 32])),
            status: TaskStatus::Running,
            retry_count: 2,
        };
        let cbor = task.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let task2 = TaskNode::from_cbor(&decoded).unwrap();
        assert_eq!(task.id, task2.id);
        assert_eq!(task.capability, task2.capability);
        assert_eq!(task.input, task2.input);
        assert_eq!(task.estimated_duration_ms, task2.estimated_duration_ms);
        assert_eq!(task.resources, task2.resources);
        assert_eq!(task.assigned_agent, task2.assigned_agent);
        assert_eq!(task.status, task2.status);
        assert_eq!(task.retry_count, task2.retry_count);
    }

    // ── 3. CBOR round-trip for TaskStatus (all variants) ──

    #[test]
    fn test_cbor_roundtrip_task_status_all_variants() {
        let statuses = vec![
            TaskStatus::Pending,
            TaskStatus::Assigned,
            TaskStatus::Running,
            TaskStatus::Completed(vec![0x01, 0x02, 0x03]),
            TaskStatus::Failed("network error".into()),
            TaskStatus::Cancelled,
        ];
        for status in &statuses {
            let cbor = status.to_cbor();
            let bytes = encode(&cbor).unwrap();
            let (decoded, _) = decode(&bytes).unwrap();
            let status2 = TaskStatus::from_cbor(&decoded).unwrap();
            assert_eq!(status, &status2);
        }
    }

    #[test]
    fn test_task_status_is_terminal() {
        assert!(!TaskStatus::Pending.is_terminal());
        assert!(!TaskStatus::Assigned.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
        assert!(TaskStatus::Completed(vec![]).is_terminal());
        assert!(TaskStatus::Failed("err".into()).is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
    }

    // ── 4. CBOR round-trip for ResourceRequirements ──

    #[test]
    fn test_cbor_roundtrip_resource_requirements() {
        let req = ResourceRequirements {
            cpu_cores: Some(8),
            memory_mb: Some(4096),
            gpu: Some(GpuRequirement {
                min_vram_mb: 16384,
                compute_capability: Some("8.6".into()),
            }),
            disk_mb: Some(500),
            network: true,
        };
        let cbor = req.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let req2 = ResourceRequirements::from_cbor(&decoded).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn test_cbor_roundtrip_resource_requirements_empty() {
        let req = ResourceRequirements::default();
        let cbor = req.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let req2 = ResourceRequirements::from_cbor(&decoded).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn test_cbor_roundtrip_gpu_requirement() {
        let gpu = GpuRequirement {
            min_vram_mb: 8192,
            compute_capability: Some("7.5".into()),
        };
        let cbor = gpu.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let gpu2 = GpuRequirement::from_cbor(&decoded).unwrap();
        assert_eq!(gpu, gpu2);
    }

    // ── 5. Topological sort correctness (linear chain) ──

    #[test]
    fn test_topological_sort_linear_chain() {
        let tasks = vec![make_task("a", 10), make_task("b", 20), make_task("c", 30)];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (1, 2, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("linear", tasks, edges);
        let order = plan.topological_sort();
        assert_eq!(order, vec![0, 1, 2]);
    }

    // ── 6. Topological sort correctness (diamond pattern) ──

    #[test]
    fn test_topological_sort_diamond() {
        //     0
        //    / \
        //   1   2
        //    \ /
        //     3
        let tasks = vec![
            make_task("a", 10),
            make_task("b", 20),
            make_task("c", 30),
            make_task("d", 40),
        ];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (0, 2, DependencyType::DataDependency),
            (1, 3, DependencyType::DataDependency),
            (2, 3, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("diamond", tasks, edges);
        let order = plan.topological_sort();
        assert_eq!(order.len(), 4);
        assert_eq!(order[0], 0); // root must come first
        assert_eq!(order[3], 3); // sink must come last
                                 // 1 and 2 can be in either order
        let mut middle = order[1..3].to_vec();
        middle.sort();
        assert_eq!(middle, vec![1, 2]);
    }

    // ── 7. Cycle detection (validate returns error) ──

    #[test]
    fn test_cycle_detection() {
        let tasks = vec![make_task("a", 10), make_task("b", 20)];
        // Create a cycle: 0 -> 1 -> 0
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (1, 0, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("cycle", tasks, edges);
        let result = plan.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cycle"), "error should mention cycle: {msg}");
    }

    #[test]
    fn test_validate_out_of_bounds_edge() {
        let tasks = vec![make_task("a", 10)];
        // Edge references non-existent task index
        let edges = vec![(0, 5, DependencyType::DataDependency)];
        let plan = ExecutionPlan::new("oob", tasks, edges);
        let result = plan.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_valid_plan() {
        let tasks = vec![make_task("a", 10), make_task("b", 20), make_task("c", 30)];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (1, 2, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("valid", tasks, edges);
        assert!(plan.validate().is_ok());
    }

    // ── 8. Critical path calculation ──

    #[test]
    fn test_critical_path_linear() {
        let tasks = vec![make_task("a", 100), make_task("b", 200), make_task("c", 50)];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (1, 2, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("linear-cp", tasks, edges);
        let path = plan.critical_path();
        assert_eq!(path, vec![0, 1, 2]);
        // Critical path duration = 100 + 200 + 50 = 350
        assert_eq!(plan.estimated_latency_ms, 350);
    }

    #[test]
    fn test_critical_path_diamond() {
        //     0 (100ms)
        //    / \
        //   1   2
        // 50ms 300ms
        //    \ /
        //     3 (10ms)
        // Critical path: 0 -> 2 -> 3 = 100 + 300 + 10 = 410
        let tasks = vec![
            make_task("a", 100),
            make_task("b", 50),
            make_task("c", 300),
            make_task("d", 10),
        ];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (0, 2, DependencyType::DataDependency),
            (1, 3, DependencyType::DataDependency),
            (2, 3, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("diamond-cp", tasks, edges);
        let path = plan.critical_path();
        assert_eq!(path, vec![0, 2, 3]);
        assert_eq!(plan.estimated_latency_ms, 410);
    }

    // ── 9. Parallel group identification ──

    #[test]
    fn test_parallel_groups_linear() {
        let tasks = vec![make_task("a", 10), make_task("b", 20), make_task("c", 30)];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (1, 2, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("linear-pg", tasks, edges);
        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0], vec![0]);
        assert_eq!(groups[1], vec![1]);
        assert_eq!(groups[2], vec![2]);
    }

    #[test]
    fn test_parallel_groups_diamond() {
        //     0
        //    / \
        //   1   2   <- parallel
        //    \ /
        //     3
        let tasks = vec![
            make_task("a", 10),
            make_task("b", 20),
            make_task("c", 30),
            make_task("d", 40),
        ];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (0, 2, DependencyType::DataDependency),
            (1, 3, DependencyType::DataDependency),
            (2, 3, DependencyType::DataDependency),
        ];
        let plan = ExecutionPlan::new("diamond-pg", tasks, edges);
        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0], vec![0]);
        let mut middle = groups[1].clone();
        middle.sort();
        assert_eq!(middle, vec![1, 2]);
        assert_eq!(groups[2], vec![3]);
    }

    #[test]
    fn test_parallel_groups_independent() {
        // Three independent tasks — all in the same group.
        let tasks = vec![make_task("a", 10), make_task("b", 20), make_task("c", 30)];
        let plan = ExecutionPlan::new("independent", tasks, vec![]);
        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 3);
    }

    // ── 10. from_capability_graph conversion ──

    #[test]
    fn test_from_capability_graph() {
        let steps = vec![
            make_planned_step(0, "search", vec![], 100.0, 50),
            make_planned_step(1, "fetch", vec![0], 200.0, 75),
            make_planned_step(2, "summarize", vec![1], 150.0, 100),
        ];
        let plan = ExecutionPlan::from_capability_graph(&steps, "research topic");
        assert_eq!(plan.goal, "research topic");
        assert_eq!(plan.tasks.len(), 3);
        assert_eq!(plan.tasks[0].capability, "search");
        assert_eq!(plan.tasks[1].capability, "fetch");
        assert_eq!(plan.tasks[2].capability, "summarize");
        assert_eq!(plan.tasks[0].estimated_duration_ms, 100);
        assert_eq!(plan.tasks[1].estimated_duration_ms, 200);
        assert_eq!(plan.tasks[2].estimated_duration_ms, 150);
        // Check edges from depends_on
        assert_eq!(plan.edges.len(), 2);
        assert_eq!(plan.edges[0].0, 0);
        assert_eq!(plan.edges[0].1, 1);
        assert_eq!(plan.edges[0].2, DependencyType::DataDependency);
        assert_eq!(plan.edges[1].0, 1);
        assert_eq!(plan.edges[1].1, 2);
        // All tasks should be Pending
        assert_eq!(plan.tasks[0].status, TaskStatus::Pending);
        // No assigned agents (all agent_ids are zero)
        assert!(plan.tasks[0].assigned_agent.is_none());
    }

    #[test]
    fn test_from_capability_graph_with_agent() {
        let mut step = make_planned_step(0, "inference", vec![], 100.0, 50);
        step.agent_id = [0x42; 32];
        let plan = ExecutionPlan::from_capability_graph(&[step], "run inference");
        assert_eq!(plan.tasks.len(), 1);
        assert_eq!(plan.tasks[0].assigned_agent, Some(AgentId([0x42; 32])));
    }

    #[test]
    fn test_from_capability_graph_nan_latency() {
        let mut step = make_planned_step(0, "bad", vec![], f64::NAN, 50);
        step.estimated_latency_ms = f64::NAN;
        let plan = ExecutionPlan::from_capability_graph(&[step], "nan test");
        // NaN should be guarded to 0
        assert_eq!(plan.tasks[0].estimated_duration_ms, 0);
    }

    // ── 11. Empty plan handling ──

    #[test]
    fn test_empty_plan() {
        let plan = ExecutionPlan::new("empty", vec![], vec![]);
        assert_eq!(plan.tasks.len(), 0);
        assert_eq!(plan.edges.len(), 0);
        assert_eq!(plan.estimated_cost, 0);
        assert_eq!(plan.estimated_latency_ms, 0);
        assert_eq!(plan.topological_sort(), Vec::<usize>::new());
        assert_eq!(plan.critical_path(), Vec::<usize>::new());
        assert_eq!(plan.parallel_groups(), Vec::<Vec<usize>>::new());
        assert!(plan.validate().is_ok());
    }

    // ── 12. Single-task plan ──

    #[test]
    fn test_single_task_plan() {
        let task = make_task("solo", 42);
        let plan = ExecutionPlan::new("single", vec![task], vec![]);
        assert_eq!(plan.tasks.len(), 1);
        assert_eq!(plan.estimated_cost, 42);
        assert_eq!(plan.estimated_latency_ms, 42);
        assert_eq!(plan.topological_sort(), vec![0]);
        assert_eq!(plan.critical_path(), vec![0]);
        assert_eq!(plan.parallel_groups(), vec![vec![0]]);
        assert!(plan.validate().is_ok());
    }

    // ── 13. Diamond dependency pattern ──

    #[test]
    fn test_diamond_dependency_pattern() {
        let tasks = vec![
            make_task("root", 10),
            make_task("left", 20),
            make_task("right", 30),
            make_task("sink", 40),
        ];
        let edges = vec![
            (0, 1, DependencyType::DataDependency),
            (0, 2, DependencyType::ControlDependency),
            (1, 3, DependencyType::DataDependency),
            (2, 3, DependencyType::ResourceDependency),
        ];
        let plan = ExecutionPlan::new("diamond-deps", tasks, edges);
        assert!(plan.validate().is_ok());
        // Check different dependency types are preserved
        assert_eq!(plan.edges[0].2, DependencyType::DataDependency);
        assert_eq!(plan.edges[1].2, DependencyType::ControlDependency);
        assert_eq!(plan.edges[2].2, DependencyType::DataDependency);
        assert_eq!(plan.edges[3].2, DependencyType::ResourceDependency);
    }

    // ── 14. Resource requirement aggregation ──

    #[test]
    fn test_resource_aggregation() {
        let tasks = vec![
            make_task_with_resources(
                "a",
                10,
                ResourceRequirements {
                    cpu_cores: Some(2),
                    memory_mb: Some(1024),
                    gpu: Some(GpuRequirement {
                        min_vram_mb: 4096,
                        compute_capability: None,
                    }),
                    disk_mb: Some(100),
                    network: false,
                },
            ),
            make_task_with_resources(
                "b",
                20,
                ResourceRequirements {
                    cpu_cores: Some(4),
                    memory_mb: Some(512),
                    gpu: Some(GpuRequirement {
                        min_vram_mb: 8192,
                        compute_capability: Some("8.0".into()),
                    }),
                    disk_mb: Some(200),
                    network: true,
                },
            ),
            make_task_with_resources("c", 30, ResourceRequirements::default()),
        ];
        let plan = ExecutionPlan::new("agg", tasks, vec![]);
        let req = &plan.resource_requirements;
        assert_eq!(req.cpu_cores, Some(4)); // max(2, 4, 0) = 4
        assert_eq!(req.memory_mb, Some(1024)); // max(1024, 512, 0) = 1024
        assert_eq!(req.gpu.as_ref().unwrap().min_vram_mb, 8192); // higher VRAM
        assert_eq!(req.disk_mb, Some(200)); // max(100, 200, 0) = 200
        assert!(req.network); // any true
    }

    #[test]
    fn test_resource_aggregation_empty() {
        let req = ResourceRequirements::aggregate(&[]);
        assert_eq!(req, ResourceRequirements::default());
    }

    // ── 15. Plan ID is deterministic (same input → same ID) ──

    #[test]
    fn test_plan_id_deterministic() {
        let tasks = vec![make_task("a", 100), make_task("b", 200)];
        let edges = vec![(0, 1, DependencyType::DataDependency)];
        let plan1 = ExecutionPlan::new("deterministic", tasks.clone(), edges.clone());
        let plan2 = ExecutionPlan::new("deterministic", tasks.clone(), edges.clone());
        assert_eq!(plan1.id, plan2.id);
    }

    #[test]
    fn test_plan_id_differs_for_different_goals() {
        let tasks = vec![make_task("a", 100)];
        let plan1 = ExecutionPlan::new("goal-a", tasks.clone(), vec![]);
        let plan2 = ExecutionPlan::new("goal-b", tasks.clone(), vec![]);
        assert_ne!(plan1.id, plan2.id);
    }

    #[test]
    fn test_plan_id_differs_for_different_tasks() {
        let plan1 = ExecutionPlan::new("goal", vec![make_task("a", 100)], vec![]);
        let plan2 = ExecutionPlan::new("goal", vec![make_task("b", 100)], vec![]);
        assert_ne!(plan1.id, plan2.id);
    }

    // ── Additional tests ──

    #[test]
    fn test_dependency_type_cbor_roundtrip() {
        let deps = vec![
            DependencyType::DataDependency,
            DependencyType::ControlDependency,
            DependencyType::ResourceDependency,
        ];
        for dep in &deps {
            let cbor = dep.to_cbor();
            let bytes = encode(&cbor).unwrap();
            let (decoded, _) = decode(&bytes).unwrap();
            let dep2 = DependencyType::from_cbor(&decoded).unwrap();
            assert_eq!(dep, &dep2);
        }
    }

    #[test]
    fn test_task_id_from_seed_deterministic() {
        let id1 = TaskId::from_seed(b"hello world");
        let id2 = TaskId::from_seed(b"hello world");
        assert_eq!(id1, id2);
        let id3 = TaskId::from_seed(b"hello earth");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_data_dependencies() {
        let tasks = vec![make_task("a", 10), make_task("b", 20), make_task("c", 30)];
        let edges = vec![
            (0, 2, DependencyType::DataDependency),
            (1, 2, DependencyType::ControlDependency),
        ];
        let plan = ExecutionPlan::new("deps", tasks, edges);
        // Task 2 has one DataDependency (from 0) and one ControlDependency (from 1)
        let data_deps = plan.data_dependencies(2);
        assert_eq!(data_deps, vec![0]);
    }

    #[test]
    fn test_dependencies_met() {
        let mut tasks = vec![make_task("a", 10), make_task("b", 20)];
        let edges = vec![(0, 1, DependencyType::DataDependency)];
        let mut plan = ExecutionPlan::new("deps-met", tasks.clone(), edges);
        // Initially, task 0 is Pending, so deps not met for task 1
        assert!(!plan.dependencies_met(1));
        // Complete task 0
        plan.tasks[0].status = TaskStatus::Completed(vec![42]);
        assert!(plan.dependencies_met(1));
        // Task 0 has no deps, so always met
        assert!(plan.dependencies_met(0));
    }

    #[test]
    fn test_cbor_roundtrip_task_node_no_agent() {
        let task = TaskNode {
            id: TaskId([0x55; 32]),
            capability: "translate".into(),
            input: vec![],
            estimated_duration_ms: 1000,
            resources: ResourceRequirements::default(),
            assigned_agent: None,
            status: TaskStatus::Pending,
            retry_count: 0,
        };
        let cbor = task.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let task2 = TaskNode::from_cbor(&decoded).unwrap();
        assert_eq!(task, task2);
        assert!(task2.assigned_agent.is_none());
    }

    #[test]
    fn test_estimated_cost_is_sum_of_durations() {
        let tasks = vec![
            make_task("a", 100),
            make_task("b", 200),
            make_task("c", 300),
        ];
        let plan = ExecutionPlan::new("cost", tasks, vec![]);
        assert_eq!(plan.estimated_cost, 600);
    }

    #[test]
    fn test_estimated_cost_saturates() {
        let mut tasks = Vec::new();
        for _ in 0..3 {
            tasks.push(make_task("big", u64::MAX / 2));
        }
        let plan = ExecutionPlan::new("saturate", tasks, vec![]);
        assert_eq!(plan.estimated_cost, u64::MAX);
    }

    #[test]
    fn test_topological_sort_empty() {
        let plan = ExecutionPlan::new("empty", vec![], vec![]);
        assert_eq!(plan.topological_sort(), Vec::<usize>::new());
    }

    #[test]
    fn test_critical_path_empty() {
        let plan = ExecutionPlan::new("empty", vec![], vec![]);
        assert_eq!(plan.critical_path(), Vec::<usize>::new());
    }

    #[test]
    fn test_parallel_groups_empty() {
        let plan = ExecutionPlan::new("empty", vec![], vec![]);
        assert_eq!(plan.parallel_groups(), Vec::<Vec<usize>>::new());
    }

    #[test]
    fn test_from_cbor_invalid_id_length() {
        let bad_cbor = int_map(vec![
            (1, Value::ByteString(vec![0xAB; 16])), // wrong length
            (2, Value::TextString("test".into())),
            (3, Value::Array(vec![])),
            (4, Value::Array(vec![])),
            (5, Value::Unsigned(0)),
            (6, Value::Unsigned(0)),
            (7, ResourceRequirements::default().to_cbor()),
            (8, Value::Unsigned(0)),
            (9, Value::Unsigned(1)),
        ]);
        let result = ExecutionPlan::from_cbor(&bad_cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_cbor_missing_goal() {
        let bad_cbor = int_map(vec![
            (1, Value::ByteString(vec![0xAB; 32])),
            // missing goal (key 2)
            (3, Value::Array(vec![])),
            (4, Value::Array(vec![])),
        ]);
        let result = ExecutionPlan::from_cbor(&bad_cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_cbor_invalid_task_status_variant() {
        let bad_status = int_map(vec![(1, Value::Unsigned(99))]);
        let task_cbor = int_map(vec![
            (1, Value::ByteString(vec![0x55; 32])),
            (2, Value::TextString("test".into())),
            (3, Value::ByteString(vec![])),
            (4, Value::Unsigned(100)),
            (5, ResourceRequirements::default().to_cbor()),
            (6, Value::Null),
            (7, bad_status),
            (8, Value::Unsigned(0)),
        ]);
        let result = TaskNode::from_cbor(&task_cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_cbor_invalid_dependency_type() {
        let bad_edge = Value::Array(vec![
            Value::Unsigned(0),
            Value::Unsigned(1),
            Value::Unsigned(99), // invalid variant
        ]);
        let plan_cbor = int_map(vec![
            (1, Value::ByteString(vec![0xAB; 32])),
            (2, Value::TextString("test".into())),
            (3, Value::Array(vec![])),
            (4, Value::Array(vec![bad_edge])),
            (5, Value::Unsigned(0)),
            (6, Value::Unsigned(0)),
            (7, ResourceRequirements::default().to_cbor()),
            (8, Value::Unsigned(0)),
            (9, Value::Unsigned(1)),
        ]);
        let result = ExecutionPlan::from_cbor(&plan_cbor);
        assert!(result.is_err());
    }
}
