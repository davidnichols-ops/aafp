//! A2A v1.0 data model types.
//!
//! All types use `#[serde(rename_all = "camelCase")]` to match A2A's JSON
//! convention. See RFC 0008 §"Data Type Mappings" for the type mapping rules:
//! - protobuf Message → JSON object (camelCase fields)
//! - bytes → base64 string
//! - Timestamp → ISO 8601 string in UTC
//! - enum → SCREAMING_SNAKE_CASE string (ProtoJSON convention, A2A v1.0 §5.5)
//!
//! Updated for A2A v1.0.0 spec (2025): the `kind` discriminator on Part was
//! removed (Appendix A.2.1), TaskState/Role use ProtoJSON SCREAMING_SNAKE_CASE,
//! and Message gained `extensions` and `referenceTaskIds` fields.

use serde::{Deserialize, Serialize};

// --- Task lifecycle ---

/// An A2A Task, the core unit of work exchanged between agents.
/// Per A2A v1.0 §4.1.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    /// The unique identifier of the task.
    pub id: String,
    /// The context ID that groups related tasks in a conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// The current status of the task.
    pub status: TaskStatus,
    /// Artifacts produced by the task, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
    /// The message history of the task, if retained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Message>>,
    /// Arbitrary metadata associated with the task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// The status of a task, including its state and optional timestamp/message.
/// Per A2A v1.0 §4.1.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    /// The lifecycle state of the task.
    pub state: TaskState,
    /// ISO 8601 UTC timestamp of the status update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>, // ISO 8601 UTC
    /// An optional message associated with the status update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

/// Task lifecycle states per A2A v1.0 §4.1.3.
/// Serialized as SCREAMING_SNAKE_CASE per ProtoJSON (A2A v1.0 §5.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskState {
    /// The task state has not been specified.
    TaskStateUnspecified,
    /// The task has been submitted to the agent.
    TaskStateSubmitted,
    /// The task is currently being worked on by the agent.
    TaskStateWorking,
    /// The task has completed successfully.
    TaskStateCompleted,
    /// The task has failed.
    TaskStateFailed,
    /// The task has been canceled.
    TaskStateCanceled,
    /// The task is awaiting additional input from the user.
    TaskStateInputRequired,
    /// The task has been rejected by the agent.
    TaskStateRejected,
    /// The task requires authentication to proceed.
    TaskStateAuthRequired,
}

/// Message sender role per A2A v1.0 §4.1.5.
/// Serialized as SCREAMING_SNAKE_CASE per ProtoJSON (A2A v1.0 §5.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    /// The role has not been specified.
    RoleUnspecified,
    /// The message sender is the user (client).
    RoleUser,
    /// The message sender is the agent (server).
    RoleAgent,
}

// --- Messages ---

/// A message exchanged between agents, containing one or more parts.
/// Per A2A v1.0 §4.1.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// The role of the message sender (user or agent).
    pub role: Role,
    /// The content parts of the message.
    pub parts: Vec<Part>,
    /// The unique identifier of the message.
    pub message_id: String,
    /// The context ID that groups related messages in a conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// The task ID this message belongs to, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Arbitrary metadata associated with the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Extension URIs used in this message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    /// IDs of referenced tasks for cross-task correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_task_ids: Option<Vec<String>>,
}

/// A Part is a container for one section of communication content.
///
/// Per A2A v1.0 §4.1.6, exactly one of `text`, `raw`, `url`, `data` MUST be
/// set. The v0.3 `kind` discriminator was removed in v1.0 (Appendix A.2.1).
/// The `metadata`, `filename`, and `mediaType` fields are optional and
/// available for all part types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    /// Text content of the part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64-encoded raw byte content of the part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>, // base64-encoded bytes
    /// A URL pointing to external content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Structured JSON data content of the part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Arbitrary metadata associated with the part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// The filename for file-type parts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// The MIME media type of the part content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

impl Part {
    /// Create a text part.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            raw: None,
            url: None,
            data: None,
            metadata: None,
            filename: None,
            media_type: None,
        }
    }

    /// Create a data part with structured JSON content.
    pub fn data(data: serde_json::Value) -> Self {
        Self {
            text: None,
            raw: None,
            url: None,
            data: Some(data),
            metadata: None,
            filename: None,
            media_type: None,
        }
    }

    /// Create a file part from base64-encoded bytes.
    pub fn file_bytes(bytes: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self {
            text: None,
            raw: Some(bytes.into()),
            url: None,
            data: None,
            metadata: None,
            filename: None,
            media_type: Some(mime_type.into()),
        }
    }

    /// Create a file part from a URL.
    pub fn file_url(url: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self {
            text: None,
            raw: None,
            url: Some(url.into()),
            data: None,
            metadata: None,
            filename: None,
            media_type: Some(mime_type.into()),
        }
    }
}

// --- Artifacts ---

/// An artifact produced by a task, containing one or more parts.
/// Per A2A v1.0 §4.1.7.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    /// The unique identifier of the artifact.
    pub artifact_id: String,
    /// A human-readable name for the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A human-readable description of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The content parts of the artifact.
    pub parts: Vec<Part>,
    /// Arbitrary metadata associated with the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Extension URIs used in this artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

// --- Streaming events ---

/// Status update event sent during streaming operations.
/// Per A2A v1.0 §4.2.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatusUpdateEvent {
    /// The ID of the task being updated.
    pub task_id: String,
    /// The context ID of the task.
    pub context_id: String,
    /// The new status of the task.
    pub status: TaskStatus,
    /// `final` signals the last event in a stream. RFC 0008 uses this for
    /// stream completion signaling. The v1.0 data model places completion
    /// signaling in metadata, but `final` is retained for backward
    /// compatibility and is ignored by implementations that don't use it
    /// (per §5.7 "Unrecognized Fields").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#final: Option<bool>,
    /// Arbitrary metadata associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Artifact update event sent during streaming operations.
/// Per A2A v1.0 §4.2.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifactUpdateEvent {
    /// The ID of the task being updated.
    pub task_id: String,
    /// The context ID of the task.
    pub context_id: String,
    /// The artifact being added or updated.
    pub artifact: Artifact,
    /// Whether this artifact chunk should be appended to existing artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append: Option<bool>,
    /// Whether this is the last chunk of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chunk: Option<bool>,
    /// Arbitrary metadata associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// --- Push notifications ---

/// Configuration for push notifications sent to a client endpoint.
/// Per A2A v1.0 §4.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfig {
    /// The URL to which push notifications are delivered.
    pub url: String,
    /// A token used to authenticate push notification requests.
    pub token: String,
    /// Optional authentication configuration for the push notification endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<PushNotificationAuthentication>,
}

/// Authentication schemes and credentials for push notification delivery.
/// Per A2A v1.0 §4.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationAuthentication {
    /// The supported authentication scheme names.
    pub schemes: Vec<String>,
    /// Optional credentials required for authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<serde_json::Value>,
}

// --- Agent Card ---

/// The Agent Card describing an agent's capabilities, skills, and endpoints.
/// Per A2A v1.0 §4.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// The human-readable name of the agent.
    pub name: String,
    /// A human-readable description of the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The version of the agent.
    pub version: String,
    /// The URL where the agent is reachable.
    pub url: String,
    /// The capabilities supported by the agent.
    pub capabilities: AgentCapabilities,
    /// The default input modes the agent accepts.
    pub default_input_modes: Vec<String>,
    /// The default output modes the agent produces.
    pub default_output_modes: Vec<String>,
    /// The skills offered by the agent.
    pub skills: Vec<AgentSkill>,
    /// Whether the agent supports an authenticated extended agent card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_authenticated_extended_agent_card: Option<bool>,
    /// The protocol interfaces supported by the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_interfaces: Option<Vec<AgentInterface>>,
}

/// The capabilities of an A2A agent.
/// Per A2A v1.0 §4.4.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Whether the agent supports streaming responses.
    pub streaming: bool,
    /// Whether the agent supports push notifications.
    pub push_notifications: bool,
    /// Whether the agent retains and exposes task state transition history.
    pub state_transition_history: bool,
}

/// A skill offered by an A2A agent.
/// Per A2A v1.0 §4.4.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    /// The unique identifier of the skill.
    pub id: String,
    /// The human-readable name of the skill.
    pub name: String,
    /// A human-readable description of the skill.
    pub description: String,
    /// Tags categorizing the skill.
    pub tags: Vec<String>,
    /// Example inputs that demonstrate the skill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Input modes accepted by this skill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    /// Output modes produced by this skill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
    /// Default input modes for this skill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_input_modes: Option<Vec<String>>,
    /// Default output modes for this skill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_output_modes: Option<Vec<String>>,
}

/// A supported protocol interface, used for binding declaration.
/// Per A2A v1.0 §4.4.6 and RFC 0008 §"Agent Card Declaration".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    /// The URL of the interface endpoint.
    pub url: String,
    /// The protocol binding identifier (e.g. "aafp").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_binding: Option<String>,
    /// The protocol version supported by this interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
}

// --- Task query filter (ListTasks params) ---

/// Filter/pagination parameters for ListTasks.
/// Per A2A v1.0 §9.4.4, field names are `contextId`, `status`, `pageSize`,
/// `pageToken`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TaskListFilter {
    /// Filter tasks by lifecycle state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskState>,
    /// Filter tasks by context ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// The maximum number of tasks to return per page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// An opaque token for pagination, returned in a previous response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

// --- Response wrappers ---

/// SendMessageResponse per A2A v1.0 §9.4.1.
/// Contains either a Task or a Message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    /// The task returned by the operation, if a task was created or updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<Task>,
    /// The message returned by the operation, if a message was returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

impl From<Task> for SendMessageResponse {
    fn from(task: Task) -> Self {
        Self {
            task: Some(task),
            message: None,
        }
    }
}

/// ListTasksResponse per A2A v1.0 §9.4.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTasksResponse {
    /// The tasks matching the query.
    pub tasks: Vec<Task>,
    /// The total number of tasks matching the query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<u32>,
    /// The number of tasks returned in this page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// An opaque token for retrieving the next page of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

impl From<Vec<Task>> for ListTasksResponse {
    fn from(tasks: Vec<Task>) -> Self {
        let len = tasks.len() as u32;
        Self {
            tasks,
            total_size: Some(len),
            page_size: Some(len),
            next_page_token: Some(String::new()),
        }
    }
}
