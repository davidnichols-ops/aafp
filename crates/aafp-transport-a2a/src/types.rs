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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Message>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    pub state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>, // ISO 8601 UTC
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

/// Task lifecycle states per A2A v1.0 §4.1.3.
/// Serialized as SCREAMING_SNAKE_CASE per ProtoJSON (A2A v1.0 §5.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskState {
    TaskStateUnspecified,
    TaskStateSubmitted,
    TaskStateWorking,
    TaskStateCompleted,
    TaskStateFailed,
    TaskStateCanceled,
    TaskStateInputRequired,
    TaskStateRejected,
    TaskStateAuthRequired,
}

/// Message sender role per A2A v1.0 §4.1.5.
/// Serialized as SCREAMING_SNAKE_CASE per ProtoJSON (A2A v1.0 §5.5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    RoleUnspecified,
    RoleUser,
    RoleAgent,
}

// --- Messages ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub role: Role,
    pub parts: Vec<Part>,
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>, // base64-encoded bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub artifact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parts: Vec<Part>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

// --- Streaming events ---

/// Status update event sent during streaming operations.
/// Per A2A v1.0 §4.2.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatusUpdateEvent {
    pub task_id: String,
    pub context_id: String,
    pub status: TaskStatus,
    /// `final` signals the last event in a stream. RFC 0008 uses this for
    /// stream completion signaling. The v1.0 data model places completion
    /// signaling in metadata, but `final` is retained for backward
    /// compatibility and is ignored by implementations that don't use it
    /// (per §5.7 "Unrecognized Fields").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#final: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Artifact update event sent during streaming operations.
/// Per A2A v1.0 §4.2.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifactUpdateEvent {
    pub task_id: String,
    pub context_id: String,
    pub artifact: Artifact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chunk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// --- Push notifications ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationConfig {
    pub url: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<PushNotificationAuthentication>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushNotificationAuthentication {
    pub schemes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<serde_json::Value>,
}

// --- Agent Card ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub version: String,
    pub url: String,
    pub capabilities: AgentCapabilities,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<AgentSkill>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_authenticated_extended_agent_card: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_interfaces: Option<Vec<AgentInterface>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    pub streaming: bool,
    pub push_notifications: bool,
    pub state_transition_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_input_modes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_output_modes: Option<Vec<String>>,
}

/// A supported protocol interface, used for binding declaration.
/// Per A2A v1.0 §4.4.6 and RFC 0008 §"Agent Card Declaration".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_binding: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

// --- Response wrappers ---

/// SendMessageResponse per A2A v1.0 §9.4.1.
/// Contains either a Task or a Message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<Task>,
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
    pub tasks: Vec<Task>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
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
