//! A2A server handler trait and request dispatch.
//!
//! The `A2aServerHandler` trait defines the 11 core A2A operations.
//! `dispatch_request` routes JSON-RPC requests to the appropriate handler method.
//!
//! Per A2A v1.0 §9.4, SendMessage/SendStreamingMessage params are wrapped in a
//! `SendMessageRequest` object containing `message`, `configuration`, and
//! `metadata`. Responses wrap Task objects in `{"task": ...}` and ListTasks
//! in `{"tasks": [...], "totalSize": N, ...}`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::A2aError;
use crate::types::*;

/// A streaming update event — either a status update or an artifact update.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TaskUpdateEvent {
    /// A task status update event.
    Status(TaskStatusUpdateEvent),
    /// A task artifact update event.
    Artifact(TaskArtifactUpdateEvent),
}

/// Server-side handler for A2A operations.
///
/// Implement this trait to provide A2A agent functionality. Each method
/// corresponds to one of the 11 core A2A operations.
#[async_trait]
pub trait A2aServerHandler: Send + Sync {
    /// Send a message to the agent. Returns the created or updated Task.
    async fn send_message(&self, message: Message) -> Result<Task, A2aError>;

    /// Send a streaming message. Returns a sequence of update events.
    async fn send_streaming_message(
        &self,
        message: Message,
    ) -> Result<Vec<TaskUpdateEvent>, A2aError>;

    /// Get a task by ID.
    async fn get_task(&self, task_id: String) -> Result<Task, A2aError>;

    /// List tasks matching the filter.
    async fn list_tasks(&self, filter: TaskListFilter) -> Result<Vec<Task>, A2aError>;

    /// Cancel a task by ID.
    async fn cancel_task(&self, task_id: String) -> Result<Task, A2aError>;

    /// Subscribe to task updates. Returns a sequence of update events.
    async fn subscribe_to_task(&self, task_id: String) -> Result<Vec<TaskUpdateEvent>, A2aError>;

    /// Create a push notification config for a task.
    async fn create_push_notification_config(
        &self,
        task_id: String,
        config: PushNotificationConfig,
    ) -> Result<PushNotificationConfig, A2aError>;

    /// Get a push notification config by task ID and config ID.
    async fn get_push_notification_config(
        &self,
        task_id: String,
        config_id: String,
    ) -> Result<PushNotificationConfig, A2aError>;

    /// List push notification configs for a task.
    async fn list_push_notification_configs(
        &self,
        task_id: String,
    ) -> Result<Vec<PushNotificationConfig>, A2aError>;

    /// Delete a push notification config.
    async fn delete_push_notification_config(
        &self,
        task_id: String,
        config_id: String,
    ) -> Result<(), A2aError>;

    /// Get the extended agent card.
    async fn get_extended_agent_card(&self) -> Result<AgentCard, A2aError>;
}

/// Extract the `message` field from a SendMessageRequest params object.
/// Per A2A v1.0 §9.4.1, params is `{"message": {...}, "configuration": {...}, ...}`.
fn extract_message(
    params: &serde_json::Value,
    id: &serde_json::Value,
) -> Result<Message, serde_json::Value> {
    let message_val = match params.get("message") {
        Some(m) => m,
        None => return Err(A2aError::InvalidParams.to_jsonrpc_error(id.clone())),
    };
    match serde_json::from_value::<Message>(message_val.clone()) {
        Ok(m) => Ok(m),
        Err(_) => Err(A2aError::InvalidParams.to_jsonrpc_error(id.clone())),
    }
}

/// Dispatch a JSON-RPC request to the appropriate handler method.
/// Returns a JSON-RPC response (success or error).
///
/// Response wrapping per A2A v1.0:
/// - SendMessage/GetTask/CancelTask: `{"task": <Task>}` (SendMessageResponse)
/// - ListTasks: `{"tasks": [...], "totalSize": N, "pageSize": N, "nextPageToken": ""}`
/// - SendStreamingMessage/SubscribeToTask: array of events
/// - Push notification configs: the config object directly
/// - GetExtendedAgentCard: the AgentCard object directly
pub async fn dispatch_request(
    handler: &Arc<dyn A2aServerHandler>,
    request: &serde_json::Value,
) -> serde_json::Value {
    let method = match request.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            return A2aError::InvalidRequest.to_jsonrpc_error(
                request
                    .get("id")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
    };

    let id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // Each arm returns Result<serde_json::Value, A2aError> for type uniformity.
    // The Ok(value) is placed directly in the JSON-RPC "result" field.
    let result: Result<serde_json::Value, A2aError> = match method {
        "SendMessage" => {
            let msg = match extract_message(&params, &id) {
                Ok(m) => m,
                Err(error_response) => return error_response,
            };
            handler.send_message(msg).await.map(|task| {
                serde_json::to_value(SendMessageResponse::from(task))
                    .unwrap_or(serde_json::Value::Null)
            })
        }
        "SendStreamingMessage" => {
            let msg = match extract_message(&params, &id) {
                Ok(m) => m,
                Err(error_response) => return error_response,
            };
            handler
                .send_streaming_message(msg)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
        }
        "GetTask" => {
            let task_id = params
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if task_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            // historyLength is extracted but not passed to the handler yet;
            // the handler trait can be extended in a future revision.
            handler
                .get_task(task_id)
                .await
                .map(|task| serde_json::json!({ "task": serde_json::to_value(task).unwrap_or(serde_json::Value::Null) }))
        }
        "ListTasks" => {
            let filter: TaskListFilter = serde_json::from_value(params).unwrap_or_default();
            handler.list_tasks(filter).await.map(|tasks| {
                serde_json::to_value(ListTasksResponse::from(tasks))
                    .unwrap_or(serde_json::Value::Null)
            })
        }
        "CancelTask" => {
            let task_id = params
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if task_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            handler
                .cancel_task(task_id)
                .await
                .map(|task| serde_json::json!({ "task": serde_json::to_value(task).unwrap_or(serde_json::Value::Null) }))
        }
        "SubscribeToTask" => {
            let task_id = params
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if task_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            handler
                .subscribe_to_task(task_id)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
        }
        "CreateTaskPushNotificationConfig" => {
            let task_id = params
                .get("taskId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let config: PushNotificationConfig = match params.get("config") {
                Some(c) => match serde_json::from_value(c.clone()) {
                    Ok(cfg) => cfg,
                    Err(_) => return A2aError::InvalidParams.to_jsonrpc_error(id),
                },
                None => return A2aError::InvalidParams.to_jsonrpc_error(id),
            };
            if task_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            handler
                .create_push_notification_config(task_id, config)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
        }
        "GetTaskPushNotificationConfig" => {
            let task_id = params
                .get("taskId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let config_id = params
                .get("configId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if task_id.is_empty() || config_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            handler
                .get_push_notification_config(task_id, config_id)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
        }
        "ListTaskPushNotificationConfigs" => {
            let task_id = params
                .get("taskId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if task_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            handler
                .list_push_notification_configs(task_id)
                .await
                .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
        }
        "DeleteTaskPushNotificationConfig" => {
            let task_id = params
                .get("taskId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let config_id = params
                .get("configId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if task_id.is_empty() || config_id.is_empty() {
                return A2aError::InvalidParams.to_jsonrpc_error(id);
            }
            handler
                .delete_push_notification_config(task_id, config_id)
                .await
                .map(|_| serde_json::Value::Null)
        }
        "GetExtendedAgentCard" => handler
            .get_extended_agent_card()
            .await
            .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null)),
        _ => {
            return A2aError::MethodNotFound {
                method: method.to_string(),
            }
            .to_jsonrpc_error(id);
        }
    };

    match result {
        Ok(value) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": value,
        }),
        Err(e) => e.to_jsonrpc_error(id),
    }
}
