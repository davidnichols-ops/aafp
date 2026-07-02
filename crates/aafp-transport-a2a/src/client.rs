//! A2A client — high-level API for A2A operations.
//!
//! Each method serializes a JSON-RPC 2.0 request, sends it via the AAFP
//! transport, reads the response, and deserializes the result.

use crate::error::{A2aError, AafpA2aError};
use crate::server::TaskUpdateEvent;
use crate::types::*;
use crate::AafpA2aTransport;

/// High-level A2A client.
///
/// Wraps an `AafpA2aTransport` and provides typed methods for each
/// of the 11 A2A core operations.
pub struct A2aClient {
    transport: AafpA2aTransport,
    next_id: u64,
}

impl A2aClient {
    /// Connect to an A2A server over AAFP.
    pub async fn connect(agent: &aafp_sdk::Agent, addr: &str) -> Result<Self, AafpA2aError> {
        let transport = AafpA2aTransport::connect(agent, addr).await?;
        Ok(Self {
            transport,
            next_id: 1,
        })
    }

    /// Connect with a custom authorization provider.
    pub async fn connect_with_auth(
        agent: &aafp_sdk::Agent,
        addr: &str,
        auth: std::sync::Arc<dyn aafp_core::AuthorizationProvider>,
    ) -> Result<Self, AafpA2aError> {
        let transport = AafpA2aTransport::connect_with_auth(agent, addr, auth).await?;
        Ok(Self {
            transport,
            next_id: 1,
        })
    }

    /// Get the verified peer AgentId.
    pub fn peer_agent_id(&self) -> Option<&aafp_identity::AgentId> {
        self.transport.peer_agent_id()
    }

    fn next_request_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Send a request and receive a single response.
    async fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AafpA2aError> {
        let id = self.next_request_id();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        self.transport.send_jsonrpc(&request).await?;

        let response = self
            .transport
            .recv_jsonrpc()
            .await
            .ok_or(AafpA2aError::Closed)?;

        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-32603);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(AafpA2aError::A2a(A2aError::Internal {
                message: format!("[{code}] {message}"),
            }));
        }

        Ok(response
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Send a message to the agent. Returns the created or updated Task.
    pub async fn send_message(&mut self, message: Message) -> Result<Task, AafpA2aError> {
        let params = serde_json::to_value(&message)?;
        let result = self.request("SendMessage", params).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Send a streaming message. Returns a sequence of update events.
    ///
    /// The server returns a single JSON-RPC response with the array of events
    /// as the result. This is the simplest streaming model — for true
    /// incremental streaming, a future revision may use multiple responses.
    pub async fn send_streaming_message(
        &mut self,
        message: Message,
    ) -> Result<Vec<TaskUpdateEvent>, AafpA2aError> {
        let params = serde_json::to_value(&message)?;
        let result = self.request("SendStreamingMessage", params).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Get a task by ID.
    pub async fn get_task(&mut self, task_id: &str) -> Result<Task, AafpA2aError> {
        let params = serde_json::json!({ "id": task_id });
        let result = self.request("GetTask", params).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// List tasks matching the filter.
    pub async fn list_tasks(&mut self, filter: TaskListFilter) -> Result<Vec<Task>, AafpA2aError> {
        let params = serde_json::to_value(&filter)?;
        let result = self.request("ListTasks", params).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Cancel a task by ID.
    pub async fn cancel_task(&mut self, task_id: &str) -> Result<Task, AafpA2aError> {
        let params = serde_json::json!({ "id": task_id });
        let result = self.request("CancelTask", params).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Subscribe to task updates. Returns a sequence of update events.
    ///
    /// The server returns a single JSON-RPC response with the array of events.
    pub async fn subscribe_to_task(
        &mut self,
        task_id: &str,
    ) -> Result<Vec<TaskUpdateEvent>, AafpA2aError> {
        let params = serde_json::json!({ "id": task_id });
        let result = self.request("SubscribeToTask", params).await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Create a push notification config for a task.
    pub async fn create_push_notification_config(
        &mut self,
        task_id: &str,
        config: PushNotificationConfig,
    ) -> Result<PushNotificationConfig, AafpA2aError> {
        let params = serde_json::json!({
            "taskId": task_id,
            "config": serde_json::to_value(&config)?,
        });
        let result = self
            .request("CreateTaskPushNotificationConfig", params)
            .await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Get a push notification config by task ID and config ID.
    pub async fn get_push_notification_config(
        &mut self,
        task_id: &str,
        config_id: &str,
    ) -> Result<PushNotificationConfig, AafpA2aError> {
        let params = serde_json::json!({ "taskId": task_id, "configId": config_id });
        let result = self
            .request("GetTaskPushNotificationConfig", params)
            .await?;
        Ok(serde_json::from_value(result)?)
    }

    /// List push notification configs for a task.
    pub async fn list_push_notification_configs(
        &mut self,
        task_id: &str,
    ) -> Result<Vec<PushNotificationConfig>, AafpA2aError> {
        let params = serde_json::json!({ "taskId": task_id });
        let result = self
            .request("ListTaskPushNotificationConfigs", params)
            .await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Delete a push notification config.
    pub async fn delete_push_notification_config(
        &mut self,
        task_id: &str,
        config_id: &str,
    ) -> Result<(), AafpA2aError> {
        let params = serde_json::json!({ "taskId": task_id, "configId": config_id });
        self.request("DeleteTaskPushNotificationConfig", params)
            .await?;
        Ok(())
    }

    /// Get the extended agent card.
    pub async fn get_extended_agent_card(&mut self) -> Result<AgentCard, AafpA2aError> {
        let result = self
            .request("GetExtendedAgentCard", serde_json::Value::Null)
            .await?;
        Ok(serde_json::from_value(result)?)
    }

    /// Close the transport.
    pub async fn close(&mut self) -> Result<(), AafpA2aError> {
        self.transport.close().await
    }
}
