//! Integration tests for the AAFP A2A transport binding.
//!
//! These tests start a real QUIC server, perform the AAFP handshake, and
//! exchange A2A JSON-RPC messages over the secure channel.
//! Updated for A2A v1.0: Role enum, flat Part, SCREAMING_SNAKE_CASE states.

use std::collections::HashMap;
use std::sync::Arc;

use aafp_sdk::AgentBuilder;
use aafp_transport_a2a::{
    dispatch_request, A2aClient, A2aError, A2aServerHandler, Message, Part, PushNotificationConfig,
    Role, Task, TaskListFilter, TaskState, TaskStatus, TaskUpdateEvent,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

/// A simple in-memory A2A server handler for testing.
struct TestHandler {
    tasks: Mutex<HashMap<String, Task>>,
    next_id: Mutex<u64>,
}

impl TestHandler {
    fn new() -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    async fn create_task(&self, message: Message) -> Task {
        let mut id_lock = self.next_id.lock().await;
        let id = *id_lock;
        *id_lock += 1;
        drop(id_lock);

        let task = Task {
            id: format!("task-{id}"),
            context_id: Some(format!("ctx-{id}")),
            status: TaskStatus {
                state: TaskState::TaskStateWorking,
                timestamp: Some("2026-07-01T00:00:00Z".to_string()),
                message: None,
            },
            artifacts: None,
            history: Some(vec![message]),
            metadata: None,
        };
        self.tasks
            .lock()
            .await
            .insert(task.id.clone(), task.clone());
        task
    }
}

#[async_trait]
impl A2aServerHandler for TestHandler {
    async fn send_message(&self, message: Message) -> Result<Task, A2aError> {
        Ok(self.create_task(message).await)
    }

    async fn send_streaming_message(
        &self,
        message: Message,
    ) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        let task = self.create_task(message).await;
        let event = aafp_transport_a2a::TaskStatusUpdateEvent {
            task_id: task.id.clone(),
            context_id: task.context_id.clone().unwrap_or_default(),
            status: task.status.clone(),
            r#final: Some(true),
            metadata: None,
        };
        Ok(vec![TaskUpdateEvent::Status(event)])
    }

    async fn get_task(&self, task_id: String) -> Result<Task, A2aError> {
        self.tasks
            .lock()
            .await
            .get(&task_id)
            .cloned()
            .ok_or(A2aError::TaskNotFound { task_id })
    }

    async fn list_tasks(&self, _filter: TaskListFilter) -> Result<Vec<Task>, A2aError> {
        Ok(self.tasks.lock().await.values().cloned().collect())
    }

    async fn cancel_task(&self, task_id: String) -> Result<Task, A2aError> {
        let mut tasks = self.tasks.lock().await;
        let task = tasks
            .get_mut(&task_id)
            .ok_or(A2aError::TaskNotFound { task_id })?;
        task.status.state = TaskState::TaskStateCanceled;
        Ok(task.clone())
    }

    async fn subscribe_to_task(&self, task_id: String) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        let task = self
            .tasks
            .lock()
            .await
            .get(&task_id)
            .cloned()
            .ok_or(A2aError::TaskNotFound { task_id })?;
        let event = aafp_transport_a2a::TaskStatusUpdateEvent {
            task_id: task.id,
            context_id: task.context_id.unwrap_or_default(),
            status: task.status,
            r#final: Some(true),
            metadata: None,
        };
        Ok(vec![TaskUpdateEvent::Status(event)])
    }

    async fn create_push_notification_config(
        &self,
        _task_id: String,
        config: PushNotificationConfig,
    ) -> Result<PushNotificationConfig, A2aError> {
        Ok(config)
    }

    async fn get_push_notification_config(
        &self,
        _task_id: String,
        _config_id: String,
    ) -> Result<PushNotificationConfig, A2aError> {
        Err(A2aError::PushNotificationNotSupported)
    }

    async fn list_push_notification_configs(
        &self,
        _task_id: String,
    ) -> Result<Vec<PushNotificationConfig>, A2aError> {
        Ok(vec![])
    }

    async fn delete_push_notification_config(
        &self,
        _task_id: String,
        _config_id: String,
    ) -> Result<(), A2aError> {
        Ok(())
    }

    async fn get_extended_agent_card(&self) -> Result<aafp_transport_a2a::AgentCard, A2aError> {
        Ok(aafp_transport_a2a::AgentCard {
            name: "test-agent".to_string(),
            description: Some("Test A2A agent".to_string()),
            version: "1.0.0".to_string(),
            url: "quic://127.0.0.1:0".to_string(),
            capabilities: aafp_transport_a2a::AgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: true,
            },
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: vec![],
            supports_authenticated_extended_agent_card: None,
            supported_interfaces: None,
        })
    }
}

/// Start a test server that accepts one connection and serves requests.
async fn start_test_server(
    handler: Arc<dyn A2aServerHandler>,
) -> (String, tokio::task::JoinHandle<()>) {
    let agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();
    let addr = agent.transport.local_multiaddr().unwrap();

    let handle = tokio::spawn(async move {
        let mut transport = aafp_transport_a2a::AafpA2aTransport::accept(&agent)
            .await
            .unwrap();

        // Read requests and dispatch responses
        while let Some(request) = transport.recv_jsonrpc().await {
            let response = dispatch_request(&handler, &request).await;
            transport.send_jsonrpc(&response).await.unwrap();
        }
    });

    (addr, handle)
}

/// Helper to create a user message with a text part.
fn user_message(text: &str, msg_id: &str) -> Message {
    Message {
        role: Role::RoleUser,
        parts: vec![Part::text(text)],
        message_id: msg_id.to_string(),
        context_id: None,
        task_id: None,
        metadata: None,
        extensions: None,
        reference_task_ids: None,
    }
}

#[tokio::test]
async fn test_send_message() {
    let handler = Arc::new(TestHandler::new());
    let (addr, _handle) = start_test_server(handler).await;

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let mut client = A2aClient::connect(&client_agent, &addr).await.unwrap();

    let task = client
        .send_message(user_message("Hello, agent!", "msg-1"))
        .await
        .unwrap();
    assert!(task.id.starts_with("task-"));
    assert_eq!(task.status.state, TaskState::TaskStateWorking);

    client.close().await.unwrap();
}

#[tokio::test]
async fn test_get_list_cancel_task() {
    let handler = Arc::new(TestHandler::new());
    let (addr, _handle) = start_test_server(handler).await;

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let mut client = A2aClient::connect(&client_agent, &addr).await.unwrap();

    // Create a task
    let task = client
        .send_message(user_message("Do something", "msg-1"))
        .await
        .unwrap();
    let task_id = task.id.clone();

    // Get the task
    let fetched = client.get_task(&task_id).await.unwrap();
    assert_eq!(fetched.id, task_id);

    // List tasks
    let tasks = client.list_tasks(TaskListFilter::default()).await.unwrap();
    assert!(!tasks.is_empty());

    // Cancel the task
    let canceled = client.cancel_task(&task_id).await.unwrap();
    assert_eq!(canceled.status.state, TaskState::TaskStateCanceled);

    client.close().await.unwrap();
}

#[tokio::test]
async fn test_streaming_message() {
    let handler = Arc::new(TestHandler::new());
    let (addr, _handle) = start_test_server(handler).await;

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let mut client = A2aClient::connect(&client_agent, &addr).await.unwrap();

    let events = client
        .send_streaming_message(user_message("Stream me updates", "msg-1"))
        .await
        .unwrap();
    assert!(!events.is_empty());

    // The last event should have final: true
    if let Some(TaskUpdateEvent::Status(last)) = events.last() {
        assert_eq!(last.r#final, Some(true));
    }

    client.close().await.unwrap();
}

#[tokio::test]
async fn test_error_mapping() {
    let handler = Arc::new(TestHandler::new());
    let (addr, _handle) = start_test_server(handler).await;

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let mut client = A2aClient::connect(&client_agent, &addr).await.unwrap();

    // Request a nonexistent task — should get an error
    let result = client.get_task("nonexistent-task").await;
    assert!(result.is_err());

    client.close().await.unwrap();
}

#[tokio::test]
async fn test_graceful_close() {
    let handler = Arc::new(TestHandler::new());
    let (addr, _handle) = start_test_server(handler).await;

    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .unwrap();

    let mut client = A2aClient::connect(&client_agent, &addr).await.unwrap();

    // Close should not panic
    client.close().await.unwrap();
}
