//! A2A over AAFP — full agent-to-agent demo.
//!
//! This example starts a server agent that implements a simple A2A handler,
//! then connects a client agent that sends a message, receives streaming
//! updates, and cancels the task.
//! Updated for A2A v1.0: Role enum, flat Part, SCREAMING_SNAKE_CASE states.

use std::sync::Arc;

use aafp_sdk::AgentBuilder;
use aafp_transport_a2a::{
    dispatch_request, A2aClient, A2aError, A2aServerHandler, AgentCapabilities, AgentCard, Message,
    Part, PushNotificationConfig, Role, Task, TaskListFilter, TaskState, TaskStatus,
    TaskUpdateEvent,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

/// A simple A2A server that processes messages and returns tasks.
struct DemoAgent {
    task_counter: Mutex<u64>,
}

impl DemoAgent {
    fn new() -> Self {
        Self {
            task_counter: Mutex::new(1),
        }
    }
}

#[async_trait]
impl A2aServerHandler for DemoAgent {
    async fn send_message(&self, message: Message) -> Result<Task, A2aError> {
        let mut counter = self.task_counter.lock().await;
        let id = *counter;
        *counter += 1;

        println!("  [server] Received message from: {:?}", message.role);

        let task = Task {
            id: format!("task-{id}"),
            context_id: Some(format!("ctx-{id}")),
            status: TaskStatus {
                state: TaskState::TaskStateWorking,
                timestamp: Some("2026-07-01T12:00:00Z".to_string()),
                message: None,
            },
            artifacts: None,
            history: Some(vec![message]),
            metadata: None,
        };

        println!("  [server] Created task: {}", task.id);
        Ok(task)
    }

    async fn send_streaming_message(
        &self,
        message: Message,
    ) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        let task = self.send_message(message).await?;

        // Simulate streaming updates
        let events = vec![
            TaskUpdateEvent::Status(aafp_transport_a2a::TaskStatusUpdateEvent {
                task_id: task.id.clone(),
                context_id: task.context_id.clone().unwrap_or_default(),
                status: TaskStatus {
                    state: TaskState::TaskStateWorking,
                    timestamp: Some("2026-07-01T12:00:01Z".to_string()),
                    message: None,
                },
                r#final: Some(false),
                metadata: None,
            }),
            TaskUpdateEvent::Status(aafp_transport_a2a::TaskStatusUpdateEvent {
                task_id: task.id.clone(),
                context_id: task.context_id.clone().unwrap_or_default(),
                status: TaskStatus {
                    state: TaskState::TaskStateCompleted,
                    timestamp: Some("2026-07-01T12:00:02Z".to_string()),
                    message: None,
                },
                r#final: Some(true),
                metadata: None,
            }),
        ];

        println!("  [server] Streamed {} events", events.len());
        Ok(events)
    }

    async fn get_task(&self, task_id: String) -> Result<Task, A2aError> {
        Err(A2aError::TaskNotFound { task_id })
    }

    async fn list_tasks(&self, _filter: TaskListFilter) -> Result<Vec<Task>, A2aError> {
        Ok(vec![])
    }

    async fn cancel_task(&self, task_id: String) -> Result<Task, A2aError> {
        Err(A2aError::TaskNotCancelable { task_id })
    }

    async fn subscribe_to_task(&self, task_id: String) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        Err(A2aError::TaskNotFound { task_id })
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

    async fn get_extended_agent_card(&self) -> Result<AgentCard, A2aError> {
        Ok(AgentCard {
            name: "demo-agent".to_string(),
            description: Some("A2A demo agent over AAFP".to_string()),
            version: "1.0.0".to_string(),
            url: "quic://127.0.0.1:0".to_string(),
            capabilities: AgentCapabilities {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== A2A over AAFP Demo ===\n");

    // Start server agent
    let server_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse()?)
        .build()
        .await?;
    let server_addr = server_agent.transport.local_multiaddr()?;
    println!("Server agent listening on: {server_addr}");

    let handler: Arc<dyn A2aServerHandler> = Arc::new(DemoAgent::new());

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        println!("[server] Waiting for connection...");
        let mut transport = aafp_transport_a2a::AafpA2aTransport::accept(&server_agent)
            .await
            .expect("accept failed");
        println!("[server] Connection established, peer verified");

        // Serve requests
        while let Some(request) = transport.recv_jsonrpc().await {
            println!("[server] Received: {}", request["method"]);
            let response = dispatch_request(&handler, &request).await;
            transport
                .send_jsonrpc(&response)
                .await
                .expect("send failed");
        }

        println!("[server] Stream closed");
    });

    // Create client agent
    let client_agent = AgentBuilder::new()
        .bind("127.0.0.1:0".parse()?)
        .build()
        .await?;

    println!("\n[client] Connecting to {server_addr}...");
    let mut client = A2aClient::connect(&client_agent, &server_addr).await?;
    println!("[client] Connected, peer: {:?}", client.peer_agent_id());

    // 1. Send a message
    println!("\n--- Step 1: SendMessage ---");
    let message = Message {
        role: Role::RoleUser,
        parts: vec![Part::text("Please analyze the data")],
        message_id: "msg-1".to_string(),
        context_id: None,
        task_id: None,
        metadata: None,
        extensions: None,
        reference_task_ids: None,
    };
    let task = client.send_message(message).await?;
    println!(
        "[client] Task created: {} (state: {:?})",
        task.id, task.status.state
    );

    // 2. Send a streaming message
    println!("\n--- Step 2: SendStreamingMessage ---");
    let stream_message = Message {
        role: Role::RoleUser,
        parts: vec![Part::text("Stream me the results")],
        message_id: "msg-2".to_string(),
        context_id: None,
        task_id: None,
        metadata: None,
        extensions: None,
        reference_task_ids: None,
    };
    let events = client.send_streaming_message(stream_message).await?;
    println!("[client] Received {} streaming events", events.len());
    for (i, event) in events.iter().enumerate() {
        if let TaskUpdateEvent::Status(s) = event {
            println!(
                "  Event {}: state={:?}, final={}",
                i + 1,
                s.status.state,
                s.r#final.unwrap_or(false)
            );
        }
    }

    // 3. Get extended agent card
    println!("\n--- Step 3: GetExtendedAgentCard ---");
    let card = client.get_extended_agent_card().await?;
    println!(
        "[client] Agent card: {} v{} ({})",
        card.name, card.version, card.url
    );

    // 4. Graceful close
    println!("\n--- Step 4: Graceful close ---");
    client.close().await?;
    println!("[client] Transport closed");

    // Wait for server to finish
    let _ = server_handle.await;

    println!("\n=== Demo complete ===");
    Ok(())
}
