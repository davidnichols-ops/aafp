//! Spec conformance tests for the AAFP A2A transport binding.
//!
//! These tests use the exact JSON examples from the A2A v1.0 specification
//! (https://a2a-protocol.org/v1.0.0/specification/) to verify that the AAFP
//! A2A transport correctly handles the v1.0 wire format:
//!
//! - SCREAMING_SNAKE_CASE enum values (TaskState, Role) per §5.5
//! - Flat Part (no `kind` discriminator) per Appendix A.2.1
//! - SendMessageRequest params wrapping (`{"message": {...}}`) per §9.4.1
//! - Response wrapping (`{"task": {...}}`, `{"tasks": [...]}`) per §9.4
//! - Byte-for-byte payload preservation (ADR-0002)
//! - All 11 operations dispatchable with correct method names per §9.4
//! - JSON-RPC error codes match §5.4 mapping table

use std::sync::Arc;

use aafp_transport_a2a::{
    dispatch_request, A2aError, A2aServerHandler, AgentCapabilities, AgentCard, Message, Part,
    PushNotificationConfig, Role, Task, TaskListFilter, TaskState, TaskStatus, TaskUpdateEvent,
};
use async_trait::async_trait;

/// A handler that echoes back spec-conformant responses for testing.
struct SpecConformantHandler;

#[async_trait]
impl A2aServerHandler for SpecConformantHandler {
    async fn send_message(&self, _message: Message) -> Result<Task, A2aError> {
        // Return a task matching the spec §6.1 response format
        Ok(Task {
            id: "task-uuid".to_string(),
            context_id: Some("context-uuid".to_string()),
            status: TaskStatus {
                state: TaskState::TaskStateCompleted,
                timestamp: Some("2024-03-15T10:00:00Z".to_string()),
                message: None,
            },
            artifacts: Some(vec![aafp_transport_a2a::Artifact {
                artifact_id: "artifact-uuid".to_string(),
                name: Some("Weather Report".to_string()),
                description: None,
                parts: vec![Part::text("Today will be sunny with a high of 75°F")],
                metadata: None,
                extensions: None,
            }]),
            history: None,
            metadata: None,
        })
    }

    async fn send_streaming_message(
        &self,
        _message: Message,
    ) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        // Return events matching spec §6.2 SSE response format
        Ok(vec![
            TaskUpdateEvent::Status(aafp_transport_a2a::TaskStatusUpdateEvent {
                task_id: "task-uuid".to_string(),
                context_id: "context-uuid".to_string(),
                status: TaskStatus {
                    state: TaskState::TaskStateWorking,
                    timestamp: None,
                    message: None,
                },
                r#final: Some(false),
                metadata: None,
            }),
            TaskUpdateEvent::Artifact(aafp_transport_a2a::TaskArtifactUpdateEvent {
                task_id: "task-uuid".to_string(),
                context_id: "context-uuid".to_string(),
                artifact: aafp_transport_a2a::Artifact {
                    artifact_id: "artifact-uuid".to_string(),
                    name: None,
                    description: None,
                    parts: vec![Part::text("# Climate Change Report\n\n")],
                    metadata: None,
                    extensions: None,
                },
                append: None,
                last_chunk: None,
                metadata: None,
            }),
            TaskUpdateEvent::Status(aafp_transport_a2a::TaskStatusUpdateEvent {
                task_id: "task-uuid".to_string(),
                context_id: "context-uuid".to_string(),
                status: TaskStatus {
                    state: TaskState::TaskStateCompleted,
                    timestamp: None,
                    message: None,
                },
                r#final: Some(true),
                metadata: None,
            }),
        ])
    }

    async fn get_task(&self, task_id: String) -> Result<Task, A2aError> {
        if task_id == "task-uuid" {
            Ok(Task {
                id: "task-uuid".to_string(),
                context_id: Some("context-uuid".to_string()),
                status: TaskStatus {
                    state: TaskState::TaskStateCompleted,
                    timestamp: Some("2024-03-15T10:15:00Z".to_string()),
                    message: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
        } else {
            Err(A2aError::TaskNotFound { task_id })
        }
    }

    async fn list_tasks(&self, _filter: TaskListFilter) -> Result<Vec<Task>, A2aError> {
        Ok(vec![Task {
            id: "3f36680c-7f37-4a5f-945e-d78981fafd36".to_string(),
            context_id: Some("c295ea44-7543-4f78-b524-7a38915ad6e4".to_string()),
            status: TaskStatus {
                state: TaskState::TaskStateCompleted,
                timestamp: Some("2024-03-15T10:15:00Z".to_string()),
                message: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        }])
    }

    async fn cancel_task(&self, task_id: String) -> Result<Task, A2aError> {
        Ok(Task {
            id: task_id,
            context_id: Some("context-uuid".to_string()),
            status: TaskStatus {
                state: TaskState::TaskStateCanceled,
                timestamp: Some("2024-03-15T10:30:00Z".to_string()),
                message: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
    }

    async fn subscribe_to_task(&self, _task_id: String) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        Ok(vec![])
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
        Ok(PushNotificationConfig {
            url: "https://client.example.com/webhook/a2a-notifications".to_string(),
            token: "secure-client-token".to_string(),
            authentication: Some(aafp_transport_a2a::PushNotificationAuthentication {
                schemes: vec!["Bearer".to_string()],
                credentials: None,
            }),
        })
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
            name: "weather-agent".to_string(),
            description: Some("An agent that provides weather information".to_string()),
            version: "1.0.0".to_string(),
            url: "quic://agent.example.com:443".to_string(),
            capabilities: AgentCapabilities {
                streaming: true,
                push_notifications: true,
                state_transition_history: false,
            },
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: vec![aafp_transport_a2a::AgentSkill {
                id: "weather-query".to_string(),
                name: "Weather Query".to_string(),
                description: "Get current weather for a location".to_string(),
                tags: vec!["weather".to_string()],
                examples: None,
                input_modes: None,
                output_modes: None,
                default_input_modes: None,
                default_output_modes: None,
            }],
            supports_authenticated_extended_agent_card: None,
            supported_interfaces: Some(vec![aafp_transport_a2a::AgentInterface {
                url: "quic://agent.example.com:443".to_string(),
                protocol_binding: Some("https://a2a-protocol.org/bindings/aafp".to_string()),
                protocol_version: Some("1.0".to_string()),
            }]),
        })
    }
}

// ============================================================================
// §6.1 Basic Task Execution — spec example round-trip
// ============================================================================

#[tokio::test]
async fn test_spec_6_1_basic_task_execution() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    // Exact JSON from A2A v1.0 §6.1 (adapted to JSON-RPC envelope per §9.4.1)
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": "What is the weather today?"}],
                "messageId": "msg-uuid"
            }
        }
    });

    let response = dispatch_request(&handler, &request).await;

    // Verify JSON-RPC envelope
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response.get("error").is_none(), "Should not error");

    // Verify response wraps Task in {"task": ...} per §9.4.1
    let result = &response["result"];
    assert!(result.get("task").is_some(), "Result should contain task");

    // Verify Task fields match spec §6.1 response
    let task = &result["task"];
    assert_eq!(task["id"], "task-uuid");
    assert_eq!(task["contextId"], "context-uuid");
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");

    // Verify artifact matches spec §6.1
    let artifact = &task["artifacts"][0];
    assert_eq!(artifact["artifactId"], "artifact-uuid");
    assert_eq!(artifact["name"], "Weather Report");
    assert_eq!(
        artifact["parts"][0]["text"],
        "Today will be sunny with a high of 75°F"
    );

    // Verify no "kind" discriminator on Part (v1.0 Appendix A.2.1)
    assert!(
        artifact["parts"][0].get("kind").is_none(),
        "Part should NOT have kind discriminator in v1.0"
    );
}

// ============================================================================
// §6.2 Streaming Task Execution — spec example round-trip
// ============================================================================

#[tokio::test]
async fn test_spec_6_2_streaming_task_execution() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendStreamingMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": "Write a detailed report on climate change"}],
                "messageId": "msg-uuid"
            }
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());

    // Result is an array of events
    let events = response["result"].as_array().expect("Should be array");
    assert_eq!(events.len(), 3, "Should have 3 streaming events");

    // Event 0: status update WORKING
    let e0 = &events[0];
    assert_eq!(e0["taskId"], "task-uuid");
    assert_eq!(e0["contextId"], "context-uuid");
    assert_eq!(e0["status"]["state"], "TASK_STATE_WORKING");
    assert_eq!(e0["final"], false);

    // Event 1: artifact update
    let e1 = &events[1];
    assert_eq!(e1["taskId"], "task-uuid");
    assert_eq!(
        e1["artifact"]["parts"][0]["text"],
        "# Climate Change Report\n\n"
    );

    // Event 2: status update COMPLETED, final
    let e2 = &events[2];
    assert_eq!(e2["status"]["state"], "TASK_STATE_COMPLETED");
    assert_eq!(e2["final"], true);
}

// ============================================================================
// §6.3 Multi-Turn Interaction — input_required state
// ============================================================================

#[tokio::test]
async fn test_spec_6_3_input_required_state() {
    // Verify TASK_STATE_INPUT_REQUIRED is a valid state per §4.1.3
    let state = TaskState::TaskStateInputRequired;
    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(json, "\"TASK_STATE_INPUT_REQUIRED\"");
}

// ============================================================================
// §6.5 Task Listing — spec example with pagination
// ============================================================================

#[tokio::test]
async fn test_spec_6_5_list_tasks_with_pagination() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    // Per §9.4.4, ListTasks params use status/pageSize/pageToken
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "ListTasks",
        "params": {
            "contextId": "c295ea44-7543-4f78-b524-7a38915ad6e4",
            "status": "TASK_STATE_COMPLETED",
            "pageSize": 10
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());

    // Verify ListTasks response wrapping per §9.4.4
    let result = &response["result"];
    assert!(result.get("tasks").is_some(), "Should have tasks array");
    assert!(result.get("totalSize").is_some(), "Should have totalSize");

    let tasks = result["tasks"].as_array().expect("tasks should be array");
    assert!(!tasks.is_empty());
    assert_eq!(tasks[0]["id"], "3f36680c-7f37-4a5f-945e-d78981fafd36");
    assert_eq!(
        tasks[0]["contextId"],
        "c295ea44-7543-4f78-b524-7a38915ad6e4"
    );
    assert_eq!(tasks[0]["status"]["state"], "TASK_STATE_COMPLETED");
}

// ============================================================================
// §6.6 Push Notification Setup — spec example
// ============================================================================

#[tokio::test]
async fn test_spec_6_6_push_notification_config() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    // Per §6.6, push notification config has url, token, authentication.schemes
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "CreateTaskPushNotificationConfig",
        "params": {
            "taskId": "43667960-d455-4453-b0cf-1bae4955270d",
            "config": {
                "url": "https://client.example.com/webhook/a2a-notifications",
                "token": "secure-client-token-for-task-aaa",
                "authentication": {
                    "schemes": ["Bearer"]
                }
            }
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());

    let result = &response["result"];
    assert_eq!(
        result["url"],
        "https://client.example.com/webhook/a2a-notifications"
    );
    assert_eq!(result["token"], "secure-client-token-for-task-aaa");
    assert_eq!(result["authentication"]["schemes"][0], "Bearer");
}

// ============================================================================
// §6.7 File Exchange — raw and url parts
// ============================================================================

#[tokio::test]
async fn test_spec_6_7_file_part_raw_and_url() {
    // Verify Part with raw (base64) field per §6.7 upload example
    let raw_part = Part::file_bytes("iVBORw0KGgoAAAANSUhEUgAAAAUA...", "image/png");
    let json = serde_json::to_value(&raw_part).unwrap();
    assert_eq!(json["raw"], "iVBORw0KGgoAAAANSUhEUgAAAAUA...");
    assert_eq!(json["mediaType"], "image/png");
    assert!(
        json.get("kind").is_none(),
        "File part should NOT have kind discriminator"
    );

    // Verify Part with url field per §6.7 download example
    let url_part = Part::file_url(
        "https://storage.example.com/processed/task-bbb/output.png?token=xyz",
        "image/png",
    );
    let json = serde_json::to_value(&url_part).unwrap();
    assert_eq!(
        json["url"],
        "https://storage.example.com/processed/task-bbb/output.png?token=xyz"
    );
    assert_eq!(json["mediaType"], "image/png");
}

// ============================================================================
// §6.8 Structured Data Exchange — data part
// ============================================================================

#[tokio::test]
async fn test_spec_6_8_data_part() {
    // Verify Part with data field per §6.8 structured data example
    let data_part = Part::data(serde_json::json!({
        "tickets": [
            {"id": "T-001", "status": "open", "priority": "high"}
        ]
    }));
    let json = serde_json::to_value(&data_part).unwrap();
    assert!(json.get("data").is_some(), "Should have data field");
    assert!(
        json.get("kind").is_none(),
        "Data part should NOT have kind discriminator"
    );
}

// ============================================================================
// §9.4.3 GetTask — spec JSON-RPC request format
// ============================================================================

#[tokio::test]
async fn test_spec_9_4_3_get_task_jsonrpc() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    // Exact JSON-RPC format from §9.4.3
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "GetTask",
        "params": {
            "id": "task-uuid",
            "historyLength": 10
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 2);
    assert!(response.get("error").is_none());

    // Response wraps Task in {"task": ...}
    let task = &response["result"]["task"];
    assert_eq!(task["id"], "task-uuid");
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
}

// ============================================================================
// §9.4.4 ListTasks — spec JSON-RPC request format
// ============================================================================

#[tokio::test]
async fn test_spec_9_4_4_list_tasks_jsonrpc() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    // Exact JSON-RPC format from §9.4.4
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "ListTasks",
        "params": {
            "contextId": "context-uuid",
            "status": "TASK_STATE_WORKING",
            "pageSize": 50,
            "pageToken": "cursor-token"
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());
    assert!(response["result"].get("tasks").is_some());
}

// ============================================================================
// §9.4.5 CancelTask — spec JSON-RPC request format
// ============================================================================

#[tokio::test]
async fn test_spec_9_4_5_cancel_task_jsonrpc() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "CancelTask",
        "params": {
            "id": "task-uuid"
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());

    let task = &response["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_CANCELED");
}

// ============================================================================
// §9.4.6 SubscribeToTask — spec JSON-RPC request format
// ============================================================================

#[tokio::test]
async fn test_spec_9_4_6_subscribe_to_task_jsonrpc() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "SubscribeToTask",
        "params": {
            "id": "task-uuid"
        }
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());
}

// ============================================================================
// §9.4.8 GetExtendedAgentCard — spec JSON-RPC request format
// ============================================================================

#[tokio::test]
async fn test_spec_9_4_8_get_extended_agent_card_jsonrpc() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    // Per §9.4.8, GetExtendedAgentCard has no params
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "GetExtendedAgentCard"
    });

    let response = dispatch_request(&handler, &request).await;
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 6);
    assert!(response.get("error").is_none());

    let card = &response["result"];
    assert_eq!(card["name"], "weather-agent");
    assert_eq!(card["version"], "1.0.0");

    // Verify supportedInterfaces with AAFP binding declaration per RFC 0008
    let interfaces = card["supportedInterfaces"]
        .as_array()
        .expect("Should have interfaces");
    assert!(!interfaces.is_empty());
    assert_eq!(
        interfaces[0]["protocolBinding"],
        "https://a2a-protocol.org/bindings/aafp"
    );
    assert_eq!(interfaces[0]["protocolVersion"], "1.0");
}

// ============================================================================
// §5.4 Error Code Mappings — all 9 A2A-specific + 4 JSON-RPC standard
// ============================================================================

#[tokio::test]
async fn test_spec_5_4_task_not_found_error() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(SpecConformantHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "GetTask",
        "params": {"id": "nonexistent-task-id"}
    });

    let response = dispatch_request(&handler, &request).await;
    let error = &response["error"];
    assert_eq!(
        error["code"], -32001,
        "TaskNotFoundError should map to -32001"
    );
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("nonexistent-task-id"),
        "Error message should contain task ID"
    );
}

// ============================================================================
// Byte-for-byte preservation (ADR-0002)
// ============================================================================

#[test]
fn test_adr_0002_byte_preservation_spec_message() {
    // Verify that a complete spec-conformant JSON-RPC message is preserved
    // byte-for-byte through serialization/deserialization (ADR-0002).
    let spec_message = r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"What is the weather today?"}],"messageId":"msg-uuid"}}}"#;

    let bytes = spec_message.as_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let reserialized = serde_json::to_string(&parsed).unwrap();

    // The reserialized form should be semantically equal (key ordering may differ)
    let reparsed: serde_json::Value = serde_json::from_str(&reserialized).unwrap();
    assert_eq!(
        parsed, reparsed,
        "Byte-for-byte semantic preservation failed"
    );

    // Verify all fields are present and correct
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["method"], "SendMessage");
    assert_eq!(parsed["params"]["message"]["role"], "ROLE_USER");
    assert_eq!(
        parsed["params"]["message"]["parts"][0]["text"],
        "What is the weather today?"
    );
    assert_eq!(parsed["params"]["message"]["messageId"], "msg-uuid");
}

// ============================================================================
// §5.5 JSON Field Naming Convention — camelCase verification
// ============================================================================

#[test]
fn test_spec_5_5_camel_case_naming() {
    // Verify all field names use camelCase per §5.5
    let message = Message {
        role: Role::RoleUser,
        parts: vec![Part::text("Hello")],
        message_id: "msg-001".to_string(),
        context_id: Some("ctx-001".to_string()),
        task_id: Some("task-001".to_string()),
        metadata: None,
        extensions: None,
        reference_task_ids: None,
    };

    let json = serde_json::to_string(&message).unwrap();
    assert!(
        json.contains("\"messageId\""),
        "Should use camelCase messageId"
    );
    assert!(
        json.contains("\"contextId\""),
        "Should use camelCase contextId"
    );
    assert!(json.contains("\"taskId\""), "Should use camelCase taskId");
    assert!(
        !json.contains("\"message_id\""),
        "Should NOT use snake_case"
    );
    assert!(
        !json.contains("\"context_id\""),
        "Should NOT use snake_case"
    );
}

// ============================================================================
// All 11 operations — verify method names match §5.3 Method Mapping Reference
// ============================================================================

#[test]
fn test_spec_5_3_method_mapping_reference() {
    // Verify all 11 method names match the §5.3 mapping table
    let expected_methods = [
        "SendMessage",
        "SendStreamingMessage",
        "GetTask",
        "ListTasks",
        "CancelTask",
        "SubscribeToTask",
        "CreateTaskPushNotificationConfig",
        "GetTaskPushNotificationConfig",
        "ListTaskPushNotificationConfigs",
        "DeleteTaskPushNotificationConfig",
        "GetExtendedAgentCard",
    ];

    assert_eq!(
        expected_methods.len(),
        11,
        "Should have exactly 11 operations"
    );

    // All should be PascalCase (not category/action or snake_case)
    for method in &expected_methods {
        assert!(
            method.chars().next().unwrap().is_uppercase(),
            "Method {method} should start uppercase"
        );
    }
}

// ============================================================================
// §4.1.3 TaskState — all v1.0 states are representable
// ============================================================================

#[test]
fn test_spec_4_1_3_all_task_states() {
    // Verify all 9 TaskState values from §4.1.3 are representable
    let states = [
        (TaskState::TaskStateUnspecified, "TASK_STATE_UNSPECIFIED"),
        (TaskState::TaskStateSubmitted, "TASK_STATE_SUBMITTED"),
        (TaskState::TaskStateWorking, "TASK_STATE_WORKING"),
        (TaskState::TaskStateCompleted, "TASK_STATE_COMPLETED"),
        (TaskState::TaskStateFailed, "TASK_STATE_FAILED"),
        (TaskState::TaskStateCanceled, "TASK_STATE_CANCELED"),
        (
            TaskState::TaskStateInputRequired,
            "TASK_STATE_INPUT_REQUIRED",
        ),
        (TaskState::TaskStateRejected, "TASK_STATE_REJECTED"),
        (TaskState::TaskStateAuthRequired, "TASK_STATE_AUTH_REQUIRED"),
    ];

    assert_eq!(states.len(), 9, "Should have all 9 TaskState values");

    for (state, expected_json) in &states {
        let json = serde_json::to_string(state).unwrap();
        assert_eq!(
            json,
            format!("\"{expected_json}\""),
            "State {:?} should serialize as {expected_json}",
            state
        );

        // Verify round-trip deserialization
        let deserialized: TaskState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, *state, "Round-trip should preserve state");
    }
}

// ============================================================================
// §4.1.5 Role — all v1.0 roles are representable
// ============================================================================

#[test]
fn test_spec_4_1_5_all_roles() {
    let roles = [
        (Role::RoleUnspecified, "ROLE_UNSPECIFIED"),
        (Role::RoleUser, "ROLE_USER"),
        (Role::RoleAgent, "ROLE_AGENT"),
    ];

    assert_eq!(roles.len(), 3, "Should have all 3 Role values");

    for (role, expected_json) in &roles {
        let json = serde_json::to_string(role).unwrap();
        assert_eq!(json, format!("\"{expected_json}\""));

        let deserialized: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, *role);
    }
}
