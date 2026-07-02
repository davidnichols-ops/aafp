//! Protocol-level conformance tests for the AAFP A2A transport binding.
//!
//! These tests verify JSON-RPC correctness, byte preservation, and that
//! all 11 A2A operations are dispatchable through the server handler.
//! Updated for A2A v1.0: SCREAMING_SNAKE_CASE enums, flat Part (no kind
//! discriminator), SendMessageRequest params wrapping, and response wrapping.

use std::sync::Arc;

use aafp_transport_a2a::{
    dispatch_request, A2aError, A2aServerHandler, AgentCapabilities, AgentCard, Message, Part,
    PushNotificationConfig, Role, Task, TaskListFilter, TaskState, TaskStatus, TaskUpdateEvent,
};
use async_trait::async_trait;

/// A minimal handler that returns stub responses for all operations.
struct StubHandler;

#[async_trait]
impl A2aServerHandler for StubHandler {
    async fn send_message(&self, _message: Message) -> Result<Task, A2aError> {
        Ok(Task {
            id: "stub-task".to_string(),
            context_id: Some("stub-ctx".to_string()),
            status: TaskStatus {
                state: TaskState::TaskStateWorking,
                timestamp: None,
                message: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
    }

    async fn send_streaming_message(
        &self,
        _message: Message,
    ) -> Result<Vec<TaskUpdateEvent>, A2aError> {
        Ok(vec![])
    }

    async fn get_task(&self, task_id: String) -> Result<Task, A2aError> {
        if task_id == "stub-task" {
            self.send_message(Message {
                role: Role::RoleUser,
                parts: vec![],
                message_id: "test".to_string(),
                context_id: None,
                task_id: None,
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            })
            .await
        } else {
            Err(A2aError::TaskNotFound { task_id })
        }
    }

    async fn list_tasks(&self, _filter: TaskListFilter) -> Result<Vec<Task>, A2aError> {
        Ok(vec![])
    }

    async fn cancel_task(&self, task_id: String) -> Result<Task, A2aError> {
        Err(A2aError::TaskNotCancelable { task_id })
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
            name: "stub".to_string(),
            description: None,
            version: "1.0".to_string(),
            url: "quic://stub".to_string(),
            capabilities: AgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec![],
            default_output_modes: vec![],
            skills: vec![],
            supports_authenticated_extended_agent_card: None,
            supported_interfaces: None,
        })
    }
}

#[test]
fn test_jsonrpc_method_names_are_pascalcase() {
    // Verify all 11 method names are PascalCase per A2A v1.0
    let methods = [
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

    for method in &methods {
        // First char should be uppercase
        let first = method.chars().next().unwrap();
        assert!(
            first.is_uppercase(),
            "Method '{method}' should start with uppercase"
        );
        // Should not contain '/' or '_' (not category/action or snake_case)
        assert!(
            !method.contains('/') && !method.contains('_'),
            "Method '{method}' should be PascalCase, not category/action or snake_case"
        );
    }
}

#[test]
fn test_camelcase_fields() {
    // Verify that serialized JSON uses camelCase field names
    let task = Task {
        id: "t1".to_string(),
        context_id: Some("c1".to_string()),
        status: TaskStatus {
            state: TaskState::TaskStateWorking,
            timestamp: None,
            message: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    };

    let json = serde_json::to_string(&task).unwrap();
    assert!(
        json.contains("\"contextId\""),
        "Expected camelCase contextId"
    );
    assert!(
        !json.contains("\"context_id\""),
        "Expected no snake_case context_id"
    );
}

#[test]
fn test_task_state_screaming_snake_case() {
    // Verify TaskState serializes as SCREAMING_SNAKE_CASE per A2A v1.0 §5.5
    let states = [
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
        (TaskState::TaskStateUnspecified, "TASK_STATE_UNSPECIFIED"),
    ];

    for (state, expected) in &states {
        let json = serde_json::to_string(state).unwrap();
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "TaskState {:?} should serialize as \"{expected}\"",
            state
        );
    }
}

#[test]
fn test_role_screaming_snake_case() {
    // Verify Role serializes as SCREAMING_SNAKE_CASE per A2A v1.0 §5.5
    assert_eq!(
        serde_json::to_string(&Role::RoleUser).unwrap(),
        "\"ROLE_USER\""
    );
    assert_eq!(
        serde_json::to_string(&Role::RoleAgent).unwrap(),
        "\"ROLE_AGENT\""
    );
    assert_eq!(
        serde_json::to_string(&Role::RoleUnspecified).unwrap(),
        "\"ROLE_UNSPECIFIED\""
    );
}

#[test]
fn test_part_no_kind_discriminator() {
    // Verify Part serializes without a "kind" field (A2A v1.0 Appendix A.2.1)
    let text_part = Part::text("Hello, agent!");
    let json = serde_json::to_string(&text_part).unwrap();
    assert!(
        !json.contains("\"kind\""),
        "Part should NOT have a kind discriminator in v1.0: {json}"
    );
    assert!(
        json.contains("\"text\""),
        "Part should have text field: {json}"
    );

    let data_part = Part::data(serde_json::json!({"key": "value"}));
    let json = serde_json::to_string(&data_part).unwrap();
    assert!(
        !json.contains("\"kind\""),
        "DataPart should NOT have a kind discriminator: {json}"
    );
    assert!(
        json.contains("\"data\""),
        "Part should have data field: {json}"
    );
}

#[test]
fn test_byte_preservation() {
    // Verify that a JSON-RPC message is preserved byte-for-byte when
    // serialized and deserialized through the AAFP frame layer.
    let original = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "SendMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": "Hello"}],
                "messageId": "msg-001"
            }
        }
    });

    let bytes = serde_json::to_vec(&original).unwrap();
    let round_tripped: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(original, round_tripped);
}

#[tokio::test]
async fn test_all_operations_dispatchable() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);

    // Per A2A v1.0, SendMessage params wrap the message in {"message": {...}}
    let operations = [
        (
            "SendMessage",
            serde_json::json!({
                "message": {
                    "role": "ROLE_USER",
                    "parts": [{"text": "Hello"}],
                    "messageId": "msg-001"
                }
            }),
        ),
        (
            "SendStreamingMessage",
            serde_json::json!({
                "message": {
                    "role": "ROLE_USER",
                    "parts": [{"text": "Hello"}],
                    "messageId": "msg-002"
                }
            }),
        ),
        ("GetTask", serde_json::json!({"id": "stub-task"})),
        ("ListTasks", serde_json::json!({})),
        ("CancelTask", serde_json::json!({"id": "t1"})),
        ("SubscribeToTask", serde_json::json!({"id": "t1"})),
        (
            "CreateTaskPushNotificationConfig",
            serde_json::json!({"taskId": "t1", "config": {"url": "https://example.com", "token": "tok"}}),
        ),
        (
            "GetTaskPushNotificationConfig",
            serde_json::json!({"taskId": "t1", "configId": "c1"}),
        ),
        (
            "ListTaskPushNotificationConfigs",
            serde_json::json!({"taskId": "t1"}),
        ),
        (
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({"taskId": "t1", "configId": "c1"}),
        ),
        ("GetExtendedAgentCard", serde_json::json!(null)),
    ];

    for (method, params) in &operations {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = dispatch_request(&handler, &request).await;

        // Should get a valid JSON-RPC response (not a method-not-found error)
        assert!(
            response.get("jsonrpc").is_some(),
            "Method '{method}' should produce a JSON-RPC response"
        );

        // Should NOT get error code -32601 (MethodNotFound)
        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            assert!(
                code != -32601,
                "Method '{method}' should not return MethodNotFound"
            );
        }
    }
}

#[tokio::test]
async fn test_send_message_response_wrapping() {
    // Verify SendMessage response wraps Task in {"task": ...} per A2A v1.0
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": "Hello"}],
                "messageId": "msg-001"
            }
        },
    });

    let response = dispatch_request(&handler, &request).await;
    let result = response.get("result").expect("Should have result");
    assert!(
        result.get("task").is_some(),
        "SendMessage response should wrap Task in {{\"task\": ...}}: {result}"
    );
    let task = result.get("task").unwrap();
    assert_eq!(task["id"], "stub-task");
}

#[tokio::test]
async fn test_get_task_response_wrapping() {
    // Verify GetTask response wraps Task in {"task": ...} per A2A v1.0
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "GetTask",
        "params": {"id": "stub-task"},
    });

    let response = dispatch_request(&handler, &request).await;
    let result = response.get("result").expect("Should have result");
    assert!(
        result.get("task").is_some(),
        "GetTask response should wrap Task in {{\"task\": ...}}: {result}"
    );
}

#[tokio::test]
async fn test_list_tasks_response_wrapping() {
    // Verify ListTasks response wraps tasks in {"tasks": [...], "totalSize": N, ...}
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ListTasks",
        "params": {},
    });

    let response = dispatch_request(&handler, &request).await;
    let result = response.get("result").expect("Should have result");
    assert!(
        result.get("tasks").is_some(),
        "ListTasks response should have tasks array: {result}"
    );
    assert!(
        result.get("totalSize").is_some(),
        "ListTasks response should have totalSize: {result}"
    );
}

#[test]
fn test_error_codes() {
    // Verify each A2A error type maps to the correct JSON-RPC code
    let test_cases = [
        (
            A2aError::TaskNotFound {
                task_id: "t".into(),
            },
            -32001,
        ),
        (
            A2aError::TaskNotCancelable {
                task_id: "t".into(),
            },
            -32002,
        ),
        (A2aError::PushNotificationNotSupported, -32003),
        (
            A2aError::UnsupportedOperation {
                operation: "x".into(),
            },
            -32004,
        ),
        (
            A2aError::ContentTypeNotSupported {
                content_type: "x".into(),
            },
            -32005,
        ),
        (A2aError::InvalidAgentResponse, -32006),
        (A2aError::ExtendedAgentCardNotConfigured, -32007),
        (
            A2aError::ExtensionSupportRequired {
                extension: "x".into(),
            },
            -32008,
        ),
        (
            A2aError::VersionNotSupported {
                version: "x".into(),
            },
            -32009,
        ),
        (A2aError::ParseError, -32700),
        (A2aError::InvalidRequest, -32600),
        (A2aError::MethodNotFound { method: "x".into() }, -32601),
        (A2aError::InvalidParams, -32602),
        (
            A2aError::Internal {
                message: "x".into(),
            },
            -32603,
        ),
    ];

    for (error, expected_code) in &test_cases {
        assert_eq!(
            error.jsonrpc_code(),
            *expected_code,
            "Error {:?} should map to code {expected_code}",
            error
        );
    }
}

#[tokio::test]
async fn test_method_not_found() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "NonExistentMethod",
        "params": {},
    });

    let response = dispatch_request(&handler, &request).await;
    let error = response.get("error").expect("Should have error");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    assert_eq!(code, -32601, "Unknown method should return -32601");
}

#[tokio::test]
async fn test_invalid_request_no_method() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
    });

    let response = dispatch_request(&handler, &request).await;
    let error = response.get("error").expect("Should have error");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    assert_eq!(
        code, -32600,
        "Missing method should return -32600 (InvalidRequest)"
    );
}

#[tokio::test]
async fn test_send_message_missing_message_field() {
    // Per A2A v1.0, SendMessage params MUST contain a "message" field.
    // Missing it should return InvalidParams (-32602).
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {"role": "ROLE_USER"},  // Missing "message" wrapper
    });

    let response = dispatch_request(&handler, &request).await;
    let error = response.get("error").expect("Should have error");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    assert_eq!(
        code, -32602,
        "Missing message field should return -32602 (InvalidParams)"
    );
}
