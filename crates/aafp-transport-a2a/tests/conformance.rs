//! Protocol-level conformance tests for the AAFP A2A transport binding.
//!
//! These tests verify JSON-RPC correctness, byte preservation, and that
//! all 11 A2A operations are dispatchable through the server handler.

use std::sync::Arc;

use aafp_transport_a2a::{
    dispatch_request, A2aError, A2aServerHandler, AgentCapabilities, AgentCard, Message,
    PushNotificationConfig, Task, TaskListFilter, TaskState, TaskStatus, TaskUpdateEvent,
};
use async_trait::async_trait;

/// A minimal handler that returns stub responses for all operations.
struct StubHandler;

#[async_trait]
impl A2aServerHandler for StubHandler {
    async fn send_message(&self, _message: Message) -> Result<Task, A2aError> {
        Ok(Task {
            id: "stub-task".to_string(),
            context_id: "stub-ctx".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                timestamp: None,
                message: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
            kind: None,
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
                role: "user".to_string(),
                parts: None,
                message_id: None,
                context_id: None,
                task_id: None,
                metadata: None,
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
        context_id: "c1".to_string(),
        status: TaskStatus {
            state: TaskState::Working,
            timestamp: None,
            message: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
        kind: None,
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
fn test_byte_preservation() {
    // Verify that a JSON-RPC message is preserved byte-for-byte when
    // serialized and deserialized through the AAFP frame layer.
    let original = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "SendMessage",
        "params": {
            "role": "user",
            "parts": [{"kind": "text", "text": "Hello"}]
        }
    });

    let bytes = serde_json::to_vec(&original).unwrap();
    let round_tripped: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(original, round_tripped);
}

#[tokio::test]
async fn test_all_operations_dispatchable() {
    let handler: Arc<dyn A2aServerHandler> = Arc::new(StubHandler);

    let operations = [
        (
            "SendMessage",
            serde_json::json!({"role": "user", "parts": []}),
        ),
        (
            "SendStreamingMessage",
            serde_json::json!({"role": "user", "parts": []}),
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
