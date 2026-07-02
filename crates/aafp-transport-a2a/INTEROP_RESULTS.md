# A2A Transport Binding — Interop Test Results

## Track D2: A2A Reference Implementation Interop

**Date:** 2026-07-02  
**Status:** ✅ PASS  
**Strategy:** B (A2A v1.0 spec examples)  
**Spec version:** A2A v1.0.0  
**Tests:** 40 passed, 0 failed

---

## Research Findings

### A2A SDKs

Six official A2A SDKs were identified:

| SDK | Language | Version | Transport |
|-----|----------|---------|-----------|
| `a2a-sdk` | Python | 1.1.0 | HTTP/gRPC/JSON-RPC |
| `a2a-go` | Go | 2.0.0 | HTTP/gRPC/JSON-RPC |
| `a2a-js` | JavaScript | — | HTTP/gRPC/JSON-RPC |
| `a2a-java` | Java | — | HTTP/gRPC/JSON-RPC |
| `a2a-dotnet` | .NET | — | HTTP/gRPC/JSON-RPC |
| `a2a-rs` | Rust | — | HTTP/gRPC/JSON-RPC |

**Key finding:** None of the official A2A SDKs support QUIC transport. All use
HTTP/gRPC/JSON-RPC as the underlying transport. Direct interop with AAFP over
QUIC would require writing a custom transport adapter for one of these SDKs.

### A2A TCK

The A2A Technology Compatibility Kit (`a2aproject/a2a-tck`) exists but operates
over HTTP/gRPC/JSON-RPC only. It does not support QUIC transport and cannot be
directly used to test the AAFP binding.

### Strategy Selection

**Strategy B (spec examples)** was chosen because:
1. No SDK supports QUIC transport — live SDK interop not feasible without
   writing a custom transport adapter
2. The A2A TCK operates over HTTP only
3. The A2A v1.0 specification provides comprehensive JSON examples that can
   verify wire-format compliance through round-trip testing
4. Byte-for-byte payload preservation (ADR-0002) can be verified directly

---

## Data Model Updates (v0.3 → v1.0)

The A2A v1.0 specification introduced significant changes from v0.3:

### Part (Appendix A.2.1)
- **v0.3:** `{"kind": "text", "text": "..."}` (tagged enum with discriminator)
- **v1.0:** `{"text": "..."}` (flat OneOf, no discriminator)

### TaskState (§4.1.3, §5.5)
- **v0.3:** `"working"` (kebab-case)
- **v1.0:** `"TASK_STATE_WORKING"` (SCREAMING_SNAKE_CASE, ProtoJSON convention)
- Added: `TASK_STATE_REJECTED`, `TASK_STATE_AUTH_REQUIRED`

### Role (§4.1.5, §5.5)
- **v0.3:** `"user"` (lowercase string)
- **v1.0:** `"ROLE_USER"` (SCREAMING_SNAKE_CASE enum)

### Message (§4.1.5)
- `messageId` now required (was optional)
- Added: `extensions`, `referenceTaskIds` fields

### Task (§4.1.2)
- `contextId` now optional (was required)
- Removed: `kind` field

### SendMessage params (§9.4.1)
- **v0.3:** params = Message object directly
- **v1.0:** params = `{"message": {...}, "configuration": {...}, "metadata": {...}}`

### Response wrapping (§9.4)
- **SendMessage/GetTask/CancelTask:** `{"task": {...}}` (SendMessageResponse)
- **ListTasks:** `{"tasks": [...], "totalSize": N, "pageSize": N, "nextPageToken": "..."}`

### ListTasks params (§9.4.4)
- `state` → `status` (with SCREAMING_SNAKE_CASE value)
- `limit` → `pageSize`
- Added: `pageToken`

---

## Test Coverage

### Conformance Tests (14 tests)
- JSON-RPC method names are PascalCase (§5.3)
- camelCase field naming (§5.5)
- SCREAMING_SNAKE_CASE TaskState (§4.1.3, §5.5)
- SCREAMING_SNAKE_CASE Role (§4.1.5, §5.5)
- Flat Part without kind discriminator (Appendix A.2.1)
- Byte-for-byte preservation (ADR-0002)
- All 11 operations dispatchable (§9.4)
- Response wrapping: SendMessage, GetTask, ListTasks (§9.4)
- Error codes: all 13 codes (§5.4)
- Method not found error (-32601)
- Invalid request error (-32600)
- Missing message field → InvalidParams (-32602)

### Spec Conformance Tests (18 tests)
- §6.1 Basic task execution — SendMessage with text part
- §6.2 Streaming task execution — 3 events (status, artifact, final status)
- §6.3 Multi-turn interaction — TASK_STATE_INPUT_REQUIRED
- §6.5 Task listing with pagination
- §6.6 Push notification config setup
- §6.7 File exchange — raw (base64) and url parts
- §6.8 Structured data exchange — data part
- §9.4.3 GetTask JSON-RPC format
- §9.4.4 ListTasks JSON-RPC format
- §9.4.5 CancelTask JSON-RPC format
- §9.4.6 SubscribeToTask JSON-RPC format
- §9.4.8 GetExtendedAgentCard JSON-RPC format
- §5.4 Error code mapping (TaskNotFound → -32001)
- §5.5 camelCase naming convention
- §5.3 Method mapping reference (all 11 methods)
- §4.1.3 All 9 TaskState values
- §4.1.5 All 3 Role values
- ADR-0002 Byte preservation with spec message

### Integration Tests (5 tests)
- SendMessage over real QUIC with AAFP handshake
- Get/List/Cancel task lifecycle
- Streaming message with final event
- Error mapping (TaskNotFound)
- Graceful close

### Unit Tests (3 tests)
- JSON-RPC error response format
- Error code mapping
- A2aError Display formatting

---

## Files Modified

| File | Change |
|------|--------|
| `src/types.rs` | Complete rewrite for v1.0 data model |
| `src/server.rs` | Dispatch: params.message extraction, response wrapping |
| `src/client.rs` | Params wrapping, response unwrapping |
| `tests/conformance.rs` | Updated for v1.0 types, added response wrapping tests |
| `tests/integration.rs` | Updated for v1.0 types (Role, Part, TaskState) |
| `tests/spec_conformance.rs` | **NEW** — 18 spec example tests |
| `examples/a2a_over_aafp.rs` | Updated for v1.0 types |

---

## Conclusion

The AAFP A2A transport binding is now fully compliant with the A2A v1.0
specification wire format. All 11 operations dispatch correctly with v1.0
JSON-RPC envelopes, and the data model matches the v1.0 schema (flat Parts,
SCREAMING_SNAKE_CASE enums, response wrapping).

Live SDK interop was not feasible because no official A2A SDK supports QUIC
transport. This remains a future work item — a custom QUIC transport adapter
for the Python or Go SDK would enable end-to-end interop testing.
