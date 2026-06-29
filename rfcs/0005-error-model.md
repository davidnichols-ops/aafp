# RFC-0005: AAFP Error Model

```
Status:         Freeze Candidate (Revision 5)
Number:         0005
Title:          Protocol Error Codes, Error Frames, and Error Handling
Author:         AAFP Project
Created:        2025-06-25
Revised:        2025-01-15 (Revision 4: no content changes, version bump
                for consistency with RFC-0002 and RFC-0003)
                2025-01-16 (Revision 5: no content changes, version bump
                for consistency with RFC-0003)
Type:           Standards Track
Obsoletes:      —
Obsoleted by:   —
```

## 1. Overview

This RFC specifies the AAFP error model: how errors are represented
on the wire, how they are categorized, and how implementations must
handle them. A standardized error model is critical for
interoperability — without it, every implementation invents its own
error semantics, making cross-implementation debugging impossible.

### 1.1 Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Design Principles

1. **Errors are part of the public contract.** Error codes are
   permanent once assigned. They cannot be renumbered or reused.
2. **Errors are categorized.** The thousands digit of the error code
   indicates the category, enabling generic handling.
3. **Errors are extensible.** New error codes can be added without
   breaking existing implementations.
4. **Human-readable messages are for debugging only.** Programmatic
   decisions MUST be based on error codes, not messages.

## 2. Error Code Format

Error codes are 32-bit unsigned integers (uint in CBOR). The code
space is divided into categories by the thousands digit:

```
Error Code: 0x0000–0xFFFF (16-bit, encoded as uint)

  Category    Range         Description
  --------    -----         -----------
  0xxx        0000–0999     Success / Information
  1xxx        1000–1999     Transport errors
  2xxx        2000–2999     Authentication errors
  3xxx        3000–3999     Authorization errors
  4xxx        4000–4999     Discovery errors
  5xxx        5000–5999     Messaging errors
  6xxx        6000–6999     Capability errors
  7xxx        7000–7999     Resource errors (reserved, not used in v1)
  8xxx        8000–8999     Protocol errors
  9xxx        9000–9999     Application errors (reserved for apps)
```

### 2.1 Error Code Properties

- **Stable**: Once assigned, an error code's meaning MUST NOT change.
- **Unique**: Each error code has exactly one meaning.
- **Categorized**: The category (thousands digit) enables generic
  handling without knowing the specific code.
- **Extensible**: New codes can be added within a category's range.

## 3. Error Code Registry

### 3.1 Success / Information (0xxx)

| Code | Name | Description |
|------|------|-------------|
| 0000 | OK | No error. |
| 0001 | PARTIAL | Partial success (some results available). |
| 0002 | NOT_FOUND | Requested resource not found (non-error). |

### 3.2 Transport Errors (1xxx)

| Code | Name | Description |
|------|------|-------------|
| 1001 | CONNECTION_RESET | Connection was reset by peer. |
| 1002 | CONNECTION_TIMEOUT | Connection timed out. |
| 1003 | STREAM_CLOSED | Stream was closed by peer. |
| 1004 | STREAM_RESET | Stream was reset by peer. |
| 1005 | FLOW_CONTROL_ERROR | Flow control violation. |
| 1006 | TRANSPORT_UNREACHABLE | Peer is unreachable. |
| 1007 | TRANSPORT_REFUSED | Connection refused by peer. |

### 3.3 Authentication Errors (2xxx)

| Code | Name | Description |
|------|------|-------------|
| 2001 | INVALID_SIGNATURE | ML-DSA-65 signature verification failed. |
| 2002 | IDENTITY_EXPIRED | Agent identity has expired (`expires_at` in the past). |
| 2003 | UNKNOWN_AGENT | Agent is not known or not in directory. |
| 2004 | VERSION_MISMATCH | Protocol version not supported. |
| 2005 | UNSUPPORTED_EXTENSIONS | Required extension not supported. |
| 2006 | HANDSHAKE_FAILED | Handshake failed (generic, including TLS exporter unavailable). |
| 2007 | INVALID_AGENT_ID | AgentId does not match SHA-256(public_key). |
| 2008 | NONCE_REUSE | Nonce reuse detected (replay attack). |
| 2009 | RECEIVER_MAC_INVALID | DoS pre-verification MAC check failed (see RFC-0002 Section 5.8). |
| 2010 | UNSUPPORTED_ALGORITHM | Key algorithm not supported (see RFC-0003 Section 2.3). |

### 3.4 Authorization Errors (3xxx)

| Code | Name | Description |
|------|------|-------------|
| 3001 | UNAUTHORIZED | No authorization for the requested action. |
| 3002 | INSUFFICIENT_CAPABILITY | Token does not grant required capability. |
| 3003 | DELEGATION_CHAIN_INVALID | Delegation chain verification failed. |
| 3004 | TOKEN_EXPIRED | Authorization token has expired. |
| 3005 | TOKEN_REVOKED | Authorization token has been revoked. |
| 3006 | DELEGATION_DEPTH_EXCEEDED | Delegation chain too deep. |

### 3.5 Discovery Errors (4xxx)

| Code | Name | Description |
|------|------|-------------|
| 4001 | DHT_ERROR | DHT operation failed. |
| 4002 | BOOTSTRAP_FAILED | Bootstrap connection failed. |
| 4003 | RECORD_INVALID | AgentRecord verification failed. |
| 4004 | RECORD_EXPIRED | AgentRecord has expired. |
| 4005 | CAPABILITY_NOT_FOUND | No agents with requested capability. |
| 4006 | ANNOUNCEMENT_REJECTED | Announcement rejected by bootstrap node. |

### 3.6 Messaging Errors (5xxx)

| Code | Name | Description |
|------|------|-------------|
| 5001 | MALFORMED_FRAME | Frame could not be parsed. |
| 5002 | UNKNOWN_METHOD | RPC method not recognized. |
| 5003 | SERIALIZATION_ERROR | CBOR serialization/deserialization failed. |
| 5004 | METHOD_PARAMS_INVALID | RPC parameters are invalid. |
| 5005 | MESSAGE_TOO_LARGE | Message exceeds maximum size. |
| 5006 | STREAM_NOT_FOUND | Referenced stream does not exist. |

### 3.7 Capability Errors (6xxx)

| Code | Name | Description |
|------|------|-------------|
| 6001 | NEGOTIATION_FAILED | Capability negotiation failed. |
| 6002 | INCOMPATIBLE | Capabilities are incompatible. |
| 6003 | UNSUPPORTED_CAPABILITY | Requested capability not supported. |
| 6004 | CAPABILITY_OVERLOADED | Agent is at capacity for this capability. |

### 3.8 Resource Errors (7xxx)

Reserved for future use. Resource exchange is out of scope for v1
(see RFC-0001 Section 1.3).

### 3.9 Protocol Errors (8xxx)

| Code | Name | Description |
|------|------|-------------|
| 8001 | FRAME_TOO_LARGE | Frame exceeds maximum size (1 MiB). |
| 8002 | UNEXPECTED_COMPRESSION | Compression flag set but not negotiated. |
| 8003 | HANDSHAKE_ON_WRONG_STREAM | HANDSHAKE frame on non-zero stream. |
| 8004 | UNKNOWN_CRITICAL_FRAME_TYPE | Unknown frame type with critical bit. |
| 8005 | UNKNOWN_CRITICAL_EXTENSION | Unknown extension with critical flag. |
| 8006 | INVALID_VERSION | Unsupported protocol version. |
| 8007 | INVALID_FLAGS | Invalid flag combination. |
| 8008 | RESERVED_FIELD_NONZERO | Reserved field is non-zero. |
| 8009 | PROTOCOL_VIOLATION | Generic protocol violation. |

### 3.10 Application Errors (9xxx)

Reserved for application-defined errors. AAFP does not assign codes
in this range. Applications MAY use codes 9000–9999 for their own
errors. The protocol treats all 9xxx codes as non-fatal unless the
`fatal` flag is set in the ERROR frame.

## 4. Error Frame

### 4.1 Wire Format

Errors are transmitted using the ERROR frame type (0x06) as specified
in RFC-0002 Section 4.6:

```cbor
ErrorMessage = {
    1: uint,            // "code": Error code from registry
    2: tstr,            // "message": Human-readable description
    3: bstr / null,     // "data": Optional structured error data
    4: bool,            // "fatal": If true, connection must close
}
```

### 4.2 Field Semantics

| Key | Name | Type | Required | Description |
|-----|------|------|----------|-------------|
| 1 | code | uint | Yes | Error code from the registry (Section 3). |
| 2 | message | tstr | Yes | Human-readable error description. For debugging only; MUST NOT be used for programmatic decisions. |
| 3 | data | bstr / null | No | Optional structured error data (CBOR-encoded). May contain additional context. |
| 4 | fatal | bool | Yes | If true, the receiver MUST close the connection after processing the error. If false, the error is non-fatal. |

### 4.3 Fatal vs Non-Fatal

**Fatal errors** indicate that the connection is in an unrecoverable
state. The receiver MUST:

1. Process the error (e.g., log it, notify the application).
2. Send a CLOSE frame (RFC-0002 Section 4.5) with the error code.
3. Close the QUIC connection.

Fatal errors include: authentication failures, protocol violations,
frame too large, unknown critical frame types.

**Non-fatal errors** indicate a recoverable error on a specific
stream or operation. The receiver MAY:

1. Process the error.
2. Close the affected stream (if the error is stream-specific).
3. Continue using the connection for other streams.

Non-fatal errors include: method not found, capability not found,
serialization errors on a single message.

### 4.4 Fatal Error Code Rules

The following error codes are ALWAYS fatal:

- All 2xxx (Authentication) errors
- 8004 (UNKNOWN_CRITICAL_FRAME_TYPE)
- 8005 (UNKNOWN_CRITICAL_EXTENSION)
- 8006 (INVALID_VERSION)
- 8009 (PROTOCOL_VIOLATION)

Error code 8001 (FRAME_TOO_LARGE) is non-fatal by default. The
sender MAY set the fatal flag to true if the oversized frame
indicates a connection-level protocol violation (e.g., the peer
repeatedly sends oversized frames despite prior errors).

All other error codes are non-fatal by default. The sender MAY set
the `fatal` flag to true for any error code if it determines the
connection state is unrecoverable.

## 5. Error Handling Rules

### 5.1 Unknown Error Codes

If a receiver encounters an error code it does not recognize:

1. Determine the category from the thousands digit.
2. Treat the error as a generic error of that category.
3. If the category is unknown (≥ 7xxx and not 8xxx or 9xxx), treat
   as a generic protocol error (8009).
4. Honor the `fatal` flag regardless of whether the code is
   recognized.

This ensures forward compatibility: new error codes can be added
without breaking existing implementations.

### 5.2 Error Propagation

Errors SHOULD be propagated to the application layer. The AAFP
protocol layer SHOULD NOT silently swallow errors. The application
decides how to handle errors (retry, abort, ignore).

### 5.3 Error in Response to Error

If an implementation receives an ERROR frame and encounters an error
while processing it, it MUST NOT send an ERROR frame in response
(this could cause infinite error loops). Instead, it MUST close the
connection with a CLOSE frame.

### 5.4 Error Logging

Implementations SHOULD log errors with:

- Error code and name
- Human-readable message
- Connection ID (if available)
- Stream ID (if applicable)
- Timestamp

Implementations MUST NOT log sensitive data (private keys, session
keys, authorization tokens) in error messages.

## 6. RPC Error Handling

### 6.1 RPC Response Errors

RPC errors are carried in the `error` field of the RPC_RESPONSE
frame (RFC-0002 Section 4.4):

```cbor
RpcResponse = {
    1: uint,                    // "id": Request correlation ID
    2: bstr / null,             // "result": Result data (null if error)
    3: {                        // "error": Error object (null if success)
        1: uint,                //   "code": Error code
        2: tstr,                //   "message": Human-readable message
        3: bstr / null,         //   "data": Optional structured data
    } / null,
}
```

RPC errors are always non-fatal (they affect only the RPC call, not
the connection). The connection remains open after an RPC error.

### 6.2 RPC Error Categories

RPC methods typically return errors in these categories:

- 4xxx (Discovery): For discovery-related RPC methods
- 5xxx (Messaging): For messaging-related RPC methods
- 6xxx (Capability): For capability-related RPC methods
- 9xxx (Application): For application-specific errors

RPC methods MUST NOT return 2xxx (Authentication) or 8xxx (Protocol)
errors in RPC responses. These categories indicate connection-level
errors and MUST be sent as ERROR frames, not RPC response errors.

## 7. Close Frame Errors

The CLOSE frame (RFC-0002 Section 4.5) carries a close reason code:

```cbor
CloseMessage = {
    1: uint,        // "code": Close reason code
    2: tstr,        // "message": Human-readable close reason
}
```

The close reason code uses the same error code registry (Section 3).
Common close codes:

| Code | Name | Description |
|------|------|-------------|
| 0000 | OK | Normal close (no error). |
| 1002 | CONNECTION_TIMEOUT | Connection timed out. |
| 2001 | INVALID_SIGNATURE | Authentication failure (signature verification). |
| 2007 | INVALID_AGENT_ID | Authentication failure (AgentId mismatch). |
| 8009 | PROTOCOL_VIOLATION | Protocol violation. |

## 8. Implementation Requirements

### 8.1 Error Code Type

Implementations MUST define a `ProtocolError` type that maps to
on-wire error codes:

```rust
pub struct ProtocolError {
    pub code: u32,
    pub message: String,
    pub data: Option<Vec<u8>>,
    pub fatal: bool,
}
```

### 8.2 Error Category Enum

Implementations SHOULD provide an enum for error categories:

```rust
pub enum ErrorCategory {
    Success,
    Transport,
    Authentication,
    Authorization,
    Discovery,
    Messaging,
    Capability,
    Resource,
    Protocol,
    Application,
    Unknown,
}
```

The category is derived from the error code: `code / 1000`.

### 8.3 Error Conversion

Implementations SHOULD provide conversions from internal error types
to `ProtocolError`:

```rust
impl From<CryptoError> for ProtocolError { ... }
impl From<IdentityError> for ProtocolError { ... }
impl From<FrameError> for ProtocolError { ... }
```

Internal errors that do not have a corresponding protocol error code
MUST be mapped to the most appropriate category's generic error
(e.g., `8009` PROTOCOL_VIOLATION for uncategorized internal errors).

## 9. Security Considerations

### 9.1 Information Disclosure

Error messages MUST NOT disclose sensitive information:

- Private keys, secret keys, session keys
- Internal memory addresses or pointers
- Stack traces (in production)
- Authorization tokens or credentials

Error messages SHOULD provide enough information for debugging
without compromising security. A RECOMMENDED pattern is:

- Include the operation that failed (e.g., "signature verification")
- Include the reason (e.g., "invalid signature bytes")
- Do NOT include the values being verified

### 9.2 Error-Based Fingerprinting

An adversary may use error responses to fingerprint an
implementation (different implementations may produce different
error messages for the same error). To mitigate:

- Implementations SHOULD use the standardized error code names
  in messages where possible.
- The error code (not the message) is the normative identifier.
- Implementations MAY omit the human-readable message in
  production deployments.

### 9.3 DoS via Error Frames

An attacker could send a large number of error frames to consume
resources. Mitigations:

- Implementations SHOULD rate-limit ERROR frame processing.
- The `data` field in ERROR frames MUST NOT exceed 4096 bytes.
  Implementations MUST truncate or reject larger `data` fields.

## 10. IANA Considerations

This RFC defines the **AAFP Error Code Registry**:

- 0xxx: Success / Information (3 codes assigned, 997 reserved)
- 1xxx: Transport (7 codes assigned, 993 reserved)
- 2xxx: Authentication (8 codes assigned, 992 reserved)
- 3xxx: Authorization (6 codes assigned, 994 reserved)
- 4xxx: Discovery (6 codes assigned, 994 reserved)
- 5xxx: Messaging (6 codes assigned, 994 reserved)
- 6xxx: Capability (4 codes assigned, 996 reserved)
- 7xxx: Resource (0 codes assigned, 1000 reserved)
- 8xxx: Protocol (9 codes assigned, 991 reserved)
- 9xxx: Application (0 codes assigned, 1000 reserved for apps)

New error codes are assigned via the process in RFC-0006.

## 11. References

- RFC 2119: Key words for use in RFCs
- RFC-0002: AAFP Transport & Framing
- RFC-0006: AAFP Versioning & Compatibility
