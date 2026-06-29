# AAFP Version Negotiation & Downgrade Behavior Matrix

This document defines the protocol behavior matrix for version
negotiation, extension handling, and downgrade protection. Each
scenario specifies the inputs, expected outcome, error codes, and
RFC requirements being exercised.

## Matrix Format

Each scenario is specified as:
- **ID**: VN-XXXX (version) or EX-XXXX (extension) or FT-XXXX (frame type)
- **Client capabilities**: What the client supports/proposes
- **Server capabilities**: What the server supports/accepts
- **Messages exchanged**: What frames are sent
- **Expected outcome**: Success or failure
- **Expected error/close code**: Error code if failure
- **Connection continues?**: Yes or no
- **RFC requirement(s)**: Which RFC sections are exercised

## Version Negotiation Scenarios

### VN-0001: Exact version match

| Field | Value |
|-------|-------|
| Client | Protocol version 1 |
| Server | Protocol version 1 |
| Messages | ClientHello(v1) → ServerHello(v1) → ClientFinished |
| Outcome | Success |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0006 §2.3 (same version MUST be fully compatible) |

### VN-0002: Client newer version, server older

| Field | Value |
|-------|-------|
| Client | Protocol version 2 |
| Server | Protocol version 1 |
| Messages | ClientHello(v2) → ERROR |
| Outcome | Failure |
| Error code | 8006 (INVALID_VERSION) |
| Connection continues? | No |
| RFC | RFC-0006 §2.3 (forward compat via extensions, not version skipping) |

### VN-0003: Client older version, server newer

| Field | Value |
|-------|-------|
| Client | Protocol version 1 |
| Server | Protocol version 2 only |
| Messages | ClientHello(v1) → ERROR |
| Outcome | Failure |
| Error code | 8006 (INVALID_VERSION) or ALPN failure |
| Connection continues? | No |
| RFC | RFC-0006 §2.3 (backward compat: new receiver applies old rules, but only if it supports v1) |

### VN-0004: No overlapping versions

| Field | Value |
|-------|-------|
| Client | Protocol version 1 only |
| Server | Protocol version 3 only |
| Messages | ClientHello(v1) → ERROR |
| Outcome | Failure |
| Error code | 8006 (INVALID_VERSION) |
| Connection continues? | No |
| RFC | RFC-0006 §2.2 (no common version → connection MUST close) |

### VN-0005: Unknown protocol version (v255)

| Field | Value |
|-------|-------|
| Client | Protocol version 255 |
| Server | Protocol version 1 |
| Messages | Frame with version=255 → rejected at frame decode |
| Outcome | Failure |
| Error code | 8006 (INVALID_VERSION) |
| Connection continues? | No |
| RFC | RFC-0006 §2.3 (unknown version → ERROR 8006 + close) |

### VN-0006: Downgrade attempt (peer omits highest version)

| Field | Value |
|-------|-------|
| Client | Supports v1 and v2, advertises only v1 |
| Server | Supports v1 and v2 |
| Messages | ALPN negotiation: client offers only aafp/1 |
| Outcome | Connection proceeds at v1 (ALPN is authoritative) |
| Error code | None |
| Connection continues? | Yes (at v1) |
| RFC | RFC-0006 §9.1 (MUST NOT fall back to lower version if requested not supported; but offering only v1 when you support v2 is valid — you just use v1) |

Note: A true downgrade *attack* would require an attacker to strip v2
from the ALPN offer. TLS integrity protection prevents this. The test
verifies that the implementation does not add an in-band fallback
mechanism that could bypass ALPN.

### VN-0007: Version 0 (pre-RFC)

| Field | Value |
|-------|-------|
| Client | Protocol version 0 |
| Server | Protocol version 1 |
| Messages | Frame with version=0 → rejected |
| Outcome | Failure |
| Error code | 8006 (INVALID_VERSION) |
| Connection continues? | No |
| RFC | RFC-0006 §2.1 (v0 NOT compatible with v1) |

## Extension Scenarios

### EX-0001: Unknown critical extension

| Field | Value |
|-------|-------|
| Client | Proposes extension type 0xBEEF, critical=true |
| Server | Does not know extension 0xBEEF |
| Messages | ClientHello(ext=0xBEEF,critical) → ERROR |
| Outcome | Failure |
| Error code | 2005 (UNSUPPORTED_EXTENSIONS) |
| Connection continues? | No |
| RFC | RFC-0002 §6.4 rule 4, RFC-0006 §6.2 |

### EX-0002: Unknown non-critical extension

| Field | Value |
|-------|-------|
| Client | Proposes extension type 0xBEEF, critical=false |
| Server | Does not know extension 0xBEEF |
| Messages | ClientHello(ext=0xBEEF,non-critical) → ServerHello(exts without 0xBEEF) |
| Outcome | Success (extension silently dropped) |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0002 §6.4 rule 4, RFC-0006 §6.1 |

### EX-0003: Multiple extensions with mixed criticality

| Field | Value |
|-------|-------|
| Client | Proposes ext 0x0001 (critical), ext 0x0002 (non-critical), ext 0xBEEF (non-critical) |
| Server | Knows 0x0001 and 0x0002, does not know 0xBEEF |
| Messages | ClientHello(3 exts) → ServerHello(0x0001, 0x0002) |
| Outcome | Success (0xBEEF dropped, critical 0x0001 accepted) |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0002 §6.4, RFC-0006 §6.1 |

### EX-0004: Duplicate extensions

| Field | Value |
|-------|-------|
| Client | Proposes ext 0x0001 twice (both non-critical) |
| Server | Knows 0x0001 |
| Messages | ClientHello(ext 0x0001, ext 0x0001) → ServerHello(0x0001 once) |
| Outcome | Success (first one used, second ignored) |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0002 §6.2 (first one MUST be used, subsequent ignored) |

### EX-0005: Duplicate critical extensions

| Field | Value |
|-------|-------|
| Client | Proposes ext 0x0001 twice (both critical) |
| Server | Knows 0x0001 |
| Messages | ClientHello(ext 0x0001 crit, ext 0x0001 crit) |
| Outcome | First used, second ignored (or rejected if critical) |
| Error code | None (first is accepted) or 2005 (if implementation rejects dup critical) |
| Connection continues? | Yes (if first accepted) |
| RFC | RFC-0002 §6.2 (subsequent MUST be ignored or rejected if critical) |

Note: The RFC says "ignored (or rejected if critical)". This is
slightly ambiguous — does "critical" refer to the duplicate's
critical flag or the original's? We interpret it as: if the
duplicate has critical=true, it MAY be rejected. This should be
clarified in Revision 4.

### EX-0006: Extensions in non-canonical order

| Field | Value |
|-------|-------|
| Client | Proposes ext 0x0003, then 0x0001, then 0x0002 |
| Server | Knows all three |
| Messages | ClientHello(exts in non-sorted order) → ServerHello |
| Outcome | Success (order doesn't matter) |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0002 §6.2 (extensions MAY appear in any order) |

### EX-0007: Empty extension list

| Field | Value |
|-------|-------|
| Client | No extensions proposed |
| Server | No extensions required |
| Messages | ClientHello(exts=[]) → ServerHello(exts=[]) |
| Outcome | Success |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0002 §6.4 (extensions are optional) |

### EX-0008: Malformed extension encoding

| Field | Value |
|-------|-------|
| Client | Frame with extension data that doesn't match declared length |
| Server | Tries to decode extensions |
| Messages | Frame with truncated extension data |
| Outcome | Failure |
| Error code | Parse error (not a protocol error code — frame rejected) |
| Connection continues? | No |
| RFC | RFC-0002 §6.1 (extensions are self-delimiting via Data Length) |

### EX-0009: Server proposes extension client didn't offer

| Field | Value |
|-------|-------|
| Client | Proposes ext 0x0001 only |
| Server | Accepts 0x0001 AND includes 0x0002 (not proposed by client) |
| Messages | ClientHello(0x0001) → ServerHello(0x0001, 0x0002) |
| Outcome | Failure (server MUST NOT include extensions client didn't propose) |
| Error code | 2005 (UNSUPPORTED_EXTENSIONS) or 8007 |
| Connection continues? | No |
| RFC | RFC-0002 §6.4 (server MUST NOT include extensions client did not propose) |

## Frame Type Scenarios

### FT-0001: Unknown critical frame type

| Field | Value |
|-------|-------|
| Sender | Frame type 0x09 (reserved), flags=0x80 (critical) |
| Receiver | Does not know type 0x09 |
| Messages | Frame(type=0x09, flags=0x80) |
| Outcome | Failure |
| Error code | 8004 (UNKNOWN_CRITICAL_FRAME_TYPE) |
| Connection continues? | No |
| RFC | RFC-0006 §4.2 (critical unknown → ERROR 8004 + close) |

### FT-0002: Unknown non-critical frame type

| Field | Value |
|-------|-------|
| Sender | Frame type 0x80 (experimental), flags=0x00 (non-critical) |
| Receiver | Does not know type 0x80 |
| Messages | Frame(type=0x80, flags=0x00) |
| Outcome | Frame skipped, connection continues |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0006 §4.2 (non-critical unknown → MUST skip frame) |

### FT-0003: Known frame types

| Field | Value |
|-------|-------|
| Sender | All known frame types (0x01-0x08) |
| Receiver | v1 implementation |
| Messages | DATA, HANDSHAKE, RPC_REQUEST, RPC_RESPONSE, CLOSE, ERROR, PING, PONG |
| Outcome | All processed normally |
| Error code | None |
| Connection continues? | Yes |
| RFC | RFC-0006 §4.1 (frame type registry) |

## Transcript Behavior Scenarios

### TR-0001: Rejected negotiation never reaches authenticated state

| Field | Value |
|-------|-------|
| Scenario | ClientHello with unsupported critical extension |
| Verification | No session ID is derived, no ClientFinished is sent |
| RFC | RFC-0002 §5 (handshake must complete before authenticated state) |

### TR-0002: Transcript hash is deterministic for rejected handshakes

| Field | Value |
|-------|-------|
| Scenario | ClientHello with version=2 (rejected) |
| Verification | Transcript hash after ClientHello is still computable (SHA-256 chain), but no session ID is derived |
| RFC | RFC-0002 §5.6 (transcript hash is computed before rejection check) |

### TR-0003: Failure occurs at same stage in both implementations

| Field | Value |
|-------|-------|
| Scenario | Each rejection scenario above |
| Verification | Both Rust and Go reject at the same protocol stage (frame decode, handshake decode, or extension check) |
| RFC | RFC-0005 §3 (error codes are stage-specific) |

## Summary

| Category | Scenarios | Expected Pass | Expected Fail |
|----------|-----------|---------------|---------------|
| Version negotiation | 7 | 2 (VN-0001, VN-0006) | 5 |
| Extensions | 9 | 5 (EX-0002,3,4,6,7) | 4 |
| Frame types | 3 | 2 (FT-0002,3) | 1 |
| Transcript behavior | 3 | 0 (verification only) | 0 |
| **Total** | **22** | **9** | **10** |
