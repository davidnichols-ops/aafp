# Attack Surface Review and Hardening Report (Track Q7)

## Overview

Systematic review of all code paths that handle untrusted/network input,
identifying potential vulnerabilities and applying hardening measures.

## Review Scope

| Component | File(s) | Input Source |
|-----------|---------|-------------|
| CBOR decoder | `aafp-cbor/src/lib.rs` | Network frames, handshake messages |
| Frame decoder | `aafp-messaging/src/framing.rs` | QUIC streams |
| Frame pipeline | `aafp-messaging/src/pipeline.rs` | QUIC streams |
| Handshake parsers | `aafp-crypto/src/handshake_v1.rs` | Network (pre-auth) |
| Handshake verification | `aafp-crypto/src/handshake_v1.rs` | Network (pre-auth) |
| RPC parsers | `aafp-messaging/src/rpc_v1.rs` | Authenticated peers |
| Server connection handler | `aafp-sdk/src/server.rs` | Network (pre-auth) |
| Rate limiter | `aafp-sdk/src/server.rs` | Network (pre-auth) |
| Discovery/DHT | `aafp-discovery/src/` | Network (post-auth) |
| Identity | `aafp-identity/src/identity_v1.rs` | Network + local |

## Findings and Actions

### 1. Constant-Time AgentId Comparison (FIXED)

**Finding**: `AgentId` derived `PartialEq` used standard byte-by-byte
comparison, which is not constant-time. This creates a timing side-channel
in security-critical paths:
- ReplayCache: `(agent_id, nonce)` lookup
- Server: `HashMap<AgentId, ServerPeerConnection>` lookup
- Session: peer identity comparison

**Risk**: Low — AgentId is a public hash, not a secret. However,
defense-in-depth requires constant-time comparison in security-critical code.

**Action**: Implemented `PartialEq` manually using `subtle::ConstantTimeEq`.
All `AgentId` comparisons now run in constant time, including those used
by `HashMap` key lookups.

**File**: `aafp-identity/src/identity_v1.rs`

### 2. Constant-Time AgentId Binding Verification (FIXED)

**Finding**: `verify_agent_id_binding()` in `handshake_v1.rs` used
`computed.as_slice() != agent_id` (non-constant-time slice comparison)
to verify that `agent_id == SHA-256(public_key)`.

**Risk**: Low — both values are attacker-provided, so no secret leaks.
However, defense-in-depth.

**Action**: Replaced with `subtle::ConstantTimeEq` comparison.

**File**: `aafp-crypto/src/handshake_v1.rs`

### 3. Rate Limiter Unbounded Memory Growth (FIXED)

**Finding**: `HandshakeRateLimiter` in `server.rs` maintained a
`HashMap<String, (u32, Instant)>` mapping IP addresses to rate limit
windows. Expired entries were never evicted, allowing unbounded memory
growth from connections originating from many unique source IPs.

**Risk**: Medium — An attacker (or botnet) connecting from many unique
IPs could cause the server's memory to grow without bound, eventually
causing OOM.

**Action**: Added periodic eviction of expired entries (every 100 checks)
and a `max_entries` cap (10,000) with forced eviction when exceeded.

**File**: `aafp-sdk/src/server.rs`

### 4. CBOR Decoder unwrap() Calls (SAFE)

**Finding**: Three `try_into().unwrap()` calls in the CBOR decoder for
u16/u32/u64 integer parsing.

**Assessment**: All three are preceded by explicit bounds checks
(`if *pos + N > data.len()`) that guarantee the slice has exactly the
required length. The `unwrap()` can never panic on valid input.

**Action**: No change needed. Verified safe.

### 5. Frame Decoder (SAFE)

**Finding**: Frame decoder uses `try_into().unwrap()` for stream_id,
payload_len, ext_len parsing.

**Assessment**: Preceded by `data.len() < FRAME_HEADER_SIZE` check (28 bytes).
All slice accesses are within bounds. Additionally:
- Version check rejects non-AAFP frames
- `MAX_PAYLOAD_SIZE` and `MAX_EXTENSION_SIZE` limits enforced
- `checked_add` prevents integer overflow in total frame size
- Unknown frame types with critical bit set are rejected

**Action**: No change needed. Verified safe.

### 6. Handshake Parsers (SAFE)

**Finding**: `ClientHello::from_cbor`, `ServerHello::from_cbor`,
`ClientFinished::from_cbor` parse untrusted CBOR.

**Assessment**: All parsers:
- Validate field types (reject wrong types with `InvalidField`)
- Check for missing required fields (return `MissingField`)
- Enforce A-1 (null params rejected) and A-2 (null optional fields rejected)
- Validate public_key and signature via `from_bytes()` (size-checked)
- Verify protocol version and key algorithm
- Check expiry timestamp
- Verify agent_id ↔ public_key binding

**Action**: No change needed. Verified safe.

### 7. RPC Parsers (SAFE)

**Finding**: `RpcRequest::from_cbor`, `RpcResponse::from_cbor` parse
CBOR from authenticated peers.

**Assessment**: Parsers validate field types, check for missing fields,
and enforce A-1 (null params rejected). Method names and params are
bounded by `MAX_PAYLOAD_SIZE` (1MB) at the frame layer.

**Action**: No change needed. Verified safe.

### 8. Server Connection Handler (SAFE)

**Finding**: `AgentServer::accept_one()` handles incoming connections.

**Assessment**: Already hardened in Q4:
- Connection limit enforced before accepting
- Per-IP handshake rate limiting
- Rate-limited connections closed immediately
- Full handshake + authorization before storing connection

**Action**: No change needed (beyond rate limiter fix above).

## Summary

| # | Finding | Risk | Status |
|---|---------|------|--------|
| 1 | Non-CT AgentId comparison | Low | FIXED |
| 2 | Non-CT agent_id binding | Low | FIXED |
| 3 | Rate limiter memory growth | Medium | FIXED |
| 4 | CBOR decoder unwrap() | None | SAFE |
| 5 | Frame decoder | None | SAFE |
| 6 | Handshake parsers | None | SAFE |
| 7 | RPC parsers | None | SAFE |
| 8 | Server connection handler | None | SAFE |

**Result**: 3 issues fixed, 5 verified safe. No critical or high-risk
vulnerabilities found. All parsers reject malformed input without panics.
