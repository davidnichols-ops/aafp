# Negative Conformance Test Suite

**Date**: 2025-06-25
**Status**: Phase 3 — Interoperability and Hardening
**Crate**: `aafp-conformance/src/negative.rs`

## Purpose

The negative conformance suite verifies that the implementation correctly
**rejects** malformed and adversarial inputs per RFC requirements. This is
distinct from the positive conformance suite (rfc0002-0005 modules) which
verifies that valid inputs are accepted and processed correctly.

Negative testing is where "spec-compliant" implementations most commonly
diverge — different implementations make different assumptions about how to
handle invalid inputs, leading to interoperability failures.

## Test Categories

### 1. Non-Canonical CBOR (18 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-CBOR-001 | Non-shortest uint (5 as 0x1805) | RFC-0002 §8 | Rejected |
| N-CBOR-002 | Non-shortest uint (20 as 0x1814) | RFC-0002 §8 | Rejected |
| N-CBOR-003 | Non-shortest uint (100 in 2-byte) | RFC-0002 §8 | Rejected |
| N-CBOR-004 | Non-shortest uint (255 in 2-byte) | RFC-0002 §8 | Rejected |
| N-CBOR-005 | Non-shortest uint (1000 in 4-byte) | RFC-0002 §8 | Rejected |
| N-CBOR-006 | Indefinite-length array (0x9F) | RFC-0002 §8 | Rejected |
| N-CBOR-007 | Indefinite-length map (0xBF) | RFC-0002 §8 | Rejected |
| N-CBOR-008 | Bare break code (0xFF) | RFC-0002 §8 | Rejected |
| N-CBOR-009 | Empty input | RFC-0002 §8 | Rejected |
| N-CBOR-010 | Truncated byte string | RFC-0002 §8 | Rejected |
| N-CBOR-011 | Truncated text string | RFC-0002 §8 | Rejected |
| N-CBOR-012 | Invalid UTF-8 in text string | RFC 8949 | Rejected |
| N-CBOR-013 | Duplicate integer map keys | RFC-0002 §8 | Rejected |
| N-CBOR-014 | Duplicate string map keys | RFC-0002 §8 | Rejected |
| N-CBOR-015 | CBOR tag (major type 6) | RFC-0002 §8 | Rejected |
| N-CBOR-016 | Unknown simple value | RFC 8949 | Rejected |
| N-CBOR-017 | Truncated map (fewer entries than declared) | RFC-0002 §8 | Rejected |
| N-CBOR-018 | Truncated array | RFC-0002 §8 | Rejected |

### 2. Invalid Frames (10 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-FRAME-001 | Wrong protocol version | RFC-0002 §3.1 | InvalidVersion error |
| N-FRAME-002 | Unknown frame type (non-critical) | RFC-0002 §4 | UnknownFrameType error |
| N-FRAME-003 | Unknown critical frame type (0xFF\|0x80) | RFC-0002 §4 | Rejected (fatal) |
| N-FRAME-004 | Truncated header (< 28 bytes) | RFC-0002 §3 | Incomplete error |
| N-FRAME-005 | Payload > MAX_PAYLOAD_SIZE | RFC-0002 §3 | PayloadTooLarge error |
| N-FRAME-006 | Payload length mismatch | RFC-0002 §3 | Incomplete error |
| N-FRAME-007 | Extension length mismatch | RFC-0002 §3 | Incomplete error |
| N-FRAME-008 | Empty input | RFC-0002 §3 | Incomplete error |
| N-FRAME-009 | Non-zero reserved byte | RFC-0002 §3.1 | Ignored (per spec) |
| N-FRAME-010 | Encode oversized payload | RFC-0002 §3 | Encoding fails |

### 3. Invalid AgentRecords (8 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-REC-001 | Tampered agent_id | RFC-0003 §2 | InvalidAgentId error |
| N-REC-002 | Tampered public_key | RFC-0003 §2 | InvalidAgentId (hash mismatch) |
| N-REC-003 | Tampered signature | RFC-0003 §3 | SignatureVerificationFailed |
| N-REC-004 | Expired record | RFC-0003 §8.4 | Expired error |
| N-REC-005 | Wrong record_type | RFC-0003 §3 | InvalidRecordType error |
| N-REC-006 | Wrong key_algorithm | RFC-0003 §3.6 step 8 | UnsupportedAlgorithm error (enforced) |
| N-REC-007 | Expiry exceeds 30-day max | RFC-0003 §8.4 (Rev 5) | Accepted by verify() (warning, not rejection) |
| N-REC-008 | Empty public key | RFC-0003 §2 | InvalidAgentId error |

### 4. Invalid Signatures (6 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-SIG-001 | Wrong message | RFC-0002 §5 | Verify returns false |
| N-SIG-002 | Tampered signature | RFC-0002 §5 | Verify returns false |
| N-SIG-003 | Wrong key | RFC-0002 §5 | Verify returns false |
| N-SIG-004 | Empty signature | RFC-0002 §5 | Verify returns false |
| N-SIG-005 | Truncated signature | RFC-0002 §5 | Verify returns false |
| N-SIG-006 | Empty public key | RFC-0002 §5 | Verify returns false |

### 5. Invalid Error Frames (4 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-ERR-001 | Data > 4096 bytes | RFC-0005 §4 | Truncated to 4096 |
| N-ERR-002 | Cannot override always-fatal | RFC-0005 §4.4 | Fatal stays true |
| N-ERR-003 | Empty message | RFC-0005 | No crash |
| N-ERR-004 | All 2xxx codes always-fatal | RFC-0005 §4.4 | Verified |

### 6. Invalid Handshake (5 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-HS-001 | DoS MAC wrong agent_id | RFC-0002 §5.7 | Verify returns false |
| N-HS-002 | DoS MAC wrong message | RFC-0002 §5.7 | Verify returns false |
| N-HS-003 | DoS MAC tampered | RFC-0002 §5.7 | Verify returns false |
| N-HS-004 | Empty MAC | RFC-0002 §5.7 | Verify returns false |
| N-HS-005 | Short MAC (16 bytes) | RFC-0002 §5.7 | Verify returns false |

### 7. Discovery Edge Cases (3 tests)

| ID | Test | RFC | Behavior Verified |
|----|------|-----|-------------------|
| N-DHT-001 | Put expired record | RFC-0004 | No crash |
| N-DHT-002 | Lookup non-existent capability | RFC-0004 | Returns empty |
| N-DHT-003 | Many capabilities (100) | RFC-0004 | No crash, all indexed |

## Implementation Hardening

The following hardening changes were made to the CBOR decoder as part of this
negative conformance work:

### Canonical CBOR Decoding Validation

The CBOR decoder now rejects non-canonical encodings per RFC 8949 §4.2.1:

1. **Non-shortest integer encoding**: Values that could be encoded in fewer
   bytes are rejected. For example, encoding 5 as `0x18 0x05` (two bytes)
   instead of `0x05` (one byte) is now rejected.

2. **Duplicate map keys**: Maps with duplicate keys are rejected per
   RFC 8949 §3.1: "A map that has duplicate keys may be well-formed, but
   it is not valid (distinct keys are required)."

3. **Indefinite-length**: Already rejected (AI_BREAK = 0x1F triggers
   `Unsupported` error).

## Spec Gaps Identified

The following gaps were identified during negative testing:

1. **N-REC-006** (resolved): AgentRecord verification now checks
   `key_algorithm` against the known set (ML-DSA-65 = 1) per
   RFC-0003 §3.6 step 8, rejecting unknown algorithms with
   `UnsupportedAlgorithm`. The test now asserts rejection.

2. **N-REC-007** (resolved in RFC Revision 5, SA-0003): The 30-day
   maximum expiry is a deployment warning, not a verification-rejection
   requirement. RFC-0003 §8.4 (Rev 5) clarifies that `verify()` does
   NOT reject records whose lifetime exceeds 30 days; callers SHOULD
   use `exceeds_max_expiry_warning(now)` to warn users. The test now
   asserts that `verify()` accepts an unexpired >30-day record while
   the warning predicate fires. See `SPEC_AMBIGUITIES.md` SA-0003.

## Summary

- **54 negative conformance tests** (N-REC-006 and N-REC-007 updated
  to reflect resolved semantics in RFC Revision 5)
- **0 failures** — all tests pass
- **0 open spec gaps** (both N-REC-006 and N-REC-007 resolved)
- **CBOR decoder hardened** with canonical encoding validation
