# AAFP Implementation Issues

This document tracks bugs and deviations discovered in the AAFP
implementations during interoperability testing and conformance
verification. Unlike SPEC_AMBIGUITIES.md (which tracks specification
defects), this document tracks cases where implementations deviate
from clear RFC requirements.

## IMPL-0001: Non-critical unknown frame types rejected instead of skipped

**Status**: Open
**Discovered**: During version negotiation and downgrade testing (Phase 3)
**Severity**: Medium — breaks forward compatibility for experimental frame types
**Affected**: Both Rust and Go implementations
**RFC Reference**: RFC-0006 §4.2

### Description

RFC-0006 §4.2 states:

> **Non-critical (0x80 clear)**: If the receiver does not recognize
> the frame type, it MUST skip the frame and continue processing.

However, both the Rust and Go frame decoders reject ALL unknown frame
types, regardless of the critical bit:

- **Rust** (`aafp-messaging/src/framing.rs:252`):
  `FrameType::from_u8(frame_type_raw).ok_or(FrameError::UnknownFrameType(...))?`
  This returns an error for any frame type not in the known enum,
  including non-critical experimental types (0x80–0xFF).

- **Go** (`aafp-go/frame/frame.go`, original version):
  `isValidFrameType` returned `false` for all unknown types, and
  `Decode` rejected them with an error.

### Evidence

The version negotiation test `FT-0002` (unknown non-critical frame
type 0x80) was written to verify that such frames are decoded
successfully (so the caller can skip them). The test passes in Go
after the fix, but the Rust implementation still rejects them.

### Impact

- Experimental frame types (0x80–0xFF) with the critical bit clear
  will be rejected by both implementations, even though the RFC says
  they should be skipped.
- This breaks forward compatibility for any future experimental
  frame type that uses the non-critical bit.
- A peer sending an experimental non-critical frame will have its
  connection terminated instead of the frame being silently skipped.

### Fix

The frame decoder should:
1. Decode the frame header and body regardless of frame type.
2. If the frame type is unknown AND the critical bit is set, return
   an error (caller sends ERROR 8004).
3. If the frame type is unknown AND the critical bit is clear, return
   the decoded frame with a flag indicating it should be skipped.
4. The caller is responsible for skipping or rejecting based on the
   critical bit.

The Go implementation has been partially fixed: `Decode` now succeeds
for non-critical unknown types, and helper functions
(`IsCriticalUnknownFrameType`, `IsSkippableUnknownFrameType`) are
provided for the caller to make the skip/reject decision.

The Rust implementation has not yet been fixed. The `decode_frame`
function still rejects all unknown frame types.

### Resolution

- [x] Go: Fixed in `aafp-go/frame/frame.go`
- [x] Rust: Fixed in `aafp-messaging/src/framing.rs` — `FrameType` enum now has
      `Unknown(u8)` variant; `decode_frame` succeeds for non-critical unknown
      types and rejects only critical unknown types.
- [x] Verify both implementations agree on FT-0002 behavior
