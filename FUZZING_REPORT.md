# Fuzzing Report

**Date**: 2026-07-04 (Track Q2 update)
**Status**: Track Q — Security audit fuzzing complete
**Tool**: cargo-fuzz (libfuzzer)
**Toolchain**: nightly-aarch64-apple-darwin (1.98.0-nightly)

## Fuzz Targets

| Target | File | Description |
|--------|------|-------------|
| `fuzz_cbor_decode` | `fuzz_targets/fuzz_cbor_decode.rs` | CBOR decoder with arbitrary bytes |
| `fuzz_frame_decode` | `fuzz_targets/fuzz_frame_decode.rs` | Frame decoder with arbitrary bytes |
| `fuzz_handshake_cbor` | `fuzz_targets/fuzz_handshake_cbor.rs` | Handshake message parsers (ClientHello, ServerHello, ClientFinished) |
| `fuzz_agent_record_cbor` | `fuzz_targets/fuzz_agent_record_cbor.rs` | AgentRecord parser |
| `fuzz_rpc_decode` | `fuzz_targets/fuzz_rpc_decode.rs` | RPC request/response parsers |
| `fuzz_relay_request` | `fuzz_targets/fuzz_relay_request.rs` | Relay RPC params + handler (Track Q2) |
| `fuzz_discovery_request` | `fuzz_targets/fuzz_discovery_request.rs` | Discovery params parsers (Track Q2) |
| `fuzz_dht_router` | `fuzz_targets/fuzz_dht_router.rs` | DHT capability store + record parsing (Track Q2) |

## Results (Track Q2 — 2026-07-04)

| Target | Iterations | Duration | Crashes | Status |
|--------|-----------|----------|---------|--------|
| `fuzz_cbor_decode` | ~112,000 | 60s | 0 (after depth fix) | PASS |
| `fuzz_frame_decode` | 14,051,591 | 61s | 0 | PASS |
| `fuzz_handshake_cbor` | 2,692,116 | 61s | 0 | PASS |
| `fuzz_agent_record_cbor` | 2,332,488 | 61s | 0 | PASS |
| `fuzz_rpc_decode` | 1,468,714 | 61s | 0 | PASS |
| `fuzz_relay_request` | 1,987,225 | 61s | 0 | PASS |
| `fuzz_discovery_request` | 2,171,143 | 61s | 0 | PASS |
| `fuzz_dht_router` | 2,007,779 | 61s | 0 | PASS |

**Total (Track Q2)**: ~26.8 million iterations, 1 bug found and fixed, 0 crashes after fix.

## Bugs Found and Fixed

### Bug 1: CBOR Decoder Out-of-Memory (OOM) — Phase 3

**Target**: `fuzz_cbor_decode`
**Severity**: High (denial of service)
**Root Cause**: The CBOR decoder used `Vec::with_capacity(len)` for arrays and
maps without checking if `len` was reasonable relative to the available input
data. A malicious input could declare an array of 2^64 elements, causing the
decoder to attempt to allocate 224 GB of memory.

**Fix**: Added a check `if len > data.len()` before `Vec::with_capacity()` for
both arrays and maps. Since each element requires at least 1 byte, the declared
length cannot exceed the available data.

**File**: `crates/aafp-cbor/src/lib.rs`

### Bug 2: CBOR Decoder Integer Overflow — Phase 3

**Target**: `fuzz_cbor_decode`
**Severity**: High (panic / denial of service)
**Root Cause**: The byte string and text string decoders used `*pos + len` to
compute the end position, which could overflow `usize` on 64-bit platforms when
`len` was very large (e.g., 0xFFFFFFFFFFFFFFFF).

**Fix**: Replaced `*pos + len` with `(*pos).checked_add(len)` and return an
error on overflow instead of panicking.

**File**: `crates/aafp-cbor/src/lib.rs`

### Bug 3: Frame Decoder Integer Overflow — Phase 3

**Target**: `fuzz_frame_decode`
**Severity**: High (panic / denial of service)
**Root Cause**: The frame decoder computed `ext_len + payload_len` and
`FRAME_HEADER_SIZE + total_body` without checked arithmetic. When both values
were near `usize::MAX`, the addition overflowed and panicked.

**Fix**: Used `checked_add()` for all length computations.

**File**: `crates/aafp-messaging/src/framing.rs`

### Bug 4: CBOR Decoder Unbounded Nesting Depth (OOM) — Track Q2

**Target**: `fuzz_cbor_decode`
**Severity**: High (denial of service — OOM / stack overflow)
**Root Cause**: The `decode_value` function was recursive without any depth
limit. A crafted CBOR input with deeply nested arrays/maps (200+ levels)
caused unbounded memory allocation and eventual OOM. The fuzzer found this
on the first run (before the fix, exit code 71 with `oom-` artifact).

**Fix**: Added `MAX_DECODE_DEPTH = 100` constant and a `depth` parameter to
`decode_value`. When depth exceeds the limit, returns `CborError::DepthExceeded`.
AAFP messages are shallow (handshake maps, RPC maps, arrays of capabilities) —
100 levels is far more than any legitimate use.

**Regression tests**: `test_deep_nesting_rejected` and
`test_nesting_at_limit_succeeds` in `crates/aafp-cbor/src/lib.rs`.

**File**: `crates/aafp-cbor/src/lib.rs`

## Hardening Changes

In addition to the fuzz-found bug fixes, the following hardening was applied:

1. **Canonical CBOR validation**: The decoder rejects non-shortest integer
   encodings per RFC 8949 §4.2.1.
2. **Duplicate map key detection**: The decoder rejects maps with duplicate
   keys per RFC 8949 §3.1.
3. **Indefinite-length rejection**: AI_BREAK triggers error.
4. **CBOR nesting depth limit** (Track Q2): `MAX_DECODE_DEPTH = 100` prevents
   stack overflow and OOM from adversarial deeply-nested structures.

## Recommendations for Future Fuzzing

1. **Longer runs**: Run each target for at least 1 hour (vs 60 seconds) to
   increase the chance of finding deep bugs.
2. **Larger inputs**: Increase `max_len` to 4096 or higher to test larger
   structures (AgentRecord with many capabilities, large RPC params).
3. **Structure-aware fuzzing**: Use `arbitrary` to generate semi-valid CBOR
   structures instead of pure random bytes, to reach deeper parser states.
4. **Sanitizer combinations**: Run with `-Zsanitizer=memory` in addition to
   AddressSanitizer to detect uninitialized memory reads.
5. **Continuous fuzzing**: Integrate with OSS-Fuzz or a CI fuzzing job for
   ongoing coverage.
