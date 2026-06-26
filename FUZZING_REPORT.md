# Fuzzing Report

**Date**: 2025-06-25
**Status**: Phase 3 — Initial fuzzing complete
**Tool**: cargo-fuzz (libfuzzer) with AddressSanitizer
**Toolchain**: nightly-aarch64-apple-darwin

## Fuzz Targets

| Target | File | Description |
|--------|------|-------------|
| `fuzz_cbor_decode` | `fuzz_targets/fuzz_cbor_decode.rs` | CBOR decoder with arbitrary bytes |
| `fuzz_frame_decode` | `fuzz_targets/fuzz_frame_decode.rs` | Frame decoder with arbitrary bytes |
| `fuzz_handshake_cbor` | `fuzz_targets/fuzz_handshake_cbor.rs` | Handshake message parsers (ClientHello, ServerHello, ClientFinished) |
| `fuzz_agent_record_cbor` | `fuzz_targets/fuzz_agent_record_cbor.rs` | AgentRecord parser |
| `fuzz_rpc_decode` | `fuzz_targets/fuzz_rpc_decode.rs` | RPC request/response parsers |

## Results

| Target | Iterations | Duration | Max Len | Crashes | Status |
|--------|-----------|----------|---------|---------|--------|
| `fuzz_cbor_decode` | 4,335,107 | 31s | 256 | 0 (after fix) | PASS |
| `fuzz_frame_decode` | ~500K | 30s | 256 | 0 (after fix) | PASS |
| `fuzz_handshake_cbor` | 2,394,346 | 16s | 256 | 0 | PASS |
| `fuzz_agent_record_cbor` | 2,404,964 | 16s | 256 | 0 | PASS |
| `fuzz_rpc_decode` | 839,507 | 16s | 256 | 0 | PASS |

**Total**: ~10.5 million iterations, 0 crashes after fixes.

## Bugs Found and Fixed

### Bug 1: CBOR Decoder Out-of-Memory (OOM)

**Target**: `fuzz_cbor_decode`
**Severity**: High (denial of service)
**Root Cause**: The CBOR decoder used `Vec::with_capacity(len)` for arrays and
maps without checking if `len` was reasonable relative to the available input
data. A malicious input could declare an array of 2^64 elements, causing the
decoder to attempt to allocate 224 GB of memory.

**Fix**: Added a check `if len > data.len()` before `Vec::with_capacity()` for
both arrays and maps. Since each element requires at least 1 byte, the declared
length cannot exceed the available data.

**File**: `crates/aafp-cbor/src/lib.rs` lines 303-320

### Bug 2: CBOR Decoder Integer Overflow

**Target**: `fuzz_cbor_decode`
**Severity**: High (panic / denial of service)
**Root Cause**: The byte string and text string decoders used `*pos + len` to
compute the end position, which could overflow `usize` on 64-bit platforms when
`len` was very large (e.g., 0xFFFFFFFFFFFFFFFF).

**Fix**: Replaced `*pos + len` with `(*pos).checked_add(len)` and return an
error on overflow instead of panicking.

**File**: `crates/aafp-cbor/src/lib.rs` lines 273-301

### Bug 3: Frame Decoder Integer Overflow

**Target**: `fuzz_frame_decode`
**Severity**: High (panic / denial of service)
**Root Cause**: The frame decoder computed `ext_len + payload_len` and
`FRAME_HEADER_SIZE + total_body` without checked arithmetic. When both values
were near `usize::MAX`, the addition overflowed and panicked.

Additionally, the `ok_or()` call in the `checked_add` result eagerly evaluated
the error argument `ext_len + payload_len`, which itself overflowed.

**Fix**: Used `checked_add()` for all length computations and replaced the
eager `ok_or()` with a fixed `usize::MAX` value in the error constructor to
avoid the overflow in the error path.

**File**: `crates/aafp-messaging/src/framing.rs` lines 237-244

## Hardening Changes

In addition to the fuzz-found bug fixes, the following hardening was applied
during Phase 3:

1. **Canonical CBOR validation**: The decoder now rejects non-shortest integer
   encodings per RFC 8949 §4.2.1.
2. **Duplicate map key detection**: The decoder now rejects maps with duplicate
   keys per RFC 8949 §3.1.
3. **Indefinite-length rejection**: Already in place (AI_BREAK triggers error).

## Recommendations for Future Fuzzing

1. **Longer runs**: Run each target for at least 1 hour (vs 30 seconds) to
   increase the chance of finding deep bugs.
2. **Larger inputs**: Increase `max_len` to 4096 or higher to test larger
   structures (AgentRecord with many capabilities, large RPC params).
3. **Structure-aware fuzzing**: Use `arbitrary` to generate semi-valid CBOR
   structures instead of pure random bytes, to reach deeper parser states.
4. **Sanitizer combinations**: Run with `-Zsanitizer=memory` in addition to
   AddressSanitizer to detect uninitialized memory reads.
5. **Continuous fuzzing**: Integrate with OSS-Fuzz or a CI fuzzing job for
   ongoing coverage.
