# Rust ↔ Go Cross-Language Interop Results

## Interop Level Achieved: Level 2 (Frame-Level)

### Level 1 (Full live QUIC interop): NO
The Go implementation does not have a QUIC transport layer. It is explicitly
transport-agnostic — a wire-format library focused on protocol correctness.
Live QUIC interop would require adding a QUIC transport to the Go
implementation (ROADMAP.md v1.1 item B-2).

### Level 2 (Frame-level interop): YES
- 39 Go-produced fixtures verified by Rust (byte-for-byte round-trip)
- 7 Rust integration tests spawn the Go fixture generator and verify output
- All 48 Go test vector tests pass
- All 17 golden trace cross-verifications pass
- Covers: CBOR (16 types), frames (6 types), handshake (3 messages),
  AgentRecord (2 variants), transcript hash (4 stages), session ID,
  RPC (6 messages)

### Level 3 (CBOR-level interop): YES
- 16 CBOR type fixtures round-trip verified
- ML-DSA-65 cross-signature verification: 19/19 + 15/15 + 100/100 (A-10)

---

## Test Architecture

The Rust integration test (`crates/aafp-tests/tests/go_interop.rs`) spawns
the Go fixture generator as a subprocess:

```
go run ./cmd/generate_interop_fixtures <output_dir>
```

The Go generator produces binary fixtures using fixed (non-random) inputs
that both implementations can reproduce from the RFCs alone. The Rust test
then:
1. Reads each binary fixture
2. Decodes it using Rust's CBOR/frame/handshake decoders
3. Re-encodes the decoded value
4. Compares the re-encoded bytes against the original Go bytes
5. Reports any discrepancies

This is a true two-implementation conformance check: the Go implementation
was written independently from the RFCs alone, without reference to the Rust
code.

---

## Fixture Regeneration

The Go interop fixtures were stale — they had been generated before the
A-3 (record_version) and A-4 (session_id binding) changes were added.
After regeneration with the current Go code:
- AgentRecord now includes key 10 (record_version) → 4 failures fixed
- Session ID now binds to server_agent_id → 1 failure fixed
- All 39 fixtures now pass

---

## Files

| File | Purpose |
|------|---------|
| `crates/aafp-tests/tests/go_interop.rs` | 7 Rust integration tests |
| `crates/aafp-conformance/src/bin/verify_go_fixtures.rs` | Standalone verifier (39 fixtures) |
| `implementations/go/cmd/generate_interop_fixtures/main.go` | Go fixture generator |
| `implementations/go/go_interop_fixtures/` | Generated fixtures (Go side) |
| `implementations/rust/go_interop_fixtures/` | Generated fixtures (Rust side) |

---

## Conclusion

Rust ↔ Go cross-language interop is verified at Level 2 (frame-level).
The Go implementation serves as an independent second implementation,
confirming that the AAFP RFCs are sufficiently clear to produce
byte-compatible implementations. All 39 wire-format fixtures round-trip
correctly between the two implementations.

Level 1 (live QUIC interop) remains a v1.1 milestone, pending the addition
of a QUIC transport layer to the Go implementation.
