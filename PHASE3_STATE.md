# AAFP Project State — Phase 3

**Last updated**: 2025-06-25
**Session context**: 157k/200k tokens — save state for continuation

## Project Location
`/Users/david/AAFP-research/aafp/`

## Current Test State
- **379 tests pass**, 0 failures across the workspace
- 95 positive conformance tests (rfc0002-0005 modules)
- 54 negative conformance tests (negative.rs)
- 38 test vectors + 13 verification tests (test_vectors.rs)
- 10 handshake vector tests (handshake_vectors.rs)

## Phase 3 Todo Status
1. [x] Deterministic wire-format test vectors → TEST_VECTORS.md
2. [x] Handshake transcript + signature vectors → HANDSHAKE_VECTORS.md
3. [x] Negative conformance suite → NEGATIVE_CONFORMANCE.md
4. [x] Fuzzing (5 targets, 10.5M iterations) → FUZZING_REPORT.md
5. [ ] Sanitizer-backed test suites (ASAN already in fuzzing; add MSan/UBSan)
6. [ ] Independent minimal second implementation (Go or TypeScript from RFCs only)
7. [ ] Cross-implementation interoperability tests
8. [ ] Golden wire traces (WIRE_TRACES/)
9. [ ] Downgrade/extension-criticality/version-negotiation validation
10. [ ] Dependency and supply-chain review
11. [ ] RFC Revision 4 (only for ambiguities found during interop)
12. [ ] Tag v0.9-rc1

## Key Files
- `Cargo.toml` — workspace root, 13 crates
- `crates/aafp-conformance/` — conformance suite (lib.rs, rfc0002-0005.rs, test_vectors.rs, handshake_vectors.rs, negative.rs, bin/generate_vectors.rs)
- `crates/aafp-cbor/src/lib.rs` — CBOR encoder/decoder (hardened with canonical validation + checked arithmetic)
- `crates/aafp-messaging/src/framing.rs` — frame encoder/decoder (hardened with checked_add)
- `crates/aafp-messaging/src/rpc_v1.rs` — RPC request/response/error messages
- `crates/aafp-crypto/src/handshake_v1.rs` — ClientHello/ServerHello/ClientFinished, transcript hash
- `crates/aafp-identity/src/identity_v1.rs` — AgentId, AgentRecord, CapabilityDescriptor
- `crates/aafp-discovery/src/discovery_v1.rs` — CapabilityDht, AnnounceParams, LookupParams
- `crates/aafp-core/src/error.rs` — ProtocolError, error codes (RFC-0005)
- `fuzz/` — 5 fuzz targets (separate workspace, needs nightly)

## Bugs Fixed During Fuzzing
1. CBOR OOM: Vec::with_capacity(len) without bounds check for arrays/maps
2. CBOR overflow: *pos + len could overflow usize (fixed with checked_add)
3. Frame overflow: ext_len + payload_len overflow (fixed with checked_add)

## Spec Gaps for RFC Revision 4
1. AgentRecord verification does not check key_algorithm against known set
2. AgentRecord max expiry (30 days) not enforced during verification

## How to Run Tests
```bash
cd /Users/david/AAFP-research/aafp
cargo test --workspace                    # all 379 tests
cargo test -p aafp-conformance            # conformance only
cargo test -p aafp-conformance negative   # negative tests only
cargo run -p aafp-conformance --bin generate_vectors > TEST_VECTORS.md
cargo run -p aafp-conformance --bin generate_vectors handshake > HANDSHAKE_VECTORS.md
```

## How to Run Fuzzing
```bash
cd /Users/david/AAFP-research/aafp/fuzz
cargo +nightly fuzz run fuzz_cbor_decode -- -max_total_time=30 -max_len=256
```

## Next Steps Priority
1. Task 6: Second implementation (highest value — proves RFCs are implementable)
2. Task 9: Downgrade/version-negotiation validation
3. Task 10: Dependency review
4. Task 5: MSan/UBSan test runs
5. Tasks 7-8: Interop tests and wire traces (depend on task 6)
6. Tasks 11-12: RFC Rev 4 and RC tag (final steps)
