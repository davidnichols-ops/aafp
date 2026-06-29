# AAFP v0.9-rc1 Release Criteria

This document defines the objective, measurable criteria that must be
satisfied before the AAFP protocol and reference implementation can be
tagged as release candidate v0.9-rc1. Each criterion is binary: it is
either met or not met. No criterion is "mostly done."

## Criteria

### 1. Two independent implementations

- [x] Rust reference implementation (aafp)
- [x] Go independent implementation (aafp-go), written from RFCs alone

**Status**: MET

### 2. Bidirectional wire interoperability

- [x] Rust produces fixtures → Go decodes and verifies (73 tests)
- [x] Go produces fixtures → Rust decodes and verifies (39 tests)
- [x] All fixtures produce byte-for-byte identical output after
      decode→re-encode round-trip
- [x] Transcript hashes match at every handshake stage
- [x] Session ID derivation matches across implementations

**Status**: MET

### 3. Cross-signature verification

- [ ] Rust signs AgentRecord → Go verifies signature
- [ ] Go signs AgentRecord → Rust verifies signature
- [ ] Wrong public key rejected
- [ ] Modified transcript rejected
- [ ] Truncated signature rejected
- [ ] Malformed signature encoding rejected

**Status**: NOT MET — requires ML-DSA-65 in Go

### 4. Published deterministic test vectors

- [x] TEST_VECTORS.md with 31+ vectors covering all core RFC objects
- [x] Go implementation reproduces all vectors from RFCs alone
- [x] Vectors include CBOR, frames, handshake, AgentRecord, RPC, discovery

**Status**: MET

### 5. Published golden wire traces

- [x] Successful handshake trace (ClientHello → ServerHello → ClientFinished)
- [x] Failed handshake traces (bad signature, wrong version, unknown critical ext)
- [x] RPC request/response trace
- [x] Discovery announce trace
- [x] Raw bytes stored with decoded interpretations
- [x] Transcript hashes at each stage
- [x] Session ID captured
- [x] Verified by Go implementation (19 tests, all pass)

**Evidence**: `golden_traces/` directory with 9 traces, `golden_traces/README.md`

**Status**: MET

### 6. No unresolved interoperability ambiguities

- [x] SA-0001: CapabilityDescriptor metadata field presence — documented
- [x] SA-0002: Empty CBOR map key-type ambiguity — documented
- [x] SA-0001 resolved in RFC Revision 4 (metadata MUST always be present,
      encoded as `a0` when empty)
- [x] SA-0002 resolved in RFC Revision 4 (schema-driven key-type
      interpretation for empty CBOR maps)
- [x] Conformance tests added for both clarifications (8 Rust, 7 Go)

**Evidence**: `rfcs/RFC_CHANGELOG.md` (Revision 4 section),
`SPEC_AMBIGUITIES.md` (resolution sections), `rfcs/0002-transport-framing.md`
§8.1, `rfcs/0003-identity-authentication.md` §4.2, §4.4, §4.5

**Status**: MET

### 7. No known security-critical issues

- [x] Integer overflow protection verified (frame decoder)
- [x] OOM protection verified (CBOR decoder)
- [x] No unchecked allocations in parsing paths
- [ ] Signature verification cannot be bypassed
- [x] Downgrade attacks rejected (no in-band fallback; all non-v1
      versions rejected; verified in both implementations)

**Status**: NOT MET — signature verification review pending

### 8. Conformance suite passing in both implementations

- [x] Rust: all tests pass (`cargo test`) — 413 tests
- [x] Go: all tests pass (`go test ./...`) — 138 tests
- [x] Negative conformance tests (malformed frames, CBOR, signatures)
- [x] Fuzzing infrastructure in place
- [x] Version negotiation and downgrade behavior matrix (22 scenarios,
      tested in both implementations)
- [x] RFC Revision 4 conformance tests (SA-0001, SA-0002) in both
      implementations

**Status**: MET

### 9. Performance targets met

- [ ] Handshake completion < 100ms (excluding network)
- [ ] Frame encode/decode < 1µs per frame
- [ ] CBOR encode/decode < 10µs for typical messages
- [ ] AgentRecord verification < 50ms

**Status**: NOT MET — benchmarks exist but not validated against targets

### 10. Supply-chain review completed

- [x] All dependency versions locked (Cargo.lock committed, Go has no deps)
- [x] Cryptographic dependencies reviewed (10 direct, 10 transitive identified)
- [x] SBOM generated for both implementations
      (`supply_chain/sbom_rust.json`, `supply_chain/sbom_go.json`)
- [x] Vulnerability scan run (`supply_chain/cargo-audit.txt`,
      `supply_chain/govulncheck.txt`)
- [x] Build reproducibility verified (clean build succeeds for both)
- [x] License review completed (`supply_chain/LICENSE_REVIEW.md`)
- [ ] **pqcrypto unmaintained advisory resolved** (RUSTSEC-2026-0162/0163/0166)

**Evidence**: `supply_chain/SUPPLY_CHAIN_REVIEW.md`,
`supply_chain/LICENSE_REVIEW.md`, `supply_chain/sbom_rust.json`,
`supply_chain/sbom_go.json`, `supply_chain/cargo-audit.txt`,
`supply_chain/govulncheck.txt`

**Status**: NOT MET — pqcrypto migration required before rc1.
0 vulnerabilities found, but 3 unmaintained cryptographic dependency
warnings (pqcrypto family) must be resolved by migrating to a
maintained ML-DSA-65 implementation.

## Summary

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Two independent implementations | MET |
| 2 | Bidirectional wire interop | MET |
| 3 | Cross-signature verification | NOT MET |
| 4 | Published test vectors | MET |
| 5 | Published golden traces | MET |
| 6 | No unresolved ambiguities | MET |
| 7 | No security-critical issues | NOT MET (partial) |
| 8 | Conformance suite passing | MET |
| 9 | Performance targets | NOT MET |
| 10 | Supply-chain review | NOT MET (review done, pqcrypto migration pending) |

**7 of 10 criteria met (1 partial). Release candidate cannot be tagged
until all 10 are satisfied.**

## Remaining Work

1. **Migrate pqcrypto-mldsa to a maintained ML-DSA-65 implementation**
   (criterion 10). The pqcrypto family is unmaintained (PQClean
   archived). Candidates: aws-lc-rs, fips204, or vendored PQClean.
2. Add ML-DSA-65 to Go implementation (evaluate libraries carefully)
   and complete cross-signature verification (criterion 3).
3. Conduct security review of signature verification paths
   (criterion 7).
4. Validate performance benchmarks against targets (criterion 9).
5. Run sanitizer checks (Miri, race detector) on both implementations.
