# AAFP Protocol Compliance Matrix

**Date**: 2025-06-25
**RFC Revision**: 3 (Freeze Candidate)
**Purpose**: Bridge between RFC normative requirements and implementation. Every normative statement maps to one or more tests.

## Summary

| RFC | Title | Requirements | CRITICAL | HIGH | LOW |
|-----|-------|-------------|----------|------|-----|
| 0001 | Protocol Overview | 5 | 4 | 0 | 1 |
| 0002 | Transport & Framing | 84 | 52 | 16 | 16 |
| 0003 | Identity & Authentication | 78 | 48 | 22 | 8 |
| 0004 | Discovery | 42 | 16 | 14 | 12 |
| 0005 | Error Model | 38 | 22 | 8 | 8 |
| 0006 | Versioning & Compatibility | 68 | 48 | 4 | 16 |
| **Total** | | **315** | **190** | **64** | **61** |

## Implementation Priority

Phase 2 implementation focuses on CRITICAL and HIGH requirements.
LOW requirements (MAY) are deferred unless needed for interop.

## Compliance Matrix

### RFC-0001: Protocol Overview

| Req ID | Section | Keyword | Requirement | Priority | Impl Status | Test ID |
|--------|---------|---------|-------------|----------|-------------|---------|
| R1-001 | 7.3 | MUST | Conforming implementations MUST satisfy RFC-0006 §8.1 conformance requirements | CRITICAL | PENDING | T-R1-001 |
| R1-002 | 7.3 | MUST NOT | v0.1 MVP conformance requirements MUST NOT be used for conformance claims | CRITICAL | PENDING | T-R1-002 |
| R1-003 | 9.0 | MUST | Implementations MUST support configuring multiple bootstrap nodes | CRITICAL | PENDING | T-R1-003 |
| R1-004 | 9.0 | MAY | Future versions MAY introduce trusted third parties | LOW | N/A | — |
| R1-005 | 9.6 | MUST | Implementations MUST assess whether security limitations are acceptable for their threat model | CRITICAL | PENDING | T-R1-005 |

### RFC-0002: Transport & Framing

| Req ID | Section | Keyword | Requirement | Priority | Impl Status | Test ID |
|--------|---------|---------|-------------|----------|-------------|---------|
| R2-001 | 2.2 | MUST | MUST negotiate aafp/1 ALPN during TLS handshake | CRITICAL | PENDING | T-R2-001 |
| R2-002 | 2.2 | MUST | If ALPN fails, MUST close connection with TLS alert | CRITICAL | PENDING | T-R2-002 |
| R2-003 | 2.3 | MUST | MUST offer X25519MLKEM768 key exchange group | CRITICAL | PENDING | T-R2-003 |
| R2-004 | 2.3 | SHOULD | SHOULD prefer X25519MLKEM768 over classical-only | HIGH | PENDING | T-R2-004 |
| R2-005 | 2.3 | MAY | MAY offer X25519 as fallback | LOW | N/A | — |
| R2-006 | 2.3 | SHOULD | X25519 fallback SHOULD be disabled in PQ production | HIGH | PENDING | T-R2-006 |
| R2-007 | 2.4 | MUST | MUST use self-signed certificates | CRITICAL | PENDING | T-R2-007 |
| R2-008 | 2.4 | MUST NOT | MUST NOT require CA-signed certificates | CRITICAL | PENDING | T-R2-008 |
| R2-009 | 2.4 | MUST NOT | MUST NOT perform certificate chain validation beyond self-signed integrity | CRITICAL | PENDING | T-R2-009 |
| R2-010 | 2.5 | SHOULD | SHOULD send close frame before closing QUIC connection | HIGH | PENDING | T-R2-010 |
| R2-011 | 2.5 | MUST | Both sides MUST compute TLS channel binding after TLS handshake | CRITICAL | PENDING | T-R2-011 |
| R2-012 | 2.5 | MUST NOT | If TLS exporter unavailable, MUST NOT proceed with handshake | CRITICAL | PENDING | T-R2-012 |
| R2-013 | 2.5 | MUST | MUST close with error 2006 if TLS exporter unavailable | CRITICAL | PENDING | T-R2-013 |
| R2-014 | 3.1 | MUST | Reserved field MUST be set to 0 by senders | CRITICAL | PENDING | T-R2-014 |
| R2-015 | 3.1 | MUST | Reserved field MUST be ignored by receivers | CRITICAL | PENDING | T-R2-015 |
| R2-016 | 3.3 | MUST NOT | MUST NOT assume cross-stream ordering | CRITICAL | PENDING | T-R2-016 |
| R2-017 | 3.4 | MUST | MUST reject frames with payload > 1 MiB with error 8001 | CRITICAL | PENDING | T-R2-017 |
| R2-018 | 3.4 | SHOULD | ERROR fatal flag SHOULD be false for oversized frames | HIGH | PENDING | T-R2-018 |
| R2-019 | 3.4 | MAY | MAY set fatal flag for repeated oversized frames | LOW | N/A | — |
| R2-020 | 3.4 | MUST | Larger messages MUST be fragmented across multiple frames | CRITICAL | PENDING | T-R2-020 |
| R2-021 | 3.5 | MUST | MUST use frame format specified in §3.1 | CRITICAL | PENDING | T-R2-021 |
| R2-022 | 4.1 | MUST | Receiver MUST buffer fragments until DATA without MORE flag | CRITICAL | PENDING | T-R2-022 |
| R2-023 | 4.1 | MUST | If compression not negotiated, MUST return error 8002 | CRITICAL | PENDING | T-R2-023 |
| R2-024 | 4.2 | MUST NOT | HANDSHAKE frame MUST NOT be sent on non-zero streams | CRITICAL | PENDING | T-R2-024 |
| R2-025 | 4.2 | MUST | MUST return error 8003 for handshake on non-zero stream | CRITICAL | PENDING | T-R2-025 |
| R2-026 | 4.5 | MUST NOT | After CLOSE frame, sender MUST NOT send additional frames | CRITICAL | PENDING | T-R2-026 |
| R2-027 | 4.5 | SHOULD | Receiver SHOULD send CLOSE frame in response | HIGH | PENDING | T-R2-027 |
| R2-028 | 4.6 | MUST | If fatal=true, receiver MUST close connection | CRITICAL | PENDING | T-R2-028 |
| R2-029 | 4.7 | MUST | Receiver MUST respond with PONG on same stream | CRITICAL | PENDING | T-R2-029 |
| R2-030 | 4.7 | MAY | PING MAY be sent on any open stream | LOW | N/A | — |
| R2-031 | 4.7 | RECOMMENDED | PING on stream 0 RECOMMENDED for keepalive | HIGH | PENDING | T-R2-031 |
| R2-032 | 4.7 | MAY | MAY use either or both keepalive mechanisms | LOW | N/A | — |
| R2-033 | 4.8 | MUST | PONG MUST be sent on same stream as PING | CRITICAL | PENDING | T-R2-033 |
| R2-034 | 4.9 | MUST | Unknown frame types MUST follow critical bit rules | CRITICAL | PENDING | T-R2-034 |
| R2-035 | 4.9 | MUST | Critical bit set + unknown type → error 8004 + close | CRITICAL | PENDING | T-R2-035 |
| R2-036 | 4.9 | MUST | Critical bit not set + unknown type → skip frame | CRITICAL | PENDING | T-R2-036 |
| R2-037 | 5.1 | MUST NOT | Stream 0 MUST NOT be used for DATA/RPC after handshake | CRITICAL | PENDING | T-R2-037 |
| R2-038 | 5.7 | MUST | Session ID MUST satisfy uniqueness, unpredictability, binding | CRITICAL | PENDING | T-R2-038 |
| R2-039 | 5.7 | MUST | Session ID MUST be derived via HKDF-SHA256 over h_after_ch + nonces | CRITICAL | PENDING | T-R2-039 |
| R2-040 | 5.7 | MUST | Client MUST verify Session ID in ServerHello matches derived value | CRITICAL | PENDING | T-R2-040 |
| R2-041 | 5.7 | MUST | If Session IDs differ, MUST send error 2006 + close | CRITICAL | PENDING | T-R2-041 |
| R2-042 | 5.7 | MUST | All implementations MUST use exact Session ID derivation | CRITICAL | PENDING | T-R2-042 |
| R2-043 | 5.8 | SHOULD | DoS-threat deployments SHOULD implement pre-verification | HIGH | PENDING | T-R2-043 |
| R2-044 | 5.8 | MAY | Private networks MAY omit DoS pre-verification | LOW | N/A | — |
| R2-045 | 5.8 | MAY | AAFP v1 conforming implementations not required to implement DoS profile | LOW | N/A | — |
| R2-046 | 5.8 | SHOULD | Internet-facing deployments SHOULD enable DoS profile | HIGH | PENDING | T-R2-046 |
| R2-047 | 5.8 | MUST | Server requiring DoS profile + client didn't propose → error 2005 | CRITICAL | PENDING | T-R2-047 |
| R2-048 | 5.8 | MAY | receiver_mac MAY be null if DoS profile not active | LOW | N/A | — |
| R2-049 | 5.9 | MUST | Handshake failure → MUST send ERROR frame + close | CRITICAL | PENDING | T-R2-049 |
| R2-050 | 6.1 | MUST | Unknown critical extensions MUST cause frame rejection | CRITICAL | PENDING | T-R2-050 |
| R2-051 | 6.1 | MUST | Unknown non-critical extensions MUST be skipped | CRITICAL | PENDING | T-R2-051 |
| R2-052 | 6.1 | MUST | Extension reserved field MUST be 0 | CRITICAL | PENDING | T-R2-052 |
| R2-053 | 6.1 | MUST | Extension reserved field MUST be ignored by receivers | CRITICAL | PENDING | T-R2-053 |
| R2-054 | 6.1 | MUST | Total extension size MUST equal Extension Length field | CRITICAL | PENDING | T-R2-054 |
| R2-055 | 6.2 | MAY | Extensions MAY appear in any order | LOW | N/A | — |
| R2-056 | 6.2 | MUST NOT | MUST NOT assume specific extension ordering | CRITICAL | PENDING | T-R2-056 |
| R2-057 | 6.2 | MUST | Duplicate extension type: first one MUST be used | CRITICAL | PENDING | T-R2-057 |
| R2-058 | 6.2 | MUST | Subsequent duplicates MUST be ignored (or rejected if critical) | CRITICAL | PENDING | T-R2-058 |
| R2-059 | 6.3 | MUST | Unrecognized mandatory extension → frame MUST be rejected | CRITICAL | PENDING | T-R2-059 |
| R2-060 | 6.4 | MUST | Server not accepting critical extension → handshake MUST fail with 2005 | CRITICAL | PENDING | T-R2-060 |
| R2-061 | 6.4 | MAY | Optional extension (critical=false) MAY be silently dropped | LOW | N/A | — |
| R2-062 | 6.4 | MUST | ServerHello.extensions MUST be subset of client's proposals | CRITICAL | PENDING | T-R2-062 |
| R2-063 | 6.4 | MUST NOT | Server MUST NOT include extensions client didn't propose | CRITICAL | PENDING | T-R2-063 |
| R2-064 | 6.4 | MAY | Server's extension parameters MAY differ from client's | LOW | N/A | — |
| R2-065 | 6.4 | MUST | Critical extension not accepted → MUST send error 2005 | CRITICAL | PENDING | T-R2-065 |
| R2-066 | 6.4 | MAY | Non-critical extension MAY be silently dropped | LOW | N/A | — |
| R2-067 | 6.4 | MUST | Non-negotiated extension in subsequent frame → error 8007 | CRITICAL | PENDING | T-R2-067 |
| R2-068 | 6.4 | MAY | Handshake extension MAY correspond to frame extension type | LOW | N/A | — |
| R2-069 | 7.3 | SHOULD | SHOULD rely on QUIC's built-in flow control | HIGH | PENDING | T-R2-069 |
| R2-070 | 8.1 | MUST | CBOR MUST use length-first core deterministic encoding (RFC 8949 §4.2.3) | CRITICAL | PENDING | T-R2-070 |
| R2-071 | 8.1 | MUST NOT | Indefinite-length arrays and maps MUST NOT be used | CRITICAL | PENDING | T-R2-071 |
| R2-072 | 8.1 | MUST | All CBOR maps MUST use integer keys (exception: metadata map) | CRITICAL | PENDING | T-R2-072 |
| R2-073 | 8.3 | MAY | New fields MAY be added to maps | LOW | N/A | — |
| R2-074 | 8.3 | MUST | MUST ignore unknown fields unless marked critical | CRITICAL | PENDING | T-R2-074 |
| R2-075 | 8.3 | MUST NOT | Fields MUST NOT be removed | CRITICAL | PENDING | T-R2-075 |
| R2-076 | 8.3 | MUST | Deprecated fields MUST be retained with original semantics | CRITICAL | PENDING | T-R2-076 |
| R2-077 | 8.3 | MUST NOT | Field types MUST NOT change | CRITICAL | PENDING | T-R2-077 |
| R2-078 | 8.3 | MUST | uint in v1 MUST remain uint in all future versions | CRITICAL | PENDING | T-R2-078 |
| R2-079 | 9.1 | MUST NOT | MUST NOT rely on AAFP-level encryption; QUIC provides transport encryption | CRITICAL | PENDING | T-R2-079 |
| R2-080 | 9.2 | MUST | MUST process critical extensions before payload | CRITICAL | PENDING | T-R2-080 |
| R2-081 | 9.2 | MAY | Non-critical extensions MAY be processed after payload | LOW | N/A | — |
| R2-082 | 9.3 | SHOULD | SHOULD enforce max concurrent streams per connection | HIGH | PENDING | T-R2-082 |
| R2-083 | 9.3 | SHOULD | SHOULD enforce rate limit on PING frames | HIGH | PENDING | T-R2-083 |
| R2-084 | 9.3 | SHOULD | SHOULD close connections sending malformed frames at high rate | HIGH | PENDING | T-R2-084 |

### RFC-0003: Identity & Authentication

| Req ID | Section | Keyword | Requirement | Priority | Impl Status | Test ID |
|--------|---------|---------|-------------|----------|-------------|---------|
| R3-001 | 2.1 | MUST | MUST verify AgentId == SHA-256(public_key) during handshake | CRITICAL | PENDING | T-R3-001 |
| R3-002 | 2.1 | MUST | If verification fails, MUST reject with error 2007 | CRITICAL | PENDING | T-R3-002 |
| R3-003 | 2.1 | MUST | If ML-DSA-65 signature fails, MUST reject with error 2001 | CRITICAL | PENDING | T-R3-003 |
| R3-004 | 2.3 | MUST | v1 implementations MUST support ML-DSA-65 (algorithm 1) | CRITICAL | PENDING | T-R3-004 |
| R3-005 | 2.3 | MAY | MAY support additional algorithms | LOW | N/A | — |
| R3-006 | 2.4 | MUST | MUST use cryptographically secure RNG for key generation | CRITICAL | PENDING | T-R3-006 |
| R3-007 | 2.4 | SHOULD | SHOULD use hedged signing with fresh randomness | HIGH | PENDING | T-R3-007 |
| R3-008 | 2.4 | MAY | MAY use deterministic signing for testing | LOW | N/A | — |
| R3-009 | 2.5 | MAY | Agents MAY rotate their ML-DSA-65 key pair | LOW | N/A | — |
| R3-010 | 2.5 | MUST | Agents maintaining identity across rotation MUST use out-of-band mechanism | CRITICAL | PENDING | T-R3-010 |
| R3-011 | 2.6 | SHOULD | SHOULD display AgentIds in fingerprint format | HIGH | PENDING | T-R3-011 |
| R3-012 | 2.6 | MUST | MUST display AgentId fingerprint on new agent connection | CRITICAL | PENDING | T-R3-012 |
| R3-013 | 2.6 | MUST | MUST provide API to retrieve and compare fingerprints | CRITICAL | PENDING | T-R3-013 |
| R3-014 | 2.6 | MUST | Fingerprint display MUST occur before sensitive data exchange | CRITICAL | PENDING | T-R3-014 |
| R3-015 | 2.6 | MAY | Applications MAY override if they do their own verification | LOW | N/A | — |
| R3-016 | 3.3 | MUST | record_type MUST be "aafp-record-v1" | CRITICAL | PENDING | T-R3-016 |
| R3-017 | 3.5 | MUST | Future contexts MUST define domain separators per pattern | CRITICAL | PENDING | T-R3-017 |
| R3-018 | 3.6 | MUST | Verify agent_id == SHA-256(public_key), else error 2007 | CRITICAL | PENDING | T-R3-018 |
| R3-019 | 3.6 | MUST | Verify ML-DSA-65 signature in field 8 | CRITICAL | PENDING | T-R3-019 |
| R3-020 | 3.6 | MUST | If signature fails, reject with error 2001 | CRITICAL | PENDING | T-R3-020 |
| R3-021 | 3.6 | MUST | Check expires_at > current_time, else error 2002 | CRITICAL | PENDING | T-R3-021 |
| R3-022 | 3.6 | MUST | Check record_type == "aafp-record-v1" | CRITICAL | PENDING | T-R3-022 |
| R3-023 | 3.6 | MUST | Check key_algorithm is supported, else error 2010 | CRITICAL | PENDING | T-R3-023 |
| R3-024 | 3.7 | MAY | Future versions MAY add fields with keys >= 10 | LOW | N/A | — |
| R3-025 | 3.7 | MUST | MUST ignore unknown fields | CRITICAL | PENDING | T-R3-025 |
| R3-026 | 3.7 | MUST | MUST NOT reject record solely for unknown fields | CRITICAL | PENDING | T-R3-026 |
| R3-027 | 3.7 | MUST NOT | Field types for existing keys MUST NOT change between versions | CRITICAL | PENDING | T-R3-027 |
| R3-028 | 4.7 | SHOULD | SHOULD use lowercase ASCII names with - separators | HIGH | PENDING | T-R3-028 |
| R3-029 | 4.7 | MAY | Well-known capability names registry MAY be established | LOW | N/A | — |
| R3-030 | 4.8 | MAY | CapabilityDescriptor MAY add fields with keys >= 3 | LOW | N/A | — |
| R3-031 | 4.8 | MAY | MetadataValue enum MAY add new variants | LOW | N/A | — |
| R3-032 | 4.8 | MUST | MUST ignore unknown fields in CapabilityDescriptor | CRITICAL | PENDING | T-R3-032 |
| R3-033 | 4.8 | MUST | MUST handle unknown MetadataValue variants by skipping entry | CRITICAL | PENDING | T-R3-033 |
| R3-034 | 5.6 | MAY | MAY support multiple AuthorizationProvider implementations | LOW | N/A | — |
| R3-035 | 6.3 | MUST | MUST use exact Session ID derivation from RFC-0002 §5.7 | CRITICAL | PENDING | T-R3-035 |
| R3-036 | 6.5 | MAY | MAY enforce session timeouts based on inactivity | LOW | N/A | — |
| R3-037 | 6.5 | MAY | PING/PONG MAY be used for keepalive | LOW | N/A | — |
| R3-038 | 7.2 | MUST | Client MUST verify server_agent_id == SHA-256(server_public_key) | CRITICAL | PENDING | T-R3-038 |
| R3-039 | 7.2 | MUST | Client MUST verify server_signature, else error 2001 | CRITICAL | PENDING | T-R3-039 |
| R3-040 | 7.2 | MUST | Client MUST verify server_expires_at > current_time | CRITICAL | PENDING | T-R3-040 |
| R3-041 | 7.2 | SHOULD | SHOULD use earlier expiry if handshake and AgentRecord differ | HIGH | PENDING | T-R3-041 |
| R3-042 | 7.2 | MUST | Client MUST verify server_key_algorithm supported, else 2010 | CRITICAL | PENDING | T-R3-042 |
| R3-043 | 7.2 | MUST | Client MUST verify protocol_version supported, else 2004 | CRITICAL | PENDING | T-R3-043 |
| R3-044 | 7.2 | MUST | Client MUST verify session_id present and correctly derived | CRITICAL | PENDING | T-R3-044 |
| R3-045 | 7.2 | MUST | Server MUST verify client_agent_id == SHA-256(client_public_key) | CRITICAL | PENDING | T-R3-045 |
| R3-046 | 7.2 | MUST | Server MUST verify client_signature, else error 2001 | CRITICAL | PENDING | T-R3-046 |
| R3-047 | 7.2 | MUST | Server MUST verify client_expires_at > current_time | CRITICAL | PENDING | T-R3-047 |
| R3-048 | 7.2 | SHOULD | Server SHOULD use earlier expiry if handshake and AgentRecord differ | HIGH | PENDING | T-R3-048 |
| R3-049 | 7.2 | MUST | Server MUST verify client_key_algorithm supported, else 2010 | CRITICAL | PENDING | T-R3-049 |
| R3-050 | 7.2 | MUST | Server MUST verify protocol_version supported, else 2004 | CRITICAL | PENDING | T-R3-050 |
| R3-051 | 7.2 | MUST | Server MUST verify ClientFinished signature, else 2001 | CRITICAL | PENDING | T-R3-051 |
| R3-052 | 7.2 | MUST | Server MUST verify session_id matches ServerHello | CRITICAL | PENDING | T-R3-052 |
| R3-053 | 7.3 | MAY | Authorization tokens MAY be exchanged during handshake | LOW | N/A | — |
| R3-054 | 7.3 | MAY | Subsequent operations MAY check authorization | LOW | N/A | — |
| R3-055 | 8.3 | SHOULD | SHOULD provide mechanism for out-of-band identity verification | HIGH | PENDING | T-R3-055 |
| R3-056 | 8.4 | MUST | Compromised agents MUST generate new ML-DSA-65 key pair | CRITICAL | PENDING | T-R3-056 |
| R3-057 | 8.4 | MUST | Compromised agents MUST publish new AgentRecord | CRITICAL | PENDING | T-R3-057 |
| R3-058 | 8.4 | MUST | Compromised agents MUST notify peers out-of-band | CRITICAL | PENDING | T-R3-058 |
| R3-059 | 8.4 | MUST | Compromised agents MUST revoke UCAN tokens | CRITICAL | PENDING | T-R3-059 |
| R3-060 | 8.4 | MUST | MUST support AgentRecord expiry no longer than 30 days | CRITICAL | PENDING | T-R3-060 |
| R3-061 | 8.4 | MUST | MUST warn users if expires_at exceeds 30 days | CRITICAL | PENDING | T-R3-061 |
| R3-062 | 8.4 | SHOULD | SHOULD renew AgentRecords every 7 days | HIGH | PENDING | T-R3-062 |
| R3-063 | 8.4 | SHOULD | SHOULD implement out-of-band revocation checking | HIGH | PENDING | T-R3-063 |
| R3-064 | 8.5 | MUST | MUST enforce max UCAN delegation chain depth of 8 | CRITICAL | PENDING | T-R3-064 |
| R3-065 | 8.5 | MUST | Tokens exceeding depth 8 MUST be rejected with error 3006 | CRITICAL | PENDING | T-R3-065 |
| R3-066 | 8.5 | SHOULD | SHOULD use short UCAN expiry times (RECOMMENDED: 1 hour) | HIGH | PENDING | T-R3-066 |
| R3-067 | 8.6 | MUST | Key pairs MUST be generated per FIPS 204 | CRITICAL | PENDING | T-R3-067 |
| R3-068 | 8.6 | MUST | MUST use cryptographically secure RNG | CRITICAL | PENDING | T-R3-068 |
| R3-069 | 8.6 | SHOULD | SHOULD use hedged signing per FIPS 204 | HIGH | PENDING | T-R3-069 |
| R3-070 | 8.6 | MUST | MUST protect secret keys at rest using encryption | CRITICAL | PENDING | T-R3-070 |
| R3-071 | 8.6 | SHOULD | SHOULD use hardware-backed key storage when available | HIGH | PENDING | T-R3-071 |
| R3-072 | 8.6 | MUST NOT | Secret keys MUST NOT be logged, transmitted in plaintext, or world-readable | CRITICAL | PENDING | T-R3-072 |
| R3-073 | 8.6 | MUST | MUST zeroize secret key material from memory when no longer needed | CRITICAL | PENDING | T-R3-073 |
| R3-074 | 8.6 | SHOULD | SHOULD generate new key before retiring old key | HIGH | PENDING | T-R3-074 |
| R3-075 | 8.6 | SHOULD | SHOULD publish new AgentRecord before notifying peers | HIGH | PENDING | T-R3-075 |
| R3-076 | 8.6 | SHOULD | SHOULD notify peers out-of-band of new AgentId | HIGH | PENDING | T-R3-076 |
| R3-077 | 8.6 | SHOULD | SHOULD maintain old key until all peers migrated | HIGH | PENDING | T-R3-077 |
| R3-078 | 8.6 | SHOULD | SHOULD provide mechanisms to detect key compromise | HIGH | PENDING | T-R3-078 |

### RFC-0004: Discovery

| Req ID | Section | Keyword | Requirement | Priority | Impl Status | Test ID |
|--------|---------|---------|-------------|----------|-------------|---------|
| R4-001 | 3.1 | MUST | MUST support configuring multiple bootstrap nodes | CRITICAL | PENDING | T-R4-001 |
| R4-002 | 3.1 | SHOULD | SHOULD use at least 3 bootstrap nodes from different domains | HIGH | PENDING | T-R4-002 |
| R4-003 | 3.4 | MUST | Bootstrap nodes MUST accept incoming connections | CRITICAL | PENDING | T-R4-003 |
| R4-004 | 3.4 | MUST | MUST store AgentRecords received via announce | CRITICAL | PENDING | T-R4-004 |
| R4-005 | 3.4 | MUST | MUST respond to lookup requests with matching records | CRITICAL | PENDING | T-R4-005 |
| R4-006 | 3.4 | SHOULD | SHOULD evict expired records | HIGH | PENDING | T-R4-006 |
| R4-007 | 3.4 | SHOULD | SHOULD limit records stored (RECOMMENDED: 100K) | HIGH | PENDING | T-R4-007 |
| R4-008 | 3.4 | MUST | MUST rate-limit discovery requests per connection | CRITICAL | PENDING | T-R4-008 |
| R4-009 | 3.4 | MUST | MUST verify requester's AgentRecord signature before lookup | CRITICAL | PENDING | T-R4-009 |
| R4-010 | 3.4 | MUST | Invalid/expired AgentRecord → reject with 4003 or 4004 | CRITICAL | PENDING | T-R4-010 |
| R4-011 | 3.4 | MAY | MAY reject requests from agents that haven't announced | LOW | N/A | — |
| R4-012 | 3.4 | MAY | MAY rate-limit at IP level | LOW | N/A | — |
| R4-013 | 3.4 | MUST | MUST limit lookup to 5 records for unauthenticated | CRITICAL | PENDING | T-R4-013 |
| R4-014 | 3.4 | MAY | Authenticated lookup MAY receive up to 10 records | LOW | N/A | — |
| R4-015 | 3.4 | SHOULD | SHOULD enforce max concurrent streams per connection | HIGH | PENDING | T-R4-015 |
| R4-016 | 4.3 | MUST | New record MUST have created_at >= existing record's created_at | CRITICAL | PENDING | T-R4-016 |
| R4-017 | 4.4 | SHOULD | DHT SHOULD periodically evict expired records | HIGH | PENDING | T-R4-017 |
| R4-018 | 5.2 | MAY | Future versions MAY add regions | LOW | N/A | — |
| R4-019 | 5.3 | MAY | MAY use latency probes or IP geolocation | LOW | N/A | — |
| R4-020 | 5.4 | MAY | MAY use measured latency instead of static matrix | LOW | N/A | — |
| R4-021 | 6.3 | SHOULD | SHOULD perform PEX with newly connected peers | HIGH | PENDING | T-R4-021 |
| R4-022 | 6.3 | SHOULD NOT | SHOULD NOT send more than 50 records per PEX response | HIGH | PENDING | T-R4-022 |
| R4-023 | 6.3 | SHOULD NOT | SHOULD NOT perform PEX more than once per minute per peer | HIGH | PENDING | T-R4-023 |
| R4-024 | 6.3 | MUST NOT | MUST NOT advertise peers with expired AgentRecords | CRITICAL | PENDING | T-R4-024 |
| R4-025 | 6.3 | MAY | MAY filter PEX responses by region or capability | LOW | N/A | — |
| R4-026 | 7.2 | MAY | MAY support filtering by metadata fields | LOW | N/A | — |
| R4-027 | 8.1 | MUST | All AgentRecords in DHT MUST be self-signed | CRITICAL | PENDING | T-R4-027 |
| R4-028 | 8.1 | MUST | MUST verify signatures before storing or returning records | CRITICAL | PENDING | T-R4-028 |
| R4-029 | 8.1 | MUST | Records with invalid signatures MUST be rejected | CRITICAL | PENDING | T-R4-029 |
| R4-030 | 8.2 | MUST NOT | MUST NOT serve expired records | CRITICAL | PENDING | T-R4-030 |
| R4-031 | 8.2 | MUST | Expired records MUST be evicted from DHT | CRITICAL | PENDING | T-R4-031 |
| R4-032 | 8.3 | MAY | MAY introduce proof-of-work | LOW | N/A | — |
| R4-033 | 8.3 | MAY | MAY introduce reputation systems | LOW | N/A | — |
| R4-034 | 8.3 | MAY | MAY introduce trusted issuer requirements | LOW | N/A | — |
| R4-035 | 8.4 | MUST | MUST support configuring multiple bootstrap nodes | CRITICAL | PENDING | T-R4-035 |
| R4-036 | 8.4 | SHOULD | SHOULD use at least 3 bootstrap nodes from different domains | HIGH | PENDING | T-R4-036 |
| R4-037 | 8.4 | SHOULD | SHOULD use PEX with multiple peers to cross-check | HIGH | PENDING | T-R4-037 |
| R4-038 | 8.4 | SHOULD | Bootstrap nodes SHOULD rate-limit requests | HIGH | PENDING | T-R4-038 |
| R4-039 | 8.5 | SHOULD NOT | Private agents SHOULD NOT advertise in DHT | HIGH | PENDING | T-R4-039 |
| R4-040 | 8.5 | SHOULD | Private agents SHOULD connect only to known peers | HIGH | PENDING | T-R4-040 |
| R4-041 | 8.5 | MAY | MAY support private AgentRecords | LOW | N/A | — |
| R4-042 | 8.5 | MAY | MAY support relay-based discovery | LOW | N/A | — |

### RFC-0005: Error Model

| Req ID | Section | Keyword | Requirement | Priority | Impl Status | Test ID |
|--------|---------|---------|-------------|----------|-------------|---------|
| R5-001 | 2.1 | MUST NOT | Error code meaning MUST NOT change once assigned | CRITICAL | PENDING | T-R5-001 |
| R5-002 | 1.2 | MUST | Programmatic decisions MUST be based on error codes, not messages | CRITICAL | PENDING | T-R5-002 |
| R5-003 | 4.2 | MUST NOT | Human-readable message MUST NOT be used for programmatic decisions | CRITICAL | PENDING | T-R5-003 |
| R5-004 | 4.2 | MUST | If fatal=true, receiver MUST close connection | CRITICAL | PENDING | T-R5-004 |
| R5-005 | 4.3 | MUST | Fatal errors: MUST process error, send CLOSE, close QUIC | CRITICAL | PENDING | T-R5-005 |
| R5-006 | 4.3 | MAY | Non-fatal: MAY process error, close stream, continue | LOW | N/A | — |
| R5-007 | 4.4 | MUST | All 2xxx Authentication errors are ALWAYS fatal | CRITICAL | PENDING | T-R5-007 |
| R5-008 | 4.4 | MUST | 8004 UNKNOWN_CRITICAL_FRAME_TYPE is ALWAYS fatal | CRITICAL | PENDING | T-R5-008 |
| R5-009 | 4.4 | MUST | 8005 UNKNOWN_CRITICAL_EXTENSION is ALWAYS fatal | CRITICAL | PENDING | T-R5-009 |
| R5-010 | 4.4 | MUST | 8006 INVALID_VERSION is ALWAYS fatal | CRITICAL | PENDING | T-R5-010 |
| R5-011 | 4.4 | MUST | 8009 PROTOCOL_VIOLATION is ALWAYS fatal | CRITICAL | PENDING | T-R5-011 |
| R5-012 | 4.4 | MAY | MAY set fatal for 8001 if protocol violation | LOW | N/A | — |
| R5-013 | 4.4 | MAY | MAY set fatal for any code if unrecoverable | LOW | N/A | — |
| R5-014 | 5.1 | MUST | Unknown category → treat as 8009 | CRITICAL | PENDING | T-R5-014 |
| R5-015 | 5.1 | MUST | MUST honor fatal flag regardless of code recognition | CRITICAL | PENDING | T-R5-015 |
| R5-016 | 5.2 | SHOULD | Errors SHOULD be propagated to application layer | HIGH | PENDING | T-R5-016 |
| R5-017 | 5.2 | SHOULD NOT | SHOULD NOT silently swallow errors | HIGH | PENDING | T-R5-017 |
| R5-018 | 5.3 | MUST NOT | Error processing ERROR frame → MUST NOT send ERROR frame | CRITICAL | PENDING | T-R5-018 |
| R5-019 | 5.3 | MUST | Error processing ERROR frame → MUST close with CLOSE frame | CRITICAL | PENDING | T-R5-019 |
| R5-020 | 5.4 | SHOULD | SHOULD log errors with code, message, connection ID, stream ID, timestamp | HIGH | PENDING | T-R5-020 |
| R5-021 | 5.4 | MUST NOT | MUST NOT log sensitive data in error messages | CRITICAL | PENDING | T-R5-021 |
| R5-022 | 6.2 | MUST NOT | RPC methods MUST NOT return 2xxx errors in RPC responses | CRITICAL | PENDING | T-R5-022 |
| R5-023 | 6.2 | MUST NOT | RPC methods MUST NOT return 8xxx errors in RPC responses | CRITICAL | PENDING | T-R5-023 |
| R5-024 | 6.2 | MUST | 2xxx and 8xxx errors MUST be sent as ERROR frames | CRITICAL | PENDING | T-R5-024 |
| R5-025 | 8.1 | MUST | MUST define ProtocolError type mapping to on-wire codes | CRITICAL | PENDING | T-R5-025 |
| R5-026 | 8.2 | SHOULD | SHOULD provide enum for error categories | HIGH | PENDING | T-R5-026 |
| R5-027 | 8.3 | SHOULD | SHOULD provide conversions from internal errors to ProtocolError | HIGH | PENDING | T-R5-027 |
| R5-028 | 8.3 | MUST | Internal errors without protocol code → map to category generic | CRITICAL | PENDING | T-R5-028 |
| R5-029 | 9.1 | MUST NOT | MUST NOT disclose private/secret/session keys in errors | CRITICAL | PENDING | T-R5-029 |
| R5-030 | 9.1 | MUST NOT | MUST NOT disclose memory addresses or pointers | CRITICAL | PENDING | T-R5-030 |
| R5-031 | 9.1 | MUST NOT | MUST NOT disclose stack traces in production | CRITICAL | PENDING | T-R5-031 |
| R5-032 | 9.1 | MUST NOT | MUST NOT disclose authorization tokens or credentials | CRITICAL | PENDING | T-R5-032 |
| R5-033 | 9.1 | SHOULD | SHOULD provide enough info for debugging without compromising security | HIGH | PENDING | T-R5-033 |
| R5-034 | 9.2 | SHOULD | SHOULD use standardized error code names | HIGH | PENDING | T-R5-034 |
| R5-035 | 9.2 | MAY | MAY omit human-readable message in production | LOW | N/A | — |
| R5-036 | 9.3 | SHOULD | SHOULD rate-limit ERROR frame processing | HIGH | PENDING | T-R5-036 |
| R5-037 | 9.3 | MUST NOT | ERROR frame data field MUST NOT exceed 4096 bytes | CRITICAL | PENDING | T-R5-037 |
| R5-038 | 9.3 | MUST | MUST truncate or reject larger data fields | CRITICAL | PENDING | T-R5-038 |

### RFC-0006: Versioning & Compatibility

| Req ID | Section | Keyword | Requirement | Priority | Impl Status | Test ID |
|--------|---------|---------|-------------|----------|-------------|---------|
| R6-001 | 2.1 | MUST NOT | Version 0 implementations MUST NOT claim conformance | CRITICAL | PENDING | T-R6-001 |
| R6-002 | 2.2 | MUST | If ALPN fails, connection MUST be closed | CRITICAL | PENDING | T-R6-002 |
| R6-003 | 2.3 | MUST | MUST be fully compatible with same protocol version | CRITICAL | PENDING | T-R6-003 |
| R6-004 | 2.3 | MUST | Unknown version → MUST send error 8006 + close | CRITICAL | PENDING | T-R6-004 |
| R6-005 | 2.3 | MUST | New receiver MUST process old sender per old version rules | CRITICAL | PENDING | T-R6-005 |
| R6-006 | 2.4 | SHOULD NOT | New implementations SHOULD NOT use deprecated versions | HIGH | PENDING | T-R6-006 |
| R6-007 | 2.4 | MAY | Existing implementations MAY continue using deprecated versions | LOW | N/A | — |
| R6-008 | 2.4 | MAY | ALPN identifiers for retired versions MAY be reassigned | LOW | N/A | — |
| R6-009 | 2.5 | MAY | Clarifications MAY be made without new revision if no normative change | LOW | N/A | — |
| R6-010 | 2.5 | MUST | Normative changes require new revision + RFC_CHANGELOG.md | CRITICAL | PENDING | T-R6-010 |
| R6-011 | 2.5 | MUST | Freeze candidate changes MUST be documented as amendment proposal | CRITICAL | PENDING | T-R6-011 |
| R6-012 | 2.5 | MUST | Freeze candidate changes MUST be reviewed through approval gate | CRITICAL | PENDING | T-R6-012 |
| R6-013 | 3.1 | MUST NOT | Reserved extension types 0xC000-0xFFFF MUST NOT be used | CRITICAL | PENDING | T-R6-013 |
| R6-014 | 3.3 | MUST NOT | MUST NOT rely on experimental extensions for production | CRITICAL | PENDING | T-R6-014 |
| R6-015 | 3.3 | MAY | Experimental types MAY be used for testing | LOW | N/A | — |
| R6-016 | 3.4 | MUST NOT | MUST NOT assume interoperability of private-use extensions | CRITICAL | PENDING | T-R6-016 |
| R6-017 | 4.2 | MUST | Unknown critical frame type → error 8004 + close | CRITICAL | PENDING | T-R6-017 |
| R6-018 | 4.2 | MUST | Unknown non-critical frame type → skip + continue | CRITICAL | PENDING | T-R6-018 |
| R6-019 | 4.2 | MAY | MAY override critical bit default | LOW | N/A | — |
| R6-020 | 5.3 | MUST NOT | Non-negotiated features MUST NOT be used in subsequent frames | CRITICAL | PENDING | T-R6-020 |
| R6-021 | 5.4 | MUST | Reserved flag bits 0x10-0x40 MUST be 0 by senders | CRITICAL | PENDING | T-R6-021 |
| R6-022 | 5.4 | MUST | Reserved flag bits 0x10-0x40 MUST be ignored by receivers | CRITICAL | PENDING | T-R6-022 |
| R6-023 | 6.1 | MUST | MUST handle unknown fields per specified rules | CRITICAL | PENDING | T-R6-023 |
| R6-024 | 6.2 | MUST | Authentication extension critical flag MUST be set | CRITICAL | PENDING | T-R6-024 |
| R6-025 | 6.2 | MUST | Authorization extension critical flag MUST be set | CRITICAL | PENDING | T-R6-025 |
| R6-026 | 6.2 | MUST | Crypto suite extension critical flag MUST be set | CRITICAL | PENDING | T-R6-026 |
| R6-027 | 6.2 | MUST | Unrecognized critical extension → reject with error 8005 | CRITICAL | PENDING | T-R6-027 |
| R6-028 | 6.3 | SHOULD | SHOULD use lenient parsing for metadata/extension fields | HIGH | PENDING | T-R6-028 |
| R6-029 | 6.3 | SHOULD | SHOULD use strict parsing for security-critical fields | HIGH | PENDING | T-R6-029 |
| R6-030 | 7.3 | MUST | Mandatory extensions MUST be implemented by all conforming implementations | CRITICAL | PENDING | T-R6-030 |
| R6-031 | 7.3 | MUST NOT | Non-conforming implementations MUST negotiate lower version or fail | CRITICAL | PENDING | T-R6-031 |
| R6-032 | 7.4 | MUST | New version implementations MUST NOT send deprecated feature | CRITICAL | PENDING | T-R6-032 |
| R6-033 | 7.4 | MAY | MAY accept deprecated feature for backward compatibility | LOW | N/A | — |
| R6-034 | 7.4 | MUST NOT | Deprecated features MUST NOT be removed within same major version | CRITICAL | PENDING | T-R6-034 |
| R6-035 | 8.1 | MUST | MUST use QUIC version 1 as transport | CRITICAL | PENDING | T-R6-035 |
| R6-036 | 8.1 | MUST | MUST negotiate ALPN aafp/1 during TLS handshake | CRITICAL | PENDING | T-R6-036 |
| R6-037 | 8.1 | MUST | MUST offer X25519MLKEM768 for TLS key exchange | CRITICAL | PENDING | T-R6-037 |
| R6-038 | 8.1 | MUST | MUST use frame format specified in RFC-0002 §3 | CRITICAL | PENDING | T-R6-038 |
| R6-039 | 8.1 | MUST | MUST derive AgentId as SHA-256(public_key) | CRITICAL | PENDING | T-R6-039 |
| R6-040 | 8.1 | MUST | MUST serialize AgentRecord as CBOR per RFC-0003 §3 | CRITICAL | PENDING | T-R6-040 |
| R6-041 | 8.1 | MUST | MUST use CapabilityDescriptor per RFC-0003 §4 | CRITICAL | PENDING | T-R6-041 |
| R6-042 | 8.1 | MUST | MUST handle unknown fields per §6 of RFC-0006 | CRITICAL | PENDING | T-R6-042 |
| R6-043 | 8.1 | MUST | MUST return protocol errors per RFC-0005 | CRITICAL | PENDING | T-R6-043 |
| R6-044 | 8.1 | MUST | MUST support all frame types in §4.1 of RFC-0002 | CRITICAL | PENDING | T-R6-044 |
| R6-045 | 8.1 | MUST | MUST support PING/PONG keepalive mechanism | CRITICAL | PENDING | T-R6-045 |
| R6-046 | 8.1 | MUST | MUST support CLOSE frame for connection termination | CRITICAL | PENDING | T-R6-046 |
| R6-047 | 8.1 | MUST | MUST compute TLS channel binding + include in transcript hash | CRITICAL | PENDING | T-R6-047 |
| R6-048 | 8.1 | MUST | MUST use domain separators in all signature computations | CRITICAL | PENDING | T-R6-048 |
| R6-049 | 8.1 | MUST | MUST include key_algorithm in ClientHello, ServerHello, AgentRecord | CRITICAL | PENDING | T-R6-049 |
| R6-050 | 8.1 | MUST | MUST support ML-DSA-65 (algorithm 1) | CRITICAL | PENDING | T-R6-050 |
| R6-051 | 8.1 | MUST | MUST include expires_at in ClientHello and ServerHello | CRITICAL | PENDING | T-R6-051 |
| R6-052 | 8.1 | MUST | MUST use integer keys for all CBOR structures | CRITICAL | PENDING | T-R6-052 |
| R6-053 | 8.1 | MUST | MUST compute Session ID using normative HKDF derivation | CRITICAL | PENDING | T-R6-053 |
| R6-054 | 8.1 | MUST | MUST use handshake extension negotiation protocol | CRITICAL | PENDING | T-R6-054 |
| R6-055 | 9.1 | MUST NOT | MUST NOT fall back to lower version if requested not supported | CRITICAL | PENDING | T-R6-055 |
| R6-056 | 9.1 | MUST | If no common version, connection MUST fail | CRITICAL | PENDING | T-R6-056 |
| R6-057 | 9.2 | MUST | Critical extensions MUST be understood by receiver | CRITICAL | PENDING | T-R6-057 |
| R6-058 | 9.2 | MAY | Non-critical extensions MAY be skipped | LOW | N/A | — |
| R6-059 | 9.3 | MUST | Reserved fields MUST be 0 by senders | CRITICAL | PENDING | T-R6-059 |
| R6-060 | 9.3 | MAY | Receivers MAY log non-zero reserved fields as warning | LOW | N/A | — |
| R6-061 | 9.3 | MUST NOT | Receivers MUST NOT fail connection for non-zero reserved fields | CRITICAL | PENDING | T-R6-061 |
| R6-062 | 11.2 | MUST | Changes to Stable/Freeze Candidate MUST follow amendment process | CRITICAL | PENDING | T-R6-062 |
| R6-063 | 11.4 | MUST | Same major version MUST be wire-compatible | CRITICAL | PENDING | T-R6-063 |
| R6-064 | 11.4 | MUST | Changes within major version MUST be backward compatible | CRITICAL | PENDING | T-R6-064 |
| R6-065 | 11.4 | MUST | New extensions MUST NOT break implementations that don't support them | CRITICAL | PENDING | T-R6-065 |
| R6-066 | 11.4 | SHOULD | Migration paths for cross major version SHOULD be documented | HIGH | PENDING | T-R6-066 |
| R6-067 | 11.5 | SHALL | Conformance test suite SHALL be maintained | CRITICAL | PENDING | T-R6-067 |
| R6-068 | 11.5 | MUST | Conformance test suite MUST be used to validate conformance claims | CRITICAL | PENDING | T-R6-068 |

## Implementation Phase Mapping

| Phase | Requirements | Description |
|-------|-------------|-------------|
| Framing | R2-014 through R2-036, R2-050 through R2-068, R6-017 through R6-022 | Frame header, types, extensions, flags |
| Handshake | R2-001 through R2-013, R2-037 through R2-049, R3-001 through R3-052 | TLS, channel binding, transcript, signatures, session ID |
| Identity | R3-001 through R3-078, R6-039 through R6-054 | AgentId, AgentRecord, UCAN, fingerprints, key management |
| Discovery | R4-001 through R4-042 | Bootstrap, DHT, PEX, rate limiting |
| Messaging | R2-022 through R2-033, R5-001 through R5-038 | RPC, error handling, PING/PONG, CLOSE |
| Conformance | R1-001 through R1-005, R6-001 through R6-068 | Version negotiation, conformance checklist |
