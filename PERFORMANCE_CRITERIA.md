# Performance Validation Success Criteria

**Date**: 2025-06-25
**Status**: Draft
**Purpose**: Define measurable success criteria for Phase 2 performance validation before benchmarking begins. Per user guidance: "define success criteria before running benchmarks."

## Methodology

Performance will be measured against two reference points:
1. **libp2p over QUIC**: The closest comparable protocol (P2P, QUIC transport, identity layer)
2. **WireGuard over QUIC**: For handshake size and latency comparison (simpler protocol, no PQ)

The objective is NOT to match WireGuard's handshake size (AAFP includes richer identity and post-quantum primitives). The objective is to evaluate whether the additional functionality and cryptography deliver acceptable overhead for the intended use case (agent-to-agent communication).

## Success Criteria

### 1. Handshake Performance

| Metric | Target | Rationale | Reference |
|--------|--------|-----------|-----------|
| Successful handshake completion rate | > 99% under normal conditions | Protocol must be reliable | — |
| Time to first authenticated application message | < 500ms (localhost) | Includes TLS + AAFP handshake | libp2p: ~200-400ms |
| Handshake round trips | 1.5 RTT (ClientHello + ServerHello + ClientFinished) | Per RFC-0002 §5.2 | TLS 1.3: 1 RTT, libp2p: 1-2 RTT |
| Handshake byte size (wire) | < 15 KB | ML-DSA-65 pub key (1952B) + sig (3309B) x2 + overhead | WireGuard: ~148B, libp2p: ~2-4KB |
| CPU time for handshake | < 50ms (single core, modern CPU) | ML-DSA-65 sign + verify x2 + TLS | ML-DSA-65 verify: ~1ms each |

### 2. Throughput

| Metric | Target | Rationale | Reference |
|--------|--------|-----------|-----------|
| Messages per second (small, 1KB) | > 10,000/s | Framing overhead should be minimal | libp2p: ~50K/s |
| Messages per second (large, 100KB) | > 1,000/s | Should be bandwidth-limited, not CPU | — |
| Frames per second (parse/encode) | > 100,000/s | Framing layer must be fast | — |
| Concurrent active sessions | > 1,000 per process | Memory per session must be low | libp2p: ~10K |

### 3. Resource Usage

| Metric | Target | Rationale | Reference |
|--------|--------|-----------|-----------|
| Memory per active session | < 50 KB | Excludes TLS buffers | libp2p: ~20-50KB |
| Memory at startup (no sessions) | < 10 MB | Base footprint | — |
| CPU when idle (100 sessions) | < 1% | Background processing | — |

### 4. Discovery Performance

| Metric | Target | Rationale | Reference |
|--------|--------|-----------|-----------|
| Discovery latency (bootstrap) | < 100ms (localhost) | First peer lookup | libp2p DHT: ~100-500ms |
| AgentRecord publish latency | < 50ms | Announce to bootstrap | — |
| AgentRecord lookup latency | < 50ms | Query by capability | — |
| Bootstrap to first connection | < 200ms | End-to-end | — |

### 5. Resilience

| Metric | Target | Rationale | Reference |
|--------|--------|-----------|-----------|
| Connection setup under 1% packet loss | > 95% success | QUIC handles retransmission | — |
| Connection setup under 5% packet loss | > 80% success | Degrades gracefully | — |
| Handshake timeout | < 10s default | Must not hang indefinitely | — |

### 6. Cryptographic Operations

| Metric | Target | Rationale | Reference |
|--------|--------|-----------|-----------|
| ML-DSA-65 key generation | < 10ms | One-time cost | NIST ref: ~5ms |
| ML-DSA-65 signing | < 5ms | Per handshake | NIST ref: ~1-3ms |
| ML-DSA-65 verification | < 5ms | Per handshake | NIST ref: ~1ms |
| SHA-256 (1KB) | < 1μs | Transcript hash | — |
| HKDF-Extract + Expand | < 1μs | Session ID derivation | — |
| HMAC-SHA256 | < 1μs | DoS MAC | — |
| CBOR encode (ClientHello) | < 100μs | Serialization | — |
| CBOR decode (ClientHello) | < 100μs | Deserialization | — |

## Benchmark Plan

### Environment
- Localhost (no network latency)
- Single machine, modern x86_64 or ARM64
- Release build with LTO
- No other CPU-intensive processes

### Test Vectors
1. **Handshake latency**: 1000 sequential handshakes, measure p50/p95/p99
2. **Handshake throughput**: 100 concurrent handshakes, measure completion time
3. **Message throughput**: 100K messages of varying sizes (64B, 1KB, 100KB, 1MB)
4. **Frame parse/encode**: 1M frame parse+encode cycles
5. **Session memory**: Measure memory with 0, 10, 100, 1000 sessions
6. **Discovery**: 100 announce+lookup cycles
7. **Packet loss**: Simulated via `tc netem` (Linux) or `Network Link Conditioner` (macOS)

### Comparison Baselines
1. **libp2p over QUIC**: Same machine, similar handshake flow
2. **Raw QUIC (quinn)**: TLS-only, no application handshake — lower bound
3. **WireGuard**: Handshake size comparison only (different protocol class)

## Acceptance Thresholds

The implementation passes performance validation if:

1. **All CRITICAL criteria met**: Handshake completion > 99%, no crashes, no panics
2. **80% of HIGH criteria met**: Time to first message, throughput, memory targets
3. **50% of MEDIUM criteria met**: Discovery latency, packet loss resilience
4. **Cryptographic operations within 2x of NIST reference implementations**

Failure of a criterion does not block progress but triggers investigation:
- Is the target realistic?
- Is there a specification issue?
- Is there an implementation issue?
- Is there a dependency issue (e.g., pqcrypto-mldsa performance)?

## RFCs as Authoritative Source

Per project guidance: if the implementation suggests a change to the protocol, update the RFC first, then modify the code to match the revised specification. Performance issues that suggest protocol changes (e.g., handshake too large) must be documented as amendment proposals, not silently implemented differently.
