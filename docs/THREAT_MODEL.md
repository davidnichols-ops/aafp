# AAFP Threat Model

**Document version:** 1.0 (Track Q1)
**Date:** 2026-07-04
**Scope:** AAFP Rust implementation — all 17 crates, ~66K lines

This document defines the threat model for the AAFP (Agent-to-Agent
Federated Protocol) implementation. It enumerates the assets we protect,
the attack surfaces an adversary can reach, the trust boundaries that
separate authenticated from unauthenticated code paths, the attackers we
design against, and the specific attacks we mitigate. It is the
foundation for the security audit in Track Q (Q2–Q8).

---

## 1. Assets

| Asset | Description | Compromise impact |
|-------|-------------|-------------------|
| **Agent private keys** | ML-DSA-65 secret keys (4032 bytes). Stored in `AgentKeypair`. | Total identity compromise. Attacker can impersonate the agent, sign handshakes, derive session keys. |
| **Session data** | Session IDs (32 bytes), session keys, negotiated features. | Session hijacking, message decryption, replay within session window. |
| **Message content** | Application data exchanged over QUIC streams after handshake. | Confidentiality/integrity loss of all traffic on the session. |
| **Agent identity** | AgentId (SHA-256 of public key), AgentRecord, trust relationships. | Impersonation, reputation damage, authorization bypass. |
| **Network metadata** | IP addresses, connection timing, stream counts, byte volumes. | Traffic analysis, agent graph mapping, de-anonymization. |
| **Relay reservations** | Reservation slots on relay nodes (NAT traversal). | Resource exhaustion of relay, denial of relay service to legitimate agents. |
| **DHT records** | AgentRecord entries in the capability DHT. | Discovery poisoning, routing attacks, eclipse attacks. |

---

## 2. Attack Surfaces

Each attack surface is a code path that processes data from an
untrusted source. For each, we document the inputs accepted, the
validation performed, what happens on invalid input, and the resources
consumed.

### 2.1 QUIC Listener (`aafp-transport-quic`)

| Property | Detail |
|----------|--------|
| **Inputs** | Raw UDP datagrams on the bind address. QUIC initial packets from any source IP. |
| **Validation** | quinn/rustls validate QUIC packet structure, TLS handshake, ALPN negotiation (`aafp/1`). PQ KEX (X25519MLKEM768) preferred. |
| **On invalid input** | quinn drops malformed packets silently. TLS handshake failures close the connection. ALPN mismatch → connection close. |
| **Resources consumed** | 1 file descriptor per connection, ~50KB memory per connection (quinn buffers), CPU for TLS handshake (PQ KEX ~1ms). |
| **Mitigations** | `max_concurrent_streams` (default 100), `max_idle_timeout` (30s), `crypto_buffer_size` (8KB). **Gap: no max_connections limit — addressed in Q4.** |

### 2.2 TLS Handshake (`aafp-transport-quic` → rustls)

| Property | Detail |
|----------|--------|
| **Inputs** | TLS ClientHello, certificate, key share. |
| **Validation** | rustls validates TLS 1.3 handshake. Self-signed certs accepted (transport encryption only; identity verified at application layer). ALPN must select `aafp/1`. PQ KEX preferred via `prefer-post-quantum` feature. |
| **On invalid input** | TLS alert, connection close. |
| **Resources consumed** | CPU for X25519MLKEM768 key exchange (~1-2ms). Memory for TLS state (~20KB). |
| **Mitigations** | rustls is FIPS-validated (aws-lc-rs). PQ KEX protects against harvest-now-decrypt-later. |

### 2.3 AAFP Handshake (`aafp-crypto/handshake_v1`, `aafp-sdk/handshake_driver`)

| Property | Detail |
|----------|--------|
| **Inputs** | CBOR-encoded ClientHello, ServerHello, ClientFinished on QUIC stream 0 (bidirectional). |
| **Validation** | `verify_client_hello` / `verify_server_hello` / `verify_client_finished`: protocol version check, key algorithm check, AgentId ↔ public_key binding (SHA-256), ML-DSA-65 public key validity, signature verification over transcript hash, expiry check. ReplayCache check-and-insert (nonce uniqueness). |
| **On invalid input** | `HandshakeError` returned, connection closed. No partial state retained. |
| **Resources consumed** | ML-DSA-65 verify: 76–103µs per verification. CBOR decode: ~1µs. ReplayCache lookup: ~100ns. **Gap: no rate limiting on handshake attempts — addressed in Q4.** |
| **Mitigations** | ReplayCache (check-before-verify, insert-after-verify). Transcript hash binds TLS channel. Domain separator `"aafp-v1-handshake"`. |

### 2.4 Frame Parser (`aafp-messaging/framing`)

| Property | Detail |
|----------|--------|
| **Inputs** | 28-byte frame header + extensions + payload on any QUIC stream. |
| **Validation** | Version check (must be 1). Frame type validation (known vs unknown; critical bit check per RFC-0006). Payload length ≤ 1MB (`MAX_PAYLOAD_SIZE`). Extension length ≤ 64KB (`MAX_EXTENSION_SIZE`). Reserved byte must be 0 (MUST be ignored). |
| **On invalid input** | `FrameError` returned. Oversized frames rejected before allocation. |
| **Resources consumed** | Up to 1MB + 64KB per frame allocation. CPU for CBOR decode of payload. |
| **Mitigations** | Size limits enforced before buffer allocation. Unknown frame types with critical bit → reject; without → skip. |

### 2.5 CBOR Decoder (`aafp-cbor`)

| Property | Detail |
|----------|--------|
| **Inputs** | Arbitrary byte sequences. |
| **Validation** | RFC 8949 deterministic decoding. Length-prefix validation. UTF-8 validation for text strings. Depth tracking (max 100 levels). |
| **On invalid input** | `CborError` returned (truncated, invalid type, invalid UTF-8, depth exceeded). |
| **Resources consumed** | Proportional to input length. Bounded by frame size limits (1MB) when called from frame parser. **Unbounded when called directly from fuzz targets — by design.** |
| **Mitigations** | No `unwrap()`/`expect()` in decode path. All array/map sizes validated before allocation. |

### 2.6 RPC Handler (`aafp-messaging/rpc_v1`, `aafp-discovery/rpc_handler`, `aafp-nat/relay_v1`)

| Property | Detail |
|----------|--------|
| **Inputs** | CBOR-encoded `RpcRequest` / `RpcResponse` inside frame payloads. Method name, params. |
| **Validation** | Field type validation (id: uint, method: text, params: any non-null). Method name validation per handler (discovery: `aafp.discovery.*`, relay: `aafp.relay.*`). Params validation per method. |
| **On invalid input** | `RpcError` / `DiscoveryError` / `RelayV1Error` returned. |
| **Resources consumed** | CPU for CBOR decode + handler logic. Memory for params (bounded by frame size). |
| **Mitigations** | Method allowlisting. Rate limiting on discovery (RATE_LIMIT_ANNOUNCE/LOOKUP). **Gap: no rate limiting on relay RPCs — addressed in Q4.** |

### 2.7 Discovery DHT (`aafp-discovery/discovery_v1`, `aafp-discovery/rpc_handler`)

| Property | Detail |
|----------|--------|
| **Inputs** | Announce/Lookup/PEX RPC requests from authenticated peers. |
| **Validation** | AgentRecord validation (signature, expiry, AgentId binding). Rate limiting (RATE_LIMIT_ANNOUNCE: 10/s, RATE_LIMIT_LOOKUP: 50/s). Max records (MAX_RECORDS). |
| **On invalid input** | `DiscoveryError` returned. Invalid records rejected. |
| **Resources consumed** | Memory for DHT records (bounded by MAX_RECORDS). CPU for signature verification. |
| **Mitigations** | Rate limiting. Record count limits. Signature verification on announce. |

### 2.8 Relay Service (`aafp-nat/relay_v1`, `aafp-nat/relay_forwarding`)

| Property | Detail |
|----------|--------|
| **Inputs** | Reserve/Renew/Cancel/Connect RPC requests. Data stream forwarding requests. |
| **Validation** | Reservation limits (DEFAULT_MAX_RESERVATIONS). Duration limits (DEFAULT_MAX_DURATION_SECS). Connection limits (DEFAULT_MAX_CONNECTIONS). |
| **On invalid input** | `RelayV1Error` returned. |
| **Resources consumed** | Memory per reservation (~1KB). Bandwidth for forwarded data. File descriptors for relayed connections. |
| **Mitigations** | Reservation/connection/duration caps. **Gap: no per-IP rate limiting — addressed in Q4.** |

### 2.9 AutoNAT (`aafp-nat/auto_nat_v1`)

| Property | Detail |
|----------|--------|
| **Inputs** | DialBack request/response RPCs. Observe RPC. |
| **Validation** | Confirmation threshold (DEFAULT_CONFIRMATION_THRESHOLD). DialBack timeout (DEFAULT_DIALBACK_TIMEOUT_SECS). |
| **On invalid input** | `AutoNatV1Error` returned. |
| **Resources consumed** | CPU for dial-back connections. Network bandwidth. |
| **Mitigations** | Timeout enforcement. Confirmation threshold prevents false-positive NAT detection. |

### 2.10 DCuTR (`aafp-nat/dcutr_v1`)

| Property | Detail |
|----------|--------|
| **Inputs** | Coordinate messages (CBOR) over relayed connection. Hole-punch SYN packets (UDP). |
| **Validation** | Coordinate message validation. Hole-punch timeout (DEFAULT_HOLE_PUNCH_TIMEOUT_SECS). Sync delay (DEFAULT_SYNC_DELAY_MS). |
| **On invalid input** | `DcutrV1Error` returned. Invalid coordinate messages rejected. |
| **Resources consumed** | CPU for coordination. Network bandwidth for hole-punch attempts. |
| **Mitigations** | Timeout enforcement. Single hole-punch attempt per coordination. |

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  UNAUTHENTICATED (pre-handshake)                                 │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │
│  │ QUIC      │  │ TLS       │  │ Frame     │  │ Handshake │    │
│  │ Listener  │→ │ Handshake │→ │ Parser    │→ │ Verifier  │    │
│  └───────────┘  └───────────┘  └───────────┘  └─────┬─────┘    │
│                                                   │ verify     │
│                                                   │ passes     │
├───────────────────────────────────────────────────┼───────────┤
│  AUTHENTICATED (post-handshake)                    ▼           │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │
│  │ Session   │  │ RPC       │  │ Discovery │  │ Relay     │    │
│  │ Manager   │  │ Handler   │  │ DHT       │  │ Service   │    │
│  └───────────┘  └───────────┘  └─────┬─────┘  └───────────┘    │
│                                     │ authz check              │
├─────────────────────────────────────┼─────────────────────────┤
│  AUTHORIZED (post-authorization)    ▼                           │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐                   │
│  │ App Data  │  │ Capability│  │ Trust     │                   │
│  │ Exchange  │  │ Delegation│  │ Manager   │                   │
│  └───────────┘  └───────────┘  └───────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 Unauthenticated (pre-handshake)

Any network attacker can reach this boundary. Code here processes
untrusted input and must:

- **Never panic** on malformed input (no `unwrap()`/`expect()`).
- **Bound resource consumption** (timeouts, size limits, rate limits).
- **Not leak information** through error messages or timing.
- **Reject early** — validate before allocating, verify signatures last.

Code in this boundary: QUIC listener, TLS handshake, frame parser
(before handshake complete), handshake message parsing/verification,
ReplayCache.

### 3.2 Authenticated (post-handshake)

The peer's identity has been cryptographically verified (AgentId =
SHA-256(public_key), signature valid). The peer is **authenticated but
not necessarily trusted**. Code here must:

- **Enforce authorization** before acting on requests.
- **Rate-limit** per-peer resource consumption.
- **Validate** all RPC params, DHT records, relay requests.

Code in this boundary: Session manager, RPC handler, discovery DHT,
relay service, AutoNAT, DCuTR.

### 3.3 Authorized (post-authorization)

The peer has been authenticated AND authorized for a specific
capability (via UCAN capability chain, trust manager, or custom
AuthorizationProvider). Code here can:

- **Execute** the authorized capability.
- **Delegate** capabilities (if permitted by the chain).
- **Access** application data.

Code in this boundary: Application data exchange, capability
delegation, trust manager operations.

---

## 4. In-Scope Attacks

| Attack | Affected surfaces | Mitigation | Track Q step |
|--------|-------------------|------------|--------------|
| **Man-in-the-middle (MITM)** | TLS handshake, AAFP handshake | TLS channel binding folded into transcript hash. ML-DSA-65 signature over transcript. AgentId ↔ public_key binding. | Q3 |
| **Replay attack** | AAFP handshake | ReplayCache: check-before-verify, insert-after-verify. Nonce uniqueness across connections. | Q3 |
| **Signature forgery** | AAFP handshake | ML-DSA-65 (FIPS 204) signatures. 128-bit classical + PQ security. AgentId binding prevents key substitution. | Q3 |
| **Resource exhaustion (DoS)** | All surfaces | Size limits (1MB frames, 64KB extensions). Timeouts (30s idle). Rate limiting (Q4 adds per-IP handshake rate limit, max_connections). | Q4 |
| **Downgrade attack** | TLS, AAFP handshake | PQ KEX preferred (rustls `prefer-post-quantum`). Protocol version check (must be 1). Key algorithm check (must be ML-DSA-65). | Q3 |
| **Timing side-channel** | Signature verify, AgentId comparison, ReplayCache, CBOR decode | ML-DSA-65 verify is constant-time (aws-lc-rs). AgentId comparison uses constant-time eq (Q5 verifies). ReplayCache HashMap lookup (Q5 verifies). | Q5 |
| **Malformed input** | All parsers | No panics on any input. All `from_cbor`/`decode` return `Result`. Fuzz testing (Q2). | Q2, Q6 |
| **Discovery poisoning** | DHT | Signature verification on AgentRecord. Rate limiting. Max records. | Q2, Q7 |
| **Relay abuse** | Relay service | Reservation/duration/connection limits. | Q4, Q7 |

---

## 5. Out-of-Scope

These attacks are documented but **not mitigated** in this implementation.
They are either the responsibility of the deployment environment or
require capabilities beyond the protocol layer.

| Attack | Why out-of-scope | Recommendation |
|--------|------------------|----------------|
| **Physical access** | OS-level security is the operator's responsibility. | Use full-disk encryption, secure boot, physical access controls. |
| **OS compromise** | If the OS is compromised, private keys in memory are exposed. | Use HSM/TPM for key storage. Run in hardened containers. |
| **Supply chain** | Compromised dependencies (crates, rustc, OS libraries). | Use `cargo audit`, pin dependencies, reproducible builds. AAFP runs `cargo audit` in CI. |
| **Social engineering** | Operator tricked into revealing keys or running malicious code. | Operator training, key management policies. |
| **Quantum signature forgery** | ML-DSA-65 is PQ-resistant, but if broken, all signatures are forgeable. | Monitor NIST/PQC standardization. Support algorithm agility (key_algorithm field). |
| **Global passive adversary with quantum computer** | Harvest-now-decrypt-later on recorded TLS traffic. | PQ KEX (X25519MLKEM768) mitigates this. Already in scope but noted here. |
| **Traffic analysis** | Packet sizes, timing, connection patterns leak metadata. | Padding, dummy traffic, mix networks are future work. Not in v1. |

---

## 6. Attackers

| Attacker | Capabilities | Motivation | Primary defense |
|----------|-------------|------------|-----------------|
| **Passive eavesdropper** | Can read all network traffic. Cannot modify. | Surveillance, metadata collection. | TLS 1.3 encryption with PQ KEX. |
| **Active MITM** | Can read, modify, inject, drop network traffic. | Impersonation, downgrade, replay. | TLS channel binding + ML-DSA-65 signatures + transcript hash. |
| **Malicious peer (authenticated, untrusted)** | Has valid agent identity. Can send any RPC, frame, or handshake. | Resource exhaustion, discovery poisoning, relay abuse. | Authorization, rate limiting, resource caps. |
| **Compromised CA** | Can issue TLS certificates. | TLS MITM (but not AAFP identity forgery). | AAFP identity is independent of TLS PKI. Self-signed TLS certs; identity verified at application layer. |
| **Relay operator** | Can observe and modify relayed traffic. Can drop connections. | Surveillance, censorship. | End-to-end AAFP encryption (TLS + application-layer). Relay sees only encrypted frames. |
| **Botnet (distributed DoS)** | Many source IPs, each sending handshake requests. | CPU exhaustion via ML-DSA-65 verify. | Per-IP rate limiting (Q4). ReplayCache. Proof-of-work (future work). |

---

## 7. Security Properties (Verifiable)

These properties are verified by Track Q tests:

| Property | Verification | Step |
|----------|-------------|------|
| No panics on any input | Fuzz all parsers (CBOR, frame, handshake, RPC, agent record, relay, discovery, DHT) | Q2 |
| Signature forgery rejected | Adversarial handshake test: wrong key → reject | Q3 |
| AgentId forgery rejected | Adversarial handshake test: agent_id ≠ hash(pk) → reject | Q3 |
| Replay rejected | Adversarial handshake test: same nonce twice → reject | Q3 |
| Expired handshake rejected | Adversarial handshake test: expires_at in past → reject | Q3 |
| Version downgrade rejected | Adversarial handshake test: version=0 → reject | Q3 |
| MITM modification rejected | Adversarial handshake test: modified field → sig invalid | Q3 |
| PQ KEX enforced | Adversarial handshake test: classical-only KEX → reject | Q3 |
| Connection flood survived | Resource exhaustion test: 1000 connections, max_connections=100 | Q4 |
| Stream exhaustion survived | Resource exhaustion test: 1000 streams, quinn enforces limit | Q4 |
| Large frame rejected | Resource exhaustion test: 1GB frame header → immediate reject | Q4 |
| Slow loris closed | Resource exhaustion test: 1 byte/s → closed after 30s | Q4 |
| Memory bounded | Resource exhaustion test: many large messages, backpressure | Q4 |
| CPU bounded | Resource exhaustion test: handshake flood, rate limiting 10/s/IP | Q4 |
| Constant-time sig verify | Timing analysis: valid vs invalid sig, no significant difference | Q5 |
| Constant-time AgentId compare | Timing analysis: matching vs non-matching, constant-time eq | Q5 |
| Constant-time ReplayCache | Timing analysis: hit vs miss, no significant difference | Q5 |
| Constant-time CBOR decode | Timing analysis: valid vs invalid, no significant difference | Q5 |
| Malformed CBOR rejected | Malformed input test: empty, deep nesting, u64::MAX, bad UTF-8, indefinite, dup keys, tags | Q6 |
| Malformed frames rejected | Malformed input test: 0 payload, mismatched lengths, bad version/type, truncated | Q6 |
| Malformed handshake rejected | Malformed input test: empty key, wrong-size key, empty sig, null caps | Q6 |
| Malformed RPC rejected | Malformed input test: empty method, evil method, null/empty/1MB params | Q6 |

---

## 8. Cryptographic Primitives

| Primitive | Implementation | Security level | Notes |
|-----------|---------------|----------------|-------|
| **Signature** | ML-DSA-65 (FIPS 204) via `fips204` crate | 128-bit PQ + classical | Constant-time verify (aws-lc-rs). |
| **TLS KEX** | X25519MLKEM768 (hybrid PQ) via rustls `prefer-post-quantum` | 128-bit PQ + classical | Protects against harvest-now-decrypt-later. |
| **Hash** | SHA-256 (`sha2` crate) | 128-bit | Used for AgentId, transcript hash, HKDF. |
| **KDF** | HKDF-SHA-256 (`hkdf` crate) | 128-bit | Session ID derivation, DoS MAC key. |
| **MAC** | HMAC-SHA-256 (`hmac` crate) | 128-bit | DoS receiver MAC. |
| **AEAD** | ChaCha20-Poly1305 / AES-256-GCM | 256-bit | Application-layer encryption (future). TLS provides transport encryption. |
| **Nonce** | 32-byte random (`rand` crate) | 122-bit (birthday bound at 2^61) | Unique per handshake; ReplayCache enforces. |

---

## 9. References

- RFC-0002: AAFP Core Protocol (handshake, framing, session)
- RFC-0003: AAFP Cryptography (ML-DSA-65, domain separators)
- RFC-0006: AAFP Extension Framework (critical bit, version negotiation)
- RFC-0010: AAFP NAT Traversal (relay, AutoNAT, DCuTR)
- FIPS 204: Module-Lattice-Based Digital Signature Standard
- RFC 8949: Concise Binary Object Representation (CBOR)
- OWASP Top 10 (2021): Injection, broken auth, crypto failures, etc.
- QUIC-Fuzz (arxiv 2503.19402): Fuzzing QUIC implementations
