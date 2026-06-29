# RFC-0001: AAFP Protocol Overview

```
Status:         Freeze Candidate (Revision 5)
Number:         0001
Title:          Protocol Overview, Goals, and Layer Architecture
Author:         AAFP Project
Created:        2025-06-25
Revised:        2025-01-15 (Revision 4: no content changes, version bump
                for consistency with RFC-0002 and RFC-0003)
                2025-01-16 (Revision 5: no content changes, version bump
                for consistency with RFC-0003)
Type:           Informational
Obsoletes:      —
Obsoleted by:   —
```

## 1. Introduction

AAFP (Agent-Agent First Networking Protocol) is a post-quantum peer-to-peer
networking protocol designed for autonomous AI agents. It provides identity,
transport, discovery, and messaging primitives that enable agents to discover
each other by capability, authenticate via post-quantum signatures, and
communicate over encrypted QUIC streams.

### 1.1 Motivation

Existing P2P networking stacks (libp2p, Tor, BitTorrent) are designed for
generic peers, not AI agents. They lack:

- **Capability-based discovery**: Agents need to find peers by what they can
  do (e.g., "inference", "translation"), not just by peer ID.
- **Post-quantum identity**: Agent identities should survive the advent of
  quantum computers. Classical signature schemes (Ed25519, RSA) are broken
  by Shor's algorithm.
- **Agent-native authorization**: Agents delegate authority to other agents
  (e.g., "agent A may invoke agent B's inference capability"). This requires
  a capability delegation model, not just TLS certificate verification.
- **QUIC-native transport**: Agents benefit from QUIC's multiplexed streams,
  0-RTT resumption, and built-in flow control, which TCP-based P2P stacks
  must reimplement.

### 1.2 Design Philosophy

AAFP follows three principles:

1. **Preserve abstractions, replace implementations.** AAFP adopts the
   proven abstractions from libp2p (Transport, Connection, Stream, Swarm,
   NetworkBehaviour, Multiaddr) but replaces the implementations with
   QUIC-native, AgentId-based, post-quantum internals. This gives ecosystem
   familiarity while allowing a clean redesign.

2. **Post-quantum by default.** All key exchange uses hybrid post-quantum
   cryptography (X25519MLKEM768). All signatures use ML-DSA-65 (FIPS 204).
   There is no classical-only mode. This protects against
   harvest-now-decrypt-later attacks.

3. **Specify before implementing.** The wire format, error codes, and
   extension mechanisms are specified in RFCs before implementation. The
   implementation conforms to the specification, not the reverse. This
   enables independent interoperable implementations.

### 1.3 Non-Goals

The following are explicitly out of scope for AAFP v1:

- **Resource exchange**: CPU, GPU, storage, bandwidth, and inference credit
  markets. These are higher-layer protocols that may be built on top of
  AAFP but are not part of the base protocol.
- **Distributed scheduling**: Coordinating compute tasks across agents is
  an application-layer concern.
- **Semantic capability routing**: Multi-dimensional capability queries
  (cost, latency, trust score, hardware) are deferred until usage patterns
  emerge. v1 supports string-keyed capability lookup only.
- **Payment and settlement**: Financial transactions between agents are
  out of scope.
- **Swarm intelligence protocols**: Collective reasoning, consensus, and
  emergent behavior are application-layer concerns.

These non-goals are documented to set scope expectations. The protocol
architecture does not preclude them; it provides extension points for
future work.

## 2. Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Application                          │
│              (agent logic, MCP, tools)                    │
├─────────────────────────────────────────────────────────┤
│                       aafp-sdk                             │
│            (builder, client, server)                      │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│ Identity │ Discovery│   NAT    │Messaging │  Session      │
│          │          │Traversal │          │  (future)     │
├──────────┴──────────┴──────────┴──────────┴──────────────┤
│                   aafp-core                               │
│         (Transport, Connection, Stream,                   │
│          Swarm, NetworkBehaviour traits)                  │
├─────────────────────────────────────────────────────────┤
│                 aafp-transport-quic                        │
│        (QUIC + TLS 1.3 with X25519MLKEM768)               │
├─────────────────────────────────────────────────────────┤
│                      QUIC                                  │
│              (quinn + rustls + aws-lc-rs)                  │
└─────────────────────────────────────────────────────────┘
```

### 2.1 Layer Responsibilities

| Layer | Responsibility | RFC |
|-------|---------------|-----|
| QUIC | Reliable, ordered, multiplexed streams; congestion control; flow control | (IETF QUIC) |
| TLS 1.3 | Transport encryption; PQ key exchange; certificate authentication | (IETF TLS 1.3) |
| Transport (aafp-transport-quic) | QUIC configuration; PQ KEX setup; connection lifecycle | RFC-0002 |
| Core (aafp-core) | Trait abstractions for Transport, Connection, Stream, Swarm | RFC-0001 |
| Identity (aafp-identity) | AgentId, AgentRecord, ML-DSA-65 signatures, authorization | RFC-0003 |
| Discovery (aafp-discovery) | Bootstrap, regional, capability DHT | RFC-0004 |
| NAT Traversal (aafp-nat) | AutoNAT, circuit relay, DCuTR | (future RFC) |
| Messaging (aafp-messaging) | Framing, stream multiplexing, RPC, pubsub | RFC-0002 |
| Session (future) | Session lifecycle, feature negotiation, reconnect | RFC-0003 |
| SDK (aafp-sdk) | High-level builder API | (informational) |

### 2.2 What AAFP Does Not Reimplement

AAFP relies on existing protocols for the following, rather than
reimplementing them:

- **Transport reliability**: QUIC provides reliable, ordered delivery.
  AAFP does not implement retransmission or flow control.
- **Congestion control**: QUIC provides CUBIC/BBR congestion control.
  AAFP does not manage congestion state.
- **Transport encryption**: TLS 1.3 with X25519MLKEM768 provides
  post-quantum transport encryption. AAFP does not implement its own
  transport-level encryption.
- **Connection multiplexing**: QUIC provides stream multiplexing within
  a single connection. AAFP maps logical streams to QUIC bidirectional
  streams.
- **Certificate chain validation**: AAFP uses self-signed certificates
  with TOFU (trust-on-first-use) at the TLS layer. Agent identity is
  verified at the application layer via ML-DSA-65 signatures, not via
  TLS certificate chains.

## 3. Agent Identity

### 3.1 AgentId

An AgentId is a 32-byte identifier derived from an agent's ML-DSA-65
public key:

```
AgentId = SHA-256(ML-DSA-65 public key)
```

Properties:
- **Fixed 32 bytes**: Fits in a single cache line (with metadata),
  hash-table friendly, maps to IPv6 address space.
- **Quantum-safe**: SHA-256 is not broken by Shor's algorithm.
- **Decoupled from key format**: If ML-DSA-65 is superseded, AgentId
  derivation remains valid as long as the public key is hashable.
- **Collision-resistant**: SHA-256 collision resistance (128-bit) is
  sufficient for global agent identity.

### 3.2 AgentRecord

An AgentRecord is a self-signed CBOR document that binds an AgentId to
its capabilities and network endpoints. It is the primary identity
advertisement in the network.

The detailed CBOR schema for AgentRecord is specified in RFC-0003.

### 3.3 Authorization

AAFP uses an `AuthorizationProvider` trait to decouple the protocol from
any single authorization system. The first implementation is UCAN
(User-Controlled Authorization Networks), a JWT-style capability
delegation model signed with ML-DSA-65.

Future implementations may include OIDC, PQ capability tokens, or
custom authorization systems. The protocol mandates the trait, not the
implementation.

See RFC-0003 for the authorization flow specification.

## 4. Discovery

AAFP defines four conceptual discovery classes:

1. **Identity Discovery**: Finding an agent's network address given its
   AgentId. Implemented in v1 via bootstrap nodes and peer exchange.
2. **Capability Discovery**: Finding agents that advertise a given
   capability. Implemented in v1 via a capability-keyed DHT.
3. **Service Discovery**: Finding long-running services (e.g., a
   persistent inference endpoint). Not implemented in v1.
4. **Resource Discovery**: Finding agents with available compute
   resources. Not implemented in v1.

The v1 MVP implements Identity and Capability discovery. Service and
Resource discovery are named concepts with empty implementations,
providing conceptual scaffolding for future work.

See RFC-0004 for the discovery protocol specification.

## 5. Transport

### 5.1 QUIC

AAFP uses QUIC (RFC 9000) as its transport protocol, via the `quinn`
Rust implementation. QUIC provides:

- Multiplexed bidirectional and unidirectional streams
- 0-RTT connection resumption
- Built-in flow control and congestion control
- Connection migration (for mobile agents)
- Low connection establishment latency (1-RTT, 0-RTT with resumption)

### 5.2 Post-Quantum Key Exchange

The TLS 1.3 handshake uses the `X25519MLKEM768` hybrid key exchange
group, which combines:

- **X25519** (classical ECDH, ~128-bit classical security)
- **ML-KEM-768** (NIST FIPS 203, post-quantum lattice-based KEM)

This is configured via `rustls` with the `aws-lc-rs` backend and the
`prefer-post-quantum` feature. If either component is broken, the other
still provides security.

### 5.3 TLS Certificates

AAFP uses self-signed Ed25519 certificates at the TLS layer with a
TOFU (trust-on-first-use) model. This is a deliberate design choice:

- `rustls` does not yet support ML-DSA-65 in certificate verification.
- The PQ KEX (X25519MLKEM768) encrypts the transport regardless of
  certificate type.
- Agent identity is verified at the application layer via ML-DSA-65
  signatures in the AAFP handshake, not via TLS certificate chains.

When `rustls` adds ML-DSA-65 certificate support, AAFP may transition
to ML-DSA-65 certificates. This change would not affect the wire
protocol or AgentId derivation.

## 6. Messaging

### 6.1 Framing

AAFP messages are framed using a length-prefixed format with protocol
version and extension space. The frame format is specified in RFC-0002.

### 6.2 Stream Multiplexing

Each logical AAFP stream maps to a QUIC bidirectional stream. Stream
IDs are 64-bit unsigned integers assigned by the initiating side.

### 6.3 RPC

AAFP supports a request/response pattern with correlation IDs. Requests
and responses are CBOR-encoded and carried in frames.

### 6.4 PubSub

v1 includes an in-memory pubsub implementation. A gossipsub protocol
for distributed pubsub is deferred to a future RFC.

## 7. Compatibility Guarantees

### 7.1 Wire Format Stability

The wire format specified in RFC-0002 is stable for all `v0.x` releases.
Breaking changes require a new major version (`v1.0`, `v2.0`, etc.).

### 7.2 Extension Mechanism

The frame format includes reserved extension space and feature bits
for forward compatibility. Unknown extensions must be handled according
to the rules in RFC-0006.

### 7.3 Implementation Conformance

The normative conformance requirements for AAFP version 1 are
defined in RFC-0006 Section 8.1. Implementations conforming to
this RFC series MUST satisfy those requirements.

The v0.1 MVP conformance requirements (defined in the pre-RFC
implementation) are obsolete and MUST NOT be used for conformance
claims.

## 8. RFC Organization

| RFC | Title | Status |
|-----|-------|--------|
| RFC-0001 | Protocol Overview | This document |
| RFC-0002 | Transport & Framing | Draft |
| RFC-0003 | Identity & Authentication | Draft |
| RFC-0004 | Discovery | Draft |
| RFC-0005 | Error Model | Draft |
| RFC-0006 | Versioning & Compatibility | Draft |

## 9. Security Considerations

### 9.0 Trust Model

AAFP v1 uses a **decentralized trust model** with no trusted third
parties. The following trust assumptions apply:

**Trust Anchor**: Each agent's trust anchor is its own ML-DSA-65 secret
key. There is no certificate authority, no public key infrastructure,
and no trusted directory service in v1.

**Self-Attested Identity**: All identity claims are self-attested.
AgentRecords are self-signed (RFC-0003 Section 3.4). The `expires_at`
field is self-attested by the key holder.

**Bootstrap Node Trust**: Bootstrap nodes are trusted by configuration
(out-of-band). The protocol does not verify bootstrap node identity or
honesty. Implementations MUST support configuring multiple bootstrap
nodes (see RFC-0004 Section 3.1) to mitigate compromise of any single
bootstrap node.

**TLS Trust**: TLS certificates are self-signed with trust-on-first-use
(TOFU). The application-layer handshake provides identity verification
independent of TLS certificate validation.

**Out-of-Band Verification Required For**:
- First connection to a new agent (AgentId fingerprint verification,
  see RFC-0003 Section 2.6)
- Bootstrap node configuration
- Revocation checking (if required by threat model)

**NOT Trusted in v1**:
- No CA or PKI
- No revocation authority
- No reputation system
- No Sybil resistance mechanism

Future versions MAY introduce trusted third parties or delegation-based
trust, but v1 is fully decentralized.

### 9.1 Post-Quantum Security

AAFP is designed to be secure against quantum adversaries. All key
exchange uses hybrid PQ (X25519MLKEM768). All signatures use ML-DSA-65
(FIPS 204). AgentIds use SHA-256, which is quantum-resistant.

### 9.2 Harvest-Now-Decrypt-Later

The PQ KEX protects against adversaries who record encrypted traffic
today and decrypt it once a quantum computer becomes available.

### 9.3 Identity Binding

The AAFP application-layer handshake binds the TLS session to the
agent's ML-DSA-65 identity via TLS channel binding. The TLS exporter
value (RFC 8446 Section 7.5, using the label
"EXPORTER-AAFP-Channel-Binding" per RFC 9266) is included in the
handshake transcript hash. This prevents relay attacks: an attacker
who terminates TLS on both sides cannot relay AAFP handshake
messages because the transcript hashes will differ (the TLS sessions
differ), causing signature verification failure.

This provides end-to-end authentication independent of the TLS
certificate chain.

### 9.4 Authorization

UCAN capability delegation allows agents to delegate limited authority
to other agents. Delegation chains are verifiable and expire
automatically.

### 9.5 TOFU Limitations

The TOFU model for TLS certificates is vulnerable to man-in-the-middle
attacks on first connection. This is mitigated by:

- The application-layer handshake verifying ML-DSA-65 identity
- TLS channel binding preventing relay attacks (Section 9.3)
- AgentRecord signatures providing out-of-band verification
- AgentId fingerprints for human verification (see RFC-0003 Section 2.6)
- Future support for ML-DSA-65 TLS certificates

### 9.6 Security Limitations (v1)

The following security properties are NOT provided by AAFP v1 and are
explicitly out of scope:

1. **Network partition tolerance**: No mechanism for detecting or
   handling network partitions. The v1 DHT is in-memory with no
   replication or consistency guarantees.
2. **Traffic analysis resistance**: No padding or obfuscation
   mechanism. AAFP traffic is identifiable by characteristic
   handshake sizes (ML-DSA-65 keys and signatures are large).
3. **Identity hiding**: AgentId is sent to the peer in ClientHello
   and is public in the DHT. No ephemeral identity mechanism.
4. **Anonymous bootstrap**: No mechanism for anonymous bootstrap.
   Bootstrap nodes learn the identity of all connecting agents.
5. **Application-layer encryption**: No encryption beyond TLS.
   If TLS confidentiality is broken, all application data is exposed.
6. **Session resumption**: Deferred to a future RFC.
7. **NAT traversal**: Deferred to a future RFC.
8. **Revocation**: No in-protocol revocation mechanism (see RFC-0003
   Section 8.4).
9. **Key rotation**: No in-protocol key rotation mechanism (see
   RFC-0003 Section 2.5).
10. **Sybil resistance**: No proof-of-work, reputation system, or
    trusted issuer requirements (see RFC-0004 Section 8.3).

These limitations are documented to set explicit expectations. Future
RFCs may address some or all of these. Implementations and deployments
MUST assess whether these limitations are acceptable for their threat
model.

## 10. IANA Considerations

AAFP may require IANA registration for:

- TLS ALPN identifier (e.g., `aafp/1`)
- Well-known port numbers for bootstrap nodes
- Error code registry (managed per RFC-0005)
- Extension type registry (managed per RFC-0006)

These registrations are deferred until the protocol is stable.

## 11. Acknowledgments

The AAFP architecture draws on concepts from libp2p, QUIC, TLS 1.3,
UCAN, and the NIST post-quantum standardization process.
