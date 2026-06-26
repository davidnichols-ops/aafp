# AAFP Architecture

## Overview

AAFP (Agent-Agent First Networking Protocol) is a post-quantum P2P networking stack designed specifically for autonomous AI agents. It replaces libp2p's PeerId with a 32-byte AgentId derived from ML-DSA-65 public keys, and uses X25519MLKEM768 hybrid post-quantum key exchange over QUIC.

## Design Principles

1. **Agent-first**: The protocol is designed for AI agents, not generic P2P nodes. Agents have capabilities, delegate authority via UCAN, and discover each other by capability.
2. **Post-quantum by default**: All key exchange uses hybrid PQ (X25519MLKEM768) and all signatures use ML-DSA-65 (FIPS 204).
3. **No libp2p dependency**: Core traits are forked and simplified from libp2p, adapted for AgentId and QUIC.
4. **QUIC-native**: Uses QUIC (via quinn) for multiplexed, encrypted streams with built-in flow control.

## Layer Architecture

### Layer 1: Core Traits (`aafp-core`)
Forked and simplified from libp2p-core:
- `Transport` trait: listen, dial, poll for events
- `Connection` trait: peer ID, remote address, close
- `Stream` trait: stream ID within a connection
- `Swarm`: drives a Transport + NetworkBehaviours
- `NetworkBehaviour` trait: for future protocol implementations

### Layer 2: Cryptography (`aafp-crypto`)
- **ML-DSA-65** (FIPS 204): post-quantum signatures via `pqcrypto-mldsa`
- **X25519 KEM**: standalone KEM for testing (production uses TLS X25519MLKEM768)
- **AEAD**: ChaCha20-Poly1305 (default) and AES-256-GCM
- **HKDF-SHA256**: key derivation
- **PQ Hybrid Handshake**: 1-RTT application-layer handshake with ML-DSA-65 authentication

### Layer 3: Identity (`aafp-identity`)
- **AgentKeypair**: wraps ML-DSA-65 keypair
- **AgentId**: 32-byte SHA-256 of public key
- **AgentRecord**: self-signed CBOR record with capabilities and endpoints
- **UCAN**: JWT-style capability delegation with chain verification

### Layer 4: Transport (`aafp-transport-quic`)
- QUIC via `quinn` + `rustls`
- X25519MLKEM768 PQ KEX via `aws-lc-rs` backend
- Self-signed Ed25519 certificates (TOFU model)
- Agent identity verified at application layer, not TLS layer

### Layer 5: Discovery (`aafp-discovery`)
- **Bootstrap**: seed node configuration
- **Regional**: latency-based geographic grouping
- **Capability DHT**: in-memory Kademlia-like DHT keyed by capability strings

### Layer 6: NAT Traversal (`aafp-nat`)
- **AutoNAT**: dial-back probes for NAT detection
- **Circuit Relay**: relay node configuration and forwarding
- **DCuTR**: hole punching for direct connection upgrade (stub)

### Layer 7: Messaging (`aafp-messaging`)
- **Framing**: length-prefixed (u32 BE) frames
- **Stream Multiplexing**: each logical stream maps to a QUIC bidirectional stream
- **RPC**: request/response with correlation IDs (CBOR-encoded)
- **PubSub**: in-memory topic-based publish/subscribe

### Layer 8: SDK (`aafp-sdk`)
- `AgentBuilder`: fluent builder API
- `AgentClient`: connect, send, request/response
- `AgentServer`: accept connections, echo handler

### Layer 9: CLI (`aafp-cli`)
Commands: init, start, discover, connect, send, status, relay

## Key Design Decisions

### Why not use libp2p directly?
1. libp2p's PeerId is tied to multihash, not PQ signatures
2. libp2p's Transport trait uses Poll-based async, which is complex
3. AAFP needs capability-based discovery, not just peer ID routing
4. Removing libp2p eliminates ~50 dependencies

### Why ML-DSA-65 instead of Ed25519?
ML-DSA-65 (FIPS 204) is a post-quantum signature scheme. Ed25519 is broken by Shor's algorithm on a quantum computer. ML-DSA-65 provides ~128-bit post-quantum security.

### Why X25519MLKEM768 for KEX?
This hybrid combines classical X25519 (which we keep for robustness) with ML-KEM-768 (FIPS 203, post-quantum). If either component is broken, the other still provides security.

### Why TOFU for TLS certificates?
rustls does not yet support ML-DSA-65 in certificate verification. Using self-signed certificates with TOFU (trust-on-first-use) at the TLS layer is safe because:
1. The PQ KEX (X25519MLKEM768) encrypts the transport
2. The application-layer handshake binds the TLS session to the agent's ML-DSA-65 identity
3. Agent identity is verified via AgentRecord signatures, not TLS certificates

## Test Coverage

- 116 tests across the workspace
- Unit tests in each crate
- Integration tests in `aafp-tests`
- Benchmarks in `aafp-benchmark`

## Future Work

- Distributed Kademlia DHT (currently in-memory)
- Full circuit relay v2 protocol
- DCuTR hole punching implementation
- Gossipsub for pubsub
- ML-DSA-65 in TLS certificates (when rustls supports it)
- 1000-agent integration test at scale
