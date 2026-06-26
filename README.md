# AAFP — Agent-Agent First Networking Protocol

A post-quantum, agent-first P2P networking stack for autonomous AI agents.

AAFP replaces libp2p's PeerId with a 32-byte **AgentId** (SHA-256 of an ML-DSA-65 public key), uses **X25519MLKEM768** hybrid post-quantum key exchange over QUIC, and provides capability-based discovery and UCAN delegation for agent-to-agent authorization.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    aafp-cli                          │  CLI binary
├─────────────────────────────────────────────────────┤
│                    aafp-sdk                          │  High-level API
├──────────┬──────────┬──────────┬──────────┬──────────┤
│ aafp-    │ aafp-    │ aafp-    │ aafp-    │ aafp-    │
│ discovery│ nat      │ messaging│ crypto   │ identity │  Protocol layers
├──────────┴──────────┴──────────┴──────────┴──────────┤
│              aafp-transport-quic                      │  QUIC + PQ TLS
├─────────────────────────────────────────────────────┤
│                    aafp-core                          │  Trait abstractions
└─────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description |
|-------|-------------|
| `aafp-crypto` | ML-DSA-65 signatures, X25519 KEM, ChaCha20-Poly1305/AES-256-GCM AEAD, HKDF-SHA256, PQ hybrid 1-RTT handshake |
| `aafp-identity` | AgentKeypair, 32-byte AgentId, self-signed AgentRecord (CBOR), UCAN capability delegation |
| `aafp-core` | Transport, Connection, Stream, Swarm, NetworkBehaviour traits (forked from libp2p-core) |
| `aafp-transport-quic` | QUIC transport via `quinn` + `rustls` with `X25519MLKEM768` PQ KEX |
| `aafp-discovery` | Bootstrap seeds, regional grouping, capability-based DHT |
| `aafp-nat` | AutoNAT detection, circuit relay, DCuTR hole punching (stubs for MVP) |
| `aafp-messaging` | Length-prefixed framing, stream multiplexing, RPC, pubsub |
| `aafp-sdk` | Builder-pattern API wrapping all layers |
| `aafp-cli` | `aafp` command-line tool |
| `aafp-benchmark` | Criterion benchmarks for crypto, discovery, messaging |
| `aafp-tests` | Integration tests |

## Quick Start

### Build

```bash
cargo build --workspace
```

### Run Tests

```bash
cargo test --workspace
```

### CLI Usage

```bash
# Initialize a new agent identity
aafp init --output my-agent.bin --capabilities inference,translation

# Check status
aafp status --identity my-agent.bin

# Start an agent node
aafp start --identity my-agent.bin --bind 127.0.0.1:4433

# Discover agents by capability
aafp discover --capability inference --identity my-agent.bin

# Connect to a peer
aafp connect --addr quic://127.0.0.1:4434 --identity my-agent.bin

# Send a message
aafp send --addr quic://127.0.0.1:4434 --message "hello" --identity my-agent.bin

# Start a relay node
aafp relay --bind 127.0.0.1:4434
```

### SDK Usage

```rust
use aafp_sdk::AgentBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = AgentBuilder::new()
        .with_capabilities(vec!["inference".into()])
        .bind("127.0.0.1:4433".parse()?)
        .build()
        .await?;

    println!("Agent ID: {}", hex::encode(agent.id()));
    println!("Listening on: {}", agent.multiaddr()?);

    Ok(())
}
```

## Post-Quantum Security

### Key Exchange
The TLS 1.3 handshake uses **X25519MLKEM768** hybrid key exchange via `rustls` with the `aws-lc-rs` backend and `prefer-post-quantum` feature. This combines:
- **X25519** (classical ECDH, 128-bit security)
- **ML-KEM-768** (NIST FIPS 203, post-quantum lattice-based KEM)

This protects against **harvest-now-decrypt-later** attacks where an adversary records encrypted traffic today and decrypts it once a quantum computer becomes available.

### Signatures
Agent identity uses **ML-DSA-65** (NIST FIPS 204) for post-quantum digital signatures:
- Public key: 1952 bytes
- Secret key: 4032 bytes
- Signature: 3309 bytes

### Application-Layer Handshake
The AAFP application-layer handshake (`aafp_crypto::PqHandshake`) binds the TLS session to the agent's ML-DSA-65 identity, providing end-to-end authentication that is independent of the TLS certificate chain.

## Agent Identity

- **AgentId** = `SHA-256(ML-DSA-65 public key)` = 32 bytes
- **AgentRecord** = self-signed CBOR record binding AgentId to capabilities and endpoints
- **UCAN** = JWT-style capability delegation tokens signed with ML-DSA-65

## Discovery

- **Bootstrap**: seed nodes for initial peer discovery
- **Regional**: latency-based geographic grouping
- **Capability DHT**: Kademlia-like DHT keyed by capability strings (e.g., "inference", "translation")

## NAT Traversal

- **AutoNAT**: dial-back probes to detect NAT status
- **Circuit Relay**: relay nodes forward traffic for agents behind NAT
- **DCuTR**: hole punching to upgrade relayed connections to direct (stub for MVP)

## License

MIT OR Apache-2.0
