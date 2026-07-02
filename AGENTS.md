# AAFP Rust Implementation — Build & Test Guide

## Quick verification

```bash
cargo fmt --all -- --check   # formatting check (0 diffs expected)
cargo build --workspace       # build (0 warnings expected)
cargo clippy --workspace      # lints (0 warnings expected)
cargo test --workspace        # 1011 tests, 0 failures expected (2 ignored)
```

## Project layout

14-crate Cargo workspace under `implementations/rust/crates/`:

| Crate | Purpose |
|-------|---------|
| `aafp-cbor` | Canonical CBOR encoder/decoder (RFC 8949 deterministic) |
| `aafp-crypto` | ML-DSA-65 signatures, AEAD, HKDF, v1 handshake protocol, ReplayCache |
| `aafp-identity` | AgentId, AgentRecord, UCAN capability chains |
| `aafp-core` | Core traits, Session state machine, AuthorizationProvider |
| `aafp-transport-quic` | QUIC transport via quinn + rustls (PQ TLS) |
| `aafp-messaging` | Frame encoding/decoding, RPC, stream multiplexing |
| `aafp-discovery` | Capability-based DHT (in-memory) |
| `aafp-nat` | NAT traversal stubs (AutoNAT, DCuTR, relay) |
| `aafp-sdk` | High-level Agent SDK (client + server + handshake driver) |
| `aafp-transport-mcp` | AAFP secure transport binding for MCP Rust SDK (rmcp) |
| `aafp-cli` | Command-line tool for agent management |
| `aafp-conformance` | RFC conformance test suite + golden trace generation |
| `aafp-benchmark` | Criterion benchmarks for crypto/discovery/messaging/MCP transport |
| `aafp-tests` | Cross-crate integration tests |

## Key conventions

- **v1 types are primary**: `rpc_v1`, `handshake_v1`, `identity_v1` are the
  RFC-compliant exports. Legacy modules (`rpc`, `handshake`, `agent_record`)
  are `#[deprecated]` and kept only for backward compatibility.
- **Session enforcement**: All SDK messaging requires a completed v1 handshake
  (Session in `MessagingEnabled` state). No unauthenticated code path exists.
- **Conformance crate**: Uses crate-level `#![allow(unused_imports, dead_code)]`
  because test helpers are intentionally broad for future test expansion.
- **Legacy v0 handshake** (`handshake.rs`): Marked `#![allow(dead_code)]` —
  kept for benchmarks only, NOT RFC-compliant.
- **Handshake state machine** (`aafp-core::handshake_state`): Normative
  implementation of RFC-0002 §5.10 (Rev 6 A-6). Tracks client/server
  handshake sub-states, enforces transitions, timeouts, duplicate detection,
  and unexpected frame rejection. Separate from `SessionState` which tracks
  the higher-level session lifecycle.
- **CloseManager** (`aafp-messaging::close_manager`): Normative
  implementation of RFC-0002 §6.6 (Rev 6 A-8). Single authority for all
  CLOSE frame state transitions. Transport-agnostic and synchronous.
  5 states: Open, LocalCloseSent, RemoteCloseReceived, CloseReceived, Closed.
- **ReplayCache** (`aafp-crypto::replay_cache`): Normative
  implementation of RFC-0002 §6.7 (Rev 6 A-9). Time-bounded set of
  observed `(agent_id, nonce)` pairs for cross-connection nonce replay
  detection. Thread-safe via internal `Mutex`. Key API:
  `check_and_insert()` (atomic), `check()` (read-only), `insert()`,
  `evict_expired()`. Integrated into `drive_client_handshake` and
  `drive_server_handshake` via optional `Option<&ReplayCache>` parameter.
  Check-before-verify, insert-after-verify, LRU eviction, configurable
  retention (default 300s) and max_entries (default 100K).
- **ML-DSA-65 Cross-Language Interop** (A-10): The `aafp-crypto::dsa`
  module provides `MlDsa65::keypair_from_seed()` and
  `MlDsa65::sign_deterministic()` for FIPS 204 deterministic test vector
  generation. The Go implementation (`implementations/go/mldsa/`) uses
  `github.com/KarpelesLab/mldsa` v0.2.0. Both implementations produce
  identical keys from the same seed and identical deterministic signatures.
  Cross-verification: 19/19 Rust vectors verify in Go, 15/15 Go vectors
  verify in Rust, 100/100 diff traces cross-verify. Test vectors in
  `test-vectors/mldsa65/`.
