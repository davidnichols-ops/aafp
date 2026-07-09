# AAFP Rust Implementation — Build & Test Guide

## Quick verification

```bash
cargo fmt --all -- --check   # formatting check (0 diffs expected)
cargo build --workspace       # build (0 warnings expected)
cargo clippy --workspace      # lints (0 warnings expected)
cargo test --workspace        # 2869 tests, 0 failures expected (7 ignored)
```

## Project layout

18-crate Cargo workspace under `implementations/rust/crates/`
(plus 1 standalone crate `aafp-py` not in the workspace):

| Crate | Purpose |
|-------|---------|
| `aafp-cbor` | Canonical CBOR encoder/decoder (RFC 8949 deterministic) |
| `aafp-crypto` | ML-DSA-65 signatures, AEAD, HKDF, v1 handshake protocol, ReplayCache |
| `aafp-identity` | AgentId, AgentRecord, UCAN capability chains |
| `aafp-core` | Core traits, Session state machine, AuthorizationProvider |
| `aafp-transport-quic` | QUIC transport via quinn + rustls (PQ TLS) |
| `aafp-messaging` | Frame encoding/decoding, RPC, stream multiplexing |
| `aafp-discovery` | Capability-based DHT (Kademlia routing, bootstrap, replication, churn) |
| `aafp-nat` | NAT traversal (relay forwarding, AutoNAT dial-back, DCuTR hole punching) |
| `aafp-perception` | Agent perception capabilities (search, browse, document-read, API call/discover, code-execute, media OCR/transcribe, browsing sessions) |
| `aafp-economics` | Resource accounting, pricing engine, priority queue, compensation protocol, slashing conditions |
| `aafp-sdk` | High-level Agent SDK (client + server + handshake driver) |
| `aafp-transport-mcp` | AAFP secure transport binding for MCP Rust SDK (rmcp) |
| `aafp-transport-a2a` | AAFP secure transport binding for A2A protocol (RFC 0008) |
| `aafp-py` | Python PyO3 adapter (standalone, not in workspace) |
| `aafp-cli` | Command-line tool for agent management + perception commands (search/browse/read-pdf/ocr) |
| `aafp-conformance` | RFC conformance test suite + golden trace generation |
| `aafp-benchmark` | Criterion benchmarks for crypto/discovery/messaging/MCP transport |
| `aafp-tests` | Cross-crate integration tests (WAN, adversarial, malformed, stress, multi-node DHT) |
| `aafp-loadtest` | Load test harness (N agents, topologies, metrics, stability) |

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
- **TrustManager** (`aafp-identity::trust_manager`): RFC 0011 hybrid trust
  model. Supports Web of Trust (TOFU), CA-signed certificates, and key
  rotation. Manages trust anchors, revocation lists, and key directories.
- **DhtRouter** (`aafp-discovery::dht_router`): Kademlia-style routing
  for the capability DHT. 256 k-buckets keyed by XOR distance, iterative
  lookup with α=3 concurrency, PEX peer exchange, record replication (k=5).
  Scales to 500 nodes with 100% lookup success.
- **KeyDirectory** (`aafp-identity::key_directory`): AgentId → AgentRecord
  mapping with in-memory and SQLite backends. Rate-limited publishing
  (1/AgentId/hour), signature verification, monotonic version enforcement.
- **AgentMetrics** (`aafp-sdk::metrics`): Lock-free metrics using
  AtomicU64 counters. Tracks connections, messages, bytes, handshakes,
  DHT records, uptime. HealthStatus: Healthy/Degraded/Unhealthy.
- **Rate limiting** (`aafp-sdk::server`): Per-IP handshake rate limiting
  (10/sec default) with periodic eviction and 10K cap to prevent memory
  exhaustion. Constant-time AgentId comparison via `subtle::ConstantTimeEq`.
- **Fuzz targets**: 8 fuzz targets in `fuzz/fuzz_targets/` covering CBOR
  decode, frame decode, handshake CBOR, RPC decode, agent record, relay
  request, discovery request. Run with `cargo +nightly fuzz run <target>`.
- **Phase 4 Intelligence Plane** (v0.5-phase4-complete): 17 tracks across
  5 waves implementing the full agent intelligence stack:
  - **Execution** (aafp-sdk/execution): ExecutionPlan, TaskScheduler,
    CheckpointManager, MigrationManager, ResultAggregator, FailureRecovery.
  - **Perception** (aafp-perception): Search, WebBrowse, DocumentRead,
    ApiCall, ApiDiscover, CodeExecute, Media (OCR/transcribe),
    BrowsingSession.
  - **Economics** (aafp-economics): ResourceAccount, PricingEngine,
    PriorityQueue, CompensationProtocol, SlashingConditions.
  - **Discovery** (aafp-discovery/semantic): DhtSemanticQuery, IntentResolver.
  - **Identity** (aafp-identity/extensions): ReputationScoreEngine,
    ReputationPropagation (gossip), UCAN capability chains.
  - **Routing** (aafp-sdk/routing): TemporalPredictionEngine,
    PredictivePrefetcher.
  All new modules use pluggable provider traits, CBOR serialization,
  ML-DSA-65 signatures where applicable, and comprehensive test suites
  (993 new tests, total 2857).

- **Perception CLI Integration**: The `aafp-cli` now imports `aafp-perception`
  and exposes 4 real-world perception commands:
  - `aafp search "<query>" [--num N] [--json]` — DuckDuckGo web search (free, no API key)
  - `aafp browse <url> [--json]` — Firecrawl web browsing (requires `FIRECRAWL_API_KEY` in `.env`)
  - `aafp read-pdf <path> [--json] [--python PATH]` — PyMuPDF PDF text extraction (uses `AAFP_PYTHON` env or `python3`)
  - `aafp ocr <path> [--json] [--lang LANG]` — Tesseract OCR on images (.png/.jpg/.webp/.tiff)
  All commands load `.env` via `dotenvy` for API keys. The `research-agent` example
  (`examples/research-agent/`) chains search → browse → structured summary.
  Firecrawl provider updated to v1 API (response wrapped in `data` field, no
  `onlyMain_content` request param). Total tests: 2869 (12 new perception tests).
