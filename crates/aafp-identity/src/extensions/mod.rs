//! AgentRecord extensions (Phase E): heartbeat liveness tracking and
//! third-party attestation storage.
//!
//! These modules implement the extension layer specified in
//! `AGENT_RECORD_EXTENSIONS.md` §7 (Attestations), §8.2.1 (Heartbeat),
//! and §10.3 (DHT attestation storage).

pub mod attestation_store;
pub mod heartbeat;
