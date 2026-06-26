//! AAFP discovery layer: bootstrap, regional grouping, and capability-based DHT.
//!
//! ## Design (from AAFP_Architecture_Deliverable.md Phase 2.4)
//! - **Bootstrap**: hardcoded seed nodes for initial peer discovery.
//! - **Regional**: agents are grouped by geographic region (latency-based).
//! - **Capability DHT**: a simplified Kademlia-like DHT keyed by capability
//!   strings (e.g., "inference", "translation") rather than by AgentId.
//!   This lets agents discover peers by capability without scanning the
//!   entire network.
//!
//! For MVP, the DHT is implemented as an in-memory store. A production
//! version would distribute records across the network via Kademlia-style
//! RPCs over QUIC streams.

pub mod bootstrap;
pub mod capability_dht;
pub mod discovery_v1;
pub mod regional;

pub use bootstrap::{BootstrapConfig, BootstrapDiscovery};
pub use capability_dht::{CapabilityDht, DhtError, DhtRecord};
pub use discovery_v1::{
    AnnounceParams, AnnounceResult, CapabilityDht as CapabilityDhtV1, DiscoveryError,
    LookupParams, LookupResult, SharedCapabilityDht, METHOD_ANNOUNCE, METHOD_LOOKUP, METHOD_PEX,
    DEFAULT_LIMIT_AUTH, DEFAULT_LIMIT_UNAUTH, MAX_CONCURRENT_STREAMS, MAX_RECORDS,
    RATE_LIMIT_ANNOUNCE, RATE_LIMIT_LOOKUP, shared_dht,
};
pub use regional::{RegionalDiscovery, Region};
