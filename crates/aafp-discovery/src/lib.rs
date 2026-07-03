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
/// Legacy MVP capability DHT module. In-memory only, not RFC-compliant.
/// Use [`discovery_v1`] instead.
#[deprecated = "Use discovery_v1 instead. Legacy capability_dht is in-memory only, not RFC-compliant."]
#[allow(deprecated)]
pub mod capability_dht;
pub mod discovery_v1;
/// Persistent DHT backend using SQLite.
pub mod persistent_dht;
pub mod regional;
pub mod rpc_handler;

pub use bootstrap::{BootstrapConfig, BootstrapDiscovery};
pub use discovery_v1::{
    shared_arc_swap_dht, shared_dht, shared_sharded_dht, AnnounceParams, AnnounceResult,
    ArcSwapDht, CapabilityDht as CapabilityDhtV1, DiscoveryError, LookupParams, LookupResult,
    ShardedCapabilityDht, SharedArcSwapDht, SharedCapabilityDht, SharedShardedDht,
    DEFAULT_LIMIT_AUTH, DEFAULT_LIMIT_UNAUTH, DHT_SHARD_COUNT, MAX_CONCURRENT_STREAMS, MAX_RECORDS,
    METHOD_ANNOUNCE, METHOD_LOOKUP, METHOD_PEX, RATE_LIMIT_ANNOUNCE, RATE_LIMIT_LOOKUP,
};
pub use persistent_dht::PersistentDht;
pub use regional::{Region, RegionalDiscovery};
pub use rpc_handler::{DiscoveryClient, DiscoveryRpcHandler, ShardedDiscoveryRpcHandler};
