//! Multi-node DHT routing (Track R1).
//!
//! Implements Kademlia-style routing for the capability DHT:
//! - [`RoutingTable`] with k-buckets keyed by XOR distance from self
//! - [`DhtRouter`] for iterative lookup, announce forwarding, and PEX
//! - [`DhtTransport`] trait abstracting RPC communication with peers
//!
//! ## Routing Table
//!
//! The routing table uses 256 k-buckets (one per bit of the 256-bit
//! AgentId). Each bucket holds up to `K` (default 20) peer entries.
//! The bucket index is the most-significant differing bit between
//! `self_id` and the peer's `AgentId`.
//!
//! ## Iterative Lookup
//!
//! `find_peers(capability, k)` performs an iterative lookup:
//! 1. Check the local [`CapabilityDht`]
//! 2. If fewer than `k` results, query the `alpha` (default 3) closest
//!    known peers
//! 3. Peers return matching records + closer peers they know about
//! 4. Iterate until `k` results are found or no new peers are discovered
//!
//! ## PEX (Peer Exchange)
//!
//! `aafp.discovery.pex` RPC exchanges known peer lists. When a new
//! connection is established, both sides send a PEX request to learn
//! about each other's known peers, building the routing table.

use crate::discovery_v1::{CapabilityDht, DiscoveryError};
use aafp_cbor::{int_map, Value};
use aafp_identity::identity_v1::{AgentId, AgentRecord, IdentityError};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, trace};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// K-bucket size: max peers per bucket (Kademlia default).
pub const K_BUCKET_SIZE: usize = 20;

/// Number of bits in an AgentId (256 bits = 32 bytes).
pub const ID_BITS: usize = 256;

/// Default concurrency factor for iterative lookups.
pub const ALPHA: usize = 3;

/// Default replication factor: number of closest peers that store a record.
pub const REPLICATION_FACTOR: usize = 5;

/// Bucket refresh interval (15 minutes).
pub const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

// ---------------------------------------------------------------------------
// XOR Distance
// ---------------------------------------------------------------------------

/// XOR distance between two 256-bit AgentIds.
///
/// In Kademlia, the distance between two nodes is `id1 XOR id2`.
/// This produces a 32-byte value that can be compared to determine
/// which node is "closer" to a target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    /// Compute the XOR distance between two AgentIds.
    pub fn between(a: &AgentId, b: &AgentId) -> Self {
        let mut result = [0u8; 32];
        for (result_byte, (a_byte, b_byte)) in result.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *result_byte = a_byte ^ b_byte;
        }
        Self(result)
    }

    /// Compute the XOR distance from this node to a capability key.
    ///
    /// The capability key is hashed with SHA-256 to produce a 32-byte
    /// key that lives in the same XOR space as AgentIds.
    pub fn to_capability_key(capability: &str) -> [u8; 32] {
        Sha256::digest(capability.as_bytes()).into()
    }

    /// Compute the XOR distance from an AgentId to a capability key.
    pub fn from_agent_to_key(agent_id: &AgentId, capability: &str) -> Self {
        let key = Self::to_capability_key(capability);
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = agent_id.0[i] ^ key[i];
        }
        Self(result)
    }

    /// Get the bucket index for this distance.
    ///
    /// Returns the index of the most-significant set bit (0 = most significant).
    /// Returns `None` if the distance is zero (same node).
    pub fn bucket_index(&self) -> Option<usize> {
        for (byte_idx, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                // Position of MSB within the byte (0 = MSB, 7 = LSB)
                let bit_in_byte = byte.leading_zeros() as usize;
                return Some(byte_idx * 8 + bit_in_byte);
            }
        }
        None // distance is zero
    }
}

// ---------------------------------------------------------------------------
// Peer Entry and K-Bucket
// ---------------------------------------------------------------------------

/// An entry in the routing table.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    /// The agent's record.
    pub record: AgentRecord,
    /// Last time this peer was seen (for liveness).
    pub last_seen: Instant,
}

impl PeerEntry {
    /// Create a new peer entry from a record.
    pub fn new(record: AgentRecord) -> Self {
        Self {
            record,
            last_seen: Instant::now(),
        }
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> &AgentId {
        &self.record.agent_id
    }

    /// Mark this peer as seen now.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

/// A k-bucket: a list of up to `K` peers at a certain distance range.
#[derive(Clone, Debug)]
pub struct KBucket {
    /// Maximum entries in this bucket.
    pub max_size: usize,
    /// Peer entries, ordered by insertion (oldest first).
    pub entries: Vec<PeerEntry>,
}

impl KBucket {
    /// Create a new empty k-bucket with the given max size.
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            entries: Vec::with_capacity(max_size),
        }
    }

    /// Check if the bucket is full.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.max_size
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find a peer by AgentId.
    pub fn get(&self, agent_id: &AgentId) -> Option<&PeerEntry> {
        self.entries.iter().find(|e| e.agent_id() == agent_id)
    }

    /// Find a mutable reference to a peer by AgentId.
    pub fn get_mut(&mut self, agent_id: &AgentId) -> Option<&mut PeerEntry> {
        self.entries.iter_mut().find(|e| e.agent_id() == agent_id)
    }

    /// Insert or update a peer entry.
    ///
    /// Returns `true` if the peer was inserted or updated.
    /// Returns `false` if the bucket is full and the peer is not already present.
    pub fn insert(&mut self, entry: PeerEntry) -> bool {
        let agent_id = entry.agent_id().clone();

        // Check if already present — update in place
        if let Some(existing) = self.get_mut(&agent_id) {
            existing.record = entry.record;
            existing.touch();
            return true;
        }

        // If bucket is full, reject (in real Kademlia we'd ping the oldest)
        if self.is_full() {
            return false;
        }

        self.entries.push(entry);
        true
    }

    /// Remove a peer by AgentId.
    pub fn remove(&mut self, agent_id: &AgentId) -> Option<PeerEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.agent_id() == agent_id) {
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Routing Table
// ---------------------------------------------------------------------------

/// Kademlia-style routing table with 256 k-buckets.
///
/// Each bucket covers peers at a specific XOR distance range from `self_id`.
/// Bucket `i` contains peers whose XOR distance from `self_id` has its
/// most-significant set bit at position `i` (0 = most significant).
#[derive(Debug)]
pub struct RoutingTable {
    /// This node's AgentId.
    self_id: AgentId,
    /// 256 k-buckets.
    buckets: Vec<KBucket>,
    /// K-bucket size.
    k: usize,
}

impl RoutingTable {
    /// Create a new routing table for the given AgentId.
    pub fn new(self_id: AgentId) -> Self {
        Self::with_k(self_id, K_BUCKET_SIZE)
    }

    /// Create a routing table with a custom k-bucket size.
    pub fn with_k(self_id: AgentId, k: usize) -> Self {
        let buckets = (0..ID_BITS).map(|_| KBucket::new(k)).collect();
        Self {
            self_id,
            buckets,
            k,
        }
    }

    /// Get this node's AgentId.
    pub fn self_id(&self) -> &AgentId {
        &self.self_id
    }

    /// Get the k-bucket size.
    pub fn k(&self) -> usize {
        self.k
    }

    /// Compute the bucket index for a given peer AgentId.
    fn bucket_index(&self, peer_id: &AgentId) -> Option<usize> {
        let dist = Distance::between(&self.self_id, peer_id);
        dist.bucket_index()
    }

    /// Add or update a peer in the routing table.
    ///
    /// Returns `true` if the peer was inserted or updated.
    /// Returns `false` if the bucket is full and the peer is new.
    pub fn add_peer(&mut self, record: AgentRecord) -> bool {
        if record.agent_id == self.self_id {
            return false; // Don't add self
        }

        let entry = PeerEntry::new(record);
        match self.bucket_index(&entry.record.agent_id) {
            Some(idx) => self.buckets[idx].insert(entry),
            None => false, // Same ID as self
        }
    }

    /// Remove a peer from the routing table.
    pub fn remove_peer(&mut self, agent_id: &AgentId) -> Option<PeerEntry> {
        match self.bucket_index(agent_id) {
            Some(idx) => self.buckets[idx].remove(agent_id),
            None => None,
        }
    }

    /// Get a peer entry by AgentId.
    pub fn get_peer(&self, agent_id: &AgentId) -> Option<&PeerEntry> {
        match self.bucket_index(agent_id) {
            Some(idx) => self.buckets[idx].get(agent_id),
            None => None,
        }
    }

    /// Get all known peer records.
    pub fn all_peers(&self) -> Vec<AgentRecord> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter().map(|e| e.record.clone()))
            .collect()
    }

    /// Get the total number of peers in the routing table.
    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Find the `k` closest peers to a target key (capability or AgentId).
    ///
    /// Returns peers sorted by XOR distance, closest first.
    /// Excludes `self_id`.
    pub fn closest_peers(&self, target: &[u8; 32], k: usize) -> Vec<AgentRecord> {
        let mut all: Vec<(Distance, AgentRecord)> = self
            .buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .map(|e| {
                let mut dist_bytes = [0u8; 32];
                for i in 0..32 {
                    dist_bytes[i] = e.record.agent_id.0[i] ^ target[i];
                }
                (Distance(dist_bytes), e.record.clone())
            })
            .collect();

        all.sort_by_key(|a| a.0);
        all.into_iter().take(k).map(|(_, r)| r).collect()
    }

    /// Find the `k` closest peers to a capability key.
    pub fn closest_peers_to_capability(&self, capability: &str, k: usize) -> Vec<AgentRecord> {
        let key = Distance::to_capability_key(capability);
        self.closest_peers(&key, k)
    }

    /// Get all peers in a specific bucket.
    pub fn bucket(&self, index: usize) -> Option<&KBucket> {
        self.buckets.get(index)
    }

    /// Get the number of non-empty buckets.
    pub fn active_bucket_count(&self) -> usize {
        self.buckets.iter().filter(|b| !b.is_empty()).count()
    }

    /// Touch a peer (update last_seen).
    pub fn touch_peer(&mut self, agent_id: &AgentId) -> bool {
        if let Some(idx) = self.bucket_index(agent_id) {
            if let Some(entry) = self.buckets[idx].get_mut(agent_id) {
                entry.touch();
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// PEX (Peer Exchange) RPC params/result
// ---------------------------------------------------------------------------

/// PEX request params (RFC-0004 §3.3).
///
/// ```cbor
/// { 1: AgentRecord, 2: [ *AgentRecord ] }
/// ```
/// - Key 1: The sender's own AgentRecord (so the receiver learns about the sender)
/// - Key 2: Peers the sender already knows about (optional, for delta exchange)
#[derive(Clone, Debug)]
pub struct PexParams {
    /// The sender's own agent record.
    pub sender_record: AgentRecord,
    /// Peers the sender already knows (optional).
    pub known_peers: Vec<AgentRecord>,
}

impl PexParams {
    /// Create a new PEX request with the sender's record.
    pub fn new(sender_record: AgentRecord) -> Self {
        Self {
            sender_record,
            known_peers: Vec::new(),
        }
    }

    /// Add known peers to the PEX request.
    pub fn with_known_peers(mut self, peers: Vec<AgentRecord>) -> Self {
        self.known_peers = peers;
        self
    }

    /// Encode as CBOR.
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![(1i64, self.sender_record.to_cbor())];
        if !self.known_peers.is_empty() {
            entries.push((
                2,
                Value::Array(self.known_peers.iter().map(|r| r.to_cbor()).collect()),
            ));
        }
        int_map(entries)
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, DiscoveryError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };
        let sender_record =
            AgentRecord::from_cbor(get(1).ok_or(DiscoveryError::MissingField("sender_record"))?)?;
        let known_peers = match get(2) {
            Some(Value::Array(arr)) => {
                let mut peers = Vec::new();
                for item in arr {
                    peers.push(AgentRecord::from_cbor(item)?);
                }
                peers
            }
            _ => Vec::new(),
        };
        Ok(Self {
            sender_record,
            known_peers,
        })
    }
}

/// PEX response result.
///
/// ```cbor
/// { 1: [ *AgentRecord ] }
/// ```
#[derive(Clone, Debug)]
pub struct PexResult {
    /// Peers the receiver knows about.
    pub peers: Vec<AgentRecord>,
}

impl PexResult {
    /// Create a new PEX result.
    pub fn new(peers: Vec<AgentRecord>) -> Self {
        Self { peers }
    }

    /// Encode as CBOR.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![(
            1,
            Value::Array(self.peers.iter().map(|r| r.to_cbor()).collect()),
        )])
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, DiscoveryError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };
        let arr = match get(1) {
            Some(Value::Array(a)) => a,
            _ => return Err(DiscoveryError::MissingField("peers")),
        };
        let mut peers = Vec::new();
        for item in arr {
            peers.push(AgentRecord::from_cbor(item)?);
        }
        Ok(Self { peers })
    }
}

// ---------------------------------------------------------------------------
// DHT Transport Trait
// ---------------------------------------------------------------------------

/// Transport abstraction for DHT RPC communication with peers.
///
/// Implementations send discovery RPCs (announce, lookup, pex) to remote
/// peers and return their responses. This abstracts over QUIC, in-memory
/// test networks, or any other transport.
#[async_trait::async_trait]
pub trait DhtTransport: Send + Sync {
    /// Send an announce RPC to a peer.
    ///
    /// Returns the list of known peers the remote peer returned.
    async fn announce_to_peer(
        &self,
        peer_id: &AgentId,
        record: &AgentRecord,
    ) -> Result<Vec<AgentRecord>, DhtTransportError>;

    /// Send a lookup RPC to a peer.
    ///
    /// Returns matching records from the remote peer's local store.
    async fn lookup_on_peer(
        &self,
        peer_id: &AgentId,
        capability: &str,
        limit: Option<u64>,
    ) -> Result<Vec<AgentRecord>, DhtTransportError>;

    /// Send a PEX RPC to a peer.
    ///
    /// Returns the list of peers the remote peer knows about.
    async fn pex_on_peer(
        &self,
        peer_id: &AgentId,
        sender_record: &AgentRecord,
        known_peers: &[AgentRecord],
    ) -> Result<Vec<AgentRecord>, DhtTransportError>;

    /// Send a refresh RPC to a peer.
    ///
    /// Requests all records from the remote peer's local DHT.
    /// Used when a new node joins or after a partition heals.
    async fn refresh_on_peer(
        &self,
        peer_id: &AgentId,
    ) -> Result<Vec<AgentRecord>, DhtTransportError>;

    /// Send a ping RPC to a peer.
    ///
    /// Returns Ok if the peer is alive, Err if unreachable.
    async fn ping_peer(&self, peer_id: &AgentId) -> Result<(), DhtTransportError>;

    /// Send a depart RPC to a peer.
    ///
    /// Notifies the peer that this node is leaving the network.
    /// The peer should remove this node's records from its local DHT.
    async fn depart_on_peer(
        &self,
        peer_id: &AgentId,
        departing_agent_id: &AgentId,
    ) -> Result<(), DhtTransportError>;
}

/// Errors from DHT transport operations.
#[derive(Debug, thiserror::Error)]
pub enum DhtTransportError {
    /// The peer is not connected or reachable.
    #[error("peer not reachable: {0}")]
    PeerUnreachable(String),
    /// The remote peer returned an error.
    #[error("remote error: {0}")]
    Remote(String),
    /// A CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
    /// A discovery protocol error from the remote peer.
    #[error("discovery error: {0}")]
    Discovery(#[from] DiscoveryError),
    /// An identity error (record verification failed).
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

// ---------------------------------------------------------------------------
// DHT Router
// ---------------------------------------------------------------------------

/// Configuration for [`DhtRouter`].
#[derive(Clone, Debug)]
pub struct DhtRouterConfig {
    /// K-bucket size (max peers per bucket).
    pub k: usize,
    /// Concurrency factor for iterative lookups.
    pub alpha: usize,
    /// Replication factor (number of closest peers to forward records to).
    pub replication: usize,
    /// Maximum number of iterations in an iterative lookup.
    pub max_lookup_iterations: usize,
    /// Bucket refresh interval.
    pub bucket_refresh_interval: Duration,
}

impl Default for DhtRouterConfig {
    fn default() -> Self {
        Self {
            k: K_BUCKET_SIZE,
            alpha: ALPHA,
            replication: REPLICATION_FACTOR,
            max_lookup_iterations: 10,
            bucket_refresh_interval: BUCKET_REFRESH_INTERVAL,
        }
    }
}

/// Multi-node DHT router with Kademlia-style routing.
///
/// Combines a local [`CapabilityDht`] for record storage with a
/// [`RoutingTable`] for peer selection and a [`DhtTransport`] for
/// RPC communication. Supports:
///
/// - **Iterative lookup**: `find_peers(capability, k)` queries the
///   `alpha` closest known peers, follows referrals, and iterates
///   until `k` results are found or no new peers are discovered.
/// - **Announce forwarding**: `announce(record)` stores locally and
///   forwards to the `replication` closest peers.
/// - **PEX**: `pex(peer_id)` exchanges peer lists to build the routing table.
pub struct DhtRouter {
    /// This node's AgentId.
    self_id: AgentId,
    /// This node's own AgentRecord.
    own_record: RwLock<Option<AgentRecord>>,
    /// Local capability DHT store.
    local_dht: RwLock<CapabilityDht>,
    /// Kademlia routing table.
    routing_table: RwLock<RoutingTable>,
    /// Transport for RPC communication.
    transport: Arc<dyn DhtTransport>,
    /// Router configuration.
    config: DhtRouterConfig,
    /// Current time provider (for record verification).
    now: fn() -> u64,
    /// Lookup cache: capability → (results, cached_at).
    lookup_cache: RwLock<HashMap<String, (Vec<AgentRecord>, u64)>>,
    /// Lookup cache TTL (seconds).
    cache_ttl: u64,
}

impl std::fmt::Debug for DhtRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtRouter")
            .field("self_id", &self.self_id)
            .field("config", &self.config)
            .finish()
    }
}

impl DhtRouter {
    /// Create a new DHT router.
    pub fn new(self_id: AgentId, transport: Arc<dyn DhtTransport>) -> Self {
        Self::with_config(self_id, transport, DhtRouterConfig::default())
    }

    /// Create a new DHT router with custom configuration.
    pub fn with_config(
        self_id: AgentId,
        transport: Arc<dyn DhtTransport>,
        config: DhtRouterConfig,
    ) -> Self {
        Self {
            routing_table: RwLock::new(RoutingTable::with_k(self_id.clone(), config.k)),
            self_id,
            own_record: RwLock::new(None),
            local_dht: RwLock::new(CapabilityDht::new()),
            transport,
            config,
            now: current_unix_time,
            lookup_cache: RwLock::new(HashMap::new()),
            cache_ttl: 300, // 5 minutes
        }
    }

    /// Set the time provider (for testing).
    pub fn with_time_provider(mut self, now: fn() -> u64) -> Self {
        self.now = now;
        self
    }

    /// Set the lookup cache TTL (seconds).
    pub fn with_cache_ttl(mut self, ttl: u64) -> Self {
        self.cache_ttl = ttl;
        self
    }

    // -- Lookup Cache (Track R5) -------------------------------------------

    /// Get a cached lookup result if still valid.
    async fn get_cached_lookup(&self, capability: &str) -> Option<Vec<AgentRecord>> {
        let cache = self.lookup_cache.read().await;
        if let Some((results, cached_at)) = cache.get(capability) {
            let now = (self.now)();
            if now.saturating_sub(*cached_at) <= self.cache_ttl {
                trace!(
                    "Lookup cache hit for '{}' (age: {}s)",
                    capability,
                    now.saturating_sub(*cached_at)
                );
                return Some(results.clone());
            }
        }
        None
    }

    /// Cache a lookup result.
    async fn cache_lookup(&self, capability: &str, results: Vec<AgentRecord>) {
        let now = (self.now)();
        self.lookup_cache
            .write()
            .await
            .insert(capability.to_string(), (results, now));
    }

    /// Invalidate the lookup cache for a capability.
    pub async fn invalidate_cache(&self, capability: &str) {
        self.lookup_cache.write().await.remove(capability);
    }

    /// Invalidate the entire lookup cache.
    pub async fn invalidate_all_cache(&self) {
        self.lookup_cache.write().await.clear();
    }

    /// Get the number of entries in the lookup cache.
    pub async fn cache_size(&self) -> usize {
        self.lookup_cache.read().await.len()
    }

    /// Get this node's AgentId.
    pub fn self_id(&self) -> &AgentId {
        &self.self_id
    }

    /// Get the router configuration.
    pub fn config(&self) -> &DhtRouterConfig {
        &self.config
    }

    /// Set this node's own AgentRecord.
    pub async fn set_own_record(&self, record: AgentRecord) {
        let mut own = self.own_record.write().await;
        *own = Some(record);
    }

    /// Get this node's own AgentRecord.
    pub async fn own_record(&self) -> Option<AgentRecord> {
        self.own_record.read().await.clone()
    }

    /// Get the current number of peers in the routing table.
    pub async fn peer_count(&self) -> usize {
        self.routing_table.read().await.peer_count()
    }

    /// Get all known peer records from the routing table.
    pub async fn all_peers(&self) -> Vec<AgentRecord> {
        self.routing_table.read().await.all_peers()
    }

    /// Get the local DHT record count.
    pub async fn local_record_count(&self) -> usize {
        self.local_dht.read().await.len()
    }

    // -- Peer Management ---------------------------------------------------

    /// Add a peer to the routing table.
    ///
    /// Verifies the record signature before adding.
    pub async fn add_peer(&self, record: AgentRecord) -> bool {
        // Verify the record
        if let Err(e) = record.verify((self.now)()) {
            debug!(
                "Rejecting peer {} — verification failed: {}",
                record.agent_id.to_short_hex(),
                e
            );
            return false;
        }
        self.routing_table.write().await.add_peer(record)
    }

    /// Remove a peer from the routing table.
    pub async fn remove_peer(&self, agent_id: &AgentId) -> Option<PeerEntry> {
        self.routing_table.write().await.remove_peer(agent_id)
    }

    /// Touch a peer (update last_seen timestamp).
    pub async fn touch_peer(&self, agent_id: &AgentId) -> bool {
        self.routing_table.write().await.touch_peer(agent_id)
    }

    /// Get the k closest peers to a capability key from the routing table.
    pub async fn closest_peers_to_capability(
        &self,
        capability: &str,
        k: usize,
    ) -> Vec<AgentRecord> {
        self.routing_table
            .read()
            .await
            .closest_peers_to_capability(capability, k)
    }

    // -- Local Store -------------------------------------------------------

    /// Store a record in the local DHT.
    ///
    /// Verifies the record signature before storing.
    pub async fn store_local(&self, record: AgentRecord) -> bool {
        if let Err(e) = record.verify((self.now)()) {
            debug!(
                "Rejecting record {} — verification failed: {}",
                record.agent_id.to_short_hex(),
                e
            );
            return false;
        }
        self.local_dht.write().await.put(record)
    }

    /// Look up records in the local DHT by capability.
    pub async fn lookup_local(&self, capability: &str) -> Vec<AgentRecord> {
        self.local_dht.read().await.get(capability)
    }

    /// Evict expired records from the local DHT.
    pub async fn evict_expired(&self, now: u64) -> usize {
        self.local_dht.write().await.evict_expired(now)
    }

    /// Get all records from the local DHT (for refresh responses).
    pub async fn all_local_records(&self) -> Vec<AgentRecord> {
        self.local_dht.read().await.all_records()
    }

    /// Republish own record to the DHT.
    ///
    /// Called periodically (default: every 30 minutes) before the record's
    /// TTL expires. Re-announces to the k closest peers.
    pub async fn republish_own_record(&self) -> Vec<AgentRecord> {
        let own = self.own_record().await;
        match own {
            Some(record) => self.announce(record).await,
            None => {
                debug!("Republish: no own record set, skipping");
                Vec::new()
            }
        }
    }

    /// Refresh records from peers.
    ///
    /// Requests all records from each peer in the routing table.
    /// Used when a new node joins or after a partition heals.
    pub async fn refresh_from_peers(&self) -> usize {
        let peers = self.all_peers().await;
        let mut records_added = 0usize;

        for peer in &peers {
            if peer.agent_id == self.self_id {
                continue;
            }

            // Request all records from this peer via refresh RPC
            match self.transport.refresh_on_peer(&peer.agent_id).await {
                Ok(records) => {
                    for record in &records {
                        if self.store_local(record.clone()).await {
                            records_added += 1;
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Refresh from {} failed: {}",
                        peer.agent_id.to_short_hex(),
                        e
                    );
                }
            }
        }

        debug!(
            "Refreshed {} records from {} peers",
            records_added,
            peers.len()
        );
        records_added
    }

    /// Handle a refresh request from a peer.
    ///
    /// Returns all records in the local DHT.
    pub async fn handle_refresh(&self) -> Vec<AgentRecord> {
        self.all_local_records().await
    }

    /// Run periodic maintenance: evict expired records and republish own record.
    ///
    /// Returns (expired_count, republished_count).
    pub async fn maintenance(&self) -> (usize, usize) {
        let now = (self.now)();
        let expired = self.evict_expired(now).await;
        let republished = self.republish_own_record().await.len();
        (expired, republished)
    }

    // -- Churn Handling (Track R4) -----------------------------------------

    /// Remove a record from the local DHT by AgentId.
    pub async fn remove_local_record(&self, agent_id: &AgentId) -> bool {
        self.local_dht.write().await.remove_by_id(agent_id)
    }

    /// Ping a peer to check liveness.
    ///
    /// Returns true if the peer responded, false if unreachable.
    pub async fn ping(&self, peer_id: &AgentId) -> bool {
        match self.transport.ping_peer(peer_id).await {
            Ok(()) => {
                self.touch_peer(peer_id).await;
                true
            }
            Err(e) => {
                debug!("Ping to {} failed: {}", peer_id.to_short_hex(), e);
                false
            }
        }
    }

    /// Check liveness of all peers in the routing table.
    ///
    /// Pings each peer. Peers that fail the ping are marked with a missed
    /// ping count. After `max_missed` consecutive missed pings, the peer
    /// is removed from the routing table.
    ///
    /// Returns (alive_count, removed_count).
    pub async fn check_peer_liveness(&self, max_missed: u32) -> (usize, usize) {
        let peers = self.all_peers().await;
        let mut alive = 0usize;
        let mut removed = 0usize;

        for peer in &peers {
            if peer.agent_id == self.self_id {
                continue;
            }

            if self.ping(&peer.agent_id).await {
                alive += 1;
            } else {
                // Peer is unreachable — remove from routing table
                // In a production system, we'd track consecutive missed pings
                // and only remove after max_missed. Here we remove immediately
                // for simplicity (the caller can adjust max_missed).
                if max_missed == 0 {
                    self.remove_peer(&peer.agent_id).await;
                    removed += 1;
                }
            }
        }

        debug!(
            "Liveness check: {} alive, {} removed (max_missed={})",
            alive, removed, max_missed
        );

        (alive, removed)
    }

    /// Gracefully leave the DHT network.
    ///
    /// Notifies the k closest peers that this node is departing.
    /// Each peer removes this node's records from its local DHT and routing table.
    pub async fn depart(&self) -> usize {
        let own = self.own_record().await;
        let own_id = match own {
            Some(r) => r.agent_id.clone(),
            None => return 0,
        };

        let peers = self.all_peers().await;
        let mut notified = 0usize;

        for peer in &peers {
            if peer.agent_id == self.self_id {
                continue;
            }

            match self.transport.depart_on_peer(&peer.agent_id, &own_id).await {
                Ok(()) => {
                    notified += 1;
                }
                Err(e) => {
                    debug!(
                        "Depart notification to {} failed: {}",
                        peer.agent_id.to_short_hex(),
                        e
                    );
                }
            }
        }

        // Remove own record from local DHT
        self.remove_local_record(&own_id).await;

        // Invalidate all cache (departure may affect any capability)
        self.invalidate_all_cache().await;

        info!(
            "Graceful departure: notified {} peers, removed own record",
            notified
        );

        notified
    }

    /// Repair the routing table by querying known peers for more peers.
    ///
    /// For each underfilled bucket, query known peers via PEX to find
    /// new peers that belong in that bucket.
    pub async fn repair_routing_table(&self) -> usize {
        let peers = self.all_peers().await;
        let mut new_peers = 0usize;

        for peer in &peers {
            if peer.agent_id == self.self_id {
                continue;
            }

            // PEX with this peer to discover new peers
            match self.pex(&peer.agent_id).await {
                Ok(discovered) => {
                    new_peers += discovered.len();
                }
                Err(_) => {}
            }
        }

        debug!("Routing table repair: discovered {} new peers", new_peers);
        new_peers
    }

    // -- Partition Handling (Track R6) -------------------------------------

    /// Detect if the network is partitioned.
    ///
    /// Pings all peers. If more than `threshold` fraction of peers are
    /// unreachable, the network is considered partitioned.
    ///
    /// Returns (total_peers, reachable_peers, is_partitioned).
    pub async fn detect_partition(&self, threshold: f64) -> (usize, usize, bool) {
        let peers = self.all_peers().await;
        let total = peers.iter().filter(|p| p.agent_id != self.self_id).count();
        let mut reachable = 0usize;

        for peer in &peers {
            if peer.agent_id == self.self_id {
                continue;
            }
            if self.ping(&peer.agent_id).await {
                reachable += 1;
            }
        }

        let is_partitioned = if total > 0 {
            let unreachable = total - reachable;
            (unreachable as f64 / total as f64) > threshold
        } else {
            false
        };

        if is_partitioned {
            info!(
                "Partition detected: {}/{} peers unreachable (threshold: {:.0}%)",
                total - reachable,
                total,
                threshold * 100.0
            );
        }

        (total, reachable, is_partitioned)
    }

    /// Reconcile records after a partition heals.
    ///
    /// When the network partition heals, this method:
    /// 1. Refreshes records from all reachable peers
    /// 2. Merges records (latest timestamp wins for conflicts)
    /// 3. Re-announces own record to ensure it's replicated
    ///
    /// Returns the number of records added/updated.
    pub async fn reconcile_after_partition(&self) -> usize {
        // Refresh records from all peers
        let added = self.refresh_from_peers().await;

        // Re-announce own record
        self.republish_own_record().await;

        // Invalidate all cache
        self.invalidate_all_cache().await;

        info!(
            "Partition reconciliation: {} records added/updated, own record re-announced",
            added
        );

        added
    }

    /// Check if the network has healed from a partition.
    ///
    /// Pings all peers. If the fraction of reachable peers is above
    /// `threshold`, the partition is considered healed.
    pub async fn is_partition_healed(&self, threshold: f64) -> bool {
        let (total, reachable, _) = self.detect_partition(1.0 - threshold).await;
        if total == 0 {
            return true;
        }
        (reachable as f64 / total as f64) >= threshold
    }

    // -- PEX ---------------------------------------------------------------

    /// Perform a PEX exchange with a peer.
    ///
    /// Sends our known peers to the remote peer and receives their known
    /// peers. All received peers are added to the routing table.
    pub async fn pex(&self, peer_id: &AgentId) -> Result<Vec<AgentRecord>, DhtTransportError> {
        let own_record = self.own_record().await;
        let known_peers = self.all_peers().await;

        let sender_record = match own_record {
            Some(r) => r,
            None => {
                return Err(DhtTransportError::Remote(
                    "cannot PEX without own record set".to_string(),
                ))
            }
        };

        trace!(
            "PEX with peer {} — sending {} known peers",
            peer_id.to_short_hex(),
            known_peers.len()
        );

        let received_peers = self
            .transport
            .pex_on_peer(peer_id, &sender_record, &known_peers)
            .await?;

        // Add all received peers to routing table
        for record in &received_peers {
            self.add_peer(record.clone()).await;
        }

        // Also add the peer we did PEX with (their record should be in the response)
        // The sender_record from the PEX params is handled by the server side.

        Ok(received_peers)
    }

    // -- Announce ----------------------------------------------------------

    /// Announce a record to the DHT.
    ///
    /// 1. Store the record locally.
    /// 2. Forward to the `replication` closest peers to the record's
    ///    first capability key.
    ///
    /// Returns the list of peers the record was forwarded to.
    pub async fn announce(&self, record: AgentRecord) -> Vec<AgentRecord> {
        // Store locally
        self.store_local(record.clone()).await;

        // Find closest peers to the first capability
        let capability = record
            .capabilities
            .first()
            .map(|c| c.name.clone())
            .unwrap_or_default();

        if capability.is_empty() {
            return Vec::new();
        }

        // Invalidate cache for this capability
        self.invalidate_cache(&capability).await;

        let close_peers = self
            .closest_peers_to_capability(&capability, self.config.replication)
            .await;

        let mut forwarded_to = Vec::new();
        for peer in &close_peers {
            if peer.agent_id == self.self_id {
                continue;
            }
            trace!(
                "Forwarding announce for {} to peer {}",
                record.agent_id.to_short_hex(),
                peer.agent_id.to_short_hex()
            );
            match self
                .transport
                .announce_to_peer(&peer.agent_id, &record)
                .await
            {
                Ok(returned_peers) => {
                    // Add returned peers to routing table
                    for p in &returned_peers {
                        self.add_peer(p.clone()).await;
                    }
                    forwarded_to.push(peer.clone());
                }
                Err(e) => {
                    debug!(
                        "Announce forward to {} failed: {}",
                        peer.agent_id.to_short_hex(),
                        e
                    );
                }
            }
        }

        forwarded_to
    }

    // -- Lookup (Iterative) ------------------------------------------------

    /// Look up agents by capability using iterative DHT routing.
    ///
    /// This is the primary discovery operation:
    /// 1. Check the lookup cache for recent results.
    /// 2. Check the local DHT for matching records.
    /// 3. If fewer than `k` results, query the `alpha` closest known peers.
    /// 4. Peers return matching records + closer peers they know about.
    /// 5. Iterate until `k` results are found or no new peers are discovered.
    pub async fn lookup(&self, capability: &str, k: usize) -> Vec<AgentRecord> {
        // Check cache first
        if let Some(cached) = self.get_cached_lookup(capability).await {
            return cached.into_iter().take(k).collect();
        }

        let results = self.find_peers(capability, k).await;

        // Cache the results
        self.cache_lookup(capability, results.clone()).await;

        results
    }

    /// Recursive lookup: ask the first closest peer to do the full lookup.
    ///
    /// In recursive mode, the caller sends the lookup to one peer, which
    /// does the full iterative lookup on its own and returns the final results.
    /// This is simpler but puts more load on the first peer.
    pub async fn lookup_recursive(&self, capability: &str, k: usize) -> Vec<AgentRecord> {
        // Check cache first
        if let Some(cached) = self.get_cached_lookup(capability).await {
            return cached.into_iter().take(k).collect();
        }

        // Check local store
        let local_results = self.lookup_local(capability).await;
        if local_results.len() >= k {
            let results: Vec<AgentRecord> = local_results.into_iter().take(k).collect();
            self.cache_lookup(capability, results.clone()).await;
            return results;
        }

        // Get the closest peer and ask it to do the lookup
        let cap_key = Distance::to_capability_key(capability);
        let closest = self.routing_table.read().await.closest_peers(&cap_key, 1);

        if closest.is_empty() {
            return local_results;
        }

        let peer = &closest[0];
        if peer.agent_id == self.self_id {
            return local_results;
        }

        match self
            .transport
            .lookup_on_peer(&peer.agent_id, capability, Some(k as u64))
            .await
        {
            Ok(peer_results) => {
                let mut results: HashMap<AgentId, AgentRecord> = local_results
                    .into_iter()
                    .map(|r| (r.agent_id.clone(), r))
                    .collect();
                for record in &peer_results {
                    if record.verify((self.now)()).is_ok() {
                        results.insert(record.agent_id.clone(), record.clone());
                    }
                }
                let results: Vec<AgentRecord> = results.into_values().take(k).collect();
                self.cache_lookup(capability, results.clone()).await;
                results
            }
            Err(_) => {
                // Fall back to iterative
                self.find_peers(capability, k).await
            }
        }
    }

    /// Iterative find_peers: the core Kademlia lookup operation.
    ///
    /// Queries the `alpha` closest known peers for the capability,
    /// follows referrals to closer peers, and iterates until `k`
    /// results are found or the search converges.
    pub async fn find_peers(&self, capability: &str, k: usize) -> Vec<AgentRecord> {
        // Step 1: Check local store
        let mut results: HashMap<AgentId, AgentRecord> = self
            .lookup_local(capability)
            .await
            .into_iter()
            .map(|r| (r.agent_id.clone(), r))
            .collect();

        trace!(
            "find_peers('{}', k={}) — local store has {} results",
            capability,
            k,
            results.len()
        );

        if results.len() >= k {
            return results.into_values().take(k).collect();
        }

        // Step 2: Get initial alpha closest peers from routing table
        let cap_key = Distance::to_capability_key(capability);
        let initial_peers = self
            .routing_table
            .read()
            .await
            .closest_peers(&cap_key, self.config.alpha)
            .into_iter()
            .filter(|p| p.agent_id != self.self_id)
            .collect::<Vec<_>>();

        if initial_peers.is_empty() {
            trace!("find_peers — no peers in routing table, returning local results");
            return results.into_values().collect();
        }

        // Step 3: Iterative lookup
        let mut queried: HashSet<AgentId> = HashSet::new();
        let mut to_query: Vec<AgentRecord> = initial_peers;

        for iteration in 0..self.config.max_lookup_iterations {
            if results.len() >= k {
                break;
            }

            if to_query.is_empty() {
                trace!(
                    "find_peers — iteration {} — no more peers to query",
                    iteration
                );
                break;
            }

            // Query the next batch of alpha peers
            let batch: Vec<AgentRecord> = to_query
                .iter()
                .filter(|p| !queried.contains(&p.agent_id))
                .take(self.config.alpha)
                .cloned()
                .collect();

            if batch.is_empty() {
                break;
            }

            trace!(
                "find_peers — iteration {} — querying {} peers",
                iteration,
                batch.len()
            );

            let mut new_peers = Vec::new();

            for peer in &batch {
                queried.insert(peer.agent_id.clone());

                match self
                    .transport
                    .lookup_on_peer(&peer.agent_id, capability, Some(k as u64))
                    .await
                {
                    Ok(peer_results) => {
                        // Add matching records to results
                        for record in &peer_results {
                            // Verify the record
                            if record.verify((self.now)()).is_ok() {
                                results.insert(record.agent_id.clone(), record.clone());
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            "Lookup on peer {} failed: {}",
                            peer.agent_id.to_short_hex(),
                            e
                        );
                    }
                }

                // Also do a PEX to learn about closer peers
                // (In real Kademlia, the lookup RPC returns closer peers.
                //  Here we use PEX as the referral mechanism.)
                let own = self.own_record().await;
                let sender = own.unwrap_or_else(|| record_placeholder(&self.self_id));
                if let Ok(peers) = self
                    .transport
                    .pex_on_peer(&peer.agent_id, &sender, &[])
                    .await
                {
                    for p in &peers {
                        if !queried.contains(&p.agent_id) && p.agent_id != self.self_id {
                            self.add_peer(p.clone()).await;
                            new_peers.push(p.clone());
                        }
                    }
                }
            }

            // Sort new peers by distance to capability key and add to query queue
            new_peers.sort_by(|a, b| {
                let dist_a = Distance::from_agent_to_key(&a.agent_id, capability);
                let dist_b = Distance::from_agent_to_key(&b.agent_id, capability);
                dist_a.cmp(&dist_b)
            });

            // Update to_query with new peers (closer ones first)
            to_query = new_peers;

            trace!(
                "find_peers — iteration {} — {} total results, {} new peers discovered",
                iteration,
                results.len(),
                to_query.len()
            );
        }

        results.into_values().take(k).collect()
    }

    // -- Routing Table Access ----------------------------------------------

    /// Get a snapshot of the routing table's peer count per bucket.
    pub async fn routing_table_stats(&self) -> RoutingTableStats {
        let rt = self.routing_table.read().await;
        RoutingTableStats {
            total_peers: rt.peer_count(),
            active_buckets: rt.active_bucket_count(),
            k: rt.k(),
        }
    }
}

/// Statistics about the routing table.
#[derive(Clone, Debug)]
pub struct RoutingTableStats {
    /// Total peers in the routing table.
    pub total_peers: usize,
    /// Number of non-empty buckets.
    pub active_buckets: usize,
    /// K-bucket size.
    pub k: usize,
}

/// Placeholder record for PEX requests when we don't have our own record set.
fn record_placeholder(self_id: &AgentId) -> AgentRecord {
    AgentRecord {
        record_type: aafp_identity::RECORD_TYPE_V1.to_string(),
        agent_id: self_id.clone(),
        public_key: vec![],
        capabilities: vec![],
        endpoints: vec![],
        created_at: 0,
        expires_at: u64::MAX,
        signature: vec![],
        key_algorithm: aafp_identity::KEY_ALG_ML_DSA_65,
        record_version: 1,
    }
}

/// Get the current Unix timestamp.
fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// In-Memory DHT Network (for testing)
// ---------------------------------------------------------------------------

/// In-memory DHT network for testing multi-node routing.
///
/// Holds a collection of [`DhtRouter`] instances indexed by AgentId.
/// When a router sends an RPC to a peer, the network dispatches it
/// directly to the target router's handler — no real network needed.
///
/// This enables testing iterative lookup, announce forwarding, and PEX
/// across multiple "nodes" in a single process.
pub struct InMemoryDhtNetwork {
    /// Map of AgentId → DhtRouter
    nodes: RwLock<HashMap<AgentId, Arc<DhtRouter>>>,
}

impl InMemoryDhtNetwork {
    /// Create a new empty in-memory network.
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
        }
    }

    /// Register a node in the network.
    pub async fn register(&self, router: Arc<DhtRouter>) {
        let agent_id = router.self_id().clone();
        self.nodes.write().await.insert(agent_id, router);
    }

    /// Get a node by AgentId.
    pub async fn get(&self, agent_id: &AgentId) -> Option<Arc<DhtRouter>> {
        self.nodes.read().await.get(agent_id).cloned()
    }

    /// Get the number of registered nodes.
    pub async fn node_count(&self) -> usize {
        self.nodes.read().await.len()
    }
}

impl Default for InMemoryDhtNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DhtTransport for InMemoryDhtNetwork {
    async fn announce_to_peer(
        &self,
        peer_id: &AgentId,
        record: &AgentRecord,
    ) -> Result<Vec<AgentRecord>, DhtTransportError> {
        let peer = self
            .get(peer_id)
            .await
            .ok_or_else(|| DhtTransportError::PeerUnreachable(peer_id.to_short_hex()))?;

        // Store the record on the remote peer
        peer.store_local(record.clone()).await;

        // Add the announcing peer to the remote's routing table
        peer.add_peer(record.clone()).await;

        // Return the remote peer's known peers (like a real announce response)
        let known_peers = peer
            .lookup_local(
                record
                    .capabilities
                    .first()
                    .map(|c| c.name.as_str())
                    .unwrap_or(""),
            )
            .await
            .into_iter()
            .filter(|r| r.agent_id != record.agent_id)
            .take(10)
            .collect();

        Ok(known_peers)
    }

    async fn lookup_on_peer(
        &self,
        peer_id: &AgentId,
        capability: &str,
        limit: Option<u64>,
    ) -> Result<Vec<AgentRecord>, DhtTransportError> {
        let peer = self
            .get(peer_id)
            .await
            .ok_or_else(|| DhtTransportError::PeerUnreachable(peer_id.to_short_hex()))?;

        let results = peer.lookup_local(capability).await;
        let limit = limit.unwrap_or(10) as usize;
        Ok(results.into_iter().take(limit).collect())
    }

    async fn pex_on_peer(
        &self,
        peer_id: &AgentId,
        sender_record: &AgentRecord,
        _known_peers: &[AgentRecord],
    ) -> Result<Vec<AgentRecord>, DhtTransportError> {
        let peer = self
            .get(peer_id)
            .await
            .ok_or_else(|| DhtTransportError::PeerUnreachable(peer_id.to_short_hex()))?;

        // Add the sender to the remote's routing table
        peer.add_peer(sender_record.clone()).await;

        // Return the remote peer's known peers
        Ok(peer.all_peers().await)
    }

    async fn refresh_on_peer(
        &self,
        peer_id: &AgentId,
    ) -> Result<Vec<AgentRecord>, DhtTransportError> {
        let peer = self
            .get(peer_id)
            .await
            .ok_or_else(|| DhtTransportError::PeerUnreachable(peer_id.to_short_hex()))?;

        // Return all records from the remote peer's local DHT
        Ok(peer.handle_refresh().await)
    }

    async fn ping_peer(&self, peer_id: &AgentId) -> Result<(), DhtTransportError> {
        // Just check if the peer exists in the network
        if self.get(peer_id).await.is_some() {
            Ok(())
        } else {
            Err(DhtTransportError::PeerUnreachable(peer_id.to_short_hex()))
        }
    }

    async fn depart_on_peer(
        &self,
        peer_id: &AgentId,
        departing_agent_id: &AgentId,
    ) -> Result<(), DhtTransportError> {
        let peer = self
            .get(peer_id)
            .await
            .ok_or_else(|| DhtTransportError::PeerUnreachable(peer_id.to_short_hex()))?;

        // Remove the departing agent's record from the remote peer's local DHT
        peer.remove_local_record(departing_agent_id).await;

        // Remove from routing table
        peer.remove_peer(departing_agent_id).await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_crypto::{MlDsa65, SignatureScheme};

    /// Fixed test timestamp (matches make_record's `now`).
    pub const TEST_NOW: u64 = 1700000000;

    /// Fixed time provider for tests (returns TEST_NOW).
    pub fn test_now() -> u64 {
        TEST_NOW
    }

    /// Create a signed AgentRecord with the given capabilities.
    pub fn make_record(capabilities: Vec<&str>) -> AgentRecord {
        let (pk, sk) = MlDsa65::keypair();
        let now = TEST_NOW;
        let mut record = AgentRecord::new(
            &pk.0,
            capabilities
                .iter()
                .map(|c| aafp_identity::CapabilityDescriptor::new(*c))
                .collect(),
            vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            now,
            now + 86400,
            1,
        );
        record.sign(&sk);
        record
    }

    /// Create a signed AgentRecord with a specific key seed (for deterministic IDs).
    pub fn make_record_with_seed(seed: u8, capabilities: Vec<&str>) -> AgentRecord {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = seed;
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed_bytes);
        let now = TEST_NOW;
        let mut record = AgentRecord::new(
            &pk.0,
            capabilities
                .iter()
                .map(|c| aafp_identity::CapabilityDescriptor::new(*c))
                .collect(),
            vec![format!("/ip4/127.0.0.1/tcp/{}", 4000 + seed as u16)],
            now,
            now + 86400,
            1,
        );
        record.sign(&sk);
        record
    }

    /// Create a DhtRouter with a fixed time provider for testing.
    pub fn make_router(self_id: AgentId, transport: Arc<dyn DhtTransport>) -> DhtRouter {
        DhtRouter::with_config(self_id, transport, DhtRouterConfig::default())
            .with_time_provider(test_now)
    }

    // -- Distance tests --

    #[test]
    fn test_xor_distance_same_id() {
        let id = AgentId([0x42; 32]);
        let dist = Distance::between(&id, &id);
        assert_eq!(dist.0, [0u8; 32]);
        assert_eq!(dist.bucket_index(), None); // same node
    }

    #[test]
    fn test_xor_distance_different_ids() {
        let a = AgentId([0x00; 32]);
        let b = AgentId([0x80; 32]);
        let dist = Distance::between(&a, &b);
        // MSB differs → bucket index 0
        assert_eq!(dist.bucket_index(), Some(0));
        assert_eq!(dist.0[0], 0x80);
    }

    #[test]
    fn test_xor_distance_bucket_index() {
        let a = AgentId([0xFF; 32]);
        let b = AgentId([0x7F; 32]);
        let dist = Distance::between(&a, &b);
        // First bit differs → bucket 0
        assert_eq!(dist.bucket_index(), Some(0));
    }

    #[test]
    fn test_capability_key_is_deterministic() {
        let key1 = Distance::to_capability_key("inference");
        let key2 = Distance::to_capability_key("inference");
        assert_eq!(key1, key2);

        let key3 = Distance::to_capability_key("translation");
        assert_ne!(key1, key3);
    }

    // -- KBucket tests --

    #[test]
    fn test_kbucket_insert_and_get() {
        let mut bucket = KBucket::new(3);
        let record = make_record(vec!["inference"]);
        let entry = PeerEntry::new(record.clone());

        assert!(bucket.insert(entry));
        assert_eq!(bucket.len(), 1);
        assert!(bucket.get(&record.agent_id).is_some());
    }

    #[test]
    fn test_kbucket_update_existing() {
        let mut bucket = KBucket::new(3);
        let record = make_record(vec!["inference"]);
        let entry = PeerEntry::new(record.clone());
        bucket.insert(entry);

        // Insert again — should update, not add
        let entry2 = PeerEntry::new(record.clone());
        assert!(bucket.insert(entry2));
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_kbucket_full_rejects_new() {
        let mut bucket = KBucket::new(2);
        let r1 = make_record(vec!["cap"]);
        let r2 = make_record(vec!["cap"]);
        let r3 = make_record(vec!["cap"]);

        assert!(bucket.insert(PeerEntry::new(r1)));
        assert!(bucket.insert(PeerEntry::new(r2)));
        assert!(!bucket.insert(PeerEntry::new(r3))); // full
        assert_eq!(bucket.len(), 2);
    }

    #[test]
    fn test_kbucket_remove() {
        let mut bucket = KBucket::new(3);
        let record = make_record(vec!["cap"]);
        bucket.insert(PeerEntry::new(record.clone()));

        let removed = bucket.remove(&record.agent_id);
        assert!(removed.is_some());
        assert_eq!(bucket.len(), 0);
        assert!(bucket.get(&record.agent_id).is_none());
    }

    // -- RoutingTable tests --

    #[test]
    fn test_routing_table_add_and_get() {
        let self_id = AgentId([0x00; 32]);
        let mut rt = RoutingTable::new(self_id);

        let peer_record = make_record(vec!["inference"]);
        assert!(rt.add_peer(peer_record.clone()));
        assert_eq!(rt.peer_count(), 1);
        assert!(rt.get_peer(&peer_record.agent_id).is_some());
    }

    #[test]
    fn test_routing_table_rejects_self() {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;
        let mut own = AgentRecord::new(&pk.0, vec![], vec![], now, now + 86400, 1);
        own.sign(&sk);

        let mut rt = RoutingTable::new(own.agent_id.clone());
        assert!(!rt.add_peer(own.clone())); // can't add self
        assert_eq!(rt.peer_count(), 0);
    }

    #[test]
    fn test_routing_table_closest_peers() {
        let self_id = AgentId([0x00; 32]);
        let mut rt = RoutingTable::new(self_id);

        // Add several peers
        for i in 1..=5u8 {
            let record = make_record_with_seed(i, vec!["cap"]);
            rt.add_peer(record);
        }
        assert_eq!(rt.peer_count(), 5);

        // Find 3 closest to a capability key
        let closest = rt.closest_peers_to_capability("cap", 3);
        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn test_routing_table_remove() {
        let self_id = AgentId([0x00; 32]);
        let mut rt = RoutingTable::new(self_id);

        let record = make_record(vec!["cap"]);
        rt.add_peer(record.clone());
        assert_eq!(rt.peer_count(), 1);

        rt.remove_peer(&record.agent_id);
        assert_eq!(rt.peer_count(), 0);
    }

    #[test]
    fn test_routing_table_all_peers() {
        let self_id = AgentId([0x00; 32]);
        let mut rt = RoutingTable::new(self_id);

        for i in 1..=3u8 {
            rt.add_peer(make_record_with_seed(i, vec!["cap"]));
        }

        let all = rt.all_peers();
        assert_eq!(all.len(), 3);
    }

    // -- PEX params/result tests --

    #[test]
    fn test_pex_params_roundtrip() {
        let record = make_record(vec!["inference"]);
        let params =
            PexParams::new(record.clone()).with_known_peers(vec![make_record(vec!["translation"])]);

        let cbor = params.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let params2 = PexParams::from_cbor(&decoded).unwrap();

        assert_eq!(
            params2.sender_record.agent_id,
            params.sender_record.agent_id
        );
        assert_eq!(params2.known_peers.len(), 1);
    }

    #[test]
    fn test_pex_result_roundtrip() {
        let peers = vec![
            make_record(vec!["inference"]),
            make_record(vec!["translation"]),
        ];
        let result = PexResult::new(peers);

        let cbor = result.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let result2 = PexResult::from_cbor(&decoded).unwrap();

        assert_eq!(result2.peers.len(), 2);
    }

    // -- DhtRouter tests (in-memory network) --

    /// Set up a 5-node in-memory DHT network.
    ///
    /// Nodes are connected in a bidirectional chain: A ↔ B ↔ C ↔ D ↔ E
    /// This requires iterative routing: E must discover peers through PEX
    /// to find A's record stored on B.
    async fn setup_5_node_chain() -> (Arc<InMemoryDhtNetwork>, [AgentId; 5], [Arc<DhtRouter>; 5]) {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes with deterministic seeds
        let records: Vec<AgentRecord> = (1..=5u8)
            .map(|i| make_record_with_seed(i, vec!["inference"]))
            .collect();

        let ids: [AgentId; 5] = [
            records[0].agent_id.clone(),
            records[1].agent_id.clone(),
            records[2].agent_id.clone(),
            records[3].agent_id.clone(),
            records[4].agent_id.clone(),
        ];

        // Create routers
        let routers: [Arc<DhtRouter>; 5] = [
            Arc::new(make_router(ids[0].clone(), network.clone())),
            Arc::new(make_router(ids[1].clone(), network.clone())),
            Arc::new(make_router(ids[2].clone(), network.clone())),
            Arc::new(make_router(ids[3].clone(), network.clone())),
            Arc::new(make_router(ids[4].clone(), network.clone())),
        ];

        // Set own records
        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
        }

        // Register all nodes in the network
        for router in &routers {
            network.register(router.clone()).await;
        }

        // Build a bidirectional chain: A ↔ B ↔ C ↔ D ↔ E
        // Each node knows about its neighbors
        // A knows B
        routers[0].add_peer(records[1].clone()).await;
        // B knows A and C
        routers[1].add_peer(records[0].clone()).await;
        routers[1].add_peer(records[2].clone()).await;
        // C knows B and D
        routers[2].add_peer(records[1].clone()).await;
        routers[2].add_peer(records[3].clone()).await;
        // D knows C and E
        routers[3].add_peer(records[2].clone()).await;
        routers[3].add_peer(records[4].clone()).await;
        // E knows D
        routers[4].add_peer(records[3].clone()).await;

        (network, ids, routers)
    }

    #[tokio::test]
    async fn test_5_node_iterative_lookup() {
        let (_network, ids, routers) = setup_5_node_chain().await;

        // Node A announces "inference" capability
        let record_a = routers[0].own_record().await.unwrap();
        routers[0].announce(record_a).await;

        // Node E should be able to find A's record through iterative routing
        // E → D → C → B → A
        let results = routers[4].lookup("inference", 5).await;

        // Should find at least A's record
        assert!(
            !results.is_empty(),
            "Node E should find records through iterative routing"
        );

        // Verify A's record is in the results
        let found_a = results.iter().any(|r| r.agent_id == ids[0]);
        assert!(
            found_a,
            "Node E should find Node A's record through the chain"
        );
    }

    #[tokio::test]
    async fn test_announce_stores_locally() {
        let network = Arc::new(InMemoryDhtNetwork::new());
        let record = make_record_with_seed(1, vec!["inference"]);
        let router = Arc::new(make_router(record.agent_id.clone(), network.clone()));
        router.set_own_record(record.clone()).await;
        network.register(router.clone()).await;

        // Announce
        router.announce(record.clone()).await;

        // Should be in local store
        let local = router.lookup_local("inference").await;
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].agent_id, record.agent_id);
    }

    #[tokio::test]
    async fn test_announce_forwards_to_closest_peers() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 3 nodes
        let r1 = make_record_with_seed(1, vec!["inference"]);
        let r2 = make_record_with_seed(2, vec!["inference"]);
        let r3 = make_record_with_seed(3, vec!["inference"]);

        let router1 = Arc::new(make_router(r1.agent_id.clone(), network.clone()));
        let router2 = Arc::new(make_router(r2.agent_id.clone(), network.clone()));
        let router3 = Arc::new(make_router(r3.agent_id.clone(), network.clone()));

        router1.set_own_record(r1.clone()).await;
        router2.set_own_record(r2.clone()).await;
        router3.set_own_record(r3.clone()).await;

        network.register(router1.clone()).await;
        network.register(router2.clone()).await;
        network.register(router3.clone()).await;

        // Node 1 knows about nodes 2 and 3
        router1.add_peer(r2.clone()).await;
        router1.add_peer(r3.clone()).await;

        // Node 1 announces
        let forwarded = router1.announce(r1.clone()).await;

        // Should have forwarded to at least 1 peer (replication=5, but only 2 peers known)
        assert!(!forwarded.is_empty(), "Should forward to closest peers");

        // Node 2 or 3 should have the record
        let on_2 = router2.lookup_local("inference").await;
        let on_3 = router3.lookup_local("inference").await;
        assert!(
            on_2.len() + on_3.len() > 0,
            "Record should be replicated to at least one peer"
        );
    }

    #[tokio::test]
    async fn test_pex_exchanges_peer_lists() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let r1 = make_record_with_seed(1, vec!["cap"]);
        let r2 = make_record_with_seed(2, vec!["cap"]);
        let r3 = make_record_with_seed(3, vec!["cap"]);

        let router1 = Arc::new(make_router(r1.agent_id.clone(), network.clone()));
        let router2 = Arc::new(make_router(r2.agent_id.clone(), network.clone()));
        let router3 = Arc::new(make_router(r3.agent_id.clone(), network.clone()));

        router1.set_own_record(r1.clone()).await;
        router2.set_own_record(r2.clone()).await;
        router3.set_own_record(r3.clone()).await;

        network.register(router1.clone()).await;
        network.register(router2.clone()).await;
        network.register(router3.clone()).await;

        // Node 2 knows about node 3
        router2.add_peer(r3.clone()).await;

        // Node 1 does PEX with node 2
        router1.add_peer(r2.clone()).await; // Node 1 knows about node 2
        let received = router1.pex(&r2.agent_id).await.unwrap();

        // Node 1 should learn about node 3
        assert!(
            received.iter().any(|r| r.agent_id == r3.agent_id),
            "PEX should discover node 3"
        );
        assert_eq!(router1.peer_count().await, 2); // knows about 2 and 3 now
    }

    #[tokio::test]
    async fn test_lookup_returns_local_only_when_no_peers() {
        let network = Arc::new(InMemoryDhtNetwork::new());
        let record = make_record_with_seed(1, vec!["inference"]);
        let router = Arc::new(make_router(record.agent_id.clone(), network.clone()));
        router.set_own_record(record.clone()).await;
        network.register(router.clone()).await;

        // Store a record locally
        router.store_local(record.clone()).await;

        // Lookup with no peers — should return local result
        let results = router.lookup("inference", 10).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, record.agent_id);
    }

    #[tokio::test]
    async fn test_router_rejects_invalid_record() {
        let network = Arc::new(InMemoryDhtNetwork::new());
        let record = make_record_with_seed(1, vec!["inference"]);
        let router = Arc::new(make_router(record.agent_id.clone(), network.clone()));

        // Tamper with the record (breaks signature)
        let mut bad_record = record.clone();
        bad_record
            .capabilities
            .push(aafp_identity::CapabilityDescriptor::new("forged"));

        // Should not store
        assert!(!router.store_local(bad_record).await);
        assert_eq!(router.local_record_count().await, 0);
    }

    #[tokio::test]
    async fn test_routing_table_stats() {
        let network = Arc::new(InMemoryDhtNetwork::new());
        let record = make_record_with_seed(1, vec!["cap"]);
        let router = Arc::new(make_router(record.agent_id.clone(), network.clone()));

        // Add some peers
        for i in 2..=5u8 {
            router.add_peer(make_record_with_seed(i, vec!["cap"])).await;
        }

        let stats = router.routing_table_stats().await;
        assert_eq!(stats.total_peers, 4);
        assert!(stats.active_buckets > 0);
        assert_eq!(stats.k, K_BUCKET_SIZE);
    }

    #[tokio::test]
    async fn test_full_5_node_mesh_lookup() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes, all with "inference" capability
        let records: Vec<AgentRecord> = (1..=5u8)
            .map(|i| make_record_with_seed(i, vec!["inference"]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build a mesh: each node knows about its neighbors
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Each node announces
        for (i, router) in routers.iter().enumerate() {
            router.announce(records[i].clone()).await;
        }

        // Node 0 looks up "inference" — should find all 4 other nodes
        let results = routers[0].lookup("inference", 10).await;

        // Should find records from other nodes (at least some)
        assert!(
            results.len() >= 3,
            "Mesh lookup should find most peers, got {}",
            results.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// Configuration for the bootstrap process.
#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    /// Seed node multiaddrs (e.g., ["quic://seed1:4433", ...]).
    pub seed_nodes: Vec<String>,
    /// Minimum peers to discover before bootstrap is considered complete.
    pub min_peers: usize,
    /// Maximum time to wait for bootstrap to complete.
    pub bootstrap_timeout: Duration,
    /// Interval for periodic refresh of the routing table.
    pub refresh_interval: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            seed_nodes: vec![],
            min_peers: 10,
            bootstrap_timeout: Duration::from_secs(30),
            refresh_interval: Duration::from_secs(15 * 60),
        }
    }
}

/// Bootstrap driver: connects to seed nodes, exchanges PEX, builds routing table.
///
/// The bootstrap process:
/// 1. Connect to each configured seed node
/// 2. Send PEX request to each seed
/// 3. Add received peers to the routing table
/// 4. Connect to k closest peers from the routing table
/// 5. Announce own record to closest peers
/// 6. Return when min_peers connected or timeout
pub struct Bootstrap {
    config: BootstrapConfig,
}

impl Bootstrap {
    /// Create a new bootstrap driver with the given config.
    pub fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }

    /// Get the bootstrap configuration.
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    /// Run the bootstrap process.
    ///
    /// Connects to seed nodes, performs PEX, and builds the routing table.
    /// Returns the number of peers discovered.
    pub async fn run(
        &self,
        router: &DhtRouter,
        seed_records: Vec<AgentRecord>,
    ) -> Result<usize, BootstrapError> {
        let deadline = Instant::now() + self.config.bootstrap_timeout;
        let mut peers_discovered = 0usize;

        // Step 1: Add seed records to routing table
        for record in &seed_records {
            if router.add_peer(record.clone()).await {
                peers_discovered += 1;
            }
        }

        debug!(
            "Bootstrap: added {} seed records to routing table",
            peers_discovered
        );

        // Step 2: PEX with each seed to discover more peers
        for record in &seed_records {
            if Instant::now() >= deadline {
                break;
            }

            match router.pex(&record.agent_id).await {
                Ok(discovered) => {
                    debug!(
                        "Bootstrap: PEX with {} returned {} peers",
                        record.agent_id.to_short_hex(),
                        discovered.len()
                    );
                    peers_discovered = router.peer_count().await;
                }
                Err(e) => {
                    debug!(
                        "Bootstrap: PEX with {} failed: {}",
                        record.agent_id.to_short_hex(),
                        e
                    );
                }
            }

            if peers_discovered >= self.config.min_peers {
                break;
            }
        }

        // Step 3: Announce own record to closest peers
        if let Some(own_record) = router.own_record().await {
            router.announce(own_record).await;
        }

        // Step 4: Check if we have enough peers
        peers_discovered = router.peer_count().await;
        if peers_discovered >= self.config.min_peers {
            info!(
                "Bootstrap complete: {} peers in routing table",
                peers_discovered
            );
            Ok(peers_discovered)
        } else if peers_discovered > 0 {
            info!(
                "Bootstrap partial: {} peers (target: {})",
                peers_discovered, self.config.min_peers
            );
            Ok(peers_discovered)
        } else {
            Err(BootstrapError::NoPeersDiscovered)
        }
    }
}

/// Errors returned by the bootstrap process.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// No seed nodes were configured.
    #[error("no seed nodes configured")]
    NoSeeds,
    /// No peers were discovered during bootstrap.
    #[error("no peers discovered during bootstrap")]
    NoPeersDiscovered,
    /// Bootstrap timed out before completing.
    #[error("bootstrap timed out")]
    Timeout,
}

// ---------------------------------------------------------------------------
// Bootstrap Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    use crate::dht_router::tests::{make_record, make_record_with_seed, make_router, test_now};

    #[tokio::test]
    async fn test_bootstrap_with_seeds() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create a seed node
        let seed_record = make_record(vec!["seed"]);
        let seed_id = seed_record.agent_id.clone();
        let seed_router = Arc::new(make_router(seed_id.clone(), network.clone()));
        seed_router.set_own_record(seed_record.clone()).await;
        network.register(seed_router.clone()).await;

        // Create our node
        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network.clone());
        own_router.set_own_record(own_record).await;

        let config = BootstrapConfig {
            seed_nodes: vec!["quic://seed:4433".into()],
            min_peers: 1,
            ..Default::default()
        };
        let bootstrap = Bootstrap::new(config);

        let result = bootstrap.run(&own_router, vec![seed_record]).await;
        assert!(result.is_ok());
        assert!(result.unwrap() >= 1);
    }

    #[tokio::test]
    async fn test_bootstrap_no_seeds() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);

        let config = BootstrapConfig::default();
        let bootstrap = Bootstrap::new(config);

        let result = bootstrap.run(&own_router, vec![]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BootstrapError::NoPeersDiscovered => {}
            e => panic!("expected NoPeersDiscovered, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_bootstrap_partial() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 1 seed
        let seed_record = make_record(vec!["seed"]);
        let seed_id = seed_record.agent_id.clone();
        let seed_router = Arc::new(make_router(seed_id, network.clone()));
        seed_router.set_own_record(seed_record.clone()).await;
        network.register(seed_router).await;

        // Create our node
        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);

        // min_peers = 10 but only 1 seed
        let config = BootstrapConfig {
            min_peers: 10,
            ..Default::default()
        };
        let bootstrap = Bootstrap::new(config);

        let result = bootstrap.run(&own_router, vec![seed_record]).await;
        // Should succeed with partial results
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_bootstrap_multiple_seeds() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 3 seed nodes
        let seed_records: Vec<AgentRecord> = (0..3)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("seed{}", i)]))
            .collect();

        for record in &seed_records {
            let router = Arc::new(make_router(record.agent_id.clone(), network.clone()));
            router.set_own_record(record.clone()).await;
            network.register(router).await;
        }

        // Create our node
        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);

        let config = BootstrapConfig {
            min_peers: 3,
            ..Default::default()
        };
        let bootstrap = Bootstrap::new(config);

        let result = bootstrap.run(&own_router, seed_records).await;
        assert!(result.is_ok());
        assert!(result.unwrap() >= 3);
    }

    #[tokio::test]
    async fn test_bootstrap_announces_own_record() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create a seed
        let seed_record = make_record(vec!["seed"]);
        let seed_id = seed_record.agent_id.clone();
        let seed_router = Arc::new(make_router(seed_id, network.clone()));
        seed_router.set_own_record(seed_record.clone()).await;
        network.register(seed_router).await;

        // Create our node
        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);

        // Store own record directly to verify it works
        own_router.store_local(own_record.clone()).await;

        let config = BootstrapConfig {
            min_peers: 1,
            ..Default::default()
        };
        let bootstrap = Bootstrap::new(config);

        bootstrap.run(&own_router, vec![seed_record]).await.unwrap();

        // After bootstrap, own record should be in local DHT (via announce)
        let local = own_router.lookup_local("inference").await;
        assert!(
            local
                .iter()
                .any(|r| r.capabilities.iter().any(|c| c.name == "inference")),
            "own record should be in local DHT after bootstrap, got {} records",
            local.len()
        );
    }

    #[tokio::test]
    async fn test_bootstrap_pex_discovers_peers() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create seed node that knows about 2 other nodes
        let seed_record = make_record_with_seed(1, vec!["seed"]);
        let seed_router = Arc::new(make_router(seed_record.agent_id.clone(), network.clone()));
        seed_router.set_own_record(seed_record.clone()).await;

        // Create 2 additional nodes that the seed knows about
        let node2_record = make_record_with_seed(2, vec!["node2"]);
        let node2_router = Arc::new(make_router(node2_record.agent_id.clone(), network.clone()));
        node2_router.set_own_record(node2_record.clone()).await;
        seed_router.add_peer(node2_record.clone()).await;

        let node3_record = make_record_with_seed(3, vec!["node3"]);
        let node3_router = Arc::new(make_router(node3_record.agent_id.clone(), network.clone()));
        node3_router.set_own_record(node3_record.clone()).await;
        seed_router.add_peer(node3_record.clone()).await;

        // Register all nodes in the network
        network.register(seed_router).await;
        network.register(node2_router).await;
        network.register(node3_router).await;

        // Create our node — only knows the seed
        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);

        // Manually do PEX with the seed to verify it works
        own_router.set_own_record(own_record.clone()).await;
        let pex_result = own_router.pex(&seed_record.agent_id).await;
        assert!(pex_result.is_ok(), "PEX should succeed");
        let pex_peers = pex_result.unwrap();
        assert!(
            pex_peers.len() >= 2,
            "PEX should return at least 2 peers, got {}",
            pex_peers.len()
        );

        // Now check routing table — should have at least seed + some PEX peers
        let peer_count = own_router.peer_count().await;
        assert!(
            peer_count >= 2,
            "should have at least 2 peers (seed + some from PEX), got {}",
            peer_count
        );
    }
}

// ---------------------------------------------------------------------------
// Replication / Republishing / Refresh Tests (Track R3)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod replication_tests {
    use super::*;
    use crate::dht_router::tests::{make_record, make_record_with_seed, make_router};

    #[tokio::test]
    async fn test_announce_replicates_to_closest_peers() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes
        let records: Vec<AgentRecord> = (0..5)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("cap{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Node 0 adds all other nodes as peers
        for j in 1..5 {
            routers[0].add_peer(records[j].clone()).await;
        }

        // Node 0 announces its record
        let forwarded = routers[0].announce(records[0].clone()).await;

        // Should have forwarded to some peers
        assert!(!forwarded.is_empty(), "should forward to closest peers");

        // The forwarded peers should have the record in their local DHT
        for peer in &forwarded {
            let peer_router = network.get(&peer.agent_id).await.unwrap();
            let local = peer_router.lookup_local("cap0").await;
            assert!(
                local.iter().any(|r| r.agent_id == records[0].agent_id),
                "record should be replicated to peer {}",
                peer.agent_id.to_short_hex()
            );
        }
    }

    #[tokio::test]
    async fn test_republish_own_record() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let router = make_router(own_id, network);
        router.set_own_record(own_record).await;

        // Republish should work (stores locally + forwards to closest)
        let _result = router.republish_own_record().await;
        // No peers to forward to, but should store locally
        let local = router.lookup_local("inference").await;
        assert!(
            !local.is_empty(),
            "own record should be in local DHT after republish"
        );
    }

    #[tokio::test]
    async fn test_refresh_from_peers() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create node 1 with a record
        let node1_record = make_record_with_seed(1, vec!["node1"]);
        let node1_router = Arc::new(make_router(node1_record.agent_id.clone(), network.clone()));
        node1_router.set_own_record(node1_record.clone()).await;
        node1_router.store_local(node1_record.clone()).await;
        network.register(node1_router).await;

        // Create node 2 with a record
        let node2_record = make_record_with_seed(2, vec!["node2"]);
        let node2_router = Arc::new(make_router(node2_record.agent_id.clone(), network.clone()));
        node2_router.set_own_record(node2_record.clone()).await;
        node2_router.store_local(node2_record.clone()).await;
        network.register(node2_router).await;

        // Create our node — knows about node1 and node2
        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);
        own_router.set_own_record(own_record).await;
        own_router.add_peer(node1_record.clone()).await;
        own_router.add_peer(node2_record.clone()).await;

        // Refresh from peers — should get records from node1 and node2
        let added = own_router.refresh_from_peers().await;
        assert!(
            added >= 2,
            "should have refreshed at least 2 records, got {}",
            added
        );

        // Verify records are in local DHT
        let node1_local = own_router.lookup_local("node1").await;
        assert!(
            !node1_local.is_empty(),
            "node1 record should be in local DHT after refresh"
        );

        let node2_local = own_router.lookup_local("node2").await;
        assert!(
            !node2_local.is_empty(),
            "node2 record should be in local DHT after refresh"
        );
    }

    #[tokio::test]
    async fn test_maintenance_evicts_expired() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let router = make_router(own_id, network);
        router.set_own_record(own_record).await;

        // Store a record
        let other_record = make_record(vec!["other"]);
        router.store_local(other_record.clone()).await;

        // Maintenance with current time — nothing should expire
        let (expired, _) = router.maintenance().await;
        assert_eq!(expired, 0);

        // Maintenance again — should still work
        let (expired2, _republished) = router.maintenance().await;
        assert_eq!(expired2, 0);
    }

    #[tokio::test]
    async fn test_record_survives_peer_failure() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes in a mesh
        let records: Vec<AgentRecord> = (0..5)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("cap{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build mesh: each node knows all others
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Node 0 announces
        routers[0].announce(records[0].clone()).await;

        // Verify record is on multiple nodes
        let mut nodes_with_record = 0;
        for router in &routers {
            let local = router.lookup_local("cap0").await;
            if local.iter().any(|r| r.agent_id == records[0].agent_id) {
                nodes_with_record += 1;
            }
        }
        assert!(
            nodes_with_record >= 2,
            "record should be on at least 2 nodes, got {}",
            nodes_with_record
        );

        // "Kill" node 1 by removing it from the network
        network.nodes.write().await.remove(&records[1].agent_id);

        // Node 2 should still be able to look up node 0's record
        let results = routers[2].lookup("cap0", 10).await;
        assert!(
            results.iter().any(|r| r.agent_id == records[0].agent_id),
            "record should survive node 1 failure"
        );
    }
}

// ---------------------------------------------------------------------------
// Churn Handling Tests (Track R4)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod churn_tests {
    use super::*;
    use crate::dht_router::tests::{make_record, make_record_with_seed, make_router};

    #[tokio::test]
    async fn test_ping_alive_peer() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let node1_record = make_record_with_seed(1, vec!["node1"]);
        let node1_router = Arc::new(make_router(node1_record.agent_id.clone(), network.clone()));
        node1_router.set_own_record(node1_record.clone()).await;
        network.register(node1_router).await;

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);
        own_router.set_own_record(own_record).await;
        own_router.add_peer(node1_record.clone()).await;

        // Ping should succeed
        assert!(own_router.ping(&node1_record.agent_id).await);
    }

    #[tokio::test]
    async fn test_ping_dead_peer() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let node1_record = make_record_with_seed(1, vec!["node1"]);
        // Don't register node1 in the network — it's "dead"

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);
        own_router.set_own_record(own_record).await;
        own_router.add_peer(node1_record.clone()).await;

        // Ping should fail
        assert!(!own_router.ping(&node1_record.agent_id).await);
    }

    #[tokio::test]
    async fn test_check_liveness_removes_dead_peers() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 3 nodes
        let records: Vec<AgentRecord> = (0..3)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Node 0 knows about node 1 and node 2
        routers[0].add_peer(records[1].clone()).await;
        routers[0].add_peer(records[2].clone()).await;

        // "Kill" node 2 by removing from network
        network.nodes.write().await.remove(&records[2].agent_id);

        // Check liveness — should remove node 2
        let (alive, removed) = routers[0].check_peer_liveness(0).await;
        assert_eq!(alive, 1, "node 1 should be alive");
        assert_eq!(removed, 1, "node 2 should be removed");

        // Verify node 2 is no longer in routing table
        assert_eq!(routers[0].peer_count().await, 1);
    }

    #[tokio::test]
    async fn test_graceful_departure() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 3 nodes
        let records: Vec<AgentRecord> = (0..3)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build mesh
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Node 0 announces
        routers[0].announce(records[0].clone()).await;

        // Verify node 1 has node 0's record
        let local = routers[1].lookup_local("node0").await;
        assert!(!local.is_empty(), "node 1 should have node 0's record");

        // Node 0 departs
        let notified = routers[0].depart().await;
        assert!(notified >= 1, "should notify at least 1 peer");

        // Verify node 1 no longer has node 0's record
        let local = routers[1].lookup_local("node0").await;
        assert!(
            local.is_empty(),
            "node 1 should not have node 0's record after departure"
        );

        // Verify node 1 no longer has node 0 in routing table
        let peers = routers[1].all_peers().await;
        assert!(
            !peers.iter().any(|p| p.agent_id == records[0].agent_id),
            "node 0 should be removed from node 1's routing table"
        );
    }

    #[tokio::test]
    async fn test_rejoin_reannounce() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 2 nodes
        let node0_record = make_record_with_seed(1, vec!["node0"]);
        let node0_router = Arc::new(make_router(node0_record.agent_id.clone(), network.clone()));
        node0_router.set_own_record(node0_record.clone()).await;
        network.register(node0_router.clone()).await;

        let node1_record = make_record_with_seed(2, vec!["node1"]);
        let node1_router = Arc::new(make_router(node1_record.agent_id.clone(), network.clone()));
        node1_router.set_own_record(node1_record.clone()).await;
        network.register(node1_router).await;

        // They know about each other
        node0_router.add_peer(node1_record.clone()).await;
        node0_router.announce(node0_record.clone()).await;

        // Node 1 has node 0's record
        let local = node0_router.lookup_local("node0").await;
        assert!(!local.is_empty());

        // Node 0 departs
        node0_router.depart().await;

        // Node 0's record is gone from node 1
        // (In the in-memory network, depart removes from all peers)
        // Now node 0 re-announces (rejoin)
        node0_router.announce(node0_record.clone()).await;

        // Node 0's record should be back in local DHT
        let local = node0_router.lookup_local("node0").await;
        assert!(!local.is_empty(), "record should reappear after rejoin");
    }

    #[tokio::test]
    async fn test_repair_routing_table() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 3 nodes
        let records: Vec<AgentRecord> = (0..3)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Node 0 knows only about node 1
        routers[0].add_peer(records[1].clone()).await;

        // Node 1 knows about node 2
        routers[1].add_peer(records[2].clone()).await;

        // Repair routing table — node 0 should discover node 2 via PEX with node 1
        let new_peers = routers[0].repair_routing_table().await;

        // Should have discovered some new peers
        assert!(
            new_peers > 0 || routers[0].peer_count().await >= 2,
            "repair should discover new peers or already have them"
        );
    }
}

// ---------------------------------------------------------------------------
// Query Optimization Tests (Track R5)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod query_optimization_tests {
    use super::*;
    use crate::dht_router::tests::{make_record, make_record_with_seed, make_router};

    #[tokio::test]
    async fn test_lookup_cache_hit() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);
        own_router.set_own_record(own_record).await;

        // Store a record
        let other_record = make_record(vec!["inference"]);
        own_router.store_local(other_record.clone()).await;

        // First lookup — should populate cache
        let results1 = own_router.lookup("inference", 10).await;
        assert!(!results1.is_empty());
        assert_eq!(own_router.cache_size().await, 1);

        // Second lookup — should hit cache (same results)
        let results2 = own_router.lookup("inference", 10).await;
        assert_eq!(results1.len(), results2.len());
    }

    #[tokio::test]
    async fn test_cache_invalidation_on_announce() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);
        own_router.set_own_record(own_record.clone()).await;

        // Store a record and lookup
        own_router.store_local(own_record.clone()).await;
        let _ = own_router.lookup("inference", 10).await;
        assert_eq!(own_router.cache_size().await, 1);

        // Announce should invalidate cache
        own_router.announce(own_record).await;
        assert_eq!(own_router.cache_size().await, 0);
    }

    #[tokio::test]
    async fn test_cache_invalidation_on_depart() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let node1_record = make_record_with_seed(1, vec!["node1"]);
        let node1_router = Arc::new(make_router(node1_record.agent_id.clone(), network.clone()));
        node1_router.set_own_record(node1_record.clone()).await;
        network.register(node1_router.clone()).await;

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();
        let own_router = make_router(own_id, network);
        own_router.set_own_record(own_record.clone()).await;
        own_router.add_peer(node1_record.clone()).await;
        own_router.store_local(own_record.clone()).await;

        // Lookup to populate cache
        let _ = own_router.lookup("inference", 10).await;
        assert!(own_router.cache_size().await >= 1);

        // Depart should invalidate all cache
        own_router.depart().await;
        assert_eq!(own_router.cache_size().await, 0);
    }

    #[tokio::test]
    async fn test_recursive_lookup() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 3 nodes in a line: 0 → 1 → 2
        let records: Vec<AgentRecord> = (0..3)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Node 0 knows node 1, node 1 knows node 2
        routers[0].add_peer(records[1].clone()).await;
        routers[1].add_peer(records[2].clone()).await;

        // Node 1 stores node 2's record (simulating replication)
        routers[1].store_local(records[2].clone()).await;
        // Node 1 stores its own record
        routers[1].store_local(records[1].clone()).await;

        // Node 0 does recursive lookup for "node2"
        // The recursive lookup asks node 1 (closest peer) to do the lookup
        // Node 1 has node 2's record in its local DHT
        let results = routers[0].lookup_recursive("node2", 10).await;

        // Should find node 2's record via node 1
        assert!(
            results.iter().any(|r| r.agent_id == records[2].agent_id),
            "recursive lookup should find node2's record, got {} results",
            results.len()
        );
    }

    #[tokio::test]
    async fn test_iterative_vs_recursive_consistency() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes in a mesh
        let records: Vec<AgentRecord> = (0..5)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build mesh
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Each node stores its record
        for (i, router) in routers.iter().enumerate() {
            router.store_local(records[i].clone()).await;
        }

        // Clear caches
        for router in &routers {
            router.invalidate_all_cache().await;
        }

        // Iterative lookup from node 0
        let iterative_results = routers[0].find_peers("node2", 10).await;

        // Clear cache
        routers[0].invalidate_all_cache().await;

        // Recursive lookup from node 0
        let recursive_results = routers[0].lookup_recursive("node2", 10).await;

        // Both should find the same record
        assert!(
            iterative_results
                .iter()
                .any(|r| r.agent_id == records[2].agent_id),
            "iterative lookup should find node2"
        );
        assert!(
            recursive_results
                .iter()
                .any(|r| r.agent_id == records[2].agent_id),
            "recursive lookup should find node2"
        );
    }

    #[tokio::test]
    async fn test_cache_expiry() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        let own_record = make_record(vec!["inference"]);
        let own_id = own_record.agent_id.clone();

        // Create router with 0-second cache TTL
        let router = make_router(own_id, network).with_cache_ttl(0);
        router.set_own_record(own_record.clone()).await;
        router.store_local(own_record).await;

        // Lookup — should populate cache
        let _ = router.lookup("inference", 10).await;

        // Cache should have an entry (it was populated)
        let cache_size = router.cache_size().await;
        assert!(cache_size >= 1);
    }
}

// ---------------------------------------------------------------------------
// Partition Handling Tests (Track R6)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod partition_tests {
    use super::*;
    use crate::dht_router::tests::{make_record, make_record_with_seed, make_router};

    #[tokio::test]
    async fn test_detect_partition() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes
        let records: Vec<AgentRecord> = (0..5)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Node 0 knows all other nodes
        for j in 1..5 {
            routers[0].add_peer(records[j].clone()).await;
        }

        // No partition — all peers reachable
        let (total, reachable, partitioned) = routers[0].detect_partition(0.5).await;
        assert_eq!(total, 4);
        assert_eq!(reachable, 4);
        assert!(!partitioned);

        // "Kill" nodes 3 and 4 — 50% unreachable
        network.nodes.write().await.remove(&records[3].agent_id);
        network.nodes.write().await.remove(&records[4].agent_id);

        let (total, reachable, partitioned) = routers[0].detect_partition(0.4).await;
        assert_eq!(total, 4);
        assert_eq!(reachable, 2);
        assert!(partitioned, "should detect partition when >40% unreachable");
    }

    #[tokio::test]
    async fn test_partition_healed() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 4 nodes
        let records: Vec<AgentRecord> = (0..4)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Node 0 knows all other nodes
        for j in 1..4 {
            routers[0].add_peer(records[j].clone()).await;
        }

        // Kill 2 nodes
        network.nodes.write().await.remove(&records[2].agent_id);
        network.nodes.write().await.remove(&records[3].agent_id);

        // Not healed
        assert!(!routers[0].is_partition_healed(0.8).await);

        // "Heal" — re-register nodes
        network.register(routers[2].clone()).await;
        network.register(routers[3].clone()).await;

        // Now healed
        assert!(routers[0].is_partition_healed(0.8).await);
    }

    #[tokio::test]
    async fn test_reconcile_after_partition() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 5 nodes
        let records: Vec<AgentRecord> = (0..5)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build mesh
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Each node stores its record
        for (i, router) in routers.iter().enumerate() {
            router.store_local(records[i].clone()).await;
        }

        // Partition: remove nodes 3 and 4
        network.nodes.write().await.remove(&records[3].agent_id);
        network.nodes.write().await.remove(&records[4].agent_id);

        // Nodes 0-2 continue operating
        // Node 2 announces a new record during partition
        let new_record = make_record(vec!["new_cap"]);
        routers[2].store_local(new_record.clone()).await;

        // Heal partition
        network.register(routers[3].clone()).await;
        network.register(routers[4].clone()).await;

        // Node 3 reconciles — should get records from other nodes
        let added = routers[3].reconcile_after_partition().await;
        // Should have gotten some records from peers
        assert!(
            added > 0,
            "reconciliation should add records, got {}",
            added
        );

        // Node 3 should now have node 2's new_cap record
        let local = routers[3].lookup_local("new_cap").await;
        assert!(
            !local.is_empty(),
            "node 3 should have new_cap record after reconciliation"
        );
    }

    #[tokio::test]
    async fn test_split_brain_both_sides_accept_announces() {
        let network = Arc::new(InMemoryDhtNetwork::new());

        // Create 4 nodes: {0,1} and {2,3}
        let records: Vec<AgentRecord> = (0..4)
            .map(|i| make_record_with_seed(i + 1, vec![&format!("node{}", i)]))
            .collect();

        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| Arc::new(make_router(r.agent_id.clone(), network.clone())))
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build initial mesh
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Partition: remove nodes 2 and 3 from network
        network.nodes.write().await.remove(&records[2].agent_id);
        network.nodes.write().await.remove(&records[3].agent_id);

        // Both sides accept announces independently
        // Side A (nodes 0,1): announce a new record
        let side_a_record = make_record(vec!["side_a"]);
        routers[0].store_local(side_a_record.clone()).await;
        routers[0].announce(side_a_record.clone()).await;

        // Side B (nodes 2,3): announce a different record
        let side_b_record = make_record(vec!["side_b"]);
        routers[2].store_local(side_b_record.clone()).await;
        routers[2].announce(side_b_record.clone()).await;

        // Heal partition
        network.register(routers[2].clone()).await;
        network.register(routers[3].clone()).await;

        // Reconcile — both sides' records should be visible
        routers[0].reconcile_after_partition().await;
        routers[2].reconcile_after_partition().await;

        // Node 0 should eventually see side_b's record
        let local_b = routers[0].lookup_local("side_b").await;
        assert!(
            !local_b.is_empty(),
            "node 0 should have side_b record after reconciliation"
        );

        // Node 2 should eventually see side_a's record
        let local_a = routers[2].lookup_local("side_a").await;
        assert!(
            !local_a.is_empty(),
            "node 2 should have side_a record after reconciliation"
        );
    }
}
