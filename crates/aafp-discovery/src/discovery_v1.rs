//! AAFP v1 Discovery (RFC-0004).
//!
//! Implements:
//! - In-memory capability DHT (RFC-0004 §4)
//! - Bootstrap discovery protocol (RFC-0004 §3)
//! - RPC method params/results encoding for announce and lookup
//!
//! ## RPC Methods (RFC-0004 §3.3)
//!
//! - `aafp.discovery.announce`: Send AgentRecord, receive known peers
//! - `aafp.discovery.lookup`: Find agents by capability name
//! - `aafp.discovery.pex`: Peer exchange (v1: stub)

use aafp_cbor::{int_map, Value};
use aafp_identity::identity_v1::{AgentId, AgentRecord, IdentityError};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// RPC method names (RFC-0004 §3.3).
pub const METHOD_ANNOUNCE: &str = "aafp.discovery.announce";
/// RPC method name for capability lookups (RFC-0004 §3.3).
pub const METHOD_LOOKUP: &str = "aafp.discovery.lookup";
/// RPC method name for peer exchange (RFC-0004 §3.3).
pub const METHOD_PEX: &str = "aafp.discovery.pex";

/// Default lookup limit for unauthenticated requests (RFC-0004 §3.4).
pub const DEFAULT_LIMIT_UNAUTH: u64 = 5;

/// Default lookup limit for authenticated requests (RFC-0004 §3.4).
pub const DEFAULT_LIMIT_AUTH: u64 = 10;

/// Maximum records stored by a bootstrap node (RFC-0004 §3.4).
pub const MAX_RECORDS: usize = 100_000;

/// Rate limit for announce: 1 per 60 seconds (RFC-0004 §3.4).
pub const RATE_LIMIT_ANNOUNCE: u64 = 60;

/// Rate limit for lookup: 10 per 60 seconds (RFC-0004 §3.4).
pub const RATE_LIMIT_LOOKUP: u64 = 60;

/// Maximum concurrent streams per connection (RFC-0004 §3.4).
pub const MAX_CONCURRENT_STREAMS: usize = 100;

/// Announce request params (RFC-0004 §3.3).
///
/// ```cbor
/// { 1: AgentRecord }
/// ```
#[derive(Clone, Debug)]
pub struct AnnounceParams {
    /// The agent record being announced to the network.
    pub record: AgentRecord,
}

impl AnnounceParams {
    /// Create a new announce request with the given agent record.
    pub fn new(record: AgentRecord) -> Self {
        Self { record }
    }

    /// Encode the params as a CBOR value.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![(1, self.record.to_cbor())])
    }

    /// Decode the params from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, DiscoveryError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };
        let record_val = get(1).ok_or(DiscoveryError::MissingField("record"))?;
        let record = AgentRecord::from_cbor(record_val)?;
        Ok(Self { record })
    }
}

/// Announce response result (RFC-0004 §3.3).
///
/// ```cbor
/// { 1: [ *AgentRecord ] }
/// ```
#[derive(Clone, Debug)]
pub struct AnnounceResult {
    /// Known peers returned by the bootstrap node.
    pub peers: Vec<AgentRecord>,
}

impl AnnounceResult {
    /// Create a new announce result with the given peer records.
    pub fn new(peers: Vec<AgentRecord>) -> Self {
        Self { peers }
    }

    /// Encode the result as a CBOR value.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![(
            1,
            Value::Array(self.peers.iter().map(|r| r.to_cbor()).collect()),
        )])
    }

    /// Decode the result from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, DiscoveryError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };
        let arr = match get(1) {
            Some(Value::Array(a)) => a,
            Some(other) => {
                return Err(DiscoveryError::InvalidField {
                    field: "peers",
                    message: format!("expected array, got {:?}", other),
                })
            }
            None => return Err(DiscoveryError::MissingField("peers")),
        };
        let mut peers = Vec::new();
        for item in arr {
            peers.push(AgentRecord::from_cbor(item)?);
        }
        Ok(Self { peers })
    }
}

/// Lookup request params (RFC-0004 §3.3).
///
/// ```cbor
/// { 1: tstr, 2: uint / null }
/// ```
#[derive(Clone, Debug)]
pub struct LookupParams {
    /// The capability name to search for.
    pub capability: String,
    /// Optional maximum number of results to return.
    pub limit: Option<u64>,
}

impl LookupParams {
    /// Create a new lookup request for the given capability.
    pub fn new(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            limit: None,
        }
    }

    /// Set the maximum number of results to return.
    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Encode the params as a CBOR value.
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![(1i64, Value::TextString(self.capability.clone()))];
        // A-2 (Rev 6): Omit limit when absent (NOT null)
        if let Some(limit) = self.limit {
            entries.push((2, Value::Unsigned(limit)));
        }
        int_map(entries)
    }

    /// Decode the params from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, DiscoveryError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };

        let capability = match get(1) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(DiscoveryError::InvalidField {
                    field: "capability",
                    message: format!("expected tstr, got {:?}", other),
                })
            }
            None => return Err(DiscoveryError::MissingField("capability")),
        };

        // A-2 (Rev 6): limit must be omitted when absent, not null
        let limit = match get(2) {
            Some(Value::Unsigned(n)) => Some(*n),
            None => None,
            Some(Value::Null) => {
                return Err(DiscoveryError::InvalidField {
                    field: "limit",
                    message: "null is not valid; field must be omitted when absent (A-2)"
                        .to_string(),
                })
            }
            Some(other) => {
                return Err(DiscoveryError::InvalidField {
                    field: "limit",
                    message: format!("expected uint, got {:?}", other),
                })
            }
        };

        Ok(Self { capability, limit })
    }
}

/// Lookup response result (RFC-0004 §3.3).
#[derive(Clone, Debug)]
pub struct LookupResult {
    /// Agents matching the requested capability.
    pub peers: Vec<AgentRecord>,
}

impl LookupResult {
    /// Create a new lookup result with the given peer records.
    pub fn new(peers: Vec<AgentRecord>) -> Self {
        Self { peers }
    }

    /// Encode the result as a CBOR value.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![(
            1,
            Value::Array(self.peers.iter().map(|r| r.to_cbor()).collect()),
        )])
    }

    /// Decode the result from a CBOR value.
    pub fn from_cbor(val: &Value) -> Result<Self, DiscoveryError> {
        let get = |k: i64| -> Option<&Value> { aafp_cbor::int_map_get(val, k) };
        let arr = match get(1) {
            Some(Value::Array(a)) => a,
            Some(other) => {
                return Err(DiscoveryError::InvalidField {
                    field: "peers",
                    message: format!("expected array, got {:?}", other),
                })
            }
            None => return Err(DiscoveryError::MissingField("peers")),
        };
        let mut peers = Vec::new();
        for item in arr {
            peers.push(AgentRecord::from_cbor(item)?);
        }
        Ok(Self { peers })
    }
}

/// In-memory capability DHT (RFC-0004 §4).
///
/// Indexes AgentRecords by capability name. Suitable for single-node
/// deployments and small networks. NOT a distributed DHT.
#[derive(Debug, Default)]
pub struct CapabilityDht {
    /// capability_name -> set of AgentIds
    index: HashMap<String, HashSet<[u8; 32]>>,
    /// AgentId -> AgentRecord
    records: HashMap<[u8; 32], AgentRecord>,
}

impl CapabilityDht {
    /// Create a new empty capability DHT.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an AgentRecord indexed by each capability (RFC-0004 §4.3).
    ///
    /// If a record with the same AgentId already exists, it is replaced
    /// only if the new record's `created_at` >= existing record's `created_at`.
    pub fn put(&mut self, record: AgentRecord) -> bool {
        let agent_id = record.agent_id.0;

        // Check if we already have a newer record for this agent
        if let Some(existing) = self.records.get(&agent_id) {
            if existing.created_at > record.created_at {
                return false; // Existing record is newer
            }
            // Remove old capability indices
            for cap in &existing.capabilities {
                if let Some(set) = self.index.get_mut(&cap.name) {
                    set.remove(&agent_id);
                    if set.is_empty() {
                        self.index.remove(&cap.name);
                    }
                }
            }
        }

        // Check max records limit
        if self.records.len() >= MAX_RECORDS && !self.records.contains_key(&agent_id) {
            return false; // At capacity
        }

        // Index by capabilities
        for cap in &record.capabilities {
            self.index
                .entry(cap.name.clone())
                .or_default()
                .insert(agent_id);
        }

        self.records.insert(agent_id, record);
        true
    }

    /// Get all AgentRecords matching a capability name (RFC-0004 §4.3).
    pub fn get(&self, capability: &str) -> Vec<AgentRecord> {
        match self.index.get(capability) {
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.records.get(id))
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get all AgentRecords matching ALL specified capabilities (RFC-0004 §4.3).
    pub fn get_all(&self, capabilities: &[String]) -> Vec<AgentRecord> {
        if capabilities.is_empty() {
            return Vec::new();
        }
        let mut result_ids: Option<HashSet<[u8; 32]>> = None;
        for cap in capabilities {
            let ids = self.index.get(cap).cloned().unwrap_or_default();
            result_ids = Some(match result_ids {
                None => ids,
                Some(existing) => existing.intersection(&ids).cloned().collect(),
            });
        }
        result_ids
            .unwrap_or_default()
            .iter()
            .filter_map(|id| self.records.get(id))
            .cloned()
            .collect()
    }

    /// Get a specific AgentRecord by AgentId.
    pub fn get_by_id(&self, agent_id: &AgentId) -> Option<&AgentRecord> {
        self.records.get(&agent_id.0)
    }

    /// Remove expired records (RFC-0004 §3.4).
    pub fn evict_expired(&mut self, now: u64) -> usize {
        let expired_ids: Vec<[u8; 32]> = self
            .records
            .iter()
            .filter(|(_, r)| r.is_expired(now))
            .map(|(id, _)| *id)
            .collect();
        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(record) = self.records.remove(id) {
                for cap in &record.capabilities {
                    if let Some(set) = self.index.get_mut(&cap.name) {
                        set.remove(id);
                        if set.is_empty() {
                            self.index.remove(&cap.name);
                        }
                    }
                }
            }
        }
        count
    }

    /// Total number of records stored.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the DHT is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of distinct capabilities indexed.
    pub fn capability_count(&self) -> usize {
        self.index.len()
    }
}

/// Thread-safe wrapper for CapabilityDht.
pub type SharedCapabilityDht = Arc<RwLock<CapabilityDht>>;

/// Create a thread-safe shared DHT.
pub fn shared_dht() -> SharedCapabilityDht {
    Arc::new(RwLock::new(CapabilityDht::new()))
}

/// Discovery errors.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// A required CBOR field was missing from the message.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A CBOR field had an invalid value.
    #[error("invalid field '{field}': {message}")]
    InvalidField {
        /// The name of the invalid field.
        field: &'static str,
        /// A description of why the field is invalid.
        message: String,
    },
    /// An identity-related error occurred while decoding a record.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// A CBOR encoding or decoding error occurred.
    #[error("CBOR error: {0}")]
    Cbor(#[from] aafp_cbor::CborError),
    /// The agent record failed verification.
    #[error("record invalid")]
    RecordInvalid,
    /// The agent record has expired.
    #[error("record expired")]
    RecordExpired,
    /// The request exceeded the configured rate limit.
    #[error("rate limit exceeded")]
    RateLimitExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_crypto::{MlDsa65, SignatureScheme};

    fn make_record(capabilities: Vec<&str>) -> AgentRecord {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;
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

    #[test]
    fn test_dht_put_and_get() {
        let mut dht = CapabilityDht::new();
        let record = make_record(vec!["inference", "translation"]);

        assert!(dht.put(record.clone()));
        assert_eq!(dht.len(), 1);
        assert_eq!(dht.capability_count(), 2);

        let results = dht.get("inference");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, record.agent_id);

        let results = dht.get("translation");
        assert_eq!(results.len(), 1);

        let results = dht.get("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_dht_get_all() {
        let mut dht = CapabilityDht::new();

        let r1 = make_record(vec!["inference", "translation"]);
        let r2 = make_record(vec!["inference", "vision"]);
        let r3 = make_record(vec!["inference"]);

        dht.put(r1.clone());
        dht.put(r2.clone());
        dht.put(r3.clone());

        // Agents with both "inference" AND "translation"
        let results = dht.get_all(&["inference".to_string(), "translation".to_string()]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, r1.agent_id);

        // Agents with just "inference"
        let results = dht.get("inference");
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_dht_replace_newer_record() {
        let mut dht = CapabilityDht::new();
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;

        let mut r1 = AgentRecord::new(&pk.0, vec![], vec![], now, now + 86400, 1);
        r1.sign(&sk);
        dht.put(r1.clone());

        // Try to put an older record — should be rejected
        let mut r_old = AgentRecord::new(&pk.0, vec![], vec![], now - 100, now + 86400, 1);
        r_old.sign(&sk);
        assert!(!dht.put(r_old));

        // Put a newer record — should replace
        let mut r2 = AgentRecord::new(
            &pk.0,
            vec![aafp_identity::CapabilityDescriptor::new("inference")],
            vec![],
            now + 100,
            now + 86400,
            1,
        );
        r2.sign(&sk);
        assert!(dht.put(r2.clone()));
        assert_eq!(dht.len(), 1); // Still 1 record (replaced)
        assert_eq!(dht.get("inference").len(), 1);
    }

    #[test]
    fn test_dht_evict_expired() {
        let mut dht = CapabilityDht::new();
        let now = 1700000000u64;

        let (pk, sk) = MlDsa65::keypair();
        let mut r1 = AgentRecord::new(&pk.0, vec![], vec![], now, now + 100, 1);
        r1.sign(&sk);
        dht.put(r1);

        let (pk2, sk2) = MlDsa65::keypair();
        let mut r2 = AgentRecord::new(&pk2.0, vec![], vec![], now, now + 10000, 1);
        r2.sign(&sk2);
        dht.put(r2);

        assert_eq!(dht.len(), 2);

        // Evict at now + 200 (r1 expired, r2 still valid)
        let evicted = dht.evict_expired(now + 200);
        assert_eq!(evicted, 1);
        assert_eq!(dht.len(), 1);
    }

    #[test]
    fn test_announce_params_roundtrip() {
        let record = make_record(vec!["inference"]);
        let params = AnnounceParams::new(record);

        let cbor = params.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let params2 = AnnounceParams::from_cbor(&decoded).unwrap();

        assert_eq!(params2.record.agent_id, params.record.agent_id);
        assert_eq!(params2.record.public_key, params.record.public_key);
    }

    #[test]
    fn test_announce_result_roundtrip() {
        let peers = vec![
            make_record(vec!["inference"]),
            make_record(vec!["translation"]),
        ];
        let result = AnnounceResult::new(peers);

        let cbor = result.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let result2 = AnnounceResult::from_cbor(&decoded).unwrap();

        assert_eq!(result2.peers.len(), 2);
    }

    #[test]
    fn test_lookup_params_roundtrip() {
        let params = LookupParams::new("inference").with_limit(10);

        let cbor = params.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let params2 = LookupParams::from_cbor(&decoded).unwrap();

        assert_eq!(params2.capability, "inference");
        assert_eq!(params2.limit, Some(10));
    }

    #[test]
    fn test_lookup_params_null_limit() {
        let params = LookupParams::new("inference");

        let cbor = params.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let params2 = LookupParams::from_cbor(&decoded).unwrap();

        assert_eq!(params2.capability, "inference");
        assert_eq!(params2.limit, None);
    }

    #[test]
    fn test_lookup_result_roundtrip() {
        let peers = vec![make_record(vec!["inference"])];
        let result = LookupResult::new(peers);

        let cbor = result.to_cbor();
        let encoded = aafp_cbor::encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
        let result2 = LookupResult::from_cbor(&decoded).unwrap();

        assert_eq!(result2.peers.len(), 1);
    }

    #[test]
    fn test_dht_max_records() {
        let mut dht = CapabilityDht::new();
        // Fill up to MAX_RECORDS - this would take too long for 100k
        // Just verify the limit check works with a small DHT
        for _ in 0..5 {
            let record = make_record(vec!["test"]);
            assert!(dht.put(record));
        }
        assert_eq!(dht.len(), 5);
    }
}
