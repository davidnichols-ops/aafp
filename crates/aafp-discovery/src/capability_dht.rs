//! Capability-based DHT: discover agents by their advertised capabilities.
//!
//! ## Design
//! A simplified Kademlia-like DHT where the key is a capability string
//! (e.g., "inference", "translation") and the value is a list of AgentRecords
//! that advertise that capability.
//!
//! For MVP, this is an in-memory store. A production version would:
//! 1. Hash the capability string to a DHT key.
//! 2. Route FIND_VALUE / STORE RPCs to the k closest nodes.
//! 3. Replicate records across k nodes for fault tolerance.

use aafp_identity::agent_record::AgentRecord;
use aafp_identity::AgentId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// Errors returned by capability DHT operations.
#[derive(Debug, Error)]
pub enum DhtError {
    /// The agent record failed signature verification.
    #[error("record verification failed")]
    VerificationFailed,
    /// No record was found for the requested key.
    #[error("record not found")]
    NotFound,
    /// No agents advertise the requested capability.
    #[error("capability not found: {0}")]
    CapabilityNotFound(String),
    /// Persistence backend error (SQLite, I/O, etc.).
    #[error("persistence error: {0}")]
    Persistence(String),
}

/// A DHT key = SHA-256(capability_string) = 32 bytes.
pub type DhtKey = [u8; 32];

/// A record stored in the DHT.
#[derive(Clone, Debug)]
pub struct DhtRecord {
    /// The capability string (e.g., "inference").
    pub capability: String,
    /// The DHT key = SHA-256(capability).
    pub key: DhtKey,
    /// The agent record advertising this capability.
    pub agent_record: AgentRecord,
}

/// In-memory capability DHT.
pub struct CapabilityDht {
    /// Map: DhtKey → `Vec<DhtRecord>`.
    store: HashMap<DhtKey, Vec<DhtRecord>>,
    /// Map: AgentId → Vec<capability_string> (for reverse lookup).
    agent_caps: HashMap<AgentId, Vec<String>>,
}

impl CapabilityDht {
    /// Create a new empty DHT.
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
            agent_caps: HashMap::new(),
        }
    }

    /// Hash a capability string to a DHT key.
    pub fn hash_capability(capability: &str) -> DhtKey {
        let mut hasher = Sha256::new();
        hasher.update(capability.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Store an agent record in the DHT, indexed by each of its capabilities.
    pub fn put(&mut self, record: AgentRecord) -> Result<(), DhtError> {
        if !record.verify() {
            return Err(DhtError::VerificationFailed);
        }

        let agent_id = record.agent_id;

        // Remove old capabilities for this agent.
        self.remove_agent(&agent_id);

        // Index by each capability.
        for cap in &record.capabilities {
            let key = Self::hash_capability(cap);
            let dht_record = DhtRecord {
                capability: cap.clone(),
                key,
                agent_record: record.clone(),
            };
            self.store.entry(key).or_default().push(dht_record);
        }

        // Track agent → capabilities mapping.
        self.agent_caps
            .insert(agent_id, record.capabilities.clone());

        Ok(())
    }

    /// Find all agents that advertise a given capability.
    pub fn get(&self, capability: &str) -> Vec<&AgentRecord> {
        let key = Self::hash_capability(capability);
        self.store
            .get(&key)
            .map(|records| records.iter().map(|r| &r.agent_record).collect())
            .unwrap_or_default()
    }

    /// Find all agents matching any of the given capabilities.
    pub fn get_any(&self, capabilities: &[&str]) -> Vec<&AgentRecord> {
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for cap in capabilities {
            for record in self.get(cap) {
                let key = record.agent_id;
                if seen.insert(key) {
                    results.push(record);
                }
            }
        }
        results
    }

    /// Find agents that advertise ALL of the given capabilities.
    pub fn get_all(&self, capabilities: &[&str]) -> Vec<&AgentRecord> {
        if capabilities.is_empty() {
            return Vec::new();
        }
        let mut result: Vec<&AgentRecord> = self.get(capabilities[0]);
        for cap in &capabilities[1..] {
            let cap_records: std::collections::HashSet<AgentId> =
                self.get(cap).iter().map(|r| r.agent_id).collect();
            result.retain(|r| cap_records.contains(&r.agent_id));
        }
        result
    }

    /// Get all capabilities advertised by an agent.
    pub fn agent_capabilities(&self, agent_id: &AgentId) -> Vec<&str> {
        self.agent_caps
            .get(agent_id)
            .map(|caps| caps.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Remove an agent from the DHT.
    pub fn remove_agent(&mut self, agent_id: &AgentId) {
        if let Some(caps) = self.agent_caps.remove(agent_id) {
            for cap in caps {
                let key = Self::hash_capability(&cap);
                if let Some(records) = self.store.get_mut(&key) {
                    records.retain(|r| r.agent_record.agent_id != *agent_id);
                    if records.is_empty() {
                        self.store.remove(&key);
                    }
                }
            }
        }
    }

    /// Total number of unique capabilities in the DHT.
    pub fn capability_count(&self) -> usize {
        self.store.len()
    }

    /// Total number of agents in the DHT.
    pub fn agent_count(&self) -> usize {
        self.agent_caps.len()
    }

    /// List all capabilities in the DHT.
    pub fn list_capabilities(&self) -> Vec<String> {
        self.agent_caps
            .values()
            .flat_map(|caps| caps.iter().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

impl Default for CapabilityDht {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_identity::AgentKeypair;

    fn make_record(caps: Vec<&str>) -> AgentRecord {
        let kp = AgentKeypair::generate();
        AgentRecord::new(
            &kp,
            caps.into_iter().map(String::from).collect(),
            vec!["quic://1.2.3.4:4433".into()],
        )
    }

    #[test]
    fn put_and_get() {
        let mut dht = CapabilityDht::new();
        let record = make_record(vec!["inference", "translation"]);
        dht.put(record).unwrap();

        let inference = dht.get("inference");
        assert_eq!(inference.len(), 1);

        let translation = dht.get("translation");
        assert_eq!(translation.len(), 1);

        let unknown = dht.get("unknown-cap");
        assert_eq!(unknown.len(), 0);
    }

    #[test]
    fn rejects_invalid_record() {
        let mut dht = CapabilityDht::new();
        let mut record = make_record(vec!["inference"]);
        record.capabilities.push("forged".into());
        assert!(dht.put(record).is_err());
    }

    #[test]
    fn get_any() {
        let mut dht = CapabilityDht::new();
        let r1 = make_record(vec!["inference"]);
        let r2 = make_record(vec!["translation"]);
        dht.put(r1).unwrap();
        dht.put(r2).unwrap();

        let results = dht.get_any(&["inference", "translation"]);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn get_all() {
        let mut dht = CapabilityDht::new();
        let r1 = make_record(vec!["inference", "translation"]);
        let r2 = make_record(vec!["inference"]);
        dht.put(r1).unwrap();
        dht.put(r2).unwrap();

        let both = dht.get_all(&["inference", "translation"]);
        assert_eq!(both.len(), 1);

        let one = dht.get_all(&["inference"]);
        assert_eq!(one.len(), 2);
    }

    #[test]
    fn remove_agent() {
        let mut dht = CapabilityDht::new();
        let record = make_record(vec!["inference"]);
        let agent_id = record.agent_id;
        dht.put(record).unwrap();
        assert_eq!(dht.get("inference").len(), 1);

        dht.remove_agent(&agent_id);
        assert_eq!(dht.get("inference").len(), 0);
        assert_eq!(dht.agent_count(), 0);
    }

    #[test]
    fn update_capabilities() {
        let mut dht = CapabilityDht::new();
        let kp = AgentKeypair::generate();
        let r1 = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        dht.put(r1).unwrap();
        assert_eq!(dht.get("inference").len(), 1);

        // Update with different capabilities.
        let r2 = AgentRecord::new_with_version(&kp, vec!["translation".into()], vec![], 2, 0);
        dht.put(r2).unwrap();
        assert_eq!(dht.get("inference").len(), 0);
        assert_eq!(dht.get("translation").len(), 1);
        assert_eq!(dht.agent_count(), 1);
    }

    #[test]
    fn list_capabilities() {
        let mut dht = CapabilityDht::new();
        dht.put(make_record(vec!["inference", "translation"]))
            .unwrap();
        dht.put(make_record(vec!["inference", "coding"])).unwrap();

        let caps = dht.list_capabilities();
        assert_eq!(caps.len(), 3); // inference, translation, coding
    }

    #[test]
    fn hash_capability_deterministic() {
        let k1 = CapabilityDht::hash_capability("inference");
        let k2 = CapabilityDht::hash_capability("inference");
        assert_eq!(k1, k2);
        let k3 = CapabilityDht::hash_capability("translation");
        assert_ne!(k1, k3);
    }
}
