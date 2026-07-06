//! Heartbeat liveness extension and tracking (Phase E5, §8.2.1).
//!
//! Agents with the HeartbeatExtension can send periodic heartbeat updates
//! to DHT nodes. The heartbeat is a lightweight signed message:
//!   ML-DSA-65(b"aafp-heartbeat" || agent_id || last_heartbeat)

use super::AgentRecordExtension;
use crate::identity_v1::{AgentId, IdentityError};
use aafp_cbor::{int_map, int_map_get, Value};
use std::collections::HashMap;

/// Default heartbeat interval in seconds (5 minutes).
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u32 = 300;

/// Staleness multiplier: a record is stale if its heartbeat is older than
/// `interval_secs * STALENESS_MULTIPLIER`.
pub const STALENESS_MULTIPLIER: u64 = 3;

/// Heartbeat extension for AgentRecord (key 11, namespace "aafp.heartbeat.v1").
///
/// CBOR encoding (inner data):
/// ```cbor
/// HeartbeatData = {
///     1: uint,   // interval_secs
///     2: uint,   // last_heartbeat
///     3: bstr,   // heartbeat_sig
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HeartbeatExtension {
    pub version: u64,
    pub interval_secs: u32,
    pub last_heartbeat: u64,
    pub heartbeat_sig: Vec<u8>,
}

impl AgentRecordExtension for HeartbeatExtension {
    const NAMESPACE: &'static str = "aafp.heartbeat.v1";
    const VERSION: u64 = 1;

    fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.interval_secs as u64)),
            (2, Value::Unsigned(self.last_heartbeat)),
            (3, Value::ByteString(self.heartbeat_sig.clone())),
        ])
    }

    fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        Ok(Self {
            version: 1,
            interval_secs: match int_map_get(val, 1) {
                Some(Value::Unsigned(n)) => *n as u32,
                _ => 0,
            },
            last_heartbeat: match int_map_get(val, 2) {
                Some(Value::Unsigned(n)) => *n,
                _ => 0,
            },
            heartbeat_sig: match int_map_get(val, 3) {
                Some(Value::ByteString(b)) => b.clone(),
                _ => Vec::new(),
            },
        })
    }
}

/// A heartbeat update message (separate from the full AgentRecord).
#[derive(Clone, Debug)]
pub struct HeartbeatUpdate {
    pub agent_id: AgentId,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl HeartbeatUpdate {
    /// Create and sign a new heartbeat update.
    ///
    /// Returns `None` if the secret key is malformed.
    pub fn sign_heartbeat(agent_id: &AgentId, timestamp: u64, secret_key: &[u8]) -> Option<Self> {
        use aafp_crypto::{MlDsa65, MlDsa65SecretKey, SignatureScheme};
        let sk = MlDsa65SecretKey::from_bytes(secret_key).ok()?;
        let mut input = Vec::new();
        input.extend_from_slice(b"aafp-heartbeat");
        input.extend_from_slice(&agent_id.0);
        input.extend_from_slice(&timestamp.to_be_bytes());
        let sig = MlDsa65::sign(&sk, &input);
        Some(Self {
            agent_id: *agent_id,
            timestamp,
            signature: sig.0,
        })
    }

    /// Verify the heartbeat signature against the agent's public key.
    pub fn verify_heartbeat(&self, public_key: &[u8]) -> bool {
        use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65Signature, SignatureScheme};
        let mut input = Vec::new();
        input.extend_from_slice(b"aafp-heartbeat");
        input.extend_from_slice(&self.agent_id.0);
        input.extend_from_slice(&self.timestamp.to_be_bytes());
        let pk = match MlDsa65PublicKey::from_bytes(public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match MlDsa65Signature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        MlDsa65::verify(&pk, &input, &sig)
    }
}

/// Tracks heartbeat freshness for DHT-stored records.
#[derive(Debug, Default)]
pub struct HeartbeatTracker {
    pub last_seen: HashMap<AgentId, (u64, u32)>,
}

impl HeartbeatTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, hb: &HeartbeatUpdate) -> bool {
        if let Some((existing_ts, _)) = self.last_seen.get(&hb.agent_id) {
            if hb.timestamp <= *existing_ts {
                return false;
            }
        }
        self.last_seen
            .insert(hb.agent_id, (hb.timestamp, DEFAULT_HEARTBEAT_INTERVAL_SECS));
        true
    }

    pub fn update_with_interval(&mut self, hb: &HeartbeatUpdate, interval_secs: u32) -> bool {
        if let Some((existing_ts, _)) = self.last_seen.get(&hb.agent_id) {
            if hb.timestamp <= *existing_ts {
                return false;
            }
        }
        self.last_seen
            .insert(hb.agent_id, (hb.timestamp, interval_secs));
        true
    }

    pub fn is_stale(&self, agent_id: &AgentId, now: u64) -> bool {
        match self.last_seen.get(agent_id) {
            Some((ts, interval)) => {
                let threshold = (*interval as u64).saturating_mul(STALENESS_MULTIPLIER);
                now > ts.saturating_add(threshold)
            }
            None => false,
        }
    }

    pub fn last_heartbeat(&self, agent_id: &AgentId) -> Option<u64> {
        self.last_seen.get(agent_id).map(|(ts, _)| *ts)
    }

    pub fn evict_stale(&mut self, now: u64) -> usize {
        let cutoff = now.saturating_sub(86400);
        let to_remove: Vec<AgentId> = self
            .last_seen
            .iter()
            .filter(|(_, (ts, _))| *ts < cutoff)
            .map(|(id, _)| *id)
            .collect();
        let count = to_remove.len();
        for id in to_remove {
            self.last_seen.remove(&id);
        }
        count
    }
}

/// Compute the adaptive TTL for a record, considering heartbeat freshness.
pub fn adaptive_ttl(
    record_created_at: u64,
    record_expires_at: u64,
    heartbeat_tracker: &HeartbeatTracker,
    agent_id: &AgentId,
    interval_secs: u32,
    now: u64,
) -> u64 {
    let base_ttl = record_expires_at.saturating_sub(record_created_at);
    let last_hb = match heartbeat_tracker.last_heartbeat(agent_id) {
        Some(ts) => ts,
        None => return base_ttl,
    };
    let staleness_threshold = (interval_secs as u64) * STALENESS_MULTIPLIER;
    if now > last_hb + staleness_threshold {
        return base_ttl;
    }
    let time_since_hb = now.saturating_sub(last_hb);
    let freshness_ratio = 1.0 - (time_since_hb as f64 / staleness_threshold as f64);
    let max_extension = 23 * 24 * 3600u64;
    let extension = if freshness_ratio.is_finite() && freshness_ratio > 0.0 {
        (max_extension as f64 * freshness_ratio) as u64
    } else {
        0
    };
    base_ttl.saturating_add(extension)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode};

    #[test]
    fn test_heartbeat_roundtrip() {
        let hb = HeartbeatExtension {
            version: 1,
            interval_secs: 300,
            last_heartbeat: 1700000000,
            heartbeat_sig: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let cbor = hb.to_extension_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        let hb2 = HeartbeatExtension::from_extension_cbor(&decoded).unwrap();
        assert_eq!(hb, hb2);
    }

    #[test]
    fn test_tracker_staleness() {
        let mut tracker = HeartbeatTracker::new();
        let agent = AgentId([1u8; 32]);
        let now = 1700000000u64;

        let hb = HeartbeatUpdate {
            agent_id: agent,
            timestamp: now,
            signature: vec![],
        };
        tracker.update_with_interval(&hb, 300);
        assert!(!tracker.is_stale(&agent, now));
        assert!(tracker.is_stale(&agent, now + 1000)); // > 900s = 3*300
    }
}
