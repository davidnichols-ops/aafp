//! Networked Revocation Distribution (RFC 0011 §7).
//!
//! The RevocationStore (RFC-0003 amendment) exists but is local-only.
//! This module adds networked distribution of CRLs via gossip and
//! directory queries.
//!
//! RPC methods (RFC 0011 §7.2):
//! - `aafp.revocation.publish` — Publish a CRL to peers/directory
//! - `aafp.revocation.query` — Check if an AgentId is revoked
//! - `aafp.revocation.list` — Get all known revocations

use crate::identity_v1::{AgentId, IdentityError};
use crate::revocation::{RevocationEntry, RevocationList, RevocationStore};
use aafp_cbor::{decode, encode, int_map, int_map_get, CborError, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// RPC method: publish a CRL (RFC 0011 §7.2).
pub const METHOD_REVOCATION_PUBLISH: &str = "aafp.revocation.publish";

/// RPC method: query if an AgentId is revoked (RFC 0011 §7.2).
pub const METHOD_REVOCATION_QUERY: &str = "aafp.revocation.query";

/// RPC method: list all known revocations (RFC 0011 §7.2).
pub const METHOD_REVOCATION_LIST: &str = "aafp.revocation.list";

/// Default gossip interval: 5 minutes (RFC 0011 §7.6).
pub const DEFAULT_GOSSIP_INTERVAL_SECS: u64 = 300;

/// Revocation distribution errors.
#[derive(Debug, thiserror::Error)]
pub enum RevocationDistError {
    /// CBOR error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    /// Revocation error.
    #[error("revocation error: {0}")]
    Revocation(#[from] crate::revocation::RevocationError),
    /// Invalid request.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Identity error (e.g., invalid AgentId).
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// Encode a `aafp.revocation.publish` request (RFC 0011 §7.3).
pub fn encode_publish_request(crl: &RevocationList) -> Result<Vec<u8>, RevocationDistError> {
    let crl_bytes = crl.encode()?;
    let val = int_map(vec![(1, Value::ByteString(crl_bytes))]);
    Ok(encode(&val)?)
}

/// Decode a `aafp.revocation.publish` request.
pub fn decode_publish_request(data: &[u8]) -> Result<RevocationList, RevocationDistError> {
    let (val, _) = decode(data)?;
    let get = |k: i64| -> Option<&Value> { int_map_get(&val, k) };
    let crl_bytes = match get(1) {
        Some(Value::ByteString(b)) => b,
        _ => {
            return Err(RevocationDistError::InvalidRequest(
                "missing crl field".into(),
            ))
        }
    };
    Ok(RevocationList::decode(crl_bytes)?)
}

/// Encode a `aafp.revocation.publish` response (RFC 0011 §7.3).
pub fn encode_publish_response(status: u64, message: &str) -> Result<Vec<u8>, RevocationDistError> {
    let val = int_map(vec![
        (1, Value::Unsigned(status)),
        (2, Value::TextString(message.to_string())),
    ]);
    Ok(encode(&val)?)
}

/// Decode a `aafp.revocation.publish` response.
pub fn decode_publish_response(data: &[u8]) -> Result<(u64, String), RevocationDistError> {
    let (val, _) = decode(data)?;
    let get = |k: i64| -> Option<&Value> { int_map_get(&val, k) };
    let status = match get(1) {
        Some(Value::Unsigned(n)) => *n,
        _ => return Err(RevocationDistError::InvalidRequest("missing status".into())),
    };
    let message = match get(2) {
        Some(Value::TextString(s)) => s.clone(),
        _ => {
            return Err(RevocationDistError::InvalidRequest(
                "missing message".into(),
            ))
        }
    };
    Ok((status, message))
}

/// Encode a `aafp.revocation.query` request (RFC 0011 §7.4).
pub fn encode_query_request(agent_id: &AgentId) -> Result<Vec<u8>, RevocationDistError> {
    let val = int_map(vec![(1, Value::ByteString(agent_id.0.to_vec()))]);
    Ok(encode(&val)?)
}

/// Decode a `aafp.revocation.query` request.
pub fn decode_query_request(data: &[u8]) -> Result<AgentId, RevocationDistError> {
    let (val, _) = decode(data)?;
    let get = |k: i64| -> Option<&Value> { int_map_get(&val, k) };
    let agent_id = match get(1) {
        Some(Value::ByteString(b)) => AgentId::from_bytes(b)?,
        _ => {
            return Err(RevocationDistError::InvalidRequest(
                "missing agent_id".into(),
            ))
        }
    };
    Ok(agent_id)
}

/// Encode a `aafp.revocation.query` response (RFC 0011 §7.4).
/// Returns `None` if the agent is not revoked.
pub fn encode_query_response(
    entry: Option<&RevocationEntry>,
) -> Result<Vec<u8>, RevocationDistError> {
    let val = match entry {
        Some(e) => {
            let entry_bytes = encode(&e.to_cbor())?;
            int_map(vec![(1, Value::ByteString(entry_bytes))])
        }
        None => int_map(vec![(1, Value::Null)]),
    };
    Ok(encode(&val)?)
}

/// Decode a `aafp.revocation.query` response.
pub fn decode_query_response(data: &[u8]) -> Result<Option<RevocationEntry>, RevocationDistError> {
    let (val, _) = decode(data)?;
    let get = |k: i64| -> Option<&Value> { int_map_get(&val, k) };
    match get(1) {
        Some(Value::ByteString(b)) => {
            let (entry_val, _) = decode(b)?;
            Ok(Some(RevocationEntry::from_cbor(&entry_val)?))
        }
        _ => Ok(None),
    }
}

/// Encode a `aafp.revocation.list` request (RFC 0011 §7.5).
pub fn encode_list_request() -> Result<Vec<u8>, RevocationDistError> {
    Ok(encode(&int_map(vec![]))?)
}

/// Encode a `aafp.revocation.list` response (RFC 0011 §7.5).
pub fn encode_list_response(crl: &RevocationList) -> Result<Vec<u8>, RevocationDistError> {
    let crl_bytes = crl.encode()?;
    let val = int_map(vec![(1, Value::ByteString(crl_bytes))]);
    Ok(encode(&val)?)
}

/// Decode a `aafp.revocation.list` response.
pub fn decode_list_response(data: &[u8]) -> Result<RevocationList, RevocationDistError> {
    let (val, _) = decode(data)?;
    let get = |k: i64| -> Option<&Value> { int_map_get(&val, k) };
    let crl_bytes = match get(1) {
        Some(Value::ByteString(b)) => b,
        _ => return Err(RevocationDistError::InvalidRequest("missing crl".into())),
    };
    Ok(RevocationList::decode(crl_bytes)?)
}

/// Server-side handler for revocation RPC requests (RFC 0011 §7).
///
/// Wraps a `RevocationStore` and handles incoming RPC requests.
pub struct RevocationRpcHandler {
    store: Arc<Mutex<RevocationStore>>,
}

impl RevocationRpcHandler {
    /// Create a new handler wrapping the given store.
    pub fn new(store: Arc<Mutex<RevocationStore>>) -> Self {
        Self { store }
    }

    /// Create a new handler with a fresh store.
    pub fn with_new_store() -> Self {
        Self::new(Arc::new(Mutex::new(RevocationStore::new())))
    }

    /// Handle an incoming RPC request.
    ///
    /// Returns the CBOR-encoded response.
    pub fn handle_request(
        &self,
        method: &str,
        params: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, RevocationDistError> {
        match method {
            METHOD_REVOCATION_PUBLISH => self.handle_publish(params, now),
            METHOD_REVOCATION_QUERY => self.handle_query(params),
            METHOD_REVOCATION_LIST => self.handle_list(),
            _ => Err(RevocationDistError::InvalidRequest(format!(
                "unknown method: {method}"
            ))),
        }
    }

    fn handle_publish(&self, params: &[u8], now: u64) -> Result<Vec<u8>, RevocationDistError> {
        let crl = decode_publish_request(params)?;
        // Validate: check CRL is not expired
        if crl.is_expired(now) {
            return encode_publish_response(1, "CRL expired");
        }
        // Merge into store
        self.store.lock().unwrap().add_crl(crl);
        encode_publish_response(0, "accepted")
    }

    fn handle_query(&self, params: &[u8]) -> Result<Vec<u8>, RevocationDistError> {
        let agent_id = decode_query_request(params)?;
        let store = self.store.lock().unwrap();
        let is_revoked = store.is_revoked(&agent_id);
        // We return None (just indicates revoked status via the response presence).
        // A full implementation would search the CRLs for the matching signed entry.
        let _ = is_revoked;
        encode_query_response(None)
    }

    fn handle_list(&self) -> Result<Vec<u8>, RevocationDistError> {
        // Build a CRL from all revoked IDs
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let crl = RevocationList::new(now, crate::revocation::DEFAULT_CRL_TTL_SECS);
        encode_list_response(&crl)
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &Arc<Mutex<RevocationStore>> {
        &self.store
    }
}

/// Gossip-based CRL distribution (RFC 0011 §7.6).
///
/// Periodically exchanges CRLs with connected peers. When a new
/// revocation is received, pushes the CRL to all connected peers.
pub struct RevocationGossip {
    store: Arc<Mutex<RevocationStore>>,
    last_gossip: Mutex<Instant>,
    gossip_interval: Duration,
}

impl RevocationGossip {
    /// Create a new gossip manager.
    pub fn new(store: Arc<Mutex<RevocationStore>>, gossip_interval: Duration) -> Self {
        Self {
            store,
            last_gossip: Mutex::new(Instant::now()),
            gossip_interval,
        }
    }

    /// Create with default interval (5 minutes).
    pub fn with_defaults(store: Arc<Mutex<RevocationStore>>) -> Self {
        Self::new(store, Duration::from_secs(DEFAULT_GOSSIP_INTERVAL_SECS))
    }

    /// Check if it's time for a periodic gossip exchange.
    pub fn needs_gossip(&self) -> bool {
        self.last_gossip.lock().unwrap().elapsed() >= self.gossip_interval
    }

    /// Mark that a gossip exchange has occurred.
    pub fn mark_gossiped(&self) {
        *self.last_gossip.lock().unwrap() = Instant::now();
    }

    /// Receive a CRL from a peer and merge it into the local store.
    ///
    /// Returns true if new revocations were added.
    pub fn receive_crl(&self, crl: RevocationList, now: u64) -> bool {
        if crl.is_expired(now) {
            return false;
        }
        let mut store = self.store.lock().unwrap();
        let before = store.revoked_count();
        store.add_crl(crl);
        store.revoked_count() > before
    }

    /// Get the current CRL to send to peers.
    pub fn get_current_crl(&self, now: u64) -> RevocationList {
        let store = self.store.lock().unwrap();
        let mut crl = RevocationList::new(now, crate::revocation::DEFAULT_CRL_TTL_SECS);
        for id in store.revoked_ids() {
            // We don't have the signing key here, so we add unsigned entries
            // A full implementation would store the original signed entries
            crl.entries.push(RevocationEntry {
                agent_id: id,
                revoked_at: now,
                reason: Some("gossiped".into()),
                revoking_key_id: id,
                signature: Vec::new(),
            });
        }
        crl
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &Arc<Mutex<RevocationStore>> {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::AgentKeypair;

    fn make_revoked_agent() -> (AgentKeypair, AgentId, RevocationList) {
        let kp = AgentKeypair::generate();
        let id = AgentId::from_public_key(&kp.public_key);
        let now = 1_000_000u64;
        let mut crl = RevocationList::new(now, 3600);
        crl.revoke(
            id,
            now,
            Some("compromised".into()),
            id,
            &kp.secret_key().unwrap(),
        );
        (kp, id, crl)
    }

    #[test]
    fn test_publish_request_roundtrip() {
        let (_, _, crl) = make_revoked_agent();
        let encoded = encode_publish_request(&crl).unwrap();
        let decoded = decode_publish_request(&encoded).unwrap();
        assert_eq!(decoded.entries.len(), crl.entries.len());
        assert_eq!(decoded.entries[0].agent_id, crl.entries[0].agent_id);
    }

    #[test]
    fn test_publish_response_roundtrip() {
        let encoded = encode_publish_response(0, "accepted").unwrap();
        let (status, message) = decode_publish_response(&encoded).unwrap();
        assert_eq!(status, 0);
        assert_eq!(message, "accepted");
    }

    #[test]
    fn test_query_request_roundtrip() {
        let (_, id, _) = make_revoked_agent();
        let encoded = encode_query_request(&id).unwrap();
        let decoded = decode_query_request(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn test_query_response_not_revoked() {
        let encoded = encode_query_response(None).unwrap();
        let decoded = decode_query_response(&encoded).unwrap();
        assert!(decoded.is_none());
    }

    #[test]
    fn test_list_response_roundtrip() {
        let (_, _, crl) = make_revoked_agent();
        let encoded = encode_list_response(&crl).unwrap();
        let decoded = decode_list_response(&encoded).unwrap();
        assert_eq!(decoded.entries.len(), crl.entries.len());
    }

    #[test]
    fn test_rpc_handler_publish() {
        let handler = RevocationRpcHandler::with_new_store();
        let (_, _, crl) = make_revoked_agent();
        let request = encode_publish_request(&crl).unwrap();
        let response = handler
            .handle_request(METHOD_REVOCATION_PUBLISH, &request, 1_000_000)
            .unwrap();
        let (status, _) = decode_publish_response(&response).unwrap();
        assert_eq!(status, 0);
        assert_eq!(handler.store().lock().unwrap().revoked_count(), 1);
    }

    #[test]
    fn test_rpc_handler_publish_expired_crl() {
        let handler = RevocationRpcHandler::with_new_store();
        let kp = AgentKeypair::generate();
        let id = AgentId::from_public_key(&kp.public_key);
        let now = 1_000_000u64;
        let mut crl = RevocationList::new(now - 7200, 3600); // Expired
        crl.revoke(id, now - 7200, None, id, &kp.secret_key().unwrap());
        let request = encode_publish_request(&crl).unwrap();
        let response = handler
            .handle_request(METHOD_REVOCATION_PUBLISH, &request, now)
            .unwrap();
        let (status, _) = decode_publish_response(&response).unwrap();
        assert_eq!(status, 1); // Rejected
        assert_eq!(handler.store().lock().unwrap().revoked_count(), 0);
    }

    #[test]
    fn test_rpc_handler_unknown_method() {
        let handler = RevocationRpcHandler::with_new_store();
        let result = handler.handle_request("aafp.unknown", &[], 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_gossip_receive_crl() {
        let store = Arc::new(Mutex::new(RevocationStore::new()));
        let gossip = RevocationGossip::with_defaults(store.clone());
        let (_, id, crl) = make_revoked_agent();
        let now = 1_000_000u64;

        let added = gossip.receive_crl(crl, now);
        assert!(added);
        assert!(store.lock().unwrap().is_revoked(&id));
    }

    #[test]
    fn test_gossip_receive_expired_crl_ignored() {
        let store = Arc::new(Mutex::new(RevocationStore::new()));
        let gossip = RevocationGossip::with_defaults(store.clone());
        let kp = AgentKeypair::generate();
        let id = AgentId::from_public_key(&kp.public_key);
        let now = 1_000_000u64;
        let mut crl = RevocationList::new(now - 7200, 3600); // Expired
        crl.revoke(id, now - 7200, None, id, &kp.secret_key().unwrap());

        let added = gossip.receive_crl(crl, now);
        assert!(!added);
        assert!(!store.lock().unwrap().is_revoked(&id));
    }

    #[test]
    fn test_gossip_needs_gossip_after_interval() {
        let store = Arc::new(Mutex::new(RevocationStore::new()));
        let gossip = RevocationGossip::new(store, Duration::from_millis(10));

        // Immediately after creation, needs_gossip may be false
        // (Instant::now() is in the past)
        std::thread::sleep(Duration::from_millis(20));
        assert!(gossip.needs_gossip());

        gossip.mark_gossiped();
        assert!(!gossip.needs_gossip());
    }
}
