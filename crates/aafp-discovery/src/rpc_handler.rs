//! Server-side handler for discovery RPC requests over QUIC (RFC-0004 §3).
//!
//! Handles `aafp.discovery.announce` and `aafp.discovery.lookup`
//! RPC requests received on AAFP RPC frames.
//!
//! ## Rate Limiting (RFC-0004 §3.4)
//! - Announce: 1 per 60 seconds per peer
//! - Lookup: 10 per 60 seconds per peer

use crate::discovery_v1::*;
use aafp_cbor::{encode, Value};
use aafp_identity::identity_v1::{AgentId, AgentRecord};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limit window (RFC-0004 §3.4: 60 seconds).
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum announces per window per peer (RFC-0004 §3.4).
const MAX_ANNOUNCES_PER_WINDOW: u32 = 1;

/// Maximum lookups per window per peer (RFC-0004 §3.4).
const MAX_LOOKUPS_PER_WINDOW: u32 = 10;

/// Maximum peers returned in an announce response.
const MAX_PEERS_IN_RESPONSE: usize = 10;

/// Server-side handler for discovery RPC requests.
///
/// Wraps a `CapabilityDht` and handles incoming RPC requests with
/// rate limiting and record validation.
pub struct DiscoveryRpcHandler {
    dht: Arc<Mutex<CapabilityDht>>,
    /// Rate limiter: agent_id → list of announce timestamps in current window
    announce_limits: Mutex<HashMap<AgentId, Vec<Instant>>>,
    /// Rate limiter: agent_id → list of lookup timestamps in current window
    lookup_limits: Mutex<HashMap<AgentId, Vec<Instant>>>,
}

impl DiscoveryRpcHandler {
    /// Create a new handler wrapping the given DHT.
    pub fn new(dht: Arc<Mutex<CapabilityDht>>) -> Self {
        Self {
            dht,
            announce_limits: Mutex::new(HashMap::new()),
            lookup_limits: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new handler with a fresh DHT.
    pub fn with_new_dht() -> Self {
        Self::new(Arc::new(Mutex::new(CapabilityDht::new())))
    }
}

/// Sharded server-side handler for discovery RPC requests (Track H4).
///
/// Wraps a `ShardedCapabilityDht` (256-way sharded) and handles incoming
/// RPC requests with rate limiting and record validation.
///
/// Unlike `DiscoveryRpcHandler`, this uses per-shard RwLocks, so concurrent
/// lookups proceed in parallel and announces only block operations on one
/// shard.
pub struct ShardedDiscoveryRpcHandler {
    dht: Arc<ShardedCapabilityDht>,
    /// Rate limiter: agent_id → list of announce timestamps in current window
    announce_limits: Mutex<HashMap<AgentId, Vec<Instant>>>,
    /// Rate limiter: agent_id → list of lookup timestamps in current window
    lookup_limits: Mutex<HashMap<AgentId, Vec<Instant>>>,
}

impl ShardedDiscoveryRpcHandler {
    /// Create a new sharded handler wrapping the given DHT.
    pub fn new(dht: Arc<ShardedCapabilityDht>) -> Self {
        Self {
            dht,
            announce_limits: Mutex::new(HashMap::new()),
            lookup_limits: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new sharded handler with a fresh DHT.
    pub fn with_new_dht() -> Self {
        Self::new(Arc::new(ShardedCapabilityDht::new()))
    }

    /// Handle an incoming RPC request.
    ///
    /// Returns the CBOR-encoded RPC response result value.
    pub async fn handle_request(
        &self,
        method: &str,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, DiscoveryError> {
        match method {
            METHOD_ANNOUNCE => self.handle_announce(params, caller_id).await,
            METHOD_LOOKUP => self.handle_lookup(params, caller_id).await,
            _ => Err(DiscoveryError::InvalidField {
                field: "method",
                message: format!("unknown method: {method}"),
            }),
        }
    }

    /// Handle `aafp.discovery.announce` (RFC-0004 §3.3).
    async fn handle_announce(
        &self,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, DiscoveryError> {
        // 1. Rate limit check
        if !self.check_rate_limit(&self.announce_limits, caller_id, MAX_ANNOUNCES_PER_WINDOW) {
            return Err(DiscoveryError::RateLimitExceeded);
        }

        // 2. Decode AgentRecord from params
        let announce_params = AnnounceParams::from_cbor(params)?;

        // 3. Verify the record's AgentId matches caller_id
        if &announce_params.record.agent_id != caller_id {
            return Err(DiscoveryError::InvalidField {
                field: "record.agent_id",
                message: "record agent_id does not match caller".to_string(),
            });
        }

        // 4. Insert into DHT (only locks one shard)
        self.dht.put(announce_params.record.clone()).await;

        // 5. Return known peers (up to limit) — scans all shards with read locks
        let peers = self
            .dht
            .get_all(
                &announce_params
                    .record
                    .capabilities
                    .iter()
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>(),
            )
            .await
            .into_iter()
            .filter(|r| &r.agent_id != caller_id)
            .take(MAX_PEERS_IN_RESPONSE)
            .collect::<Vec<_>>();

        let result = AnnounceResult::new(peers);
        Ok(result.to_cbor())
    }

    /// Handle `aafp.discovery.lookup` (RFC-0004 §3.3).
    async fn handle_lookup(
        &self,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, DiscoveryError> {
        // 1. Rate limit check
        if !self.check_rate_limit(&self.lookup_limits, caller_id, MAX_LOOKUPS_PER_WINDOW) {
            return Err(DiscoveryError::RateLimitExceeded);
        }

        // 2. Decode capability name from params
        let lookup_params = LookupParams::from_cbor(params)?;

        // 3. Query DHT for matching records (scans all shards with read locks)
        let limit = lookup_params.limit.unwrap_or(DEFAULT_LIMIT_AUTH) as usize;
        let peers = self
            .dht
            .get(&lookup_params.capability)
            .await
            .into_iter()
            .filter(|r| &r.agent_id != caller_id)
            .take(limit)
            .collect::<Vec<_>>();

        // 4. Return matching records
        let result = LookupResult::new(peers);
        Ok(result.to_cbor())
    }

    /// Check and update rate limit for a peer.
    fn check_rate_limit(
        &self,
        limits: &Mutex<HashMap<AgentId, Vec<Instant>>>,
        caller_id: &AgentId,
        max_per_window: u32,
    ) -> bool {
        let now = Instant::now();
        let window_start = now - RATE_LIMIT_WINDOW;
        let mut limits = limits.lock().unwrap();
        let timestamps = limits.entry(*caller_id).or_default();
        timestamps.retain(|&t| t > window_start);
        if timestamps.len() >= max_per_window as usize {
            return false;
        }
        timestamps.push(now);
        true
    }

    /// Get a reference to the underlying sharded DHT.
    pub fn dht(&self) -> &Arc<ShardedCapabilityDht> {
        &self.dht
    }
}

impl DiscoveryRpcHandler {
    /// Handle an incoming RPC request.
    ///
    /// Returns the CBOR-encoded RPC response result value.
    pub fn handle_request(
        &self,
        method: &str,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, DiscoveryError> {
        match method {
            METHOD_ANNOUNCE => self.handle_announce(params, caller_id),
            METHOD_LOOKUP => self.handle_lookup(params, caller_id),
            _ => Err(DiscoveryError::InvalidField {
                field: "method",
                message: format!("unknown method: {method}"),
            }),
        }
    }

    /// Handle `aafp.discovery.announce` (RFC-0004 §3.3).
    ///
    /// 1. Rate limit check (1 per 60s)
    /// 2. Decode AgentRecord from params
    /// 3. Verify the record's AgentId matches caller_id
    /// 4. Insert into DHT
    /// 5. Return known peers (up to MAX_PEERS_IN_RESPONSE)
    fn handle_announce(
        &self,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, DiscoveryError> {
        // 1. Rate limit check
        if !self.check_rate_limit(&self.announce_limits, caller_id, MAX_ANNOUNCES_PER_WINDOW) {
            return Err(DiscoveryError::RateLimitExceeded);
        }

        // 2. Decode AgentRecord from params
        let announce_params = AnnounceParams::from_cbor(params)?;

        // 3. Verify the record's AgentId matches caller_id
        if &announce_params.record.agent_id != caller_id {
            return Err(DiscoveryError::InvalidField {
                field: "record.agent_id",
                message: "record agent_id does not match caller".to_string(),
            });
        }

        // 4. Insert into DHT
        let peers = {
            let mut dht = self.dht.lock().unwrap();
            dht.put(announce_params.record.clone());

            // 5. Return known peers (up to limit)
            dht.get_all(
                &announce_params
                    .record
                    .capabilities
                    .iter()
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>(),
            )
            .into_iter()
            .filter(|r| &r.agent_id != caller_id) // don't echo back the announcer
            .take(MAX_PEERS_IN_RESPONSE)
            .collect::<Vec<_>>()
        };

        let result = AnnounceResult::new(peers);
        Ok(result.to_cbor())
    }

    /// Handle `aafp.discovery.lookup` (RFC-0004 §3.3).
    ///
    /// 1. Rate limit check (10 per 60s)
    /// 2. Decode capability name from params
    /// 3. Query DHT for matching records
    /// 4. Return matching records (up to limit)
    fn handle_lookup(&self, params: &Value, caller_id: &AgentId) -> Result<Value, DiscoveryError> {
        // 1. Rate limit check
        if !self.check_rate_limit(&self.lookup_limits, caller_id, MAX_LOOKUPS_PER_WINDOW) {
            return Err(DiscoveryError::RateLimitExceeded);
        }

        // 2. Decode capability name from params
        let lookup_params = LookupParams::from_cbor(params)?;

        // 3. Query DHT for matching records
        let limit = lookup_params.limit.unwrap_or(DEFAULT_LIMIT_AUTH) as usize;
        let peers = {
            let dht = self.dht.lock().unwrap();
            dht.get(&lookup_params.capability)
                .into_iter()
                .filter(|r| &r.agent_id != caller_id) // don't return caller's own record
                .take(limit)
                .collect::<Vec<_>>()
        };

        // 4. Return matching records
        let result = LookupResult::new(peers);
        Ok(result.to_cbor())
    }

    /// Check and update rate limit for a peer.
    ///
    /// Returns true if the request is allowed, false if rate-limited.
    fn check_rate_limit(
        &self,
        limits: &Mutex<HashMap<AgentId, Vec<Instant>>>,
        agent_id: &AgentId,
        max_per_window: u32,
    ) -> bool {
        let mut limits = limits.lock().unwrap();
        let now = Instant::now();
        let window_start = now - RATE_LIMIT_WINDOW;

        let timestamps = limits.entry(*agent_id).or_default();

        // Evict timestamps outside the current window
        timestamps.retain(|t| *t > window_start);

        if timestamps.len() as u32 >= max_per_window {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Get a reference to the underlying DHT (for testing or direct access).
    pub fn dht(&self) -> &Arc<Mutex<CapabilityDht>> {
        &self.dht
    }
}

/// Client-side discovery RPC helper.
///
/// Provides convenience methods for sending discovery RPC requests
/// over an established AAFP connection. The actual transport is handled
/// by the caller — these methods just encode/decode the CBOR payloads.
pub struct DiscoveryClient;

impl DiscoveryClient {
    /// Encode an announce request payload.
    ///
    /// Returns CBOR bytes suitable for sending as an RPC_REQUEST frame payload.
    pub fn encode_announce_request(
        correlation_id: u64,
        record: &AgentRecord,
    ) -> Result<Vec<u8>, DiscoveryError> {
        let request = aafp_messaging::RpcRequest {
            id: correlation_id,
            method: METHOD_ANNOUNCE.to_string(),
            params: AnnounceParams::new(record.clone()).to_cbor(),
        };
        encode(&request.to_cbor()).map_err(DiscoveryError::Cbor)
    }

    /// Encode a lookup request payload.
    ///
    /// Returns CBOR bytes suitable for sending as an RPC_REQUEST frame payload.
    pub fn encode_lookup_request(
        correlation_id: u64,
        capability: &str,
        limit: Option<u64>,
    ) -> Result<Vec<u8>, DiscoveryError> {
        let mut params = LookupParams::new(capability);
        if let Some(l) = limit {
            params = params.with_limit(l);
        }
        let request = aafp_messaging::RpcRequest {
            id: correlation_id,
            method: METHOD_LOOKUP.to_string(),
            params: params.to_cbor(),
        };
        encode(&request.to_cbor()).map_err(DiscoveryError::Cbor)
    }

    /// Decode an announce response.
    ///
    /// Parses the RPC_RESPONSE payload and returns the list of known peers.
    pub fn decode_announce_response(data: &[u8]) -> Result<Vec<AgentRecord>, DiscoveryError> {
        let response = aafp_messaging::RpcResponse::decode(data).map_err(|e| {
            DiscoveryError::InvalidField {
                field: "response",
                message: e.to_string(),
            }
        })?;
        if let Some(err) = response.error {
            return Err(DiscoveryError::InvalidField {
                field: "error",
                message: err.message,
            });
        }
        let result_val = response
            .result
            .ok_or(DiscoveryError::MissingField("result"))?;
        let announce_result = AnnounceResult::from_cbor(&result_val)?;
        Ok(announce_result.peers)
    }

    /// Decode a lookup response.
    ///
    /// Parses the RPC_RESPONSE payload and returns the matching agents.
    pub fn decode_lookup_response(data: &[u8]) -> Result<Vec<AgentRecord>, DiscoveryError> {
        let response = aafp_messaging::RpcResponse::decode(data).map_err(|e| {
            DiscoveryError::InvalidField {
                field: "response",
                message: e.to_string(),
            }
        })?;
        if let Some(err) = response.error {
            return Err(DiscoveryError::InvalidField {
                field: "error",
                message: err.message,
            });
        }
        let result_val = response
            .result
            .ok_or(DiscoveryError::MissingField("result"))?;
        let lookup_result = LookupResult::from_cbor(&result_val)?;
        Ok(lookup_result.peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_crypto::{MlDsa65, SignatureScheme};
    use aafp_identity::identity_v1::CapabilityDescriptor;

    fn make_record(capabilities: Vec<&str>) -> AgentRecord {
        let (pk, sk) = MlDsa65::keypair();
        let now = 1700000000u64;
        let mut record = AgentRecord::new(
            &pk.0,
            capabilities
                .iter()
                .map(|c| CapabilityDescriptor::new(*c))
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
    fn test_handle_announce_and_lookup() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let record = make_record(vec!["inference"]);
        let caller_id = record.agent_id.clone();

        // Announce
        let params = AnnounceParams::new(record.clone()).to_cbor();
        let result = handler
            .handle_request(METHOD_ANNOUNCE, &params, &caller_id)
            .unwrap();
        let announce_result = AnnounceResult::from_cbor(&result).unwrap();
        // No other peers yet
        assert!(announce_result.peers.is_empty());

        // Lookup by another agent
        let other_id = AgentId([0xBB; 32]);
        let lookup_params = LookupParams::new("inference").to_cbor();
        let result = handler
            .handle_request(METHOD_LOOKUP, &lookup_params, &other_id)
            .unwrap();
        let lookup_result = LookupResult::from_cbor(&result).unwrap();
        assert_eq!(lookup_result.peers.len(), 1);
        assert_eq!(lookup_result.peers[0].agent_id, caller_id);
    }

    #[test]
    fn test_announce_rate_limit() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let record = make_record(vec!["inference"]);
        let caller_id = record.agent_id.clone();
        let params = AnnounceParams::new(record.clone()).to_cbor();

        // First announce succeeds
        assert!(handler
            .handle_request(METHOD_ANNOUNCE, &params, &caller_id)
            .is_ok());

        // Second announce within 60s is rate-limited
        let result = handler.handle_request(METHOD_ANNOUNCE, &params, &caller_id);
        assert!(matches!(result, Err(DiscoveryError::RateLimitExceeded)));
    }

    #[test]
    fn test_lookup_rate_limit() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let caller_id = AgentId([0xCC; 32]);
        let params = LookupParams::new("inference").to_cbor();

        // 10 lookups succeed
        for _ in 0..10 {
            assert!(handler
                .handle_request(METHOD_LOOKUP, &params, &caller_id)
                .is_ok());
        }

        // 11th is rate-limited
        let result = handler.handle_request(METHOD_LOOKUP, &params, &caller_id);
        assert!(matches!(result, Err(DiscoveryError::RateLimitExceeded)));
    }

    #[test]
    fn test_announce_agent_id_mismatch() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let record = make_record(vec!["inference"]);
        let wrong_caller = AgentId([0xDD; 32]);
        let params = AnnounceParams::new(record).to_cbor();

        let result = handler.handle_request(METHOD_ANNOUNCE, &params, &wrong_caller);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_method() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let caller_id = AgentId([0xEE; 32]);
        let result = handler.handle_request("aafp.unknown", &Value::IntMap(vec![]), &caller_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_empty_capability() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let caller_id = AgentId([0xFF; 32]);
        let params = LookupParams::new("nonexistent").to_cbor();
        let result = handler
            .handle_request(METHOD_LOOKUP, &params, &caller_id)
            .unwrap();
        let lookup_result = LookupResult::from_cbor(&result).unwrap();
        assert!(lookup_result.peers.is_empty());
    }

    #[test]
    fn test_announce_returns_known_peers() {
        let handler = DiscoveryRpcHandler::with_new_dht();

        // First agent announces
        let record1 = make_record(vec!["inference"]);
        let caller1 = record1.agent_id.clone();
        let params1 = AnnounceParams::new(record1).to_cbor();
        handler
            .handle_request(METHOD_ANNOUNCE, &params1, &caller1)
            .unwrap();

        // Second agent announces — should get first agent as a known peer
        let record2 = make_record(vec!["inference"]);
        let caller2 = record2.agent_id.clone();
        let params2 = AnnounceParams::new(record2.clone()).to_cbor();
        let result = handler
            .handle_request(METHOD_ANNOUNCE, &params2, &caller2)
            .unwrap();
        let announce_result = AnnounceResult::from_cbor(&result).unwrap();
        assert_eq!(announce_result.peers.len(), 1);
        assert_eq!(announce_result.peers[0].agent_id, caller1);
    }

    #[test]
    fn test_client_encode_announce_request() {
        let record = make_record(vec!["inference"]);
        let encoded = DiscoveryClient::encode_announce_request(1, &record).unwrap();
        assert!(!encoded.is_empty());

        // Decode and verify
        let request = aafp_messaging::RpcRequest::decode(&encoded).unwrap();
        assert_eq!(request.id, 1);
        assert_eq!(request.method, METHOD_ANNOUNCE);
    }

    #[test]
    fn test_client_encode_lookup_request() {
        let encoded = DiscoveryClient::encode_lookup_request(2, "inference", None).unwrap();
        assert!(!encoded.is_empty());

        let request = aafp_messaging::RpcRequest::decode(&encoded).unwrap();
        assert_eq!(request.id, 2);
        assert_eq!(request.method, METHOD_LOOKUP);
    }

    #[test]
    fn test_client_decode_lookup_response() {
        let handler = DiscoveryRpcHandler::with_new_dht();
        let record = make_record(vec!["inference"]);
        let caller_id = record.agent_id.clone();
        let params = AnnounceParams::new(record).to_cbor();
        handler
            .handle_request(METHOD_ANNOUNCE, &params, &caller_id)
            .unwrap();

        // Lookup
        let other_id = AgentId([0xAA; 32]);
        let lookup_params = LookupParams::new("inference").to_cbor();
        let result_val = handler
            .handle_request(METHOD_LOOKUP, &lookup_params, &other_id)
            .unwrap();

        // Encode as RPC response
        let response = aafp_messaging::RpcResponse {
            id: 1,
            result: Some(result_val),
            error: None,
        };
        let encoded = response.encode().unwrap();

        // Decode using client helper
        let peers = DiscoveryClient::decode_lookup_response(&encoded).unwrap();
        assert_eq!(peers.len(), 1);
    }
}
