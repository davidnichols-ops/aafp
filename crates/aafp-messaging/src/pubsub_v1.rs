//! Networked PubSub: topic-based publish/subscribe over AAFP (RFC 0009).
//!
//! v1 implements floodsub: published messages are forwarded to all known
//! peers subscribed to the same topic. A gossipsub upgrade is planned for
//! the future (RFC 0009 §4).
//!
//! ## Wire Format (RFC 0009 §2)
//!
//! PubSub uses AAFP RPC frames with methods:
//! - `aafp.pubsub.subscribe`: Subscribe to a topic
//! - `aafp.pubsub.unsubscribe`: Unsubscribe from a topic
//! - `aafp.pubsub.publish`: Publish a message to a topic
//!
//! ## Message Propagation (RFC 0009 §3)
//!
//! Floodsub: messages are forwarded to ALL known peers subscribed to the
//! topic. A `seen` list prevents loops. TTL limits hop count.

use aafp_cbor::{encode, int_map, int_map_get, CborError, Value};
use aafp_identity::AgentId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::broadcast;

/// RPC method names (RFC 0009 §2.1).
pub const METHOD_SUBSCRIBE: &str = "aafp.pubsub.subscribe";
pub const METHOD_UNSUBSCRIBE: &str = "aafp.pubsub.unsubscribe";
pub const METHOD_PUBLISH: &str = "aafp.pubsub.publish";

/// Default TTL for published messages (RFC 0009 §3.4).
pub const DEFAULT_TTL: u64 = 3;

/// Default buffer size for local broadcast channels.
const DEFAULT_BUFFER_SIZE: usize = 256;

/// Seen-cache retention time (RFC 0009 §3.3).
const SEEN_CACHE_TTL: Duration = Duration::from_secs(60);

/// Maximum seen-cache entries.
const MAX_SEEN_CACHE: usize = 10_000;

/// A pubsub topic name.
pub type Topic = String;

/// A message published to a topic.
#[derive(Clone, Debug)]
pub struct TopicMessage {
    pub topic: Topic,
    pub from: AgentId,
    pub data: Vec<u8>,
}

/// PubSub errors.
#[derive(Debug, Error)]
pub enum PubSubError {
    #[error("topic not found")]
    TopicNotFound,
    #[error("broadcast error: {0}")]
    Broadcast(String),
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    #[error("message expired (TTL=0)")]
    Expired,
    #[error("already seen")]
    AlreadySeen,
}

/// Helper to create a CBOR invalid error.
fn cbor_err(msg: impl Into<String>) -> CborError {
    CborError::Invalid {
        offset: 0,
        message: msg.into(),
    }
}

/// Subscribe request params (RFC 0009 §2.2).
///
/// ```cbor
/// { 1: tstr }
/// ```
#[derive(Clone, Debug)]
pub struct SubscribeParams {
    pub topic: Topic,
}

impl SubscribeParams {
    pub fn new(topic: impl Into<String>) -> Self {
        Self {
            topic: topic.into(),
        }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![(1, Value::TextString(self.topic.clone()))])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PubSubError> {
        let topic = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            Some(other) => {
                return Err(PubSubError::Cbor(cbor_err(format!(
                    "expected tstr, got {other:?}"
                ))))
            }
            None => return Err(PubSubError::Cbor(cbor_err("missing topic"))),
        };
        Ok(Self { topic })
    }
}

/// Unsubscribe request params (RFC 0009 §2.3).
pub type UnsubscribeParams = SubscribeParams;

/// Publish request params (RFC 0009 §2.4).
///
/// ```cbor
/// { 1: tstr, 2: bstr, 3: uint, 4: [ *bstr ] }
/// ```
#[derive(Clone, Debug)]
pub struct PublishParams {
    pub topic: Topic,
    pub data: Vec<u8>,
    pub ttl: u64,
    pub seen: Vec<AgentId>,
}

impl PublishParams {
    pub fn new(topic: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            topic: topic.into(),
            data,
            ttl: DEFAULT_TTL,
            seen: Vec::new(),
        }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.topic.clone())),
            (2, Value::ByteString(self.data.clone())),
            (3, Value::Unsigned(self.ttl)),
            (
                4,
                Value::Array(
                    self.seen
                        .iter()
                        .map(|id| Value::ByteString(id.to_vec()))
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PubSubError> {
        let topic = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(PubSubError::Cbor(cbor_err("missing topic"))),
        };

        let data = match int_map_get(val, 2) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => return Err(PubSubError::Cbor(cbor_err("missing data"))),
        };

        let ttl = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n,
            _ => DEFAULT_TTL,
        };

        let seen = match int_map_get(val, 4) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::ByteString(b) = v {
                        if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(b);
                            Some(arr)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(Self {
            topic,
            data,
            ttl,
            seen,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PubSubError> {
        encode(&self.to_cbor()).map_err(PubSubError::Cbor)
    }
}

/// Seen-cache for message deduplication (RFC 0009 §3.3).
///
/// Tracks recently seen message IDs to prevent loops.
struct SeenCache {
    entries: HashMap<Vec<u8>, Instant>,
}

impl SeenCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Check if a message ID has been seen. If not, mark it as seen.
    /// Returns true if the message is new (not seen before).
    fn check_and_mark(&mut self, msg_id: &[u8]) -> bool {
        let now = Instant::now();
        // Evict expired entries
        self.entries
            .retain(|_, t| now.duration_since(*t) < SEEN_CACHE_TTL);
        // Check max size
        if self.entries.len() >= MAX_SEEN_CACHE {
            // Evict oldest 10%
            let mut sorted: Vec<(Vec<u8>, Instant)> =
                self.entries.iter().map(|(k, v)| (k.clone(), *v)).collect();
            sorted.sort_by_key(|(_, t)| *t);
            let evict_count = MAX_SEEN_CACHE / 10;
            for (k, _) in sorted.into_iter().take(evict_count) {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(msg_id.to_vec(), now).is_none()
    }
}

/// Networked PubSub system (RFC 0009).
///
/// Tracks local and remote subscriptions, handles message propagation
/// via floodsub, and deduplicates messages using a seen-cache.
pub struct NetworkedPubSub {
    /// Local subscriptions: topic → broadcast sender
    local: HashMap<Topic, broadcast::Sender<TopicMessage>>,
    /// Remote peer subscriptions: topic → set of peer AgentIds
    remote: Arc<Mutex<HashMap<Topic, HashSet<AgentId>>>>,
    /// Our agent ID
    our_id: AgentId,
    /// Buffer size for local channels
    buffer_size: usize,
    /// Seen-cache for message deduplication
    seen_cache: Mutex<SeenCache>,
}

impl NetworkedPubSub {
    /// Create a new networked pubsub with the given agent ID.
    pub fn new(our_id: AgentId) -> Self {
        Self {
            local: HashMap::new(),
            remote: Arc::new(Mutex::new(HashMap::new())),
            our_id,
            buffer_size: DEFAULT_BUFFER_SIZE,
            seen_cache: Mutex::new(SeenCache::new()),
        }
    }

    /// Create with a custom buffer size.
    pub fn with_buffer_size(our_id: AgentId, buffer_size: usize) -> Self {
        Self {
            local: HashMap::new(),
            remote: Arc::new(Mutex::new(HashMap::new())),
            our_id,
            buffer_size,
            seen_cache: Mutex::new(SeenCache::new()),
        }
    }

    /// Subscribe to a topic locally. Returns a receiver for messages.
    pub fn subscribe(&mut self, topic: &str) -> broadcast::Receiver<TopicMessage> {
        let buffer_size = self.buffer_size;
        let sender = self
            .local
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(buffer_size).0);
        sender.subscribe()
    }

    /// Unsubscribe from a topic locally (drops the broadcast channel).
    pub fn unsubscribe(&mut self, topic: &str) {
        self.local.remove(topic);
    }

    /// Publish a message locally (does not propagate to remote peers).
    ///
    /// For networked publishing, use `encode_publish_request` to get the
    /// RPC payload, send it to peers, and let them call `handle_remote_message`.
    pub fn publish_local(
        &self,
        topic: &str,
        from: AgentId,
        data: Vec<u8>,
    ) -> Result<(), PubSubError> {
        let sender = self.local.get(topic).ok_or(PubSubError::TopicNotFound)?;
        let msg = TopicMessage {
            topic: topic.to_string(),
            from,
            data,
        };
        sender
            .send(msg)
            .map(|_| ())
            .map_err(|e| PubSubError::Broadcast(e.to_string()))
    }

    /// Handle a received PubSub message from a remote peer (RFC 0009 §3.3).
    ///
    /// 1. Check seen-cache (drop if already seen)
    /// 2. Deliver to local subscribers
    /// 3. Return whether the message should be re-forwarded (TTL > 0)
    pub fn handle_remote_message(
        &self,
        params: &PublishParams,
        from: AgentId,
    ) -> Result<bool, PubSubError> {
        // Generate message ID for deduplication
        let msg_id = self.compute_msg_id(params, &from);

        // Check seen-cache
        {
            let mut cache = self.seen_cache.lock().unwrap();
            if !cache.check_and_mark(&msg_id) {
                return Err(PubSubError::AlreadySeen);
            }
        }

        // Deliver to local subscribers
        let _ = self.publish_local(&params.topic, from, params.data.clone());

        // Check TTL for re-forwarding
        Ok(params.ttl > 0)
    }

    /// Compute a message ID for deduplication.
    fn compute_msg_id(&self, params: &PublishParams, from: &AgentId) -> Vec<u8> {
        let mut id = Vec::new();
        id.extend_from_slice(params.topic.as_bytes());
        id.extend_from_slice(&params.data);
        id.extend_from_slice(from);
        id
    }

    /// Register a remote peer's subscription (RFC 0009 §3.1).
    pub fn add_remote_subscriber(&self, topic: &str, peer: AgentId) {
        let mut remote = self.remote.lock().unwrap();
        remote.entry(topic.to_string()).or_default().insert(peer);
    }

    /// Remove a remote peer's subscription.
    pub fn remove_remote_subscriber(&self, topic: &str, peer: &AgentId) {
        let mut remote = self.remote.lock().unwrap();
        if let Some(set) = remote.get_mut(topic) {
            set.remove(peer);
            if set.is_empty() {
                remote.remove(topic);
            }
        }
    }

    /// Remove all subscriptions for a peer (e.g., on connection close).
    pub fn remove_peer(&self, peer: &AgentId) {
        let mut remote = self.remote.lock().unwrap();
        let topics_to_remove: Vec<String> = remote
            .iter()
            .filter_map(|(topic, set)| {
                if set.contains(peer) {
                    Some(topic.clone())
                } else {
                    None
                }
            })
            .collect();
        for topic in topics_to_remove {
            if let Some(set) = remote.get_mut(&topic) {
                set.remove(peer);
                if set.is_empty() {
                    remote.remove(&topic);
                }
            }
        }
    }

    /// Get the list of remote peers subscribed to a topic.
    pub fn remote_subscribers(&self, topic: &str) -> Vec<AgentId> {
        let remote = self.remote.lock().unwrap();
        remote
            .get(topic)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all topics with remote subscribers.
    pub fn remote_topics(&self) -> Vec<String> {
        let remote = self.remote.lock().unwrap();
        remote.keys().cloned().collect()
    }

    /// List all active local topics.
    pub fn topics(&self) -> Vec<&str> {
        self.local.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of local subscribers for a topic.
    pub fn subscriber_count(&self, topic: &str) -> usize {
        self.local
            .get(topic)
            .map(|s| s.receiver_count())
            .unwrap_or(0)
    }

    /// Get our agent ID.
    pub fn our_id(&self) -> &AgentId {
        &self.our_id
    }

    /// Get a reference to the remote subscriptions map (for network propagation).
    pub fn remote_subscriptions(&self) -> &Arc<Mutex<HashMap<Topic, HashSet<AgentId>>>> {
        &self.remote
    }

    /// Encode a publish RPC request for sending to remote peers.
    ///
    /// Returns CBOR bytes suitable for an RPC_REQUEST frame payload.
    pub fn encode_publish_request(
        &self,
        topic: &str,
        data: Vec<u8>,
        ttl: u64,
        seen: Vec<AgentId>,
    ) -> Result<Vec<u8>, PubSubError> {
        let params = PublishParams {
            topic: topic.to_string(),
            data,
            ttl,
            seen,
        };
        params.encode()
    }
}

/// Server-side handler for PubSub RPC requests (RFC 0009 §2).
///
/// Handles subscribe, unsubscribe, and publish RPC methods.
pub struct PubSubRpcHandler {
    pubsub: Arc<NetworkedPubSub>,
}

impl PubSubRpcHandler {
    /// Create a new handler wrapping the given PubSub instance.
    pub fn new(pubsub: Arc<NetworkedPubSub>) -> Self {
        Self { pubsub }
    }

    /// Handle an incoming RPC request.
    ///
    /// Returns the CBOR-encoded RPC response result value.
    pub fn handle_request(
        &self,
        method: &str,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, PubSubError> {
        match method {
            METHOD_SUBSCRIBE => self.handle_subscribe(params, caller_id),
            METHOD_UNSUBSCRIBE => self.handle_unsubscribe(params, caller_id),
            METHOD_PUBLISH => self.handle_publish(params, caller_id),
            _ => Err(PubSubError::Cbor(cbor_err(format!(
                "unknown method: {method}"
            )))),
        }
    }

    fn handle_subscribe(&self, params: &Value, caller_id: &AgentId) -> Result<Value, PubSubError> {
        let subscribe_params = SubscribeParams::from_cbor(params)?;
        self.pubsub
            .add_remote_subscriber(&subscribe_params.topic, *caller_id);
        Ok(int_map(vec![]))
    }

    fn handle_unsubscribe(
        &self,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, PubSubError> {
        let unsubscribe_params = UnsubscribeParams::from_cbor(params)?;
        self.pubsub
            .remove_remote_subscriber(&unsubscribe_params.topic, caller_id);
        Ok(int_map(vec![]))
    }

    fn handle_publish(&self, params: &Value, caller_id: &AgentId) -> Result<Value, PubSubError> {
        let publish_params = PublishParams::from_cbor(params)?;
        match self
            .pubsub
            .handle_remote_message(&publish_params, *caller_id)
        {
            Ok(_) => Ok(int_map(vec![])),
            Err(PubSubError::AlreadySeen) => Ok(int_map(vec![])),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn make_agent_id(byte: u8) -> AgentId {
        [byte; 32]
    }

    #[tokio::test]
    async fn test_local_subscribe_and_publish() {
        let mut pubsub = NetworkedPubSub::new(make_agent_id(1));
        let mut rx = pubsub.subscribe("test-topic");
        let from = make_agent_id(2);

        pubsub
            .publish_local("test-topic", from, b"hello".to_vec())
            .unwrap();

        let msg = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.topic, "test-topic");
        assert_eq!(msg.from, from);
        assert_eq!(msg.data, b"hello");
    }

    #[tokio::test]
    async fn test_multiple_local_subscribers() {
        let mut pubsub = NetworkedPubSub::new(make_agent_id(1));
        let mut rx1 = pubsub.subscribe("topic");
        let mut rx2 = pubsub.subscribe("topic");
        let from = make_agent_id(2);

        pubsub
            .publish_local("topic", from, b"msg".to_vec())
            .unwrap();

        let msg1 = timeout(Duration::from_secs(1), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        let msg2 = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg1.data, b"msg");
        assert_eq!(msg2.data, b"msg");
    }

    #[test]
    fn test_remote_subscription_tracking() {
        let pubsub = NetworkedPubSub::new(make_agent_id(1));
        let peer_a = make_agent_id(2);
        let peer_b = make_agent_id(3);

        pubsub.add_remote_subscriber("topic1", peer_a);
        pubsub.add_remote_subscriber("topic1", peer_b);
        pubsub.add_remote_subscriber("topic2", peer_a);

        assert_eq!(pubsub.remote_subscribers("topic1").len(), 2);
        assert_eq!(pubsub.remote_subscribers("topic2").len(), 1);
        assert_eq!(pubsub.remote_subscribers("topic3").len(), 0);
        assert_eq!(pubsub.remote_topics().len(), 2);
    }

    #[test]
    fn test_remove_remote_subscriber() {
        let pubsub = NetworkedPubSub::new(make_agent_id(1));
        let peer = make_agent_id(2);

        pubsub.add_remote_subscriber("topic", peer);
        assert_eq!(pubsub.remote_subscribers("topic").len(), 1);

        pubsub.remove_remote_subscriber("topic", &peer);
        assert_eq!(pubsub.remote_subscribers("topic").len(), 0);
    }

    #[test]
    fn test_remove_peer_all_topics() {
        let pubsub = NetworkedPubSub::new(make_agent_id(1));
        let peer = make_agent_id(2);

        pubsub.add_remote_subscriber("topic1", peer);
        pubsub.add_remote_subscriber("topic2", peer);
        pubsub.add_remote_subscriber("topic3", peer);

        pubsub.remove_peer(&peer);

        assert_eq!(pubsub.remote_subscribers("topic1").len(), 0);
        assert_eq!(pubsub.remote_subscribers("topic2").len(), 0);
        assert_eq!(pubsub.remote_subscribers("topic3").len(), 0);
        assert_eq!(pubsub.remote_topics().len(), 0);
    }

    #[tokio::test]
    async fn test_handle_remote_message_delivers_locally() {
        let mut pubsub = NetworkedPubSub::new(make_agent_id(1));
        let mut rx = pubsub.subscribe("remote-topic");
        let from = make_agent_id(2);

        let params = PublishParams::new("remote-topic", b"remote data".to_vec());
        let should_forward = pubsub.handle_remote_message(&params, from).unwrap();

        assert!(should_forward);
        let msg = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.data, b"remote data");
    }

    #[tokio::test]
    async fn test_handle_remote_message_dedup() {
        let mut pubsub = NetworkedPubSub::new(make_agent_id(1));
        pubsub.subscribe("dedup-topic");
        let from = make_agent_id(2);

        let params = PublishParams::new("dedup-topic", b"msg".to_vec());

        let result1 = pubsub.handle_remote_message(&params, from);
        assert!(result1.is_ok());

        let result2 = pubsub.handle_remote_message(&params, from);
        assert!(matches!(result2, Err(PubSubError::AlreadySeen)));
    }

    #[test]
    fn test_handle_remote_message_ttl_zero() {
        let mut pubsub = NetworkedPubSub::new(make_agent_id(1));
        pubsub.subscribe("ttl-topic");
        let from = make_agent_id(2);

        let params = PublishParams {
            topic: "ttl-topic".to_string(),
            data: b"msg".to_vec(),
            ttl: 0,
            seen: vec![],
        };

        let should_forward = pubsub.handle_remote_message(&params, from).unwrap();
        assert!(!should_forward);
    }

    #[test]
    fn test_publish_params_cbor_roundtrip() {
        let params = PublishParams {
            topic: "test".to_string(),
            data: b"hello".to_vec(),
            ttl: 3,
            seen: vec![make_agent_id(1), make_agent_id(2)],
        };

        let cbor = params.to_cbor();
        let decoded = PublishParams::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.topic, "test");
        assert_eq!(decoded.data, b"hello");
        assert_eq!(decoded.ttl, 3);
        assert_eq!(decoded.seen.len(), 2);
        assert_eq!(decoded.seen[0], make_agent_id(1));
    }

    #[test]
    fn test_subscribe_params_cbor_roundtrip() {
        let params = SubscribeParams::new("my-topic");
        let cbor = params.to_cbor();
        let decoded = SubscribeParams::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.topic, "my-topic");
    }

    #[test]
    fn test_rpc_handler_subscribe() {
        let pubsub = Arc::new(NetworkedPubSub::new(make_agent_id(1)));
        let handler = PubSubRpcHandler::new(pubsub.clone());
        let caller = make_agent_id(2);

        let params = SubscribeParams::new("test-topic").to_cbor();
        let result = handler
            .handle_request(METHOD_SUBSCRIBE, &params, &caller)
            .unwrap();

        assert!(matches!(result, Value::IntMap(ref v) if v.is_empty()));
        assert_eq!(pubsub.remote_subscribers("test-topic").len(), 1);
    }

    #[test]
    fn test_rpc_handler_unsubscribe() {
        let pubsub = Arc::new(NetworkedPubSub::new(make_agent_id(1)));
        let handler = PubSubRpcHandler::new(pubsub.clone());
        let caller = make_agent_id(2);

        let params = SubscribeParams::new("test-topic").to_cbor();
        handler
            .handle_request(METHOD_SUBSCRIBE, &params, &caller)
            .unwrap();
        assert_eq!(pubsub.remote_subscribers("test-topic").len(), 1);

        let params = UnsubscribeParams::new("test-topic").to_cbor();
        handler
            .handle_request(METHOD_UNSUBSCRIBE, &params, &caller)
            .unwrap();
        assert_eq!(pubsub.remote_subscribers("test-topic").len(), 0);
    }

    #[tokio::test]
    async fn test_rpc_handler_publish() {
        let mut pubsub = NetworkedPubSub::new(make_agent_id(1));
        let mut rx = pubsub.subscribe("rpc-topic");
        let pubsub = Arc::new(pubsub);
        let handler = PubSubRpcHandler::new(pubsub.clone());
        let caller = make_agent_id(2);

        let params = PublishParams::new("rpc-topic", b"rpc data".to_vec()).to_cbor();
        let result = handler
            .handle_request(METHOD_PUBLISH, &params, &caller)
            .unwrap();
        assert!(matches!(result, Value::IntMap(ref v) if v.is_empty()));

        let msg = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.data, b"rpc data");
    }

    #[test]
    fn test_rpc_handler_unknown_method() {
        let pubsub = Arc::new(NetworkedPubSub::new(make_agent_id(1)));
        let handler = PubSubRpcHandler::new(pubsub);
        let caller = make_agent_id(2);

        let result = handler.handle_request("aafp.unknown", &int_map(vec![]), &caller);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_publish_request() {
        let pubsub = NetworkedPubSub::new(make_agent_id(1));
        let encoded = pubsub
            .encode_publish_request("test", b"data".to_vec(), 3, vec![make_agent_id(2)])
            .unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_seen_cache_eviction() {
        let mut cache = SeenCache::new();
        let msg_id = vec![1, 2, 3];

        assert!(cache.check_and_mark(&msg_id));
        assert!(!cache.check_and_mark(&msg_id));
    }
}
