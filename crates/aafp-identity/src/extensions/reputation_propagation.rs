//! Reputation propagation via gossip (Track W8).
//!
//! Gossips reputation updates across the network using a periodic
//! fanout-based broadcast with TTL decay and anti-entropy sync. This
//! module is distinct from [`super::reputation_scoring`], which *computes*
//! a score locally; here we propagate already-computed scores to peers and
//! merge incoming scores with local state, resolving conflicts by highest
//! timestamp or majority vote.
//!
//! The gossip protocol is **simulated** — there is no actual network. The
//! [`ReputationPropagator`] tracks what *would* be sent and received
//! (outbox, inbox, peer table, stats) so that callers and tests can drive
//! the protocol deterministically.

use super::reputation_scoring::ReputationScore;
use crate::identity_v1::{AgentId, IdentityError};
use aafp_cbor::{encode, int_map, int_map_get, Value};
use aafp_crypto::{MlDsa65, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, SignatureScheme};
use std::collections::HashMap;

/// Domain separator for reputation-update signatures.
pub const REPUTATION_DOMAIN_SEPARATOR: &[u8] = b"aafp-v1-reputation-update";

/// Default gossip interval in milliseconds.
pub const DEFAULT_GOSSIP_INTERVAL_MS: u64 = 5_000;
/// Default maximum number of updates batched per gossip message.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 32;
/// Default fanout (number of peers each gossip round targets).
pub const DEFAULT_FANOUT: usize = 4;
/// Default time-to-live for a gossip message in milliseconds.
pub const DEFAULT_TTL_MS: u64 = 30_000;
/// Default number of bootstrap peers.
pub const DEFAULT_BOOTSTRAP_PEERS: usize = 3;
/// Default freshness window (ms) within which an update is considered fresh.
pub const DEFAULT_FRESHNESS_WINDOW_MS: u64 = 60_000;

/// Trust level assigned to a peer, influencing how its updates are merged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[derive(Default)]
pub enum TrustLevel {
    /// Fully trusted peer; updates weighted highest.
    Trusted,
    /// Neutral peer; updates accepted at default weight.
    #[default]
    Neutral,
    /// Untrusted peer; updates accepted only with corroboration.
    Untrusted,
}


impl TrustLevel {
    /// Numeric weight used during merge (Trusted=2, Neutral=1, Untrusted=0).
    pub fn weight(self) -> u32 {
        match self {
            Self::Trusted => 2,
            Self::Neutral => 1,
            Self::Untrusted => 0,
        }
    }
}

/// A single reputation update to be gossiped.
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationUpdate {
    /// The agent whose reputation is being reported.
    pub agent_id: AgentId,
    /// The computed reputation score.
    pub score: ReputationScore,
    /// Unix-milliseconds timestamp when the score was computed.
    pub timestamp: u64,
    /// AgentId of the peer that computed (and signed) the score.
    pub source: AgentId,
    /// ML-DSA-65 signature over the canonical CBOR of the update (sans sig).
    pub signature: Vec<u8>,
}

impl ReputationUpdate {
    /// Encode the update to canonical CBOR *without* the signature field.
    pub fn to_cbor_without_sig(&self) -> Value {
        int_map(vec![
            (1, Value::ByteString(self.agent_id.0.to_vec())),
            (2, score_to_cbor(&self.score)),
            (3, Value::Unsigned(self.timestamp)),
            (4, Value::ByteString(self.source.0.to_vec())),
        ])
    }

    /// Encode the full update (including signature) to canonical CBOR.
    pub fn to_cbor(&self) -> Value {
        let mut entries = match self.to_cbor_without_sig() {
            Value::IntMap(e) => e,
            _ => unreachable!(),
        };
        entries.push((5, Value::ByteString(self.signature.clone())));
        Value::IntMap(entries)
    }

    /// Decode an update from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, IdentityError> {
        let agent_id = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                AgentId(arr)
            }
            _ => return Err(IdentityError::MissingField("agent_id")),
        };
        let score = match int_map_get(val, 2) {
            Some(v) => score_from_cbor(v)?,
            None => return Err(IdentityError::MissingField("score")),
        };
        let timestamp = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(IdentityError::MissingField("timestamp")),
        };
        let source = match int_map_get(val, 4) {
            Some(Value::ByteString(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                AgentId(arr)
            }
            _ => return Err(IdentityError::MissingField("source")),
        };
        let signature = match int_map_get(val, 5) {
            Some(Value::ByteString(b)) => b.clone(),
            _ => Vec::new(),
        };
        Ok(Self {
            agent_id,
            score,
            timestamp,
            source,
            signature,
        })
    }

    /// Sign this update in place with the given secret key.
    pub fn sign(&mut self, secret_key: &MlDsa65SecretKey) -> Result<(), IdentityError> {
        let cbor = self.to_cbor_without_sig();
        let bytes = encode(&cbor).map_err(|e| IdentityError::InvalidField {
            field: "reputation_update",
            message: e.to_string(),
        })?;
        let mut input = Vec::new();
        input.extend_from_slice(REPUTATION_DOMAIN_SEPARATOR);
        input.extend_from_slice(&bytes);
        self.signature = MlDsa65::sign(secret_key, &input).0;
        Ok(())
    }

    /// Create and sign a new update from a keypair's secret key.
    pub fn create_and_sign(
        secret_key: &MlDsa65SecretKey,
        public_key: &MlDsa65PublicKey,
        agent_id: AgentId,
        score: ReputationScore,
        timestamp: u64,
    ) -> Result<Self, IdentityError> {
        let source = AgentId::from_public_key(public_key.as_ref());
        let mut update = Self {
            agent_id,
            score,
            timestamp,
            source,
            signature: Vec::new(),
        };
        update.sign(secret_key)?;
        Ok(update)
    }

    /// Verify the signature on this update against the source's public key.
    pub fn verify_signature(&self, public_key: &MlDsa65PublicKey) -> Result<(), IdentityError> {
        let computed = AgentId::from_public_key(public_key.as_ref());
        if self.source != computed {
            return Err(IdentityError::InvalidAgentId);
        }
        let cbor = self.to_cbor_without_sig();
        let bytes = encode(&cbor).map_err(|e| IdentityError::InvalidField {
            field: "reputation_update",
            message: e.to_string(),
        })?;
        let mut input = Vec::new();
        input.extend_from_slice(REPUTATION_DOMAIN_SEPARATOR);
        input.extend_from_slice(&bytes);
        let sig = MlDsa65Signature::from_bytes(&self.signature)
            .map_err(|_| IdentityError::InvalidSignatureLength)?;
        if MlDsa65::verify(public_key, &input, &sig) {
            Ok(())
        } else {
            Err(IdentityError::SignatureVerificationFailed)
        }
    }
}

/// A gossip message carrying a batch of reputation updates.
#[derive(Clone, Debug)]
pub struct GossipMessage {
    /// The batch of updates being gossiped.
    pub updates: Vec<ReputationUpdate>,
    /// AgentId of the sender.
    pub sender: AgentId,
    /// Unix-milliseconds timestamp of the message.
    pub timestamp: u64,
    /// Time-to-live in milliseconds; decays as the message is relayed.
    pub ttl: u64,
}

impl GossipMessage {
    /// Create a new gossip message with the given TTL.
    pub fn new(updates: Vec<ReputationUpdate>, sender: AgentId, timestamp: u64, ttl: u64) -> Self {
        Self {
            updates,
            sender,
            timestamp,
            ttl,
        }
    }

    /// Whether this message has expired relative to `now` (ms).
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.timestamp) > self.ttl
    }

    /// Decrement the TTL by `delta_ms`, returning a cloned message with the
    /// reduced TTL. If the TTL would drop to zero, the message is expired.
    pub fn with_decayed_ttl(&self, delta_ms: u64) -> Self {
        let ttl = self.ttl.saturating_sub(delta_ms);
        Self {
            updates: self.updates.clone(),
            sender: self.sender,
            timestamp: self.timestamp,
            ttl,
        }
    }
}

/// Information about a known peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The peer's AgentId.
    pub peer_id: AgentId,
    /// Unix-milliseconds timestamp of last contact.
    pub last_seen: u64,
    /// The peer's last known reputation score (overall).
    pub reputation_score: u8,
    /// Trust level assigned to this peer.
    pub trust_level: TrustLevel,
}

impl PeerInfo {
    /// Create a new peer info entry with neutral trust and zero score.
    pub fn new(peer_id: AgentId, last_seen: u64) -> Self {
        Self {
            peer_id,
            last_seen,
            reputation_score: 0,
            trust_level: TrustLevel::default(),
        }
    }
}

/// Configuration for [`ReputationPropagator`].
#[derive(Clone, Debug)]
pub struct PropagationConfig {
    /// Gossip interval in milliseconds.
    pub gossip_interval_ms: u64,
    /// Maximum number of updates batched per gossip message.
    pub max_batch_size: usize,
    /// Fanout: number of peers targeted each gossip round.
    pub fanout: usize,
    /// Time-to-live for gossip messages in milliseconds.
    pub ttl_ms: u64,
    /// Number of bootstrap peers to seed the peer table.
    pub bootstrap_peers: usize,
    /// Freshness window: updates older than this (ms) are considered stale.
    pub freshness_window_ms: u64,
}

impl Default for PropagationConfig {
    fn default() -> Self {
        Self {
            gossip_interval_ms: DEFAULT_GOSSIP_INTERVAL_MS,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            fanout: DEFAULT_FANOUT,
            ttl_ms: DEFAULT_TTL_MS,
            bootstrap_peers: DEFAULT_BOOTSTRAP_PEERS,
            freshness_window_ms: DEFAULT_FRESHNESS_WINDOW_MS,
        }
    }
}

/// Statistics tracked by the propagator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropagationStats {
    /// Number of gossip messages sent (simulated).
    pub messages_sent: u64,
    /// Number of gossip messages received.
    pub messages_received: u64,
    /// Number of conflicts resolved during merge.
    pub conflicts_resolved: u64,
    /// Number of distinct peers reached (cumulative unique count).
    pub peers_reached: u64,
}

/// A local entry storing the latest known reputation for an agent, plus the
/// set of sources that have reported it (for majority-vote conflict resolution).
#[derive(Clone, Debug)]
struct LocalEntry {
    update: ReputationUpdate,
    /// Other updates for the same agent from different sources.
    alternatives: Vec<ReputationUpdate>,
}

/// Reputation propagator: gossips reputation updates across the network.
///
/// The protocol is simulated: [`propagate`](Self::propagate) enqueues a
/// [`GossipMessage`] into an outbox and increments stats; callers inspect
/// the outbox to "send" messages over a real transport. Incoming messages
/// are fed back via [`receive_update`](Self::receive_update) /
/// [`receive_message`](Self::receive_message).
pub struct ReputationPropagator {
    config: PropagationConfig,
    /// Local agent id (used as the sender for outgoing messages).
    local_id: AgentId,
    /// Known peers keyed by AgentId.
    peers: HashMap<AgentId, PeerInfo>,
    /// Local reputation state keyed by subject AgentId.
    local_state: HashMap<AgentId, LocalEntry>,
    /// Outbox of gossip messages waiting to be "sent".
    outbox: Vec<GossipMessage>,
    /// Inbox of received updates awaiting merge.
    inbox: Vec<ReputationUpdate>,
    /// Cumulative stats.
    stats: PropagationStats,
    /// Set of peer ids ever reached (for unique peers_reached counting).
    reached: HashMap<AgentId, ()>,
}

impl ReputationPropagator {
    /// Create a new propagator with the given config and local agent id.
    pub fn new(config: PropagationConfig, local_id: AgentId) -> Self {
        Self {
            config,
            local_id,
            peers: HashMap::new(),
            local_state: HashMap::new(),
            outbox: Vec::new(),
            inbox: Vec::new(),
            stats: PropagationStats::default(),
            reached: HashMap::new(),
        }
    }

    /// Create a propagator with default config.
    pub fn with_defaults(local_id: AgentId) -> Self {
        Self::new(PropagationConfig::default(), local_id)
    }

    /// Return a reference to the config.
    pub fn config(&self) -> &PropagationConfig {
        &self.config
    }

    /// Return a reference to the local agent id.
    pub fn local_id(&self) -> &AgentId {
        &self.local_id
    }

    /// Return a snapshot of the current stats.
    pub fn stats(&self) -> &PropagationStats {
        &self.stats
    }

    /// Return the peer table.
    pub fn peers(&self) -> &HashMap<AgentId, PeerInfo> {
        &self.peers
    }

    /// Add or update a peer in the peer table.
    pub fn add_peer(&mut self, peer_id: AgentId, last_seen: u64, trust_level: TrustLevel) {
        let entry = self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
            peer_id,
            last_seen,
            reputation_score: 0,
            trust_level,
        });
        entry.last_seen = last_seen;
        entry.trust_level = trust_level;
    }

    /// Record that a peer was reached (updates cumulative unique count).
    fn record_reached(&mut self, peer_id: AgentId) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.reached.entry(peer_id) {
            e.insert(());
            self.stats.peers_reached = self.reached.len() as u64;
        }
    }

    /// Select up to `fanout` peers for the next gossip round, preferring
    /// trusted peers first, then neutral. Untrusted peers are excluded.
    fn select_fanout_peers(&self) -> Vec<AgentId> {
        let mut candidates: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| p.trust_level != TrustLevel::Untrusted)
            .collect();
        // Sort by trust weight descending, then by last_seen descending.
        candidates.sort_by_key(|p| std::cmp::Reverse((p.trust_level.weight(), p.last_seen)));
        candidates
            .into_iter()
            .take(self.config.fanout)
            .map(|p| p.peer_id)
            .collect()
    }

    /// Propagate a single reputation update: enqueue a gossip message to
    /// the fanout peers and record stats. Returns the list of peer ids the
    /// message was "sent" to (simulated).
    pub fn propagate(&mut self, update: ReputationUpdate, now_ms: u64) -> Vec<AgentId> {
        let targets = self.select_fanout_peers();
        let msg = GossipMessage::new(vec![update], self.local_id, now_ms, self.config.ttl_ms);
        self.outbox.push(msg);
        self.stats.messages_sent += 1;
        for p in &targets {
            self.record_reached(*p);
        }
        targets
    }

    /// Batch-propagate multiple updates in a single gossip message, capped
    /// at `max_batch_size`. If there are more updates than the batch size,
    /// multiple messages are emitted. Returns the list of peer ids reached.
    pub fn batch_propagate(&mut self, updates: Vec<ReputationUpdate>, now_ms: u64) -> Vec<AgentId> {
        let targets = self.select_fanout_peers();
        for chunk in updates.chunks(self.config.max_batch_size.max(1)) {
            let msg = GossipMessage::new(chunk.to_vec(), self.local_id, now_ms, self.config.ttl_ms);
            self.outbox.push(msg);
            self.stats.messages_sent += 1;
        }
        for p in &targets {
            self.record_reached(*p);
        }
        targets
    }

    /// Drain the outbox, returning all pending gossip messages. Callers
    /// are expected to "send" these over a real transport.
    pub fn drain_outbox(&mut self) -> Vec<GossipMessage> {
        std::mem::take(&mut self.outbox)
    }

    /// Peek at the outbox without draining.
    pub fn outbox(&self) -> &[GossipMessage] {
        &self.outbox
    }

    /// Validate a reputation update: verify the signature against the
    /// source's public key and check freshness relative to `now_ms`.
    pub fn validate_update(
        &self,
        update: &ReputationUpdate,
        public_key: &MlDsa65PublicKey,
        now_ms: u64,
    ) -> Result<(), IdentityError> {
        // Signature check.
        update.verify_signature(public_key)?;
        // Freshness check.
        if now_ms > update.timestamp
            && now_ms.saturating_sub(update.timestamp) > self.config.freshness_window_ms
        {
            return Err(IdentityError::InvalidField {
                field: "timestamp",
                message: format!(
                    "update is stale: age={}ms > window={}ms",
                    now_ms.saturating_sub(update.timestamp),
                    self.config.freshness_window_ms
                ),
            });
        }
        Ok(())
    }

    /// Receive and validate a single update from a peer, then merge it into
    /// local state. Returns `Ok(())` if accepted, or an error if validation
    /// failed.
    pub fn receive_update(
        &mut self,
        update: ReputationUpdate,
        public_key: &MlDsa65PublicKey,
        now_ms: u64,
    ) -> Result<(), IdentityError> {
        self.validate_update(&update, public_key, now_ms)?;
        self.stats.messages_received += 1;
        self.merge_updates(vec![update], now_ms);
        Ok(())
    }

    /// Receive a full gossip message: validate each update (if a public key
    /// is available for the sender), apply TTL decay, and merge. Updates
    /// from an expired message are dropped.
    ///
    /// The `public_keys` map provides a public key per source AgentId for
    /// signature verification. Updates whose source has no known public key
    /// are accepted without signature verification (callers should populate
    /// the map in production).
    pub fn receive_message(
        &mut self,
        msg: GossipMessage,
        public_keys: &HashMap<AgentId, MlDsa65PublicKey>,
        now_ms: u64,
    ) -> Result<usize, IdentityError> {
        if msg.is_expired(now_ms) {
            // Expired message: drop silently.
            return Ok(0);
        }
        self.stats.messages_received += 1;
        // Update peer last_seen for the sender if known.
        if let Some(peer) = self.peers.get_mut(&msg.sender) {
            peer.last_seen = now_ms;
        }
        let mut accepted = 0usize;
        let mut to_merge = Vec::new();
        for update in msg.updates {
            if let Some(pk) = public_keys.get(&update.source) {
                if self.validate_update(&update, pk, now_ms).is_err() {
                    continue;
                }
            }
            to_merge.push(update);
            accepted += 1;
        }
        if !to_merge.is_empty() {
            self.merge_updates(to_merge, now_ms);
        }
        Ok(accepted)
    }

    /// Merge a set of received updates with local state, resolving conflicts.
    ///
    /// Conflict resolution policy:
    /// - If no local entry exists, the incoming update is stored.
    /// - If a local entry exists for the same agent from the same source,
    ///   the higher-timestamp update wins.
    /// - If the incoming update is from a *different* source, it is added
    ///   as an alternative and [`conflict_resolution`] is invoked to pick
    ///   the winner (majority vote with timestamp tiebreak).
    pub fn merge_updates(&mut self, updates: Vec<ReputationUpdate>, _now_ms: u64) {
        for incoming in updates {
            match self.local_state.get_mut(&incoming.agent_id) {
                None => {
                    self.local_state.insert(
                        incoming.agent_id,
                        LocalEntry {
                            update: incoming,
                            alternatives: Vec::new(),
                        },
                    );
                }
                Some(entry) => {
                    if entry.update.source == incoming.source {
                        // Same source: higher timestamp wins.
                        if incoming.timestamp > entry.update.timestamp {
                            entry.update = incoming;
                        }
                    } else {
                        // Different source: record alternative, then resolve.
                        entry.alternatives.push(incoming);
                        let resolved = conflict_resolution(&entry.update, &entry.alternatives);
                        if resolved.source != entry.update.source
                            || resolved.timestamp != entry.update.timestamp
                        {
                            entry.update = resolved;
                            self.stats.conflicts_resolved += 1;
                        }
                    }
                }
            }
        }
    }

    /// Resolve conflicting reputation scores using majority vote, with the
    /// highest timestamp as a tiebreaker. Exposed as a public method for
    /// testing and for callers that want to inspect the resolution.
    pub fn conflict_resolution(
        current: &ReputationUpdate,
        alternatives: &[ReputationUpdate],
    ) -> ReputationUpdate {
        conflict_resolution(current, alternatives)
    }

    /// Get the latest local reputation update for an agent, if any.
    pub fn local_score(&self, agent_id: &AgentId) -> Option<&ReputationUpdate> {
        self.local_state.get(agent_id).map(|e| &e.update)
    }

    /// Get all known updates for an agent (the primary plus alternatives).
    pub fn all_updates_for(&self, agent_id: &AgentId) -> Vec<&ReputationUpdate> {
        match self.local_state.get(agent_id) {
            None => Vec::new(),
            Some(entry) => {
                let mut v = vec![&entry.update];
                v.extend(entry.alternatives.iter());
                v
            }
        }
    }

    /// Number of agents currently tracked in local state.
    pub fn tracked_count(&self) -> usize {
        self.local_state.len()
    }

    /// Anti-entropy: pick a random peer (deterministically, by highest
    /// last_seen among non-untrusted peers) and produce a gossip message
    /// containing the full local state, to catch the peer up on missed
    /// updates. Returns the chosen peer id and the message, or `None` if
    /// there are no peers or no local state.
    pub fn anti_entropy_sync(&mut self, now_ms: u64) -> Option<(AgentId, GossipMessage)> {
        if self.local_state.is_empty() {
            return None;
        }
        // Deterministic "random" selection: the peer with the oldest
        // last_seen (most likely to have missed updates), among non-untrusted.
        let mut candidates: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| p.trust_level != TrustLevel::Untrusted)
            .collect();
        candidates.sort_by_key(|p| p.last_seen);
        let peer = candidates.first()?.peer_id;
        let updates: Vec<ReputationUpdate> = self
            .local_state
            .values()
            .map(|e| e.update.clone())
            .collect();
        let msg = GossipMessage::new(updates, self.local_id, now_ms, self.config.ttl_ms);
        self.stats.messages_sent += 1;
        self.record_reached(peer);
        Some((peer, msg))
    }

    /// Run one periodic gossip tick: batch-propagate any pending inbox
    /// updates to the fanout peers. This is the "periodic fanout-based
    /// broadcast" portion of the protocol. Returns the number of messages
    /// emitted.
    pub fn tick(&mut self, now_ms: u64) -> usize {
        if self.inbox.is_empty() {
            return 0;
        }
        let updates = std::mem::take(&mut self.inbox);
        let before = self.stats.messages_sent;
        self.batch_propagate(updates, now_ms);
        (self.stats.messages_sent - before) as usize
    }

    /// Enqueue an update into the inbox for the next tick.
    pub fn enqueue(&mut self, update: ReputationUpdate) {
        self.inbox.push(update);
    }

    /// Number of updates pending in the inbox.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }
}

/// Free-function form of conflict resolution so it can be tested in isolation.
///
/// Strategy:
/// 1. Collect all candidate updates (current + alternatives).
/// 2. Group by overall score; if any score has a strict majority (>50%),
///    pick the update with that score, breaking ties by highest timestamp.
/// 3. If no majority, pick the update with the highest timestamp; ties
///    broken by highest overall score.
fn conflict_resolution(
    current: &ReputationUpdate,
    alternatives: &[ReputationUpdate],
) -> ReputationUpdate {
    let mut all: Vec<&ReputationUpdate> = vec![current];
    all.extend(alternatives.iter());
    let total = all.len();
    // Majority vote on overall score.
    let mut tally: HashMap<u8, Vec<&ReputationUpdate>> = HashMap::new();
    for u in &all {
        tally.entry(u.score.overall).or_default().push(u);
    }
    // Find a score with strict majority.
    let mut majority_winner: Option<&ReputationUpdate> = None;
    for group in tally.values() {
        if group.len() * 2 > total {
            // Majority: pick the highest-timestamp update in this group.
            let best = group
                .iter()
                .copied()
                .max_by_key(|u| u.timestamp)
                .expect("non-empty group");
            match majority_winner {
                None => majority_winner = Some(best),
                Some(prev) if best.timestamp > prev.timestamp => majority_winner = Some(best),
                _ => {}
            }
            // Keep scanning in case a higher-timestamp majority exists (rare).
        }
    }
    if let Some(w) = majority_winner {
        return w.clone();
    }
    // No majority: highest timestamp wins; tiebreak by highest overall score.
    all.into_iter()
        .cloned()
        .max_by_key(|u| (u.timestamp, u.score.overall as u64))
        .expect("at least one candidate")
}

// ----- CBOR helpers for ReputationScore -------------------------------------

/// Encode a [`ReputationScore`] to CBOR (integer-keyed map).
fn score_to_cbor(s: &ReputationScore) -> Value {
    int_map(vec![
        (1, Value::Unsigned(s.overall as u64)),
        (2, Value::Unsigned(s.success_score as u64)),
        (3, Value::Unsigned(s.latency_score as u64)),
        (4, Value::Unsigned(s.cost_score as u64)),
        (5, Value::Unsigned(s.availability_score as u64)),
        (6, Value::Unsigned(s.attestation_score as u64)),
        // Confidence stored as a fixed-point u32 (confidence * 1_000_000).
        (7, Value::Unsigned(confidence_to_u64(s.confidence))),
    ])
}

/// Decode a [`ReputationScore`] from CBOR.
fn score_from_cbor(val: &Value) -> Result<ReputationScore, IdentityError> {
    let get_u8 = |key: i64| -> u8 {
        match int_map_get(val, key) {
            Some(Value::Unsigned(n)) if *n <= u8::MAX as u64 => *n as u8,
            _ => 0,
        }
    };
    let confidence = match int_map_get(val, 7) {
        Some(Value::Unsigned(n)) => *n as f64 / 1_000_000.0,
        _ => 0.0,
    };
    Ok(ReputationScore {
        overall: get_u8(1),
        success_score: get_u8(2),
        latency_score: get_u8(3),
        cost_score: get_u8(4),
        availability_score: get_u8(5),
        attestation_score: get_u8(6),
        confidence,
    })
}

/// Convert a confidence f64 to a fixed-point u64 for CBOR encoding.
fn confidence_to_u64(c: f64) -> u64 {
    if !c.is_finite() || c <= 0.0 {
        return 0;
    }
    if c >= 1.0 {
        return 1_000_000;
    }
    (c * 1_000_000.0).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_v1::AgentId;
    use aafp_crypto::{MlDsa65, SignatureScheme};

    fn agent_id(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn score(overall: u8) -> ReputationScore {
        ReputationScore {
            overall,
            success_score: overall,
            latency_score: overall,
            cost_score: overall,
            availability_score: overall,
            attestation_score: overall,
            confidence: 1.0,
        }
    }

    fn make_keypair(seed_byte: u8) -> (MlDsa65SecretKey, MlDsa65PublicKey) {
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        let (pk, sk) = MlDsa65::keypair_from_seed(&seed);
        (sk, pk)
    }

    fn signed_update(
        sk: &MlDsa65SecretKey,
        pk: &MlDsa65PublicKey,
        agent: AgentId,
        overall: u8,
        ts: u64,
    ) -> ReputationUpdate {
        ReputationUpdate::create_and_sign(sk, pk, agent, score(overall), ts).unwrap()
    }

    // 1. Default config values.
    #[test]
    fn test_default_config() {
        let cfg = PropagationConfig::default();
        assert_eq!(cfg.gossip_interval_ms, DEFAULT_GOSSIP_INTERVAL_MS);
        assert_eq!(cfg.max_batch_size, DEFAULT_MAX_BATCH_SIZE);
        assert_eq!(cfg.fanout, DEFAULT_FANOUT);
        assert_eq!(cfg.ttl_ms, DEFAULT_TTL_MS);
        assert_eq!(cfg.bootstrap_peers, DEFAULT_BOOTSTRAP_PEERS);
    }

    // 2. TrustLevel weights.
    #[test]
    fn test_trust_level_weights() {
        assert_eq!(TrustLevel::Trusted.weight(), 2);
        assert_eq!(TrustLevel::Neutral.weight(), 1);
        assert_eq!(TrustLevel::Untrusted.weight(), 0);
        assert_eq!(TrustLevel::default(), TrustLevel::Neutral);
    }

    // 3. ReputationUpdate sign + verify roundtrip.
    #[test]
    fn test_update_sign_verify() {
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(2), 80, 1000);
        assert!(update.verify_signature(&pk).is_ok());
    }

    // 4. ReputationUpdate signature tamper detection.
    #[test]
    fn test_update_tamper_detected() {
        let (sk, pk) = make_keypair(1);
        let mut update = signed_update(&sk, &pk, agent_id(2), 80, 1000);
        update.score.overall = 99; // tamper
        assert!(update.verify_signature(&pk).is_err());
    }

    // 5. ReputationUpdate CBOR roundtrip.
    #[test]
    fn test_update_cbor_roundtrip() {
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(2), 75, 5000);
        let cbor = update.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&bytes).unwrap();
        let update2 = ReputationUpdate::from_cbor(&decoded).unwrap();
        assert_eq!(update, update2);
    }

    // 6. ReputationUpdate wrong source key rejected.
    #[test]
    fn test_update_wrong_source_key() {
        let (sk1, pk1) = make_keypair(1);
        let (sk2, pk2) = make_keypair(2);
        let update = signed_update(&sk1, &pk1, agent_id(3), 70, 1000);
        // Verify with a different public key -> should fail (source mismatch).
        assert!(update.verify_signature(&pk2).is_err());
    }

    // 7. GossipMessage expiry.
    #[test]
    fn test_gossip_message_expiry() {
        let msg = GossipMessage::new(vec![], agent_id(1), 1000, 5000);
        assert!(!msg.is_expired(6000));
        assert!(msg.is_expired(6001));
        assert!(msg.is_expired(10_000));
    }

    // 8. GossipMessage TTL decay.
    #[test]
    fn test_gossip_message_ttl_decay() {
        let msg = GossipMessage::new(vec![], agent_id(1), 1000, 5000);
        let decayed = msg.with_decayed_ttl(2000);
        assert_eq!(decayed.ttl, 3000);
        let expired = msg.with_decayed_ttl(10_000);
        assert_eq!(expired.ttl, 0);
    }

    // 9. Propagator propagate enqueues message and records stats.
    #[test]
    fn test_propagate_enqueues() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        prop.add_peer(agent_id(3), 100, TrustLevel::Neutral);
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let targets = prop.propagate(update, 1000);
        assert!(!targets.is_empty());
        assert_eq!(prop.stats().messages_sent, 1);
        assert_eq!(prop.outbox().len(), 1);
        assert!(prop.stats().peers_reached >= 1);
    }

    // 10. Propagator batch_propagate respects max_batch_size.
    #[test]
    fn test_batch_propagate_splits() {
        let mut cfg = PropagationConfig::default();
        cfg.max_batch_size = 2;
        let mut prop = ReputationPropagator::new(cfg, agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        let (sk, pk) = make_keypair(1);
        let updates: Vec<ReputationUpdate> = (0..5)
            .map(|i| signed_update(&sk, &pk, agent_id(10 + i), 80, 1000 + i as u64))
            .collect();
        let _ = prop.batch_propagate(updates, 1000);
        // 5 updates / batch size 2 = 3 messages.
        assert_eq!(prop.outbox().len(), 3);
        assert_eq!(prop.stats().messages_sent, 3);
    }

    // 11. Propagator drain_outbox.
    #[test]
    fn test_drain_outbox() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let _ = prop.propagate(update, 1000);
        let drained = prop.drain_outbox();
        assert_eq!(drained.len(), 1);
        assert!(prop.outbox().is_empty());
    }

    // 12. validate_update accepts a fresh, correctly-signed update.
    #[test]
    fn test_validate_update_ok() {
        let prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        assert!(prop.validate_update(&update, &pk, 1000).is_ok());
    }

    // 13. validate_update rejects a stale update.
    #[test]
    fn test_validate_update_stale() {
        let prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        // now_ms far beyond freshness window.
        let now = 1000 + DEFAULT_FRESHNESS_WINDOW_MS + 1;
        assert!(prop.validate_update(&update, &pk, now).is_err());
    }

    // 14. validate_update rejects a bad signature.
    #[test]
    fn test_validate_update_bad_sig() {
        let prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk1, pk1) = make_keypair(1);
        let (_sk2, pk2) = make_keypair(2);
        let update = signed_update(&sk1, &pk1, agent_id(5), 80, 1000);
        // Verify against wrong key.
        assert!(prop.validate_update(&update, &pk2, 1000).is_err());
    }

    // 15. receive_update merges into local state.
    #[test]
    fn test_receive_update_merges() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(2);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        prop.receive_update(update.clone(), &pk, 1000).unwrap();
        assert_eq!(prop.local_score(&agent_id(5)), Some(&update));
        assert_eq!(prop.stats().messages_received, 1);
    }

    // 16. receive_update same source higher timestamp replaces.
    #[test]
    fn test_receive_update_same_source_newer() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(2);
        let u1 = signed_update(&sk, &pk, agent_id(5), 70, 1000);
        let u2 = signed_update(&sk, &pk, agent_id(5), 90, 2000);
        prop.receive_update(u1, &pk, 1000).unwrap();
        prop.receive_update(u2.clone(), &pk, 2000).unwrap();
        assert_eq!(prop.local_score(&agent_id(5)).unwrap().timestamp, 2000);
        assert_eq!(prop.local_score(&agent_id(5)).unwrap().score.overall, 90);
    }

    // 17. receive_update same source older timestamp ignored.
    #[test]
    fn test_receive_update_same_source_older_ignored() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(2);
        let u1 = signed_update(&sk, &pk, agent_id(5), 90, 2000);
        let u2 = signed_update(&sk, &pk, agent_id(5), 70, 1000);
        prop.receive_update(u1, &pk, 2000).unwrap();
        prop.receive_update(u2, &pk, 2000).unwrap();
        assert_eq!(prop.local_score(&agent_id(5)).unwrap().score.overall, 90);
    }

    // 18. merge_updates with different sources triggers conflict resolution.
    #[test]
    fn test_merge_updates_conflict() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk1, pk1) = make_keypair(2);
        let (sk2, pk2) = make_keypair(3);
        let u1 = signed_update(&sk1, &pk1, agent_id(5), 70, 1000);
        let u2 = signed_update(&sk2, &pk2, agent_id(5), 90, 2000);
        prop.receive_update(u1, &pk1, 1000).unwrap();
        prop.receive_update(u2, &pk2, 2000).unwrap();
        // No majority (2 candidates), highest timestamp wins -> 90.
        assert_eq!(prop.local_score(&agent_id(5)).unwrap().score.overall, 90);
        assert!(prop.stats().conflicts_resolved >= 1);
    }

    // 19. Conflict resolution majority vote.
    #[test]
    fn test_conflict_resolution_majority() {
        let (sk1, pk1) = make_keypair(1);
        let (sk2, pk2) = make_keypair(2);
        let (sk3, pk3) = make_keypair(3);
        let current = signed_update(&sk1, &pk1, agent_id(9), 80, 1000);
        let alt1 = signed_update(&sk2, &pk2, agent_id(9), 80, 1500);
        let alt2 = signed_update(&sk3, &pk3, agent_id(9), 50, 3000);
        // 2 of 3 vote 80 -> majority.
        let winner = conflict_resolution(&current, &[alt1, alt2]);
        assert_eq!(winner.score.overall, 80);
    }

    // 20. Conflict resolution no majority -> highest timestamp.
    #[test]
    fn test_conflict_resolution_no_majority_highest_ts() {
        let (sk1, pk1) = make_keypair(1);
        let (sk2, pk2) = make_keypair(2);
        let current = signed_update(&sk1, &pk1, agent_id(9), 80, 1000);
        let alt = signed_update(&sk2, &pk2, agent_id(9), 50, 3000);
        // 1 vs 1, no majority -> highest timestamp (3000) wins.
        let winner = conflict_resolution(&current, &[alt]);
        assert_eq!(winner.timestamp, 3000);
        assert_eq!(winner.score.overall, 50);
    }

    // 21. receive_message expired message dropped.
    #[test]
    fn test_receive_message_expired() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(2);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let msg = GossipMessage::new(vec![update], agent_id(2), 1000, 500);
        let mut pks = HashMap::new();
        pks.insert(agent_id(2), pk);
        // now_ms = 10_000, msg timestamp 1000 + ttl 500 -> expired.
        let n = prop.receive_message(msg, &pks, 10_000).unwrap();
        assert_eq!(n, 0);
        assert_eq!(prop.tracked_count(), 0);
    }

    // 22. receive_message valid message merged.
    #[test]
    fn test_receive_message_valid() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(2);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let msg = GossipMessage::new(vec![update.clone()], agent_id(2), 1000, 30_000);
        let mut pks = HashMap::new();
        pks.insert(agent_id(2), pk);
        let n = prop.receive_message(msg, &pks, 1000).unwrap();
        assert_eq!(n, 1);
        assert_eq!(prop.local_score(&agent_id(5)), Some(&update));
    }

    // 23. receive_message without public key still merges (no sig check).
    #[test]
    fn test_receive_message_no_pk() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(2);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let msg = GossipMessage::new(vec![update], agent_id(2), 1000, 30_000);
        let pks = HashMap::new();
        let n = prop.receive_message(msg, &pks, 1000).unwrap();
        assert_eq!(n, 1);
    }

    // 24. Fanout selection excludes untrusted peers.
    #[test]
    fn test_fanout_excludes_untrusted() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Untrusted);
        prop.add_peer(agent_id(3), 100, TrustLevel::Trusted);
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let targets = prop.propagate(update, 1000);
        assert!(targets.contains(&agent_id(3)));
        assert!(!targets.contains(&agent_id(2)));
    }

    // 25. Fanout selection respects fanout limit.
    #[test]
    fn test_fanout_limit() {
        let mut cfg = PropagationConfig::default();
        cfg.fanout = 2;
        let mut prop = ReputationPropagator::new(cfg, agent_id(1));
        for i in 2..10 {
            prop.add_peer(agent_id(i), 100, TrustLevel::Neutral);
        }
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let targets = prop.propagate(update, 1000);
        assert_eq!(targets.len(), 2);
    }

    // 26. Anti-entropy sync produces a full-state message.
    #[test]
    fn test_anti_entropy_sync() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        let (sk, pk) = make_keypair(1);
        let u1 = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let u2 = signed_update(&sk, &pk, agent_id(6), 70, 1000);
        prop.merge_updates(vec![u1, u2], 1000);
        let result = prop.anti_entropy_sync(2000);
        assert!(result.is_some());
        let (peer, msg) = result.unwrap();
        assert_eq!(peer, agent_id(2));
        assert_eq!(msg.updates.len(), 2);
    }

    // 27. Anti-entropy sync returns None with no peers.
    #[test]
    fn test_anti_entropy_no_peers() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk, pk) = make_keypair(1);
        let u = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        prop.merge_updates(vec![u], 1000);
        assert!(prop.anti_entropy_sync(2000).is_none());
    }

    // 28. Anti-entropy sync returns None with no local state.
    #[test]
    fn test_anti_entropy_no_state() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        assert!(prop.anti_entropy_sync(2000).is_none());
    }

    // 29. Tick batches inbox updates.
    #[test]
    fn test_tick_batch() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        let (sk, pk) = make_keypair(1);
        for i in 0..3 {
            prop.enqueue(signed_update(&sk, &pk, agent_id(10 + i), 80, 1000));
        }
        assert_eq!(prop.inbox_len(), 3);
        let n = prop.tick(2000);
        assert!(n >= 1);
        assert_eq!(prop.inbox_len(), 0);
        assert!(!prop.outbox().is_empty());
    }

    // 30. Tick with empty inbox does nothing.
    #[test]
    fn test_tick_empty() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        let n = prop.tick(2000);
        assert_eq!(n, 0);
        assert!(prop.outbox().is_empty());
    }

    // 31. all_updates_for returns primary plus alternatives.
    #[test]
    fn test_all_updates_for() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        let (sk1, pk1) = make_keypair(2);
        let (sk2, pk2) = make_keypair(3);
        let u1 = signed_update(&sk1, &pk1, agent_id(5), 70, 1000);
        let u2 = signed_update(&sk2, &pk2, agent_id(5), 90, 2000);
        prop.receive_update(u1, &pk1, 1000).unwrap();
        prop.receive_update(u2, &pk2, 2000).unwrap();
        let all = prop.all_updates_for(&agent_id(5));
        assert_eq!(all.len(), 2);
    }

    // 32. peers_reached counts unique peers.
    #[test]
    fn test_peers_reached_unique() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Trusted);
        prop.add_peer(agent_id(3), 100, TrustLevel::Trusted);
        let (sk, pk) = make_keypair(1);
        let u = signed_update(&sk, &pk, agent_id(5), 80, 1000);
        let _ = prop.propagate(u.clone(), 1000);
        let _ = prop.propagate(u, 2000);
        // Same 2 peers reached twice -> still 2 unique.
        assert_eq!(prop.stats().peers_reached, 2);
    }

    // 33. PeerInfo::new defaults.
    #[test]
    fn test_peer_info_defaults() {
        let pi = PeerInfo::new(agent_id(2), 1000);
        assert_eq!(pi.reputation_score, 0);
        assert_eq!(pi.trust_level, TrustLevel::Neutral);
    }

    // 34. ReputationScore CBOR roundtrip.
    #[test]
    fn test_score_cbor_roundtrip() {
        let s = ReputationScore {
            overall: 75,
            success_score: 80,
            latency_score: 70,
            cost_score: 60,
            availability_score: 90,
            attestation_score: 50,
            confidence: 0.75,
        };
        let cbor = score_to_cbor(&s);
        let s2 = score_from_cbor(&cbor).unwrap();
        assert_eq!(s, s2);
    }

    // 35. confidence_to_u64 clamps.
    #[test]
    fn test_confidence_to_u64() {
        assert_eq!(confidence_to_u64(0.0), 0);
        assert_eq!(confidence_to_u64(-1.0), 0);
        assert_eq!(confidence_to_u64(f64::NAN), 0);
        assert_eq!(confidence_to_u64(1.0), 1_000_000);
        assert_eq!(confidence_to_u64(2.0), 1_000_000);
        assert_eq!(confidence_to_u64(0.5), 500_000);
    }

    // 36. add_peer updates existing entry.
    #[test]
    fn test_add_peer_updates() {
        let mut prop = ReputationPropagator::with_defaults(agent_id(1));
        prop.add_peer(agent_id(2), 100, TrustLevel::Neutral);
        prop.add_peer(agent_id(2), 200, TrustLevel::Trusted);
        let p = prop.peers().get(&agent_id(2)).unwrap();
        assert_eq!(p.last_seen, 200);
        assert_eq!(p.trust_level, TrustLevel::Trusted);
    }

    // 37. Conflict resolution tiebreak by score when timestamps equal.
    #[test]
    fn test_conflict_resolution_tiebreak_score() {
        let (sk1, pk1) = make_keypair(1);
        let (sk2, pk2) = make_keypair(2);
        let current = signed_update(&sk1, &pk1, agent_id(9), 80, 1000);
        let alt = signed_update(&sk2, &pk2, agent_id(9), 50, 1000);
        // Same timestamp, no majority -> higher overall wins.
        let winner = conflict_resolution(&current, &[alt]);
        assert_eq!(winner.score.overall, 80);
    }

    // 38. Majority with higher-timestamp tiebreak within majority group.
    #[test]
    fn test_majority_group_highest_ts() {
        let (sk1, pk1) = make_keypair(1);
        let (sk2, pk2) = make_keypair(2);
        let (sk3, pk3) = make_keypair(3);
        let current = signed_update(&sk1, &pk1, agent_id(9), 80, 1000);
        let alt1 = signed_update(&sk2, &pk2, agent_id(9), 80, 3000);
        let alt2 = signed_update(&sk3, &pk3, agent_id(9), 50, 5000);
        // Majority for 80; within that group, ts 3000 > 1000.
        let winner = conflict_resolution(&current, &[alt1, alt2]);
        assert_eq!(winner.score.overall, 80);
        assert_eq!(winner.timestamp, 3000);
    }

    // 39. Empty conflict resolution (no alternatives) returns current.
    #[test]
    fn test_conflict_resolution_no_alts() {
        let (sk, pk) = make_keypair(1);
        let current = signed_update(&sk, &pk, agent_id(9), 80, 1000);
        let winner = conflict_resolution(&current, &[]);
        assert_eq!(winner, current);
    }

    // 40. Full CBOR roundtrip of a signed update preserves signature.
    #[test]
    fn test_signed_update_cbor_preserves_sig() {
        let (sk, pk) = make_keypair(1);
        let update = signed_update(&sk, &pk, agent_id(2), 80, 1000);
        let cbor = update.to_cbor();
        let bytes = encode(&cbor).unwrap();
        let (decoded, _) = aafp_cbor::decode(&bytes).unwrap();
        let update2 = ReputationUpdate::from_cbor(&decoded).unwrap();
        assert_eq!(update2.signature, update.signature);
        assert!(update2.verify_signature(&pk).is_ok());
    }
}
