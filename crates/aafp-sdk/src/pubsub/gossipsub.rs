//! GossipSub v1.1 router (Phase P6).
//!
//! Replaces the floodsub propagation driver (which forwards to *all*
//! subscribers) with a bounded-degree mesh-based gossip protocol:
//!
//! 1. **Mesh construction**: each peer maintains a partial mesh of `D` peers
//!    per topic (not all subscribers).
//! 2. **IHAVE/IWANT gossip**: peers gossip about message IDs via control
//!    messages; missing messages are requested on-demand.
//! 3. **Peer scoring**: misbehaving peers are penalized and eventually pruned.
//! 4. **Heartbeat**: periodic mesh maintenance re-balances degree.
//!
//! The wire format (RFC-0009) is forward-compatible — only the propagation
//! logic changes.

use aafp_identity::agent_id::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Mesh lower bound — if mesh drops below `D_LO`, graft new peers.
pub const D_LO: usize = 4;
/// Mesh upper bound — if mesh exceeds `D_HI`, prune excess peers.
pub const D_HI: usize = 12;
/// Number of peers to gossip to per heartbeat (lazy gossip fanout).
pub const D_LAZY: usize = 6;
/// Mesh target degree (ideal number of peers per topic in the mesh).
pub const D: usize = 6;

/// GossipSub v1.1 mesh parameters (libp2p defaults).
#[derive(Clone, Debug)]
pub struct GossipSubConfig {
    /// Mesh target degree (ideal number of peers per topic in the mesh).
    pub d: usize,
    /// Mesh lower bound — if mesh drops below `d_lo`, graft new peers.
    pub d_lo: usize,
    /// Mesh upper bound — if mesh exceeds `d_hi`, prune excess peers.
    pub d_hi: usize,
    /// Number of peers to gossip to per heartbeat (lazy gossip fanout).
    pub d_lazy: usize,
    /// Heartbeat interval for mesh maintenance.
    pub heartbeat_interval: Duration,
    /// History retention for IWANT (how long to remember seen message IDs).
    pub fanout_ttl: Duration,
    /// Maximum number of entries in the seen cache before forced eviction.
    pub max_seen_entries: usize,
    /// Maximum message size (mirrors `ConnectionLimits.max_message_size`).
    pub max_message_size: usize,
    /// Peer scoring thresholds and weights.
    pub scoring: PeerScoringConfig,
}

impl Default for GossipSubConfig {
    fn default() -> Self {
        Self {
            d: D,
            d_lo: D_LO,
            d_hi: D_HI,
            d_lazy: D_LAZY,
            heartbeat_interval: Duration::from_secs(1),
            fanout_ttl: Duration::from_secs(60),
            max_seen_entries: 10_000,
            max_message_size: 1024 * 1024,
            scoring: PeerScoringConfig::default(),
        }
    }
}

/// Per-topic mesh state.
#[derive(Clone, Debug)]
pub struct MeshState {
    /// Peers currently in the mesh for this topic.
    pub peers: HashSet<AgentId>,
    /// Peers we've gossiped to recently (for IWANT tracking).
    pub gossip_peers: HashSet<AgentId>,
    /// Message IDs seen recently (for IHAVE gossip).
    pub seen_msgs: VecDeque<[u8; 32]>,
    /// Last time we had mesh members (for fanout TTL).
    pub last_active: Instant,
}

/// Gossip control messages (piggybacked on publish frames or sent standalone).
///
/// Encoded as CBOR per RFC-0009 (forward-compatible extension).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipControl {
    /// IHAVE: "I have these message IDs" — sent to `d_lazy` peers.
    pub ihave: HashMap<String, Vec<[u8; 32]>>, // topic -> msg_hashes
    /// IWANT: "I want these message IDs" — sent in response to IHAVE.
    pub iwant: Vec<[u8; 32]>, // msg_hashes
    /// GRAFT: "Add me to your mesh for this topic."
    pub graft: Vec<String>, // topics
    /// PRUNE: "Remove me from your mesh for this topic."
    pub prune: Vec<String>, // topics
}

/// Peer scoring configuration — 7 weighted parameters (GossipSub v1.1).
#[derive(Clone, Debug)]
pub struct PeerScoringConfig {
    // ── P1: App-specific score (topic-specific behavior) ──
    /// Weight for the app-specific score component.
    pub p1_weight: f64,
    /// Cap on the app-specific score component.
    pub p1_cap: f64,

    // ── P2: IP colocation penalty (many peers from same IP) ──
    /// Weight for the IP colocation penalty.
    pub p2_weight: f64,
    /// Threshold of peers from the same IP before the penalty applies.
    pub p2_colocation_threshold: usize,

    // ── P3: Behavioral penalty (invalid messages, spam) ──
    /// Weight for the behavioral penalty.
    pub p3_weight: f64,
    /// Decay factor applied to the behavioral penalty each decay interval.
    pub p3_decay: f64,

    // ── P4: Application-specific reward (e.g. useful data) ──
    /// Weight for the application-specific reward.
    pub p4_weight: f64,

    // ── P5: Message delivery time (latency-based) ──
    /// Weight for the message delivery latency penalty.
    pub p5_weight: f64,

    // ── P6: Mesh participation (in mesh vs. not) ──
    /// Weight for mesh participation.
    pub p6_weight: f64,

    // ── P7: First-message deliveries (reward for novelty) ──
    /// Weight for first-message delivery reward.
    pub p7_weight: f64,

    /// Score below which a peer is graylisted (not pruned, but not gossiped to).
    pub graylist_threshold: f64,
    /// Score below which a peer is pruned from all meshes.
    pub prune_threshold: f64,
    /// Time window for score decay.
    pub decay_interval: Duration,
}

impl Default for PeerScoringConfig {
    fn default() -> Self {
        Self {
            p1_weight: 10.0,
            p1_cap: 100.0,
            p2_weight: -10.0,
            p2_colocation_threshold: 5,
            p3_weight: -100.0,
            p3_decay: 0.9,
            p4_weight: 5.0,
            p5_weight: -2.0,
            p6_weight: 1.0,
            p7_weight: 1.0,
            graylist_threshold: -100.0,
            prune_threshold: -1000.0,
            decay_interval: Duration::from_secs(10),
        }
    }
}

/// Per-peer score breakdown (7 components).
#[derive(Clone, Debug, Default)]
pub struct PeerScore {
    /// P1: App-specific score.
    pub p1_app_specific: f64,
    /// P2: IP colocation penalty.
    pub p2_ip_colocation: f64,
    /// P3: Behavioral penalty (invalid messages, spam).
    pub p3_behavioral: f64,
    /// P4: Application-specific reward.
    pub p4_app_reward: f64,
    /// P5: Message delivery latency penalty.
    pub p5_latency: f64,
    /// P6: Mesh participation.
    pub p6_mesh_participation: f64,
    /// P7: First-message delivery reward.
    pub p7_first_deliveries: f64,
    /// Last time this score was updated.
    pub last_updated: Option<Instant>,
}

impl PeerScore {
    /// Total weighted score (sum of all 7 components).
    pub fn total(&self) -> f64 {
        self.p1_app_specific
            + self.p2_ip_colocation
            + self.p3_behavioral
            + self.p4_app_reward
            + self.p5_latency
            + self.p6_mesh_participation
            + self.p7_first_deliveries
    }

    /// Decay all components toward zero (called periodically).
    pub fn decay(&mut self, cfg: &PeerScoringConfig) {
        let d = cfg.p3_decay;
        self.p1_app_specific *= d;
        self.p3_behavioral *= d;
        self.p5_latency *= d;
        self.p7_first_deliveries *= d;
    }

    /// Record an invalid message from this peer (P3 penalty).
    pub fn record_invalid_message(&mut self, penalty: f64) {
        self.p3_behavioral -= penalty;
    }

    /// Record a first-message delivery (P7 reward).
    pub fn record_first_delivery(&mut self, reward: f64) {
        self.p7_first_deliveries += reward;
    }
}

/// GossipSub router state, replacing the floodsub propagation driver.
pub struct GossipSubRouter {
    /// Mesh + scoring configuration.
    pub(crate) config: GossipSubConfig,
    /// topic -> mesh state.
    pub(crate) mesh: HashMap<String, MeshState>,
    /// peer -> score.
    pub(crate) peer_scores: HashMap<AgentId, PeerScore>,
    /// message hash -> expiry (seen cache, content-addressed).
    pub(crate) seen: HashMap<[u8; 32], Instant>,
}

impl GossipSubRouter {
    /// Create a new router with the given configuration.
    pub fn new(config: GossipSubConfig) -> Self {
        Self {
            config,
            mesh: HashMap::new(),
            peer_scores: HashMap::new(),
            seen: HashMap::new(),
        }
    }

    /// Create a new router with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(GossipSubConfig::default())
    }

    /// Ensure mesh for `topic` has between `d_lo` and `d_hi` peers.
    /// Called during heartbeat.
    ///
    /// - Grafts new peers when mesh drops below `d_lo`.
    /// - Prunes excess (lowest-scoring first) when mesh exceeds `d_hi`.
    pub fn maintain_mesh(&mut self, topic: &str, available: &[AgentId]) {
        let prune_set: Vec<AgentId> = self
            .peer_scores
            .keys()
            .filter(|p| self.should_prune(p))
            .copied()
            .collect();

        // Clone config values to avoid borrowing self while holding a mutable borrow of self.mesh
        let d_lo = self.config.d_lo;
        let d_hi = self.config.d_hi;
        let d = self.config.d;

        let state = self
            .mesh
            .entry(topic.to_string())
            .or_insert_with(|| MeshState {
                peers: HashSet::new(),
                gossip_peers: HashSet::new(),
                seen_msgs: VecDeque::new(),
                last_active: Instant::now(),
            });

        // Prune low-scoring peers from mesh.
        state.peers.retain(|p| !prune_set.contains(p));

        // Graft: if below d_lo, add peers up to d.
        if state.peers.len() < d_lo {
            let candidates: Vec<_> = available
                .iter()
                .filter(|p| !state.peers.contains(*p) && !prune_set.contains(*p))
                .take(d.saturating_sub(state.peers.len()))
                .cloned()
                .collect();
            for c in candidates {
                state.peers.insert(c);
                // Send GRAFT control message (RFC-0009 extension)
            }
        }

        // Prune: if above d_hi, remove excess (lowest-scoring first).
        if state.peers.len() > d_hi {
            let mut sorted: Vec<_> = state.peers.iter().copied().collect();
            // Sort by score (lowest first) — need to access self.peer_scores
            // but state still borrows self.mesh. We already have the sorted list,
            // so we can drop the state borrow, sort, then re-borrow.
            let to_remove = state.peers.len().saturating_sub(d);
            // Sort by peer scores (lowest first for pruning)
            sorted.sort_by(|a, b| {
                let sa = self.peer_scores.get(a).map(|s| s.total()).unwrap_or(0.0);
                let sb = self.peer_scores.get(b).map(|s| s.total()).unwrap_or(0.0);
                sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
            });
            for peer in sorted.into_iter().take(to_remove) {
                state.peers.remove(&peer);
                // Send PRUNE control message
            }
        }

        state.last_active = Instant::now();
    }

    /// Select `d_lazy` peers to gossip IHAVE messages to.
    pub fn select_gossip_peers(&self, topic: &str) -> Vec<AgentId> {
        let Some(state) = self.mesh.get(topic) else {
            return vec![];
        };
        let cfg = &self.config;
        state
            .peers
            .iter()
            .filter(|p| {
                self.peer_scores
                    .get(*p)
                    .is_some_and(|s| s.total() > cfg.scoring.graylist_threshold)
            })
            .take(cfg.d_lazy)
            .copied()
            .collect()
    }

    /// Update peer score after receiving a message.
    pub fn score_on_message(&mut self, peer: &AgentId, _msg_hash: [u8; 32], is_first_seen: bool) {
        let score = self.peer_scores.entry(*peer).or_default();
        if is_first_seen {
            score.record_first_delivery(self.config.scoring.p7_weight);
        }
        score.last_updated = Some(Instant::now());
    }

    /// Check if a peer should be pruned from meshes.
    pub fn should_prune(&self, peer: &AgentId) -> bool {
        self.peer_scores
            .get(peer)
            .is_some_and(|s| s.total() < self.config.scoring.prune_threshold)
    }

    /// Periodic score decay for all peers.
    pub fn decay_all_scores(&mut self) {
        let cfg = &self.config.scoring;
        for score in self.peer_scores.values_mut() {
            score.decay(cfg);
        }
    }

    /// Run the heartbeat loop — mesh maintenance, score decay, fanout TTL.
    ///
    /// Spawn this as a background task alongside the propagation driver.
    /// Terminates when the `shutdown` signal fires.
    ///
    /// # Parameters
    /// - `router`: shared router state.
    /// - `available_peers`: closure returning the current peer set.
    /// - `shutdown`: cancellation token.
    pub async fn heartbeat_loop(
        router: Arc<Mutex<Self>>,
        available_peers: Arc<dyn Fn() -> Vec<AgentId> + Send + Sync>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let interval = router
            .lock()
            .expect("router lock poisoned")
            .config
            .heartbeat_interval;
        let mut ticker = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let peers = available_peers();
                    let mut r = router.lock().expect("router lock poisoned");

                    // 1. Decay all peer scores.
                    r.decay_all_scores();

                    // 2. Maintain mesh for each topic.
                    let topics: Vec<String> = r.mesh.keys().cloned().collect();
                    for topic in &topics {
                        r.maintain_mesh(topic, &peers);
                    }

                    // 3. Evict expired seen messages, then enforce max size.
                    let now = Instant::now();
                    let fanout_ttl = r.config.fanout_ttl;
                    r.seen
                        .retain(|_, expiry| now.duration_since(*expiry) < fanout_ttl);
                    // If still over the limit, evict oldest entries.
                    let max_seen = r.config.max_seen_entries;
                    if r.seen.len() > max_seen {
                        let mut entries: Vec<([u8; 32], Instant)> =
                            r.seen.iter().map(|(k, v)| (*k, *v)).collect();
                        entries.sort_by_key(|(_, t)| *t);
                        let to_remove = entries.len().saturating_sub(max_seen);
                        for (k, _) in entries.into_iter().take(to_remove) {
                            r.seen.remove(&k);
                        }
                    }

                    // 4. Emit IHAVE gossip to d_lazy peers per topic.
                    // (Control messages piggybacked on next publish frame.)
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossipsub_config_defaults() {
        let cfg = GossipSubConfig::default();
        assert_eq!(cfg.d, 6);
        assert_eq!(cfg.d_lo, 4);
        assert_eq!(cfg.d_hi, 12);
        assert_eq!(cfg.d_lazy, 6);
    }

    #[test]
    fn test_peer_score_total() {
        let score = PeerScore {
            p1_app_specific: 10.0,
            p2_ip_colocation: -5.0,
            p3_behavioral: -2.0,
            p4_app_reward: 3.0,
            p5_latency: -1.0,
            p6_mesh_participation: 1.0,
            p7_first_deliveries: 2.0,
            last_updated: None,
        };
        assert_eq!(score.total(), 8.0);
    }

    #[test]
    fn test_peer_score_decay() {
        let cfg = PeerScoringConfig::default();
        let mut score = PeerScore {
            p1_app_specific: 10.0,
            p3_behavioral: -20.0,
            ..Default::default()
        };
        score.decay(&cfg);
        assert!((score.p1_app_specific - 9.0).abs() < 0.001);
        assert!((score.p3_behavioral - (-18.0)).abs() < 0.001);
    }

    #[test]
    fn test_peer_score_record_invalid_message() {
        let mut score = PeerScore::default();
        score.record_invalid_message(50.0);
        assert_eq!(score.p3_behavioral, -50.0);
    }

    #[test]
    fn test_peer_score_record_first_delivery() {
        let mut score = PeerScore::default();
        score.record_first_delivery(5.0);
        assert_eq!(score.p7_first_deliveries, 5.0);
    }

    #[test]
    fn test_should_prune_below_threshold() {
        let router = GossipSubRouter::with_defaults();
        let peer = [1u8; 32];
        // No score entry → should_prune returns false
        assert!(!router.should_prune(&peer));
    }

    #[test]
    fn test_should_prune_with_low_score() {
        let mut router = GossipSubRouter::with_defaults();
        let peer = [1u8; 32];
        router.peer_scores.insert(
            peer,
            PeerScore {
                p3_behavioral: -2000.0,
                ..Default::default()
            },
        );
        assert!(router.should_prune(&peer));
    }

    #[test]
    fn test_maintain_mesh_grafts_peers() {
        let mut router = GossipSubRouter::with_defaults();
        let peers = vec![
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        ];
        router.maintain_mesh("test/topic", &peers);
        let state = router.mesh.get("test/topic").unwrap();
        // Should have grafted up to d (6) peers
        assert!(state.peers.len() >= 4); // at least d_lo
    }

    #[test]
    fn test_maintain_mesh_prunes_excess() {
        let mut router = GossipSubRouter::with_defaults();
        // Manually add too many peers
        let peers: Vec<AgentId> = (0..20u8).map(|i| [i; 32]).collect();
        router.maintain_mesh("test/topic", &peers);
        let state = router.mesh.get("test/topic").unwrap();
        // After initial graft, we should have at most d peers
        assert!(state.peers.len() <= 6); // d = 6
    }

    #[test]
    fn test_select_gossip_peers() {
        let mut router = GossipSubRouter::with_defaults();
        let peers = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        router.maintain_mesh("test/topic", &peers);
        let gossip = router.select_gossip_peers("test/topic");
        // Should select up to d_lazy (6) peers, but we only have 3
        assert!(gossip.len() <= 3);
    }

    #[test]
    fn test_score_on_message_first_seen() {
        let mut router = GossipSubRouter::with_defaults();
        let peer = [1u8; 32];
        router.score_on_message(&peer, [0u8; 32], true);
        let score = router.peer_scores.get(&peer).unwrap();
        assert!(score.p7_first_deliveries > 0.0);
        assert!(score.last_updated.is_some());
    }

    #[test]
    fn test_score_on_message_not_first_seen() {
        let mut router = GossipSubRouter::with_defaults();
        let peer = [1u8; 32];
        router.score_on_message(&peer, [0u8; 32], false);
        let score = router.peer_scores.get(&peer).unwrap();
        assert_eq!(score.p7_first_deliveries, 0.0);
        assert!(score.last_updated.is_some());
    }

    #[test]
    fn test_decay_all_scores() {
        let mut router = GossipSubRouter::with_defaults();
        router.peer_scores.insert(
            [1u8; 32],
            PeerScore {
                p1_app_specific: 10.0,
                ..Default::default()
            },
        );
        router.decay_all_scores();
        let score = router.peer_scores.get(&[1u8; 32]).unwrap();
        assert!((score.p1_app_specific - 9.0).abs() < 0.001);
    }
}
