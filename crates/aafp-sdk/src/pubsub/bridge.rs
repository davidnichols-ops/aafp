//! `PubSubBridge` — bridge between the Simple API and the `NetworkedPubSub`
//! wire layer.
//!
//! Wraps an `Arc<NetworkedPubSub>` and runs the propagation driver
//! background task that forwards published messages to remote subscribers
//! (floodsub, RFC-0009 §3.2).
//!
//! This is the core P2 deliverable: it closes the open propagation loop in
//! `pubsub_v1.rs` by calling `encode_publish_request()` and
//! `remote_subscribers()` — which exist but are never invoked by the SDK.
//!
//! See `PS_P1_P2_API_PROPAGATION.md` Task 6 for the full design.

use std::sync::Arc;

use aafp_identity::AgentId;
use aafp_messaging::{
    NetworkedPubSub, PubSubRpcHandler, DEFAULT_TTL,
};
use tokio::sync::mpsc;

use crate::connection_pool::ConnectionPool;
use crate::Agent as SdkAgent;

/// Bridge between the Simple API and the `NetworkedPubSub` wire layer.
///
/// Wraps an `Arc<NetworkedPubSub>` and runs the propagation driver
/// background task that forwards published messages to remote subscribers
/// (floodsub, RFC-0009 §3.2).
///
/// Created by `ServeBuilder::start()` when PubSub is configured.
pub struct PubSubBridge {
    /// The underlying NetworkedPubSub instance (shared across connections).
    pubsub: Arc<NetworkedPubSub>,
    /// RPC handler for dispatching `aafp.pubsub.*` requests.
    rpc_handler: Arc<PubSubRpcHandler>,
    /// Our agent ID (used for the `seen` list in floodsub).
    our_id: AgentId,
    /// Channel for local publish events (triggers propagation).
    ///
    /// When a local publish occurs (or a remote message is received that
    /// should be re-forwarded), a `(topic, from, data)` tuple is sent here.
    /// The propagation driver task consumes from the receiver end.
    publish_events_tx: mpsc::UnboundedSender<(String, AgentId, Vec<u8>)>,
}

impl PubSubBridge {
    /// Create a new bridge wrapping the given PubSub instance.
    ///
    /// Spawns the propagation driver background task (P2). The driver
    /// consumes from the internal `publish_events` channel and forwards
    /// messages to `remote_subscribers()`.
    ///
    /// **Note**: This constructor does **not** have access to the
    /// `ConnectionPool`, so the propagation driver can only log forwards
    /// (not actually send RPC frames). Use [`PubSubBridge::new_with_pool`]
    /// for full networked propagation.
    pub fn new(pubsub: Arc<NetworkedPubSub>, our_id: AgentId) -> Self {
        let rpc_handler = Arc::new(PubSubRpcHandler::new(Arc::clone(&pubsub)));
        let (publish_events_tx, publish_events_rx) = mpsc::unbounded_channel();
        let bridge = Self {
            pubsub,
            rpc_handler,
            our_id,
            publish_events_tx,
        };
        bridge.spawn_propagation_driver(publish_events_rx);
        bridge
    }

    /// Create with pool access for networked propagation (P2).
    ///
    /// Spawns the propagation driver with access to the `ConnectionPool`
    /// and `SdkAgent`, enabling it to actually send `aafp.pubsub.publish`
    /// RPC frames to remote peers.
    ///
    /// **STUB**: The pool-integrated propagation driver is defined as
    /// [`PubSubBridge::spawn_propagation_driver_with_pool`] but is not
    /// yet wired into `new_with_pool` — it will be completed in the
    /// integration phase.
    #[allow(unused_variables)]
    pub fn new_with_pool(
        pubsub: Arc<NetworkedPubSub>,
        our_id: AgentId,
        agent: Arc<SdkAgent>,
        pool: Arc<ConnectionPool>,
    ) -> Self {
        let rpc_handler = Arc::new(PubSubRpcHandler::new(Arc::clone(&pubsub)));
        let (publish_events_tx, publish_events_rx) = mpsc::unbounded_channel();
        let bridge = Self {
            pubsub,
            rpc_handler,
            our_id,
            publish_events_tx,
        };
        // TODO(P2): switch to spawn_propagation_driver_with_pool once
        // send_publish_rpc and find_peer_addr are implemented.
        bridge.spawn_propagation_driver(publish_events_rx);
        bridge
    }

    /// Get the RPC handler for dispatching `aafp.pubsub.*` requests.
    ///
    /// The `ServingAgent` handler loop calls
    /// `bridge.rpc_handler().handle_request()` for any method starting
    /// with `aafp.pubsub.`.
    pub fn rpc_handler(&self) -> &PubSubRpcHandler {
        &self.rpc_handler
    }

    /// Get the underlying `NetworkedPubSub` (for local subscribe/publish).
    pub fn pubsub(&self) -> &Arc<NetworkedPubSub> {
        &self.pubsub
    }

    /// Get our agent ID.
    pub fn our_id(&self) -> AgentId {
        self.our_id
    }

    /// Notify the propagation driver of a local publish.
    ///
    /// Called when the agent publishes locally (via `publish_local` or
    /// when a remote message is received and should be re-forwarded).
    /// The propagation driver will query `remote_subscribers(topic)`,
    /// compute the `seen` list, decrement TTL, and forward to each peer.
    pub fn notify_local_publish(&self, topic: String, from: AgentId, data: Vec<u8>) {
        let _ = self.publish_events_tx.send((topic, from, data));
    }

    /// Spawn the propagation driver background task (no pool access).
    ///
    /// This closes the open loop in `pubsub_v1.rs`: after a local publish,
    /// it queries `remote_subscribers(topic)`, computes the seen list,
    /// decrements TTL, and sends `aafp.pubsub.publish` RPC frames to each
    /// peer over pooled connections.
    ///
    /// **STUB (no pool)**: Without pool access, this driver can only log
    /// the intended forwards. The pool-integrated variant
    /// ([`Self::spawn_propagation_driver_with_pool`]) performs the actual
    /// RPC sends.
    fn spawn_propagation_driver(
        &self,
        mut rx: mpsc::UnboundedReceiver<(String, AgentId, Vec<u8>)>,
    ) {
        let pubsub = Arc::clone(&self.pubsub);
        let our_id = self.our_id;

        tokio::spawn(async move {
            while let Some((topic, from, data)) = rx.recv().await {
                // Get remote peers subscribed to this topic
                let peers = pubsub.remote_subscribers(&topic);
                if peers.is_empty() {
                    continue;
                }

                // Compute seen list: includes our_id and the original sender
                let mut seen: Vec<AgentId> = vec![our_id, from];

                // Decrement TTL for forwarding
                let ttl = DEFAULT_TTL.saturating_sub(1);

                // Forward to each remote peer (skip those already in seen)
                for peer in &peers {
                    if seen.contains(peer) {
                        continue;
                    }
                    seen.push(*peer);

                    // Encode the publish request for this peer
                    let payload = match pubsub.encode_publish_request(
                        &topic,
                        data.clone(),
                        ttl,
                        seen.clone(),
                    ) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::warn!("pubsub encode error: {e}");
                            continue;
                        }
                    };

                    // Send the publish RPC to the peer.
                    // This requires a connection to the peer. Without pool
                    // access, we can only log. The pool-integrated variant
                    // calls send_publish_rpc().
                    tracing::debug!(
                        "pubsub: would forward to peer {:?} on topic '{}' \
                         ({} bytes, ttl={})",
                        peer,
                        topic,
                        payload.len(),
                        ttl,
                    );
                }
            }
        });
    }

    /// Spawn the propagation driver with pool access (P2 full).
    ///
    /// **STUB**: The body mirrors `spawn_propagation_driver` but adds
    /// `send_publish_rpc()` calls. The `send_publish_rpc` helper and
    /// `find_peer_addr` helper are defined below as stubs. This method
    /// is not yet called by `new_with_pool` — it will be activated in
    /// the integration phase once the helpers are implemented.
    #[allow(unused_variables, dead_code)]
    fn spawn_propagation_driver_with_pool(
        &self,
        mut rx: mpsc::UnboundedReceiver<(String, AgentId, Vec<u8>)>,
        agent: Arc<SdkAgent>,
        pool: Arc<ConnectionPool>,
    ) {
        let pubsub = Arc::clone(&self.pubsub);
        let our_id = self.our_id;

        tokio::spawn(async move {
            while let Some((topic, from, data)) = rx.recv().await {
                let peers = pubsub.remote_subscribers(&topic);
                if peers.is_empty() {
                    continue;
                }

                let mut seen: Vec<AgentId> = vec![our_id, from];
                let ttl = DEFAULT_TTL.saturating_sub(1);

                for peer in &peers {
                    if seen.contains(peer) {
                        continue;
                    }
                    seen.push(*peer);

                    // Look up the peer's address from the DHT
                    let peer_addr = match find_peer_addr(&agent, peer) {
                        Some(a) => a,
                        None => {
                            tracing::warn!(
                                "pubsub: no address for peer {:?}, skipping",
                                peer
                            );
                            continue;
                        }
                    };

                    let payload = match pubsub.encode_publish_request(
                        &topic,
                        data.clone(),
                        ttl,
                        seen.clone(),
                    ) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::warn!("pubsub encode error: {e}");
                            continue;
                        }
                    };

                    // Send publish RPC to the peer via the connection pool
                    if let Err(e) =
                        send_publish_rpc(&agent, &pool, &peer_addr, payload).await
                    {
                        tracing::warn!("pubsub forward to {} failed: {e}", peer_addr);
                    }
                }
            }
        });
    }
}

// ─── Free-function helpers (stubs) ─────────────────────────────

/// Send an `aafp.pubsub.publish` RPC frame to a peer.
///
/// Opens a bi-stream, sends the RPC request, reads the response,
/// and releases the connection back to the pool.
///
/// **STUB**: The body is a placeholder. The full implementation will:
/// 1. `pool.get_or_connect(agent, addr)` to get a connection.
/// 2. Decode `publish_params_bytes` to a `Value` and wrap in `RpcRequest`.
/// 3. `conn.open_bi()`, write the frame, `send.finish()`.
/// 4. Read the response frame header + body.
/// 5. `pool.release(&peer_id)`.
///
/// See `PS_P1_P2_API_PROPAGATION.md` §6.2 for the full implementation.
async fn send_publish_rpc(
    agent: &SdkAgent,
    pool: &ConnectionPool,
    addr: &str,
    publish_params_bytes: Vec<u8>,
) -> Result<(), crate::SdkError> {
    // TODO(P2): implement full RPC send.
    // For now, this is a no-op stub that logs.
    tracing::debug!(
        "send_publish_rpc stub: addr={}, {} bytes",
        addr,
        publish_params_bytes.len()
    );
    let _ = (agent, pool);
    Ok(())
}

/// Find a peer's address from the DHT by AgentId.
///
/// Searches all capabilities for the peer's record and returns the first
/// endpoint.
///
/// **STUB**: The full implementation iterates `agent.dht.list_capabilities()`
/// and `agent.find_by_capability()` to locate the peer's `AgentRecord`,
/// then returns `record.endpoints.first()`.
fn find_peer_addr(agent: &SdkAgent, peer_id: &AgentId) -> Option<String> {
    // TODO(P2): implement DHT lookup.
    // For now, return None — the propagation driver will skip the peer.
    let _ = (agent, peer_id);
    None
}
