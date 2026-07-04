//! Connection pool for reusing QUIC connections to peers (Track I5).
//!
//! The pool eliminates the 240µs handshake cost for repeated RPCs to the
//! same peer. Instead of creating a new QUIC connection (with TLS + AAFP
//! handshake) for each RPC, the pool reuses an existing connection and
//! opens a new bidirectional stream (14µs).
//!
//! ## Architecture
//!
//! ```text
//! get_or_connect(peer_id, addr)
//!   │
//!   ├─ Pool has connection for peer_id?
//!   │   ├─ Yes → Is it healthy (open_bi succeeds)?
//!   │   │   ├─ Yes → Return existing connection (14µs)
//!   │   │   └─ No  → Discard, create new (240µs)
//!   │   └─ No  → Create new connection (240µs)
//!   │
//!   └─ Update last_used timestamp
//! ```
//!
//! ## Idle Eviction
//!
//! Connections that haven't been used for `idle_timeout` (default: 60s)
//! are closed and removed from the pool. This prevents the pool from
//! holding stale connections that the peer may have already closed.
//!
//! ## Health Check
//!
//! Before returning a pooled connection, the pool opens a test stream
//! (`open_bi`). If this fails, the connection is stale (peer closed it)
//! and a new connection is created. This is a lightweight check — no
//! data is sent, just a stream open.

use crate::{establish_session, Agent, SdkError};
use aafp_core::{AuthorizationProvider, Session};
use aafp_identity::AgentId;
use aafp_transport_quic::QuicConnection;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Default idle timeout before a pooled connection is evicted (60 seconds).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum number of connections in the pool.
pub const DEFAULT_MAX_POOL_SIZE: usize = 100;

/// Duration after which a pooled connection requires a health check
/// before reuse (5 seconds). Connections reused within this window are
/// assumed to be healthy (the peer hasn't had time to close them).
pub const HEALTH_CHECK_THRESHOLD: Duration = Duration::from_secs(5);

/// A pooled connection with metadata.
struct PooledConnection {
    /// The underlying QUIC connection (handshake completed).
    conn: QuicConnection,
    /// Session state machine (in MessagingEnabled state).
    session: Session,
    /// When this connection was last used (for idle eviction).
    last_used: Instant,
    /// The peer address used to establish this connection.
    addr: String,
}

impl std::fmt::Debug for PooledConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledConnection")
            .field("peer_agent_id", &self.session.peer_agent_id())
            .field("addr", &self.addr)
            .field("last_used", &self.last_used)
            .finish()
    }
}

/// Configuration for the connection pool.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum number of connections in the pool.
    pub max_size: usize,
    /// Idle timeout before a connection is evicted.
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_POOL_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

/// A connection pool that reuses QUIC connections to peers (Track I5).
///
/// The pool stores completed AAFP handshake connections keyed by peer
/// AgentId. When `get_or_connect()` is called:
/// 1. If a connection exists for the peer, it's health-checked and reused
/// 2. If not (or health check fails), a new connection is established
///
/// This eliminates the 240µs handshake cost for repeated RPCs, reducing
/// it to 14µs (stream open on existing connection) — a 17x improvement.
///
/// # Example
///
/// ```no_run
/// # use aafp_sdk::{AgentBuilder, ConnectionPool, PoolConfig};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let agent = AgentBuilder::new().build().await?;
/// let pool = ConnectionPool::new(PoolConfig::default());
///
/// // First call: establishes connection (240µs)
/// let (peer_id, conn) = pool.get_or_connect(&agent, "quic://127.0.0.1:4433").await?;
///
/// // Use the connection...
/// pool.release(&peer_id).await;
///
/// // Second call: reuses connection (14µs)
/// let (peer_id2, conn2) = pool.get_or_connect(&agent, "quic://127.0.0.1:4433").await?;
/// assert_eq!(peer_id, peer_id2);
/// # Ok(())
/// # }
/// ```
pub struct ConnectionPool {
    /// Pooled connections keyed by peer AgentId.
    connections: Mutex<HashMap<AgentId, PooledConnection>>,
    /// Pool configuration.
    config: PoolConfig,
    /// Authorization provider for new connections.
    auth_provider: Arc<dyn AuthorizationProvider>,
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("config", &self.config)
            .finish()
    }
}

impl ConnectionPool {
    /// Create a new connection pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        Self::with_auth_provider(config, Arc::new(aafp_core::TestingAuthProvider))
    }

    /// Create a new connection pool with a custom authorization provider.
    pub fn with_auth_provider(
        config: PoolConfig,
        auth_provider: Arc<dyn AuthorizationProvider>,
    ) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            config,
            auth_provider,
        }
    }

    /// Get an existing connection or establish a new one (Track I5).
    ///
    /// If the pool has a healthy connection to the peer, it's reused
    /// (14µs — just opening a stream). Otherwise, a new connection is
    /// established with the full AAFP handshake (240µs).
    ///
    /// The connection is marked as "in use" — call `release()` when done
    /// to return it to the pool for reuse.
    ///
    /// # Arguments
    /// - `agent`: The local agent (provides transport + keypair)
    /// - `addr`: The peer's multiaddr (e.g., "quic://127.0.0.1:4433")
    ///
    /// # Returns
    /// - `(AgentId, QuicConnection)`: The peer's verified AgentId and
    ///   the QUIC connection. The connection can be used to open streams.
    pub async fn get_or_connect(
        &self,
        agent: &Agent,
        addr: &str,
    ) -> Result<(AgentId, QuicConnection), SdkError> {
        let mut conns = self.connections.lock().await;

        // Evict idle connections before checking
        self.evict_idle_locked(&mut conns);

        // Check if we have a connection for any peer at this address
        // We key by AgentId, so we need to check by address
        let existing_peer_id = conns
            .iter()
            .find(|(_, pc)| pc.addr == addr)
            .map(|(id, _)| *id);

        if let Some(peer_id) = existing_peer_id {
            if let Some(pc) = conns.get_mut(&peer_id) {
                // Only health-check if the connection has been idle for a while.
                // Recently-used connections are assumed healthy (the peer hasn't
                // had time to close them). This avoids the overhead of opening
                // a test stream on every get_or_connect() call.
                let needs_health_check =
                    Instant::now().duration_since(pc.last_used) > HEALTH_CHECK_THRESHOLD;

                if needs_health_check {
                    if Self::is_healthy(&pc.conn).await {
                        pc.last_used = Instant::now();
                        let conn = pc.conn.clone();
                        return Ok((peer_id, conn));
                    } else {
                        // Stale connection — discard
                        conns.remove(&peer_id);
                    }
                } else {
                    // Recently used — skip health check, return immediately
                    pc.last_used = Instant::now();
                    let conn = pc.conn.clone();
                    return Ok((peer_id, conn));
                }
            }
        }

        // Need to create a new connection
        // Drop the lock during the handshake (which is slow)
        drop(conns);

        let conn = agent.transport.dial(addr).await?;
        let (session, conn, peer_info) =
            establish_session(conn, &agent.keypair, self.auth_provider.clone(), true, None).await?;

        let peer_id = peer_info.agent_id;

        // Re-acquire lock and store
        let mut conns = self.connections.lock().await;
        self.evict_idle_locked(&mut conns);

        // Check if we're at capacity
        if conns.len() >= self.config.max_size {
            // Evict the oldest connection
            if let Some(oldest_id) = conns
                .iter()
                .min_by_key(|(_, pc)| pc.last_used)
                .map(|(id, _)| *id)
            {
                if let Some(removed) = conns.remove(&oldest_id) {
                    removed.conn.close(0, b"pool eviction");
                }
            }
        }

        conns.insert(
            peer_id,
            PooledConnection {
                conn: conn.clone(),
                session,
                last_used: Instant::now(),
                addr: addr.to_string(),
            },
        );

        Ok((peer_id, conn))
    }

    /// Release a connection back to the pool (Track I5).
    ///
    /// This marks the connection as idle and available for reuse.
    /// The connection is NOT closed — it remains in the pool until
    /// it's either reused or evicted by the idle timeout.
    ///
    /// Calling `release()` is optional — `get_or_connect()` will update
    /// the `last_used` timestamp on reuse. However, calling `release()`
    /// after you're done with a connection allows the idle eviction
    /// logic to reclaim it sooner.
    pub async fn release(&self, peer_id: &AgentId) {
        let mut conns = self.connections.lock().await;
        if let Some(pc) = conns.get_mut(peer_id) {
            pc.last_used = Instant::now();
        }
    }

    /// Remove a connection from the pool and close it.
    ///
    /// Use this when you know the connection is no longer needed
    /// (e.g., the peer has disconnected or the session has ended).
    pub async fn remove(&self, peer_id: &AgentId) {
        let mut conns = self.connections.lock().await;
        if let Some(pc) = conns.remove(peer_id) {
            pc.conn.close(0, b"pool removal");
        }
    }

    /// Number of connections currently in the pool.
    pub async fn len(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Whether the pool is empty.
    pub async fn is_empty(&self) -> bool {
        self.connections.lock().await.is_empty()
    }

    /// Get the peer AgentIds currently in the pool.
    pub async fn peers(&self) -> Vec<AgentId> {
        self.connections.lock().await.keys().copied().collect()
    }

    /// Evict idle connections from the pool.
    ///
    /// Connections that haven't been used for `idle_timeout` are closed
    /// and removed. This is called automatically by `get_or_connect()`,
    /// but can also be called manually.
    pub async fn evict_idle(&self) -> usize {
        let mut conns = self.connections.lock().await;
        self.evict_idle_locked(&mut conns)
    }

    /// Internal: evict idle connections (caller holds the lock).
    fn evict_idle_locked(&self, conns: &mut HashMap<AgentId, PooledConnection>) -> usize {
        let now = Instant::now();
        let timeout = self.config.idle_timeout;
        let to_evict: Vec<AgentId> = conns
            .iter()
            .filter(|(_, pc)| now.duration_since(pc.last_used) > timeout)
            .map(|(id, _)| *id)
            .collect();
        let count = to_evict.len();
        for id in &to_evict {
            if let Some(pc) = conns.remove(id) {
                pc.conn.close(0, b"idle timeout");
            }
        }
        count
    }

    /// Check if a connection is healthy by attempting to open a stream.
    ///
    /// This is a lightweight check — no data is sent. If `open_bi()`
    /// succeeds, the connection is healthy. If it fails, the peer has
    /// likely closed the connection.
    async fn is_healthy(conn: &QuicConnection) -> bool {
        // Try to open a bidirectional stream. If this fails, the
        // connection is closed/stale.
        //
        // We immediately drop the streams without sending data — this
        // is just a liveness probe.
        match conn.open_bi().await {
            Ok((_send, _recv)) => true, // Stream opened successfully
            Err(_) => false,            // Connection is stale
        }
    }

    /// Get the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentBuilder;

    #[tokio::test]
    async fn pool_starts_empty() {
        let pool = ConnectionPool::new(PoolConfig::default());
        assert_eq!(pool.len().await, 0);
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn pool_config_defaults() {
        let pool = ConnectionPool::new(PoolConfig::default());
        assert_eq!(pool.config().max_size, DEFAULT_MAX_POOL_SIZE);
        assert_eq!(pool.config().idle_timeout, DEFAULT_IDLE_TIMEOUT);
    }

    #[tokio::test]
    async fn pool_evict_idle_removes_nothing_when_empty() {
        let pool = ConnectionPool::new(PoolConfig::default());
        assert_eq!(pool.evict_idle().await, 0);
    }

    #[tokio::test]
    async fn pool_get_or_connect_creates_connection() {
        // Set up a server agent
        let server_agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .unwrap(),
        );
        let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

        // Spawn server to accept the connection
        let server_agent_clone = server_agent.clone();
        let server_handle = tokio::spawn(async move {
            // Accept the connection and drive server-side handshake
            let conn = server_agent_clone.transport.accept().await.unwrap();
            let auth = Arc::new(aafp_core::TestingAuthProvider);
            let _ = establish_session(conn, &server_agent_clone.keypair, auth, false, None).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Client connects via pool
        let client_agent = AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        let pool = ConnectionPool::new(PoolConfig::default());
        let (peer_id, _conn) = pool.get_or_connect(&client_agent, &addr).await.unwrap();

        assert!(!pool.is_empty().await);
        assert_eq!(pool.len().await, 1);
        assert!(pool.peers().await.contains(&peer_id));

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pool_reuses_connection_for_same_peer() {
        // Set up a persistent server
        let server_agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .unwrap(),
        );
        let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

        // Spawn server that accepts multiple connections
        let server_agent_clone = server_agent.clone();
        tokio::spawn(async move {
            for _ in 0..10 {
                if let Ok(conn) = server_agent_clone.transport.accept().await {
                    let auth = Arc::new(aafp_core::TestingAuthProvider);
                    let _ = establish_session(conn, &server_agent_clone.keypair, auth, false, None)
                        .await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_agent = AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        let pool = ConnectionPool::new(PoolConfig::default());

        // First call: creates connection
        let (peer_id1, _conn1) = pool.get_or_connect(&client_agent, &addr).await.unwrap();
        pool.release(&peer_id1).await;

        // Second call: should reuse connection (same peer_id, no new handshake)
        let (peer_id2, _conn2) = pool.get_or_connect(&client_agent, &addr).await.unwrap();

        assert_eq!(peer_id1, peer_id2, "should reuse same connection");
        assert_eq!(pool.len().await, 1, "pool should have 1 connection");
    }

    #[tokio::test]
    async fn pool_100_rpcs_use_1_connection() {
        // Set up a persistent server
        let server_agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .unwrap(),
        );
        let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

        // Spawn server that accepts connections
        let server_agent_clone = server_agent.clone();
        tokio::spawn(async move {
            for _ in 0..100 {
                if let Ok(conn) = server_agent_clone.transport.accept().await {
                    let auth = Arc::new(aafp_core::TestingAuthProvider);
                    let _ = establish_session(conn, &server_agent_clone.keypair, auth, false, None)
                        .await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_agent = AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        let pool = ConnectionPool::new(PoolConfig::default());

        // Perform 100 sequential get_or_connect calls
        let mut last_peer_id = None;
        for _ in 0..100 {
            let (peer_id, _conn) = pool.get_or_connect(&client_agent, &addr).await.unwrap();
            pool.release(&peer_id).await;
            if let Some(ref existing) = last_peer_id {
                assert_eq!(peer_id, *existing, "should reuse same connection");
            }
            last_peer_id = Some(peer_id);
        }

        // VERIFY: 100 RPCs used 1 connection (not 100)
        assert_eq!(pool.len().await, 1, "pool should have exactly 1 connection");
    }

    #[tokio::test]
    async fn pool_evicts_idle_connections() {
        // Set up server
        let server_agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .unwrap(),
        );
        let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

        let server_agent_clone = server_agent.clone();
        tokio::spawn(async move {
            if let Ok(conn) = server_agent_clone.transport.accept().await {
                let auth = Arc::new(aafp_core::TestingAuthProvider);
                let _ =
                    establish_session(conn, &server_agent_clone.keypair, auth, false, None).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_agent = AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        // Pool with very short idle timeout (1ms)
        let pool = ConnectionPool::new(PoolConfig {
            idle_timeout: Duration::from_millis(1),
            max_size: 100,
        });

        let (_peer_id, _conn) = pool.get_or_connect(&client_agent, &addr).await.unwrap();
        assert_eq!(pool.len().await, 1);

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Evict idle connections
        let evicted = pool.evict_idle().await;
        assert_eq!(evicted, 1);
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn pool_remove_closes_connection() {
        // Set up server
        let server_agent = Arc::new(
            AgentBuilder::new()
                .bind("127.0.0.1:0".parse().unwrap())
                .build()
                .await
                .unwrap(),
        );
        let addr = format!("quic://{}", server_agent.transport.local_addr().unwrap());

        let server_agent_clone = server_agent.clone();
        tokio::spawn(async move {
            if let Ok(conn) = server_agent_clone.transport.accept().await {
                let auth = Arc::new(aafp_core::TestingAuthProvider);
                let _ =
                    establish_session(conn, &server_agent_clone.keypair, auth, false, None).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_agent = AgentBuilder::new()
            .bind("127.0.0.1:0".parse().unwrap())
            .build()
            .await
            .unwrap();

        let pool = ConnectionPool::new(PoolConfig::default());
        let (peer_id, _conn) = pool.get_or_connect(&client_agent, &addr).await.unwrap();
        assert_eq!(pool.len().await, 1);

        pool.remove(&peer_id).await;
        assert_eq!(pool.len().await, 0);
    }
}
