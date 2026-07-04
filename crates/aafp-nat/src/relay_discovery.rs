//! Relay discovery: find relay nodes via DHT and bootstrap (RFC 0010 §9).
//!
//! Agents that need a relay discover relay nodes by:
//! 1. Looking up the "relay" capability in the DHT
//! 2. Checking bootstrap nodes for relay advertisements
//! 3. Maintaining a cache of known relay nodes
//! 4. Selecting the best relay based on latency, capacity, and uptime

use aafp_cbor::{int_map, int_map_get, CborError, Value};
use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Capability string for relay nodes (RFC 0010 §9).
pub const RELAY_CAPABILITY: &str = "relay";

/// Default max relays to maintain in the cache.
pub const DEFAULT_MAX_RELAYS: usize = 5;

/// Default relay refresh interval: 5 minutes.
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 300;

/// Default relay health check timeout: 5 seconds.
pub const DEFAULT_HEALTH_CHECK_TIMEOUT_SECS: u64 = 5;

/// A discovered relay node.
#[derive(Clone, Debug)]
pub struct RelayNodeInfo {
    /// The relay agent ID.
    pub agent_id: AgentId,
    /// The relay multiaddr (e.g., "quic://1.2.3.4:4433").
    pub addr: String,
    /// When this relay was discovered.
    pub discovered: Instant,
    /// Last health check result (true = healthy).
    pub last_health_check: Option<bool>,
    /// Last health check time.
    pub last_health_check_time: Option<Instant>,
    /// Measured latency in milliseconds (if known).
    pub latency_ms: Option<u64>,
    /// Reported capacity (max connections).
    pub max_connections: Option<usize>,
    /// Reported current connection count.
    pub current_connections: Option<usize>,
}

impl RelayNodeInfo {
    /// Create a new relay node info.
    pub fn new(agent_id: AgentId, addr: String) -> Self {
        Self {
            agent_id,
            addr,
            discovered: Instant::now(),
            last_health_check: None,
            last_health_check_time: None,
            latency_ms: None,
            max_connections: None,
            current_connections: None,
        }
    }

    /// Check if the relay is healthy.
    pub fn is_healthy(&self) -> bool {
        self.last_health_check.unwrap_or(false)
    }

    /// Check if the relay has capacity for more connections.
    pub fn has_capacity(&self) -> bool {
        match (self.max_connections, self.current_connections) {
            (Some(max), Some(current)) => current < max,
            _ => true, // Unknown capacity, assume yes
        }
    }

    /// Get the utilization ratio (0.0 = empty, 1.0 = full).
    pub fn utilization(&self) -> Option<f64> {
        match (self.max_connections, self.current_connections) {
            (Some(max), Some(current)) if max > 0 => Some(current as f64 / max as f64),
            _ => None,
        }
    }

    /// Update health check result.
    pub fn update_health(&mut self, healthy: bool, latency_ms: Option<u64>) {
        self.last_health_check = Some(healthy);
        self.last_health_check_time = Some(Instant::now());
        self.latency_ms = latency_ms;
    }

    /// Update capacity info.
    pub fn update_capacity(&mut self, max: usize, current: usize) {
        self.max_connections = Some(max);
        self.current_connections = Some(current);
    }

    /// Encode as CBOR for caching/persistence.
    pub fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (1, Value::ByteString(self.agent_id.to_vec())),
            (2, Value::TextString(self.addr.clone())),
        ];
        if let Some(latency) = self.latency_ms {
            entries.push((3, Value::Unsigned(latency)));
        }
        if let Some(max) = self.max_connections {
            entries.push((4, Value::Unsigned(max as u64)));
        }
        if let Some(current) = self.current_connections {
            entries.push((5, Value::Unsigned(current as u64)));
        }
        int_map(entries)
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, CborError> {
        let agent_id = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) => {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    arr
                } else {
                    return Err(CborError::Invalid {
                        offset: 0,
                        message: "agent_id must be 32 bytes".into(),
                    });
                }
            }
            _ => {
                return Err(CborError::Invalid {
                    offset: 0,
                    message: "missing agent_id".into(),
                })
            }
        };
        let addr = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => s.clone(),
            _ => {
                return Err(CborError::Invalid {
                    offset: 0,
                    message: "missing addr".into(),
                })
            }
        };
        let latency_ms = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => Some(*n),
            _ => None,
        };
        let max_connections = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => Some(*n as usize),
            _ => None,
        };
        let current_connections = match int_map_get(val, 5) {
            Some(Value::Unsigned(n)) => Some(*n as usize),
            _ => None,
        };

        Ok(Self {
            agent_id,
            addr,
            discovered: Instant::now(),
            last_health_check: None,
            last_health_check_time: None,
            latency_ms,
            max_connections,
            current_connections,
        })
    }
}

/// Relay discovery: maintains a cache of known relay nodes and provides
/// methods to discover new ones.
pub struct RelayDiscovery {
    /// Cache of known relay nodes: agent_id → RelayNodeInfo.
    relays: HashMap<AgentId, RelayNodeInfo>,
    /// Max relays to maintain in the cache.
    max_relays: usize,
    /// Bootstrap relay addresses (configured at startup).
    bootstrap_relays: Vec<String>,
    /// Refresh interval.
    refresh_interval: Duration,
}

impl RelayDiscovery {
    /// Create a new relay discovery instance.
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
            max_relays: DEFAULT_MAX_RELAYS,
            bootstrap_relays: Vec::new(),
            refresh_interval: Duration::from_secs(DEFAULT_REFRESH_INTERVAL_SECS),
        }
    }

    /// Set the max relays to maintain.
    pub fn with_max_relays(mut self, max: usize) -> Self {
        self.max_relays = max;
        self
    }

    /// Set the refresh interval.
    pub fn with_refresh_interval(mut self, secs: u64) -> Self {
        self.refresh_interval = Duration::from_secs(secs);
        self
    }

    /// Add a bootstrap relay address.
    pub fn add_bootstrap_relay(&mut self, addr: String) {
        self.bootstrap_relays.push(addr);
    }

    /// Add multiple bootstrap relay addresses.
    pub fn add_bootstrap_relays(&mut self, addrs: Vec<String>) {
        self.bootstrap_relays.extend(addrs);
    }

    /// Get the bootstrap relay addresses.
    pub fn bootstrap_relays(&self) -> &[String] {
        &self.bootstrap_relays
    }

    /// Add a discovered relay node.
    pub fn add_relay(&mut self, info: RelayNodeInfo) {
        if self.relays.len() >= self.max_relays && !self.relays.contains_key(&info.agent_id) {
            // Evict the worst relay (highest latency or unhealthiest)
            self.evict_worst();
        }
        self.relays.insert(info.agent_id, info);
        debug!("Added relay node, total: {}", self.relays.len());
    }

    /// Remove a relay node.
    pub fn remove_relay(&mut self, agent_id: &AgentId) {
        self.relays.remove(agent_id);
    }

    /// Get a relay node by agent ID.
    pub fn get_relay(&self, agent_id: &AgentId) -> Option<&RelayNodeInfo> {
        self.relays.get(agent_id)
    }

    /// Get all relay nodes.
    pub fn relays(&self) -> &HashMap<AgentId, RelayNodeInfo> {
        &self.relays
    }

    /// Get the number of known relays.
    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    /// Get all healthy relays.
    pub fn healthy_relays(&self) -> Vec<&RelayNodeInfo> {
        self.relays.values().filter(|r| r.is_healthy()).collect()
    }

    /// Get all relays with capacity.
    pub fn relays_with_capacity(&self) -> Vec<&RelayNodeInfo> {
        self.relays.values().filter(|r| r.has_capacity()).collect()
    }

    /// Select the best relay for a new connection.
    ///
    /// Selection criteria (in order):
    /// 1. Healthy
    /// 2. Has capacity
    /// 3. Lowest latency
    /// 4. Lowest utilization
    pub fn select_best_relay(&self) -> Option<&RelayNodeInfo> {
        self.relays
            .values()
            .filter(|r| r.is_healthy() && r.has_capacity())
            .min_by(|a, b| {
                // Compare by latency first, then utilization
                let a_latency = a.latency_ms.unwrap_or(u64::MAX);
                let b_latency = b.latency_ms.unwrap_or(u64::MAX);
                if a_latency != b_latency {
                    return a_latency.cmp(&b_latency);
                }
                let a_util = a.utilization().unwrap_or(1.0);
                let b_util = b.utilization().unwrap_or(1.0);
                a_util
                    .partial_cmp(&b_util)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Select the best relay, excluding a specific relay (e.g., the current one).
    pub fn select_best_relay_excluding(&self, exclude: &AgentId) -> Option<&RelayNodeInfo> {
        self.relays
            .values()
            .filter(|r| r.agent_id != *exclude && r.is_healthy() && r.has_capacity())
            .min_by(|a, b| {
                let a_latency = a.latency_ms.unwrap_or(u64::MAX);
                let b_latency = b.latency_ms.unwrap_or(u64::MAX);
                if a_latency != b_latency {
                    return a_latency.cmp(&b_latency);
                }
                let a_util = a.utilization().unwrap_or(1.0);
                let b_util = b.utilization().unwrap_or(1.0);
                a_util
                    .partial_cmp(&b_util)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Evict the worst relay (highest latency or unhealthiest).
    fn evict_worst(&mut self) {
        if let Some(worst_id) = self
            .relays
            .iter()
            .max_by(|a, b| {
                // We want to find the WORST relay to evict.
                // Worst = unhealthy, or highest latency.
                // max_by returns the "greatest" element, so we want the
                // worst relay to compare as "greatest".
                let a_health = a.1.is_healthy() as u8; // 1 = healthy, 0 = unhealthy
                let b_health = b.1.is_healthy() as u8;
                if a_health != b_health {
                    // Unhealthy (0) should be "greater" (evicted first)
                    return b_health.cmp(&a_health);
                }
                // Both same health: higher latency should be "greater" (evicted)
                let a_latency = a.1.latency_ms.unwrap_or(u64::MAX);
                let b_latency = b.1.latency_ms.unwrap_or(u64::MAX);
                a_latency.cmp(&b_latency)
            })
            .map(|(id, _)| *id)
        {
            self.relays.remove(&worst_id);
            debug!("Evicted worst relay to make room");
        }
    }

    /// Update a relay health check result.
    pub fn update_relay_health(
        &mut self,
        agent_id: &AgentId,
        healthy: bool,
        latency_ms: Option<u64>,
    ) {
        if let Some(relay) = self.relays.get_mut(agent_id) {
            relay.update_health(healthy, latency_ms);
        }
    }

    /// Update relay capacity info.
    pub fn update_relay_capacity(&mut self, agent_id: &AgentId, max: usize, current: usize) {
        if let Some(relay) = self.relays.get_mut(agent_id) {
            relay.update_capacity(max, current);
        }
    }

    /// Check if refresh is needed (based on refresh interval).
    pub fn needs_refresh(&self) -> bool {
        if self.relays.is_empty() {
            return true;
        }
        let now = Instant::now();
        self.relays
            .values()
            .any(|r| now.duration_since(r.discovered) > self.refresh_interval)
    }

    /// Get the refresh interval.
    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    /// Clear all relays.
    pub fn clear(&mut self) {
        self.relays.clear();
    }
}

impl Default for RelayDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay health checker: checks if a relay is reachable and measures latency.
pub struct RelayHealthChecker;

impl RelayHealthChecker {
    /// Check if a relay is healthy by attempting to connect.
    ///
    /// Returns (healthy, latency_ms).
    pub async fn check(addr: &str, timeout_secs: u64) -> (bool, Option<u64>) {
        let start = Instant::now();

        // Create a temporary transport
        let config = aafp_transport_quic::QuicConfig::default();
        let transport = match aafp_transport_quic::QuicTransport::new(config) {
            Ok(t) => t,
            Err(_) => return (false, None),
        };

        let timeout = Duration::from_secs(timeout_secs);
        let dial_result = tokio::time::timeout(timeout, transport.dial(addr)).await;

        match dial_result {
            Ok(Ok(_conn)) => {
                let latency = start.elapsed().as_millis() as u64;
                info!("Relay {} healthy (latency: {}ms)", addr, latency);
                (true, Some(latency))
            }
            Ok(Err(e)) => {
                warn!("Relay {} unhealthy: {}", addr, e);
                (false, None)
            }
            Err(_) => {
                warn!("Relay {} health check timed out", addr);
                (false, None)
            }
        }
    }
}

/// Relay discovery service: combines DHT lookup with health checking.
pub struct RelayDiscoveryService {
    /// The relay discovery cache.
    discovery: Arc<Mutex<RelayDiscovery>>,
    /// Health check timeout.
    health_check_timeout: u64,
}

impl RelayDiscoveryService {
    /// Create a new relay discovery service.
    pub fn new() -> Self {
        Self {
            discovery: Arc::new(Mutex::new(RelayDiscovery::new())),
            health_check_timeout: DEFAULT_HEALTH_CHECK_TIMEOUT_SECS,
        }
    }

    /// Set the health check timeout.
    pub fn with_health_check_timeout(mut self, secs: u64) -> Self {
        self.health_check_timeout = secs;
        self
    }

    /// Get a reference to the discovery cache.
    pub fn discovery(&self) -> &Arc<Mutex<RelayDiscovery>> {
        &self.discovery
    }

    /// Add a relay node and health-check it.
    pub async fn add_and_check(&self, agent_id: AgentId, addr: String) {
        let info = RelayNodeInfo::new(agent_id, addr.clone());
        self.discovery.lock().unwrap().add_relay(info);

        // Health check
        let (healthy, latency) = RelayHealthChecker::check(&addr, self.health_check_timeout).await;
        self.discovery
            .lock()
            .unwrap()
            .update_relay_health(&agent_id, healthy, latency);
    }

    /// Discover relays from a list of addresses (e.g., from DHT or bootstrap).
    pub async fn discover_from_addresses(&self, addresses: Vec<(AgentId, String)>) {
        for (agent_id, addr) in addresses {
            self.add_and_check(agent_id, addr).await;
        }
    }

    /// Select the best relay for a new connection.
    pub fn select_best_relay(&self) -> Option<RelayNodeInfo> {
        let discovery = self.discovery.lock().unwrap();
        discovery.select_best_relay().cloned()
    }

    /// Get all healthy relays.
    pub fn healthy_relays(&self) -> Vec<RelayNodeInfo> {
        let discovery = self.discovery.lock().unwrap();
        discovery.healthy_relays().into_iter().cloned().collect()
    }

    /// Refresh health checks for all known relays.
    pub async fn refresh_health_checks(&self) {
        let relays: Vec<(AgentId, String)> = {
            let discovery = self.discovery.lock().unwrap();
            discovery
                .relays()
                .iter()
                .map(|(id, info)| (*id, info.addr.clone()))
                .collect()
        };

        for (agent_id, addr) in relays {
            let (healthy, latency) =
                RelayHealthChecker::check(&addr, self.health_check_timeout).await;
            self.discovery
                .lock()
                .unwrap()
                .update_relay_health(&agent_id, healthy, latency);
        }
    }
}

impl Default for RelayDiscoveryService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_agent_id(byte: u8) -> AgentId {
        [byte; 32]
    }

    #[test]
    fn test_relay_node_info_creation() {
        let id = make_agent_id(1);
        let info = RelayNodeInfo::new(id, "quic://1.2.3.4:4433".into());
        assert_eq!(info.agent_id, id);
        assert_eq!(info.addr, "quic://1.2.3.4:4433");
        assert!(!info.is_healthy()); // No health check yet
        assert!(info.has_capacity()); // Unknown capacity, assume yes
    }

    #[test]
    fn test_relay_node_info_health_update() {
        let id = make_agent_id(1);
        let mut info = RelayNodeInfo::new(id, "quic://1.2.3.4:4433".into());
        info.update_health(true, Some(50));
        assert!(info.is_healthy());
        assert_eq!(info.latency_ms, Some(50));
    }

    #[test]
    fn test_relay_node_info_capacity() {
        let id = make_agent_id(1);
        let mut info = RelayNodeInfo::new(id, "quic://1.2.3.4:4433".into());
        info.update_capacity(100, 50);
        assert!(info.has_capacity());
        assert_eq!(info.utilization(), Some(0.5));

        info.update_capacity(100, 100);
        assert!(!info.has_capacity());
        assert_eq!(info.utilization(), Some(1.0));
    }

    #[test]
    fn test_relay_node_info_cbor_roundtrip() {
        let id = make_agent_id(1);
        let mut info = RelayNodeInfo::new(id, "quic://1.2.3.4:4433".into());
        info.update_capacity(100, 50);
        info.latency_ms = Some(42);

        let cbor = info.to_cbor();
        let decoded = RelayNodeInfo::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.agent_id, id);
        assert_eq!(decoded.addr, "quic://1.2.3.4:4433");
        assert_eq!(decoded.latency_ms, Some(42));
        assert_eq!(decoded.max_connections, Some(100));
        assert_eq!(decoded.current_connections, Some(50));
    }

    #[test]
    fn test_relay_discovery_add_and_select() {
        let mut discovery = RelayDiscovery::new();

        let id1 = make_agent_id(1);
        let id2 = make_agent_id(2);

        let mut info1 = RelayNodeInfo::new(id1, "quic://1.2.3.4:4433".into());
        info1.update_health(true, Some(100));

        let mut info2 = RelayNodeInfo::new(id2, "quic://5.6.7.8:4433".into());
        info2.update_health(true, Some(50));

        discovery.add_relay(info1);
        discovery.add_relay(info2);

        assert_eq!(discovery.relay_count(), 2);

        // Best relay should be the one with lower latency
        let best = discovery.select_best_relay().unwrap();
        assert_eq!(best.agent_id, id2);
        assert_eq!(best.latency_ms, Some(50));
    }

    #[test]
    fn test_relay_discovery_select_excluding() {
        let mut discovery = RelayDiscovery::new();

        let id1 = make_agent_id(1);
        let id2 = make_agent_id(2);

        let mut info1 = RelayNodeInfo::new(id1, "quic://1.2.3.4:4433".into());
        info1.update_health(true, Some(50));

        let mut info2 = RelayNodeInfo::new(id2, "quic://5.6.7.8:4433".into());
        info2.update_health(true, Some(100));

        discovery.add_relay(info1);
        discovery.add_relay(info2);

        // Exclude id1, should get id2
        let best = discovery.select_best_relay_excluding(&id1).unwrap();
        assert_eq!(best.agent_id, id2);
    }

    #[test]
    fn test_relay_discovery_unhealthy_not_selected() {
        let mut discovery = RelayDiscovery::new();

        let id1 = make_agent_id(1);
        let id2 = make_agent_id(2);

        let mut info1 = RelayNodeInfo::new(id1, "quic://1.2.3.4:4433".into());
        info1.update_health(false, None); // Unhealthy

        let mut info2 = RelayNodeInfo::new(id2, "quic://5.6.7.8:4433".into());
        info2.update_health(true, Some(100));

        discovery.add_relay(info1);
        discovery.add_relay(info2);

        // Should select the healthy one
        let best = discovery.select_best_relay().unwrap();
        assert_eq!(best.agent_id, id2);
    }

    #[test]
    fn test_relay_discovery_no_capacity_not_selected() {
        let mut discovery = RelayDiscovery::new();

        let id1 = make_agent_id(1);
        let id2 = make_agent_id(2);

        let mut info1 = RelayNodeInfo::new(id1, "quic://1.2.3.4:4433".into());
        info1.update_health(true, Some(50));
        info1.update_capacity(100, 100); // Full

        let mut info2 = RelayNodeInfo::new(id2, "quic://5.6.7.8:4433".into());
        info2.update_health(true, Some(100));
        info2.update_capacity(100, 50); // Has capacity

        discovery.add_relay(info1);
        discovery.add_relay(info2);

        // Should select the one with capacity
        let best = discovery.select_best_relay().unwrap();
        assert_eq!(best.agent_id, id2);
    }

    #[test]
    fn test_relay_discovery_max_relays_eviction() {
        let mut discovery = RelayDiscovery::new().with_max_relays(2);

        let id1 = make_agent_id(1);
        let id2 = make_agent_id(2);
        let id3 = make_agent_id(3);

        let mut info1 = RelayNodeInfo::new(id1, "quic://1.2.3.4:4433".into());
        info1.update_health(true, Some(50));

        let mut info2 = RelayNodeInfo::new(id2, "quic://5.6.7.8:4433".into());
        info2.update_health(true, Some(100));

        discovery.add_relay(info1);
        discovery.add_relay(info2);
        assert_eq!(discovery.relay_count(), 2);

        // Adding a third should evict the worst existing relay (highest latency).
        // id2 has latency 100 > id1 latency 50, so id2 is evicted to make room.
        let info3 = RelayNodeInfo::new(id3, "quic://9.10.11.12:4433".into());
        discovery.add_relay(info3);
        assert_eq!(discovery.relay_count(), 2);
        // One of the original two should have been evicted to make room for id3.
        // id3 should be present (it was just added)
        assert!(discovery.get_relay(&id3).is_some());
        // Only 2 relays total, so one of id1/id2 was evicted
        let has_id1 = discovery.get_relay(&id1).is_some();
        let has_id2 = discovery.get_relay(&id2).is_some();
        assert!(has_id1 ^ has_id2, "exactly one of id1/id2 should remain");
        // id2 (higher latency) should have been evicted, id1 should remain
        assert!(has_id1, "id1 (lower latency) should remain");
        assert!(!has_id2, "id2 (higher latency) should have been evicted");
    }

    #[test]
    fn test_relay_discovery_bootstrap() {
        let mut discovery = RelayDiscovery::new();
        discovery.add_bootstrap_relay("quic://bootstrap1:4433".into());
        discovery.add_bootstrap_relays(vec![
            "quic://bootstrap2:4433".into(),
            "quic://bootstrap3:4433".into(),
        ]);
        assert_eq!(discovery.bootstrap_relays().len(), 3);
    }

    #[test]
    fn test_relay_discovery_needs_refresh() {
        let mut discovery = RelayDiscovery::new().with_refresh_interval(1);
        // Empty discovery needs refresh
        assert!(discovery.needs_refresh());

        let id = make_agent_id(1);
        let info = RelayNodeInfo::new(id, "quic://1.2.3.4:4433".into());
        discovery.add_relay(info);
        // Just added, doesn't need refresh
        assert!(!discovery.needs_refresh());
    }

    #[test]
    fn test_relay_discovery_healthy_relays() {
        let mut discovery = RelayDiscovery::new();

        let id1 = make_agent_id(1);
        let id2 = make_agent_id(2);

        let mut info1 = RelayNodeInfo::new(id1, "quic://1.2.3.4:4433".into());
        info1.update_health(true, None);

        let mut info2 = RelayNodeInfo::new(id2, "quic://5.6.7.8:4433".into());
        info2.update_health(false, None);

        discovery.add_relay(info1);
        discovery.add_relay(info2);

        let healthy = discovery.healthy_relays();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].agent_id, id1);
    }

    #[tokio::test]
    async fn test_relay_health_checker_success() {
        // Start a server
        let server =
            aafp_transport_quic::QuicTransport::new(aafp_transport_quic::QuicConfig::default())
                .expect("failed to create server transport");
        let addr = format!("quic://{}", server.local_addr().unwrap());

        let server_handle = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let (healthy, latency) = RelayHealthChecker::check(&addr, 5).await;
        assert!(healthy);
        assert!(latency.is_some());

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_relay_health_checker_failure() {
        let (healthy, latency) = RelayHealthChecker::check("quic://127.0.0.1:1", 2).await;
        assert!(!healthy);
        assert!(latency.is_none());
    }

    #[tokio::test]
    async fn test_discovery_service_add_and_check() {
        let service = RelayDiscoveryService::new();

        // Start a server
        let server =
            aafp_transport_quic::QuicTransport::new(aafp_transport_quic::QuicConfig::default())
                .expect("failed to create server transport");
        let addr = format!("quic://{}", server.local_addr().unwrap());

        let server_handle = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let id = make_agent_id(1);
        service.add_and_check(id, addr).await;

        let best = service.select_best_relay();
        assert!(best.is_some());
        assert!(best.unwrap().is_healthy());

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_discovery_service_select_best() {
        let service = RelayDiscoveryService::new();

        // Start two servers
        let server1 =
            aafp_transport_quic::QuicTransport::new(aafp_transport_quic::QuicConfig::default())
                .expect("failed to create server1");
        let addr1 = format!("quic://{}", server1.local_addr().unwrap());
        let server2 =
            aafp_transport_quic::QuicTransport::new(aafp_transport_quic::QuicConfig::default())
                .expect("failed to create server2");
        let addr2 = format!("quic://{}", server2.local_addr().unwrap());

        let s1_handle = tokio::spawn(async move {
            let _ = server1.accept().await;
        });
        let s2_handle = tokio::spawn(async move {
            let _ = server2.accept().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Add both relays
        service.add_and_check(make_agent_id(1), addr1).await;
        service.add_and_check(make_agent_id(2), addr2).await;

        // Select best — should return one of them
        let best = service.select_best_relay();
        assert!(best.is_some());

        s1_handle.abort();
        s2_handle.abort();
    }
}
