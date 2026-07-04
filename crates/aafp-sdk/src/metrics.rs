//! Agent metrics and health checking (Track S4).
//!
//! `AgentMetrics` provides lock-free atomic counters for monitoring agent
//! performance. `HealthStatus` provides a simple health check based on
//! connection count and error rate.

use serde::{Deserialize, Serialize};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Lock-free atomic metrics counters for an agent.
///
/// All fields use `AtomicU64` so they can be updated from any thread without
/// locking. Call `snapshot()` to get a consistent point-in-time view.
#[derive(Debug)]
pub struct AgentMetrics {
    /// Active connections (current count).
    pub connections_active: AtomicU64,
    /// Total connections ever established (cumulative).
    pub connections_total: AtomicU64,
    /// Total messages sent.
    pub messages_sent: AtomicU64,
    /// Total messages received.
    pub messages_received: AtomicU64,
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Handshakes completed successfully.
    pub handshakes_completed: AtomicU64,
    /// Handshakes that failed.
    pub handshakes_failed: AtomicU64,
    /// DHT records stored.
    pub dht_records: AtomicU64,
    /// Relay connections (active).
    pub relay_connections: AtomicU64,
    /// Messages that failed (send error, timeout, etc.).
    pub messages_failed: AtomicU64,
    /// Agent start time (for uptime calculation).
    pub start_time: Instant,
}

impl AgentMetrics {
    /// Create a new metrics counter set initialized to zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            connections_active: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            dht_records: AtomicU64::new(0),
            relay_connections: AtomicU64::new(0),
            messages_failed: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }

    /// Record a new connection established.
    pub fn record_connection(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closed.
    pub fn record_disconnect(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a message sent.
    pub fn record_sent(&self, bytes: u64) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a message received.
    pub fn record_received(&self, bytes: u64) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a message failure.
    pub fn record_message_failure(&self) {
        self.messages_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful handshake.
    pub fn record_handshake(&self) {
        self.handshakes_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed handshake.
    pub fn record_handshake_failure(&self) {
        self.handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a DHT record stored.
    pub fn record_dht_record(&self) {
        self.dht_records.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a relay connection.
    pub fn record_relay_connection(&self) {
        self.relay_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a relay disconnection.
    pub fn record_relay_disconnect(&self) {
        self.relay_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get uptime in seconds.
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Take a consistent snapshot of all metrics.
    ///
    /// Note: Due to the lock-free nature, the snapshot may not be perfectly
    /// consistent (counters may be read at slightly different times). This
    /// is acceptable for monitoring purposes.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_active: self.connections_active.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            handshakes_completed: self.handshakes_completed.load(Ordering::Relaxed),
            handshakes_failed: self.handshakes_failed.load(Ordering::Relaxed),
            dht_records: self.dht_records.load(Ordering::Relaxed),
            relay_connections: self.relay_connections.load(Ordering::Relaxed),
            messages_failed: self.messages_failed.load(Ordering::Relaxed),
            uptime_seconds: self.uptime_seconds(),
        }
    }
}

impl Default for AgentMetrics {
    fn default() -> Self {
        Self {
            connections_active: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            dht_records: AtomicU64::new(0),
            relay_connections: AtomicU64::new(0),
            messages_failed: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

/// A point-in-time snapshot of agent metrics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Active connections (current count).
    pub connections_active: u64,
    /// Total connections ever established (cumulative).
    pub connections_total: u64,
    /// Total messages sent.
    pub messages_sent: u64,
    /// Total messages received.
    pub messages_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Handshakes completed successfully.
    pub handshakes_completed: u64,
    /// Handshakes that failed.
    pub handshakes_failed: u64,
    /// DHT records stored.
    pub dht_records: u64,
    /// Relay connections (active).
    pub relay_connections: u64,
    /// Messages that failed.
    pub messages_failed: u64,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
}

impl MetricsSnapshot {
    /// Calculate the message error rate (0.0 to 1.0).
    pub fn error_rate(&self) -> f64 {
        let total = self.messages_sent + self.messages_received;
        if total == 0 {
            return 0.0;
        }
        self.messages_failed as f64 / total as f64
    }

    /// Calculate the handshake failure rate (0.0 to 1.0).
    pub fn handshake_failure_rate(&self) -> f64 {
        let total = self.handshakes_completed + self.handshakes_failed;
        if total == 0 {
            return 0.0;
        }
        self.handshakes_failed as f64 / total as f64
    }

    /// Serialize to CBOR (for RPC response).
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserialize from CBOR.
    pub fn from_cbor(data: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
        ciborium::from_reader(data)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Agent health status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems normal: has connections, low error rate.
    Healthy,
    /// Degraded: high error rate, or very few connections.
    Degraded,
    /// Unhealthy: no connections, or critical error rate.
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

impl HealthStatus {
    /// Determine health status from a metrics snapshot.
    ///
    /// Rules:
    /// - **Unhealthy**: No active connections AND uptime > 60s, OR error rate > 50%.
    /// - **Degraded**: Error rate > 10%, OR handshake failure rate > 30%,
    ///   OR fewer than 1 active connection with uptime > 60s.
    /// - **Healthy**: Everything else.
    pub fn from_metrics(snapshot: &MetricsSnapshot) -> Self {
        let error_rate = snapshot.error_rate();
        let handshake_failure_rate = snapshot.handshake_failure_rate();
        let has_connections = snapshot.connections_active > 0;
        let uptime_ok = snapshot.uptime_seconds > 60;

        // Unhealthy: no connections after warmup, or critical error rate
        if (!has_connections && uptime_ok) || error_rate > 0.5 {
            return Self::Unhealthy;
        }

        // Degraded: high error rate, or high handshake failure rate
        if error_rate > 0.1 || handshake_failure_rate > 0.3 {
            return Self::Degraded;
        }

        Self::Healthy
    }
}

/// Response for the `aafp.metrics` RPC method (Track S4).
///
/// Returns both the metrics snapshot and the health status in a single
/// response. Serialized as CBOR for wire transmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsRpcResponse {
    /// Current metrics snapshot.
    pub metrics: MetricsSnapshot,
    /// Current health status.
    pub health: HealthStatus,
    /// Agent ID (hex-encoded).
    pub agent_id: String,
}

impl MetricsRpcResponse {
    /// Create a metrics RPC response from an agent's metrics and ID.
    pub fn from_agent(metrics: &AgentMetrics, agent_id: &str) -> Self {
        let snapshot = metrics.snapshot();
        let health = HealthStatus::from_metrics(&snapshot);
        Self {
            metrics: snapshot,
            health,
            agent_id: agent_id.to_string(),
        }
    }

    /// Serialize to CBOR for RPC wire transmission.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_record_and_snapshot() {
        let metrics = AgentMetrics::new();
        metrics.record_connection();
        metrics.record_sent(1024);
        metrics.record_received(512);
        metrics.record_handshake();

        let snap = metrics.snapshot();
        assert_eq!(snap.connections_active, 1);
        assert_eq!(snap.connections_total, 1);
        assert_eq!(snap.messages_sent, 1);
        assert_eq!(snap.messages_received, 1);
        assert_eq!(snap.bytes_sent, 1024);
        assert_eq!(snap.bytes_received, 512);
        assert_eq!(snap.handshakes_completed, 1);
    }

    #[test]
    fn test_metrics_disconnect() {
        let metrics = AgentMetrics::new();
        metrics.record_connection();
        metrics.record_connection();
        metrics.record_disconnect();

        let snap = metrics.snapshot();
        assert_eq!(snap.connections_active, 1);
        assert_eq!(snap.connections_total, 2);
    }

    #[test]
    fn test_error_rate() {
        let snap = MetricsSnapshot {
            messages_sent: 100,
            messages_received: 95,
            messages_failed: 5,
            ..Default::default()
        };
        assert!((snap.error_rate() - 0.025).abs() < 0.001); // 5/200 = 2.5%
    }

    #[test]
    fn test_health_healthy() {
        let snap = MetricsSnapshot {
            connections_active: 5,
            messages_sent: 1000,
            messages_received: 995,
            messages_failed: 5,
            uptime_seconds: 120,
            ..Default::default()
        };
        assert_eq!(HealthStatus::from_metrics(&snap), HealthStatus::Healthy);
    }

    #[test]
    fn test_health_degraded_high_error() {
        let snap = MetricsSnapshot {
            connections_active: 5,
            messages_sent: 100,
            messages_received: 80,
            messages_failed: 15,
            uptime_seconds: 120,
            ..Default::default()
        };
        // error_rate = 15/180 = 8.3% — under 10%, still healthy
        assert_eq!(HealthStatus::from_metrics(&snap), HealthStatus::Healthy);

        let snap2 = MetricsSnapshot {
            connections_active: 5,
            messages_sent: 100,
            messages_received: 70,
            messages_failed: 20,
            uptime_seconds: 120,
            ..Default::default()
        };
        // error_rate = 20/170 = 11.8% — over 10%, degraded
        assert_eq!(HealthStatus::from_metrics(&snap2), HealthStatus::Degraded);
    }

    #[test]
    fn test_health_unhealthy_no_connections() {
        let snap = MetricsSnapshot {
            connections_active: 0,
            uptime_seconds: 120,
            ..Default::default()
        };
        assert_eq!(HealthStatus::from_metrics(&snap), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_unhealthy_critical_error() {
        let snap = MetricsSnapshot {
            connections_active: 5,
            messages_sent: 100,
            messages_received: 30,
            messages_failed: 60,
            uptime_seconds: 120,
            ..Default::default()
        };
        // error_rate = 60/130 = 46% — under 50%, degraded
        assert_eq!(HealthStatus::from_metrics(&snap), HealthStatus::Degraded);

        let snap2 = MetricsSnapshot {
            connections_active: 5,
            messages_sent: 100,
            messages_received: 10,
            messages_failed: 70,
            uptime_seconds: 120,
            ..Default::default()
        };
        // error_rate = 70/110 = 63.6% — over 50%, unhealthy
        assert_eq!(HealthStatus::from_metrics(&snap2), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_warmup_period() {
        // During warmup (uptime < 60s), no connections is OK
        let snap = MetricsSnapshot {
            connections_active: 0,
            uptime_seconds: 30,
            ..Default::default()
        };
        assert_eq!(HealthStatus::from_metrics(&snap), HealthStatus::Healthy);
    }

    #[test]
    fn test_health_degraded_handshake_failures() {
        let snap = MetricsSnapshot {
            connections_active: 5,
            handshakes_completed: 70,
            handshakes_failed: 35,
            uptime_seconds: 120,
            ..Default::default()
        };
        // handshake_failure_rate = 35/105 = 33% — over 30%, degraded
        assert_eq!(HealthStatus::from_metrics(&snap), HealthStatus::Degraded);
    }

    #[test]
    fn test_metrics_cbor_serialization() {
        let snap = MetricsSnapshot {
            connections_active: 5,
            messages_sent: 1000,
            messages_received: 995,
            bytes_sent: 1024000,
            bytes_received: 1018880,
            uptime_seconds: 3600,
            ..Default::default()
        };
        let cbor = snap.to_cbor().unwrap();
        assert!(!cbor.is_empty());

        // Deserialize back
        let decoded = MetricsSnapshot::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.connections_active, 5);
        assert_eq!(decoded.messages_sent, 1000);
        assert_eq!(decoded.uptime_seconds, 3600);
    }

    #[test]
    fn test_metrics_json_serialization() {
        let snap = MetricsSnapshot {
            connections_active: 3,
            messages_sent: 500,
            uptime_seconds: 1800,
            ..Default::default()
        };
        let json = snap.to_json().unwrap();
        assert!(json.contains("\"connections_active\": 3"));
        assert!(json.contains("\"messages_sent\": 500"));
    }
}
