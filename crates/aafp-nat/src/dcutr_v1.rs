//! DCuTR v1: Direct Connection Upgrade through Relay (RFC 0010 §7).
//!
//! After a relayed connection is established, peers attempt a direct
//! connection via simultaneous open (hole punching):
//!
//! 1. Both peers exchange observed addresses through the relay.
//! 2. Both peers initiate QUIC connections to each other simultaneously.
//! 3. If either connection succeeds, it replaces the relayed connection.
//! 4. If both fail, the relayed connection continues.
//!
//! DCuTR works for cone NAT types but not symmetric NAT.
//!
//! ## Wire Format
//!
//! DCuTR uses a control message exchanged over the relayed connection:
//!
//! ```cbor
//! { 1: tstr, 2: tstr }
//! ```
//! - key 1: `observed_addr` — the address this peer observes for the other
//! - key 2: `my_addr` — the address this peer wants to be dialed at

use aafp_cbor::{decode, encode, int_map, int_map_get, CborError, Value};
use aafp_transport_quic::{QuicConfig, QuicTransport};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Default hole punch timeout: 10 seconds (RFC 0010 §7).
pub const DEFAULT_HOLE_PUNCH_TIMEOUT_SECS: u64 = 10;

/// Default delay before simultaneous open: 100ms (to allow sync).
pub const DEFAULT_SYNC_DELAY_MS: u64 = 100;

/// NAT type classification (RFC 0010 §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatType {
    /// NAT type unknown.
    Unknown,
    /// No NAT — publicly reachable.
    NoNat,
    /// Cone NAT (full cone, restricted cone, port-restricted cone).
    /// Hole punching is likely to succeed.
    ConeNat,
    /// Symmetric NAT — hole punching is unlikely to succeed.
    SymmetricNat,
}

/// DCuTR errors.
#[derive(Debug, thiserror::Error)]
pub enum DcutrV1Error {
    /// CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    /// The hole punch attempt failed.
    #[error("hole punch failed: {0}")]
    HolePunchFailed(String),
    /// The peer does not support DCuTR.
    #[error("peer does not support DCuTR")]
    NotSupported,
    /// The connection is not relayed.
    #[error("not relayed, cannot upgrade")]
    NotRelayed,
    /// Timeout waiting for peer response.
    #[error("timeout: {0}")]
    Timeout(String),
}

/// DCuTR coordinate message: exchanged between peers via the relay.
#[derive(Clone, Debug)]
pub struct CoordinateMessage {
    /// The address this peer observes for the other peer.
    pub observed_addr: String,
    /// The address this peer wants to be dialed at.
    pub my_addr: String,
}

impl CoordinateMessage {
    /// Create a new coordinate message.
    pub fn new(observed_addr: String, my_addr: String) -> Self {
        Self {
            observed_addr,
            my_addr,
        }
    }

    /// Encode as CBOR.
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::TextString(self.observed_addr.clone())),
            (2, Value::TextString(self.my_addr.clone())),
        ])
    }

    /// Decode from CBOR.
    pub fn from_cbor(val: &Value) -> Result<Self, CborError> {
        let observed_addr = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => {
                return Err(CborError::Invalid {
                    offset: 0,
                    message: "missing observed_addr".into(),
                })
            }
        };
        let my_addr = match int_map_get(val, 2) {
            Some(Value::TextString(s)) => s.clone(),
            _ => {
                return Err(CborError::Invalid {
                    offset: 0,
                    message: "missing my_addr".into(),
                })
            }
        };
        Ok(Self {
            observed_addr,
            my_addr,
        })
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        encode(&self.to_cbor())
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, CborError> {
        let (val, _) = decode(data)?;
        Self::from_cbor(&val)
    }
}

/// Result of a hole punch attempt.
#[derive(Clone, Debug)]
pub struct HolePunchResult {
    /// Whether the hole punch succeeded.
    pub success: bool,
    /// The direct address if successful.
    pub direct_addr: Option<String>,
    /// Time taken for the attempt.
    pub elapsed: Duration,
    /// Error message if failed.
    pub error: Option<String>,
    /// NAT type detected.
    pub nat_type: NatType,
}

/// DCuTR v1 driver: coordinates hole punching attempts.
pub struct DcutrV1 {
    /// Whether DCuTR is enabled.
    enabled: bool,
    /// Hole punch timeout.
    timeout_secs: u64,
    /// Sync delay before simultaneous open.
    sync_delay_ms: u64,
    /// History of hole punch attempts.
    attempts: Vec<HolePunchResult>,
    /// Detected NAT type for each peer.
    peer_nat_types: std::collections::HashMap<String, NatType>,
}

impl DcutrV1 {
    /// Create a new DCuTR v1 driver.
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_secs: DEFAULT_HOLE_PUNCH_TIMEOUT_SECS,
            sync_delay_ms: DEFAULT_SYNC_DELAY_MS,
            attempts: Vec::new(),
            peer_nat_types: std::collections::HashMap::new(),
        }
    }

    /// Set the hole punch timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set the sync delay.
    pub fn with_sync_delay(mut self, ms: u64) -> Self {
        self.sync_delay_ms = ms;
        self
    }

    /// Check if DCuTR is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable DCuTR.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the hole punch timeout.
    pub fn timeout(&self) -> u64 {
        self.timeout_secs
    }

    /// Get the sync delay in milliseconds.
    pub fn sync_delay(&self) -> u64 {
        self.sync_delay_ms
    }

    /// Get all attempts.
    pub fn attempts(&self) -> &[HolePunchResult] {
        &self.attempts
    }

    /// Get successful upgrades.
    pub fn successful_upgrades(&self) -> Vec<&HolePunchResult> {
        self.attempts.iter().filter(|a| a.success).collect()
    }

    /// Get the success rate.
    pub fn success_rate(&self) -> f64 {
        if self.attempts.is_empty() {
            return 0.0;
        }
        let successes = self.attempts.iter().filter(|a| a.success).count();
        successes as f64 / self.attempts.len() as f64
    }

    /// Record a hole punch attempt.
    pub fn record_attempt(&mut self, result: HolePunchResult) {
        self.attempts.push(result);
        // Keep only last 50 attempts.
        if self.attempts.len() > 50 {
            self.attempts.remove(0);
        }
    }

    /// Record the detected NAT type for a peer.
    pub fn record_nat_type(&mut self, peer_addr: String, nat_type: NatType) {
        self.peer_nat_types.insert(peer_addr, nat_type);
    }

    /// Get the NAT type for a peer.
    pub fn nat_type_for(&self, peer_addr: &str) -> Option<&NatType> {
        self.peer_nat_types.get(peer_addr)
    }

    /// Classify NAT type based on observed addresses.
    ///
    /// If the peer's observed address changes across multiple observations,
    /// it's likely a symmetric NAT. If it's consistent, it's likely cone NAT.
    pub fn classify_nat_type(observations: &[String]) -> NatType {
        if observations.is_empty() {
            return NatType::Unknown;
        }
        let first = &observations[0];
        if observations.iter().all(|a| a == first) {
            NatType::ConeNat
        } else {
            NatType::SymmetricNat
        }
    }

    /// Attempt a hole punch: simultaneously dial the peer's address.
    ///
    /// This creates a temporary QUIC transport and attempts to connect
    /// to the peer's advertised address. The peer should be doing the
    /// same thing at the same time.
    pub async fn attempt_hole_punch(&mut self, peer_addr: &str) -> HolePunchResult {
        let start = Instant::now();
        let timeout = Duration::from_secs(self.timeout_secs);

        // Create a temporary transport for the hole punch
        let config = QuicConfig::default();
        let transport = match QuicTransport::new(config) {
            Ok(t) => t,
            Err(e) => {
                let result = HolePunchResult {
                    success: false,
                    direct_addr: None,
                    elapsed: start.elapsed(),
                    error: Some(format!("failed to create transport: {}", e)),
                    nat_type: NatType::Unknown,
                };
                self.record_attempt(result.clone());
                return result;
            }
        };

        // Wait for sync delay to align with peer's simultaneous open
        tokio::time::sleep(Duration::from_millis(self.sync_delay_ms)).await;

        // Attempt to dial with timeout
        let dial_result = tokio::time::timeout(timeout, transport.dial(peer_addr)).await;

        let result = match dial_result {
            Ok(Ok(conn)) => {
                let direct_addr = format!("quic://{}", conn.remote_address());
                info!("Hole punch to {} succeeded", peer_addr);
                HolePunchResult {
                    success: true,
                    direct_addr: Some(direct_addr),
                    elapsed: start.elapsed(),
                    error: None,
                    nat_type: NatType::ConeNat,
                }
            }
            Ok(Err(e)) => {
                warn!("Hole punch to {} failed: {}", peer_addr, e);
                HolePunchResult {
                    success: false,
                    direct_addr: None,
                    elapsed: start.elapsed(),
                    error: Some(e.to_string()),
                    nat_type: NatType::Unknown,
                }
            }
            Err(_) => {
                warn!("Hole punch to {} timed out", peer_addr);
                HolePunchResult {
                    success: false,
                    direct_addr: None,
                    elapsed: start.elapsed(),
                    error: Some("hole punch timed out".into()),
                    nat_type: NatType::Unknown,
                }
            }
        };

        self.record_attempt(result.clone());
        result
    }
}

impl Default for DcutrV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Attempt a hole punch with explicit config (standalone, no driver state).
///
/// Creates a temporary QUIC transport and attempts to connect to the peer's
/// advertised address with the given timeout and sync delay.
pub async fn attempt_hole_punch_with_config(
    peer_addr: &str,
    timeout_secs: u64,
    sync_delay_ms: u64,
) -> HolePunchResult {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    // Create a temporary transport for the hole punch
    let config = QuicConfig::default();
    let transport = match QuicTransport::new(config) {
        Ok(t) => t,
        Err(e) => {
            return HolePunchResult {
                success: false,
                direct_addr: None,
                elapsed: start.elapsed(),
                error: Some(format!("failed to create transport: {}", e)),
                nat_type: NatType::Unknown,
            }
        }
    };

    // Wait for sync delay to align with peer's simultaneous open
    tokio::time::sleep(Duration::from_millis(sync_delay_ms)).await;

    // Attempt to dial with timeout
    let dial_result = tokio::time::timeout(timeout, transport.dial(peer_addr)).await;

    match dial_result {
        Ok(Ok(conn)) => {
            let direct_addr = format!("quic://{}", conn.remote_address());
            info!("Hole punch to {} succeeded", peer_addr);
            HolePunchResult {
                success: true,
                direct_addr: Some(direct_addr),
                elapsed: start.elapsed(),
                error: None,
                nat_type: NatType::ConeNat,
            }
        }
        Ok(Err(e)) => {
            warn!("Hole punch to {} failed: {}", peer_addr, e);
            HolePunchResult {
                success: false,
                direct_addr: None,
                elapsed: start.elapsed(),
                error: Some(e.to_string()),
                nat_type: NatType::Unknown,
            }
        }
        Err(_) => {
            warn!("Hole punch to {} timed out", peer_addr);
            HolePunchResult {
                success: false,
                direct_addr: None,
                elapsed: start.elapsed(),
                error: Some("hole punch timed out".into()),
                nat_type: NatType::Unknown,
            }
        }
    }
}

/// DCuTR coordinator: manages the full hole punching protocol.
///
/// This is used by both peers to coordinate the simultaneous open.
/// Each peer:
/// 1. Sends a CoordinateMessage to the other peer (via relay)
/// 2. Receives the peer's CoordinateMessage
/// 3. Attempts to dial the peer's advertised address
/// 4. Reports the result
pub struct DcutrCoordinator {
    /// The DCuTR driver.
    driver: Arc<Mutex<DcutrV1>>,
    /// This peer's advertised address.
    my_addr: String,
}

impl DcutrCoordinator {
    /// Create a new DCuTR coordinator.
    pub fn new(my_addr: String) -> Self {
        Self {
            driver: Arc::new(Mutex::new(DcutrV1::new())),
            my_addr,
        }
    }

    /// Create a new DCuTR coordinator with a custom timeout.
    pub fn with_timeout(my_addr: String, timeout_secs: u64) -> Self {
        let driver = DcutrV1::new().with_timeout(timeout_secs);
        Self {
            driver: Arc::new(Mutex::new(driver)),
            my_addr,
        }
    }

    /// Get this peer's advertised address.
    pub fn my_addr(&self) -> &str {
        &self.my_addr
    }

    /// Get a reference to the driver.
    pub fn driver(&self) -> &Arc<Mutex<DcutrV1>> {
        &self.driver
    }

    /// Create a coordinate message to send to the peer.
    ///
    /// `peer_observed_addr` is the address we observe for the peer
    /// (from the relayed connection's remote address).
    pub fn create_coordinate_message(&self, peer_observed_addr: String) -> CoordinateMessage {
        CoordinateMessage::new(peer_observed_addr, self.my_addr.clone())
    }

    /// Process the peer's coordinate message and attempt hole punch.
    ///
    /// Returns the result of the hole punch attempt.
    pub async fn handle_coordinate_message(&self, msg: &CoordinateMessage) -> HolePunchResult {
        // Extract the config we need without holding the lock across .await
        let (timeout_secs, sync_delay_ms) = {
            let driver = self.driver.lock().unwrap();
            (driver.timeout(), driver.sync_delay())
        };

        // Attempt hole punch without holding the lock
        let result =
            attempt_hole_punch_with_config(&msg.my_addr, timeout_secs, sync_delay_ms).await;

        // Record the attempt (short lock)
        self.driver.lock().unwrap().record_attempt(result.clone());
        result
    }

    /// Run the full DCuTR protocol: send coordinate, receive coordinate,
    /// attempt hole punch.
    ///
    /// This is a convenience method that handles the full protocol.
    /// In practice, the coordinate messages would be exchanged over the
    /// relayed connection.
    pub async fn run_hole_punch(
        &self,
        peer_observed_addr: String,
        peer_coordinate: &CoordinateMessage,
    ) -> HolePunchResult {
        // Create our coordinate message
        let _my_msg = self.create_coordinate_message(peer_observed_addr);

        // Process the peer's coordinate message and attempt hole punch
        self.handle_coordinate_message(peer_coordinate).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_transport_quic::{QuicConfig, QuicTransport};

    #[test]
    fn test_coordinate_message_roundtrip() {
        let msg = CoordinateMessage::new("1.2.3.4:4433".into(), "5.6.7.8:4433".into());
        let encoded = msg.encode().unwrap();
        let decoded = CoordinateMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.observed_addr, "1.2.3.4:4433");
        assert_eq!(decoded.my_addr, "5.6.7.8:4433");
    }

    #[test]
    fn test_coordinate_message_cbor() {
        let msg = CoordinateMessage::new("1.2.3.4:4433".into(), "5.6.7.8:4433".into());
        let cbor = msg.to_cbor();
        let decoded = CoordinateMessage::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.observed_addr, "1.2.3.4:4433");
        assert_eq!(decoded.my_addr, "5.6.7.8:4433");
    }

    #[test]
    fn test_classify_nat_type_cone() {
        let observations = vec![
            "1.2.3.4:4433".to_string(),
            "1.2.3.4:4433".to_string(),
            "1.2.3.4:4433".to_string(),
        ];
        assert_eq!(DcutrV1::classify_nat_type(&observations), NatType::ConeNat);
    }

    #[test]
    fn test_classify_nat_type_symmetric() {
        let observations = vec![
            "1.2.3.4:4433".to_string(),
            "1.2.3.4:4434".to_string(),
            "1.2.3.4:4435".to_string(),
        ];
        assert_eq!(
            DcutrV1::classify_nat_type(&observations),
            NatType::SymmetricNat
        );
    }

    #[test]
    fn test_classify_nat_type_empty() {
        assert_eq!(DcutrV1::classify_nat_type(&[]), NatType::Unknown);
    }

    #[test]
    fn test_dcutr_record_attempt() {
        let mut dcutr = DcutrV1::new();
        dcutr.record_attempt(HolePunchResult {
            success: true,
            direct_addr: Some("quic://1.2.3.4:4433".into()),
            elapsed: Duration::from_millis(100),
            error: None,
            nat_type: NatType::ConeNat,
        });
        dcutr.record_attempt(HolePunchResult {
            success: false,
            direct_addr: None,
            elapsed: Duration::from_millis(200),
            error: Some("timeout".into()),
            nat_type: NatType::Unknown,
        });
        assert_eq!(dcutr.attempts().len(), 2);
        assert_eq!(dcutr.successful_upgrades().len(), 1);
        assert_eq!(dcutr.success_rate(), 0.5);
    }

    #[test]
    fn test_dcutr_enable_disable() {
        let mut dcutr = DcutrV1::new();
        assert!(dcutr.is_enabled());
        dcutr.set_enabled(false);
        assert!(!dcutr.is_enabled());
    }

    #[test]
    fn test_dcutr_record_nat_type() {
        let mut dcutr = DcutrV1::new();
        dcutr.record_nat_type("1.2.3.4:4433".into(), NatType::ConeNat);
        dcutr.record_nat_type("5.6.7.8:4433".into(), NatType::SymmetricNat);
        assert_eq!(dcutr.nat_type_for("1.2.3.4:4433"), Some(&NatType::ConeNat));
        assert_eq!(
            dcutr.nat_type_for("5.6.7.8:4433"),
            Some(&NatType::SymmetricNat)
        );
    }

    #[test]
    fn test_dcutr_max_attempts_history() {
        let mut dcutr = DcutrV1::new();
        for _ in 0..60 {
            dcutr.record_attempt(HolePunchResult {
                success: false,
                direct_addr: None,
                elapsed: Duration::from_millis(100),
                error: None,
                nat_type: NatType::Unknown,
            });
        }
        // Should be capped at 50
        assert_eq!(dcutr.attempts().len(), 50);
    }

    #[tokio::test]
    async fn test_hole_punch_success() {
        // Start a server that will be the "peer" we're hole punching to
        let server =
            QuicTransport::new(QuicConfig::default()).expect("failed to create server transport");
        let server_addr = format!("quic://{}", server.local_addr().unwrap());

        let server_handle = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Attempt hole punch
        let mut dcutr = DcutrV1::new().with_sync_delay(10);
        let result = dcutr.attempt_hole_punch(&server_addr).await;

        assert!(result.success);
        assert!(result.direct_addr.is_some());

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_hole_punch_failure_unreachable() {
        let mut dcutr = DcutrV1::new().with_timeout(2).with_sync_delay(10);
        let result = dcutr.attempt_hole_punch("quic://127.0.0.1:1").await;

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_coordinator_create_message() {
        let coord = DcutrCoordinator::new("quic://1.2.3.4:4433".into());
        let msg = coord.create_coordinate_message("5.6.7.8:4433".into());
        assert_eq!(msg.observed_addr, "5.6.7.8:4433");
        assert_eq!(msg.my_addr, "quic://1.2.3.4:4433");
    }

    #[tokio::test]
    async fn test_coordinator_full_protocol() {
        // Start a server (the "peer")
        let server =
            QuicTransport::new(QuicConfig::default()).expect("failed to create server transport");
        let server_addr = format!("quic://{}", server.local_addr().unwrap());

        let server_handle = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Create coordinator for "us"
        let coord = DcutrCoordinator::with_timeout("quic://0.0.0.0:0".into(), 5);

        // Simulate receiving the peer's coordinate message
        let peer_msg = CoordinateMessage::new("0.0.0.0:0".into(), server_addr.clone());

        // Run hole punch
        let result = coord.run_hole_punch("0.0.0.0:0".into(), &peer_msg).await;

        assert!(result.success);
        assert!(result.direct_addr.is_some());

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_hole_punch_timeout() {
        let mut dcutr = DcutrV1::new().with_timeout(1).with_sync_delay(10);
        // Use a black-hole address
        let result = dcutr.attempt_hole_punch("quic://10.255.255.1:4433").await;

        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
