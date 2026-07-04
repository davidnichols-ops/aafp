//! AutoNAT v1: automatic NAT detection via dial-back (RFC 0010 §6).
//!
//! An agent that wants to know if it's behind NAT asks peers to dial
//! its advertised address back. If peers can reach it, it's public.
//! If not, it's behind NAT and needs a relay.
//!
//! ## RPC Methods
//!
//! - `aafp.autonat.dialback_request`: Agent sends its advertised address
//!   to a peer. The peer attempts to dial it and reports success/failure.
//! - `aafp.autonat.observe`: Agent asks a peer to report the observed
//!   address (the remote address the peer sees for the agent).

use aafp_cbor::{encode, int_map, int_map_get, CborError, Value};
use aafp_transport_quic::{QuicConfig, QuicTransport};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{info, warn};

/// RPC method: request a dial-back check (RFC 0010 §6.2).
pub const METHOD_DIALBACK_REQUEST: &str = "aafp.autonat.dialback_request";

/// RPC method: report observed address (RFC 0010 §6.3).
pub const METHOD_OBSERVE: &str = "aafp.autonat.observe";

/// Default dial-back timeout: 5 seconds (RFC 0010 §6.4).
pub const DEFAULT_DIALBACK_TIMEOUT_SECS: u64 = 5;

/// Default threshold for confirming NAT status: 2 successful or failed dial-backs.
pub const DEFAULT_CONFIRMATION_THRESHOLD: usize = 2;

/// NAT status (RFC 0010 §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatStatus {
    /// NAT status has not yet been determined.
    Unknown,
    /// The agent is not behind NAT (publicly reachable).
    Public,
    /// The agent is behind NAT and needs a relay.
    Private,
}

/// Dial-back result from a peer.
#[derive(Clone, Debug)]
pub struct DialBackResult {
    /// Whether the dial-back succeeded.
    pub success: bool,
    /// Error message if the dial-back failed.
    pub error: Option<String>,
    /// The observed address (if successful).
    pub observed_addr: Option<String>,
}

/// Observed address entry: tracks how many times an address was observed.
#[derive(Clone, Debug)]
struct ObservedAddress {
    /// The observed address string.
    addr: String,
    /// Number of times this address was observed.
    count: usize,
    /// When this was last observed.
    last_seen: Instant,
}

/// AutoNAT v1: automatic NAT detection via dial-back (RFC 0010 §6).
pub struct AutoNatV1DialBack {
    /// Current NAT status.
    status: NatStatus,
    /// Number of successful dial-backs.
    successful_dialbacks: usize,
    /// Number of failed dial-backs.
    failed_dialbacks: usize,
    /// Threshold for confirming NAT status.
    confirmation_threshold: usize,
    /// Dial-back timeout in seconds.
    dialback_timeout_secs: u64,
    /// Observed addresses: addr → entry.
    observed_addresses: HashMap<String, ObservedAddress>,
    /// The agent's local address (for comparison).
    local_addr: Option<String>,
}

impl AutoNatV1DialBack {
    /// Create a new AutoNAT dial-back instance.
    pub fn new() -> Self {
        Self {
            status: NatStatus::Unknown,
            successful_dialbacks: 0,
            failed_dialbacks: 0,
            confirmation_threshold: DEFAULT_CONFIRMATION_THRESHOLD,
            dialback_timeout_secs: DEFAULT_DIALBACK_TIMEOUT_SECS,
            observed_addresses: HashMap::new(),
            local_addr: None,
        }
    }

    /// Set the confirmation threshold.
    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.confirmation_threshold = threshold;
        self
    }

    /// Set the dial-back timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.dialback_timeout_secs = timeout_secs;
        self
    }

    /// Set the local address.
    pub fn with_local_addr(mut self, addr: String) -> Self {
        self.local_addr = Some(addr);
        self
    }

    /// Get the current NAT status.
    pub fn status(&self) -> &NatStatus {
        &self.status
    }

    /// Check if behind NAT.
    pub fn is_behind_nat(&self) -> bool {
        self.status == NatStatus::Private
    }

    /// Check if publicly reachable.
    pub fn is_public(&self) -> bool {
        self.status == NatStatus::Public
    }

    /// Record a dial-back result from a peer.
    ///
    /// Updates the NAT status based on the result:
    /// - `threshold` successful dial-backs → Public
    /// - `threshold` failed dial-backs → Private
    pub fn record_dialback(&mut self, result: &DialBackResult) {
        if result.success {
            self.successful_dialbacks += 1;
            if let Some(ref addr) = result.observed_addr {
                self.record_observed(addr.clone());
            }
        } else {
            self.failed_dialbacks += 1;
        }

        // Update status
        if self.successful_dialbacks >= self.confirmation_threshold {
            self.status = NatStatus::Public;
        } else if self.failed_dialbacks >= self.confirmation_threshold {
            self.status = NatStatus::Private;
        }
    }

    /// Record an observed address from a peer.
    pub fn record_observed(&mut self, addr: String) {
        let entry = self
            .observed_addresses
            .entry(addr.clone())
            .or_insert(ObservedAddress {
                addr: addr.clone(),
                count: 0,
                last_seen: Instant::now(),
            });
        entry.count += 1;
        entry.last_seen = Instant::now();
    }

    /// Get the best observed address (most commonly reported).
    pub fn best_observed_address(&self) -> Option<&str> {
        self.observed_addresses
            .values()
            .max_by_key(|e| e.count)
            .map(|e| e.addr.as_str())
    }

    /// Get all observed addresses.
    pub fn observed_addresses(&self) -> Vec<&str> {
        self.observed_addresses
            .values()
            .map(|e| e.addr.as_str())
            .collect()
    }

    /// Get the number of successful dial-backs.
    pub fn successful_dialbacks(&self) -> usize {
        self.successful_dialbacks
    }

    /// Get the number of failed dial-backs.
    pub fn failed_dialbacks(&self) -> usize {
        self.failed_dialbacks
    }

    /// Reset all dial-back counters (e.g., to re-check NAT status).
    pub fn reset(&mut self) {
        self.status = NatStatus::Unknown;
        self.successful_dialbacks = 0;
        self.failed_dialbacks = 0;
    }

    /// Get the dial-back timeout in seconds.
    pub fn dialback_timeout(&self) -> u64 {
        self.dialback_timeout_secs
    }
}

impl Default for AutoNatV1DialBack {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a dial-back request (RFC 0010 §6.2).
///
/// ```cbor
/// { 1: tstr }  // advertised_addr: the address to dial back
/// ```
pub fn encode_dialback_request(advertised_addr: &str) -> Result<Vec<u8>, CborError> {
    let val = int_map(vec![(1, Value::TextString(advertised_addr.to_string()))]);
    encode(&val)
}

/// Decode a dial-back request.
pub fn decode_dialback_request(data: &[u8]) -> Result<String, CborError> {
    let (val, _) = aafp_cbor::decode(data)?;
    let addr = match int_map_get(&val, 1) {
        Some(Value::TextString(s)) => s.clone(),
        _ => {
            return Err(CborError::Invalid {
                offset: 0,
                message: "missing advertised_addr".into(),
            })
        }
    };
    Ok(addr)
}

/// Encode a dial-back response (RFC 0010 §6.2).
///
/// ```cbor
/// { 1: bool, 2: tstr?, 3: tstr? }
/// ```
pub fn encode_dialback_response(result: &DialBackResult) -> Result<Vec<u8>, CborError> {
    let mut entries = vec![(1, Value::Bool(result.success))];
    if let Some(ref err) = result.error {
        entries.push((2, Value::TextString(err.clone())));
    }
    if let Some(ref addr) = result.observed_addr {
        entries.push((3, Value::TextString(addr.clone())));
    }
    encode(&int_map(entries))
}

/// Decode a dial-back response.
pub fn decode_dialback_response(data: &[u8]) -> Result<DialBackResult, CborError> {
    let (val, _) = aafp_cbor::decode(data)?;
    let success = match int_map_get(&val, 1) {
        Some(Value::Bool(b)) => *b,
        _ => {
            return Err(CborError::Invalid {
                offset: 0,
                message: "missing success".into(),
            })
        }
    };
    let error = match int_map_get(&val, 2) {
        Some(Value::TextString(s)) => Some(s.clone()),
        _ => None,
    };
    let observed_addr = match int_map_get(&val, 3) {
        Some(Value::TextString(s)) => Some(s.clone()),
        _ => None,
    };
    Ok(DialBackResult {
        success,
        error,
        observed_addr,
    })
}

/// Encode an observe request (RFC 0010 §6.3).
pub fn encode_observe_request() -> Result<Vec<u8>, CborError> {
    encode(&int_map(vec![]))
}

/// Encode an observe response with the observed address.
pub fn encode_observe_response(observed_addr: &str) -> Result<Vec<u8>, CborError> {
    encode(&int_map(vec![(
        1,
        Value::TextString(observed_addr.to_string()),
    )]))
}

/// Decode an observe response.
pub fn decode_observe_response(data: &[u8]) -> Result<String, CborError> {
    let (val, _) = aafp_cbor::decode(data)?;
    match int_map_get(&val, 1) {
        Some(Value::TextString(s)) => Ok(s.clone()),
        _ => Err(CborError::Invalid {
            offset: 0,
            message: "missing observed_addr".into(),
        }),
    }
}

/// Perform a dial-back check: attempt to dial the advertised address.
///
/// This is called by the peer that received a dial-back request.
/// It tries to connect to the advertised address and reports the result.
pub async fn perform_dialback(advertised_addr: &str, timeout_secs: u64) -> DialBackResult {
    // Create a temporary QUIC transport for the dial-back
    let config = QuicConfig::default();
    let transport = match QuicTransport::new(config) {
        Ok(t) => t,
        Err(e) => {
            return DialBackResult {
                success: false,
                error: Some(format!("failed to create transport: {}", e)),
                observed_addr: None,
            }
        }
    };

    // Attempt to dial with timeout
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let dial_result = tokio::time::timeout(timeout, transport.dial(advertised_addr)).await;

    match dial_result {
        Ok(Ok(conn)) => {
            let observed = conn.remote_address().to_string();
            info!(
                "Dial-back to {} succeeded (observed: {})",
                advertised_addr, observed
            );
            DialBackResult {
                success: true,
                error: None,
                observed_addr: Some(observed),
            }
        }
        Ok(Err(e)) => {
            warn!("Dial-back to {} failed: {}", advertised_addr, e);
            DialBackResult {
                success: false,
                error: Some(e.to_string()),
                observed_addr: None,
            }
        }
        Err(_) => {
            warn!(
                "Dial-back to {} timed out after {}s",
                advertised_addr, timeout_secs
            );
            DialBackResult {
                success: false,
                error: Some("dial-back timed out".into()),
                observed_addr: None,
            }
        }
    }
}

/// Handle a dial-back request on the peer side.
///
/// The peer receives the advertised address, attempts to dial it,
/// and returns the result.
pub async fn handle_dialback_request(
    params: &[u8],
    timeout_secs: u64,
) -> Result<Vec<u8>, CborError> {
    let advertised_addr = decode_dialback_request(params)?;
    let result = perform_dialback(&advertised_addr, timeout_secs).await;
    encode_dialback_response(&result)
}

/// Handle an observe request on the peer side.
///
/// The peer reports the remote address it sees for the requesting agent.
pub fn handle_observe_request(remote_addr: &str) -> Result<Vec<u8>, CborError> {
    encode_observe_response(remote_addr)
}

/// AutoNAT client: orchestrates dial-back checks to determine NAT status.
pub struct AutoNatClient {
    /// The AutoNAT state.
    state: Arc<Mutex<AutoNatV1DialBack>>,
    /// The agent's advertised address.
    advertised_addr: Option<String>,
}

impl AutoNatClient {
    /// Create a new AutoNAT client.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AutoNatV1DialBack::new())),
            advertised_addr: None,
        }
    }

    /// Set the advertised address.
    pub fn with_advertised_addr(mut self, addr: String) -> Self {
        self.advertised_addr = Some(addr);
        self
    }

    /// Get the current NAT status.
    pub fn status(&self) -> NatStatus {
        self.state.lock().unwrap().status().clone()
    }

    /// Get a reference to the state (for recording results).
    pub fn state(&self) -> &Arc<Mutex<AutoNatV1DialBack>> {
        &self.state
    }

    /// Get the advertised address.
    pub fn advertised_addr(&self) -> Option<&str> {
        self.advertised_addr.as_deref()
    }

    /// Encode a dial-back request to send to a peer.
    pub fn encode_request(&self) -> Result<Vec<u8>, CborError> {
        let addr = self.advertised_addr.as_ref().ok_or(CborError::Invalid {
            offset: 0,
            message: "no advertised address set".into(),
        })?;
        encode_dialback_request(addr)
    }

    /// Process a dial-back response from a peer.
    pub fn process_response(&self, data: &[u8]) -> Result<(), CborError> {
        let result = decode_dialback_response(data)?;
        self.state.lock().unwrap().record_dialback(&result);
        Ok(())
    }
}

impl Default for AutoNatClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_transport_quic::{QuicConfig, QuicTransport};

    #[test]
    fn test_dialback_request_roundtrip() {
        let encoded = encode_dialback_request("quic://127.0.0.1:4433").unwrap();
        let decoded = decode_dialback_request(&encoded).unwrap();
        assert_eq!(decoded, "quic://127.0.0.1:4433");
    }

    #[test]
    fn test_dialback_response_success_roundtrip() {
        let result = DialBackResult {
            success: true,
            error: None,
            observed_addr: Some("127.0.0.1:4433".into()),
        };
        let encoded = encode_dialback_response(&result).unwrap();
        let decoded = decode_dialback_response(&encoded).unwrap();
        assert!(decoded.success);
        assert!(decoded.error.is_none());
        assert_eq!(decoded.observed_addr, Some("127.0.0.1:4433".into()));
    }

    #[test]
    fn test_dialback_response_failure_roundtrip() {
        let result = DialBackResult {
            success: false,
            error: Some("connection refused".into()),
            observed_addr: None,
        };
        let encoded = encode_dialback_response(&result).unwrap();
        let decoded = decode_dialback_response(&encoded).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.error, Some("connection refused".into()));
        assert!(decoded.observed_addr.is_none());
    }

    #[test]
    fn test_observe_response_roundtrip() {
        let encoded = encode_observe_response("203.0.113.1:4433").unwrap();
        let decoded = decode_observe_response(&encoded).unwrap();
        assert_eq!(decoded, "203.0.113.1:4433");
    }

    #[test]
    fn test_autonat_status_transitions() {
        let mut autonat = AutoNatV1DialBack::new();
        assert_eq!(autonat.status(), &NatStatus::Unknown);

        // 1 success → still unknown (threshold = 2)
        autonat.record_dialback(&DialBackResult {
            success: true,
            error: None,
            observed_addr: Some("1.2.3.4:4433".into()),
        });
        assert_eq!(autonat.status(), &NatStatus::Unknown);

        // 2 successes → Public
        autonat.record_dialback(&DialBackResult {
            success: true,
            error: None,
            observed_addr: Some("1.2.3.4:4433".into()),
        });
        assert_eq!(autonat.status(), &NatStatus::Public);
        assert!(autonat.is_public());
    }

    #[test]
    fn test_autonat_detects_private() {
        let mut autonat = AutoNatV1DialBack::new();

        // 2 failures → Private
        autonat.record_dialback(&DialBackResult {
            success: false,
            error: Some("refused".into()),
            observed_addr: None,
        });
        assert_eq!(autonat.status(), &NatStatus::Unknown);

        autonat.record_dialback(&DialBackResult {
            success: false,
            error: Some("refused".into()),
            observed_addr: None,
        });
        assert_eq!(autonat.status(), &NatStatus::Private);
        assert!(autonat.is_behind_nat());
    }

    #[test]
    fn test_autonat_reset() {
        let mut autonat = AutoNatV1DialBack::new();
        autonat.record_dialback(&DialBackResult {
            success: true,
            error: None,
            observed_addr: None,
        });
        autonat.record_dialback(&DialBackResult {
            success: true,
            error: None,
            observed_addr: None,
        });
        assert_eq!(autonat.status(), &NatStatus::Public);

        autonat.reset();
        assert_eq!(autonat.status(), &NatStatus::Unknown);
        assert_eq!(autonat.successful_dialbacks(), 0);
    }

    #[test]
    fn test_best_observed_address() {
        let mut autonat = AutoNatV1DialBack::new();

        autonat.record_observed("1.2.3.4:4433".into());
        autonat.record_observed("1.2.3.4:4433".into());
        autonat.record_observed("5.6.7.8:4433".into());

        assert_eq!(autonat.best_observed_address(), Some("1.2.3.4:4433"));
    }

    #[test]
    fn test_autonat_client_encode_request() {
        let client = AutoNatClient::new().with_advertised_addr("quic://1.2.3.4:4433".into());
        let encoded = client.encode_request().unwrap();
        let decoded = decode_dialback_request(&encoded).unwrap();
        assert_eq!(decoded, "quic://1.2.3.4:4433");
    }

    #[test]
    fn test_autonat_client_process_response() {
        let client = AutoNatClient::new();
        let result = DialBackResult {
            success: true,
            error: None,
            observed_addr: Some("1.2.3.4:4433".into()),
        };
        let encoded = encode_dialback_response(&result).unwrap();
        client.process_response(&encoded).unwrap();
        assert_eq!(client.status(), NatStatus::Unknown); // Only 1 success
    }

    #[tokio::test]
    async fn test_dialback_success_real_connection() {
        // Start a server
        let server =
            QuicTransport::new(QuicConfig::default()).expect("failed to create server transport");
        let server_addr = format!("quic://{}", server.local_addr().unwrap());

        // Spawn server accept loop (just accept and close)
        let server_handle = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Perform dial-back
        let result = perform_dialback(&server_addr, 5).await;
        assert!(result.success);
        assert!(result.observed_addr.is_some());

        // Clean up
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_dialback_failure_unreachable() {
        // Dial an unreachable address (port 1 is privileged, should fail)
        let result = perform_dialback("quic://127.0.0.1:1", 2).await;
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_dialback_timeout() {
        // Dial a non-existent address with a short timeout
        // Using a port that's likely to cause a timeout (black hole)
        let result = perform_dialback("quic://10.255.255.1:4433", 1).await;
        assert!(!result.success);
        // Could be either timeout or connection refused
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_handle_dialback_request() {
        // Start a server
        let server =
            QuicTransport::new(QuicConfig::default()).expect("failed to create server transport");
        let server_addr = format!("quic://{}", server.local_addr().unwrap());

        let server_handle = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Handle a dial-back request for the server's address
        let request = encode_dialback_request(&server_addr).unwrap();
        let response = handle_dialback_request(&request, 5).await.unwrap();
        let result = decode_dialback_response(&response).unwrap();
        assert!(result.success);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_full_autonat_dialback_flow() {
        // Full flow: agent advertises its address, peer dials back, agent
        // processes the response and updates its NAT status.

        // Start a server (the agent that wants to know its NAT status)
        let server =
            QuicTransport::new(QuicConfig::default()).expect("failed to create server transport");
        let server_addr = format!("quic://{}", server.local_addr().unwrap());

        let server_handle = tokio::spawn(async move {
            // Accept a few connections for dial-back checks
            for _ in 0..2 {
                let _ = server.accept().await;
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Agent creates AutoNAT client with its advertised address
        let client = AutoNatClient::new().with_advertised_addr(server_addr.clone());

        // Simulate 2 peers performing dial-back
        for _ in 0..2 {
            let request = client.encode_request().unwrap();
            let response = handle_dialback_request(&request, 5).await.unwrap();
            client.process_response(&response).unwrap();
        }

        // After 2 successful dial-backs, status should be Public
        assert_eq!(client.status(), NatStatus::Public);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_full_autonat_private_detection() {
        // Agent advertises an unreachable address, peers fail to dial back.

        let client = AutoNatClient::new().with_advertised_addr("quic://127.0.0.1:1".into()); // Unreachable

        // Simulate 2 peers failing to dial back
        for _ in 0..2 {
            let request = client.encode_request().unwrap();
            let response = handle_dialback_request(&request, 2).await.unwrap();
            client.process_response(&response).unwrap();
        }

        // After 2 failed dial-backs, status should be Private
        assert_eq!(client.status(), NatStatus::Private);
    }
}
