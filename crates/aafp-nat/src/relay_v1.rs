//! Circuit relay protocol v1 (RFC 0010).
//!
//! Allows agents behind NAT to communicate through relay nodes.
//! Implements reservation lifecycle (create, renew, cancel, expire)
//! and relayed connection establishment.
//!
//! ## Wire Format (RFC 0010 §2)
//!
//! Relay uses AAFP RPC frames with methods:
//! - `aafp.relay.reserve`: Request a relay reservation
//! - `aafp.relay.renew`: Renew an existing reservation
//! - `aafp.relay.cancel`: Cancel a reservation
//! - `aafp.relay.connect`: Request a relayed connection to a target

use aafp_cbor::{int_map, int_map_get, CborError, Value};
use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

/// RPC method names (RFC 0010 §2.1).
pub const METHOD_RESERVE: &str = "aafp.relay.reserve";
pub const METHOD_RENEW: &str = "aafp.relay.renew";
pub const METHOD_CANCEL: &str = "aafp.relay.cancel";
pub const METHOD_CONNECT: &str = "aafp.relay.connect";

/// Default max concurrent reservations (RFC 0010 §5).
pub const DEFAULT_MAX_RESERVATIONS: usize = 100;

/// Default max reservation duration: 1 hour (RFC 0010 §5).
pub const DEFAULT_MAX_DURATION_SECS: u64 = 3600;

/// Default max concurrent relayed connections (RFC 0010 §5).
pub const DEFAULT_MAX_CONNECTIONS: usize = 50;

/// Relay errors.
#[derive(Debug, Error)]
pub enum RelayV1Error {
    #[error("relay at capacity")]
    AtCapacity,
    #[error("reservation not found")]
    ReservationNotFound,
    #[error("reservation expired")]
    ReservationExpired,
    #[error("target has no reservation")]
    NoReservation,
    #[error("duration exceeds maximum")]
    DurationExceeded,
    #[error("not authorized (caller does not own reservation)")]
    NotAuthorized,
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
}

/// Helper to create a CBOR invalid error.
fn cbor_err(msg: impl Into<String>) -> CborError {
    CborError::Invalid {
        offset: 0,
        message: msg.into(),
    }
}

/// A relay reservation (RFC 0010 §3).
#[derive(Clone, Debug)]
pub struct Reservation {
    pub id: u64,
    pub agent_id: AgentId,
    pub created: Instant,
    pub expires: Instant,
}

impl Reservation {
    /// Check if the reservation has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
    }

    /// Remaining time until expiry.
    pub fn remaining(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }
}

/// A relayed connection (RFC 0010 §4).
#[derive(Clone, Debug)]
pub struct RelayedConnection {
    pub id: u64,
    pub source: AgentId,
    pub target: AgentId,
    pub created: Instant,
    pub bytes_forwarded: u64,
}

/// Reserve request params (RFC 0010 §2.2).
///
/// ```cbor
/// { 1: uint }
/// ```
#[derive(Clone, Debug)]
pub struct ReserveParams {
    pub duration_secs: u64,
}

impl ReserveParams {
    pub fn new(duration_secs: u64) -> Self {
        Self { duration_secs }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![(1, Value::Unsigned(self.duration_secs))])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, RelayV1Error> {
        let duration_secs = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing duration_secs"))),
        };
        Ok(Self { duration_secs })
    }
}

/// Reserve response result (RFC 0010 §2.3).
///
/// ```cbor
/// { 1: uint, 2: uint, 3: tstr }
/// ```
#[derive(Clone, Debug)]
pub struct ReserveResult {
    pub reservation_id: u64,
    pub expires_at: u64,
    pub relay_addr: String,
}

impl ReserveResult {
    pub fn new(reservation_id: u64, expires_at: u64, relay_addr: String) -> Self {
        Self {
            reservation_id,
            expires_at,
            relay_addr,
        }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.reservation_id)),
            (2, Value::Unsigned(self.expires_at)),
            (3, Value::TextString(self.relay_addr.clone())),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, RelayV1Error> {
        let reservation_id = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing reservation_id"))),
        };
        let expires_at = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing expires_at"))),
        };
        let relay_addr = match int_map_get(val, 3) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing relay_addr"))),
        };
        Ok(Self {
            reservation_id,
            expires_at,
            relay_addr,
        })
    }
}

/// Renew request params (RFC 0010 §2.4).
///
/// ```cbor
/// { 1: uint, 2: uint }
/// ```
#[derive(Clone, Debug)]
pub struct RenewParams {
    pub reservation_id: u64,
    pub duration_secs: u64,
}

impl RenewParams {
    pub fn new(reservation_id: u64, duration_secs: u64) -> Self {
        Self {
            reservation_id,
            duration_secs,
        }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, Value::Unsigned(self.reservation_id)),
            (2, Value::Unsigned(self.duration_secs)),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, RelayV1Error> {
        let reservation_id = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing reservation_id"))),
        };
        let duration_secs = match int_map_get(val, 2) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing duration_secs"))),
        };
        Ok(Self {
            reservation_id,
            duration_secs,
        })
    }
}

/// Cancel request params (RFC 0010 §2.5).
///
/// ```cbor
/// { 1: uint }
/// ```
#[derive(Clone, Debug)]
pub struct CancelParams {
    pub reservation_id: u64,
}

impl CancelParams {
    pub fn new(reservation_id: u64) -> Self {
        Self { reservation_id }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![(1, Value::Unsigned(self.reservation_id))])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, RelayV1Error> {
        let reservation_id = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing reservation_id"))),
        };
        Ok(Self { reservation_id })
    }
}

/// Connect request params (RFC 0010 §2.6).
///
/// ```cbor
/// { 1: bstr }
/// ```
#[derive(Clone, Debug)]
pub struct ConnectParams {
    pub target: AgentId,
}

impl ConnectParams {
    pub fn new(target: AgentId) -> Self {
        Self { target }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![(1, Value::ByteString(self.target.to_vec()))])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, RelayV1Error> {
        let target = match int_map_get(val, 1) {
            Some(Value::ByteString(b)) => {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    arr
                } else {
                    return Err(RelayV1Error::Cbor(cbor_err("target must be 32 bytes")));
                }
            }
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing target"))),
        };
        Ok(Self { target })
    }
}

/// Connect response result (RFC 0010 §2.7).
///
/// ```cbor
/// { 1: uint }
/// ```
#[derive(Clone, Debug)]
pub struct ConnectResult {
    pub connection_id: u64,
}

impl ConnectResult {
    pub fn new(connection_id: u64) -> Self {
        Self { connection_id }
    }

    pub fn to_cbor(&self) -> Value {
        int_map(vec![(1, Value::Unsigned(self.connection_id))])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, RelayV1Error> {
        let connection_id = match int_map_get(val, 1) {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(RelayV1Error::Cbor(cbor_err("missing connection_id"))),
        };
        Ok(Self { connection_id })
    }
}

/// Relay service configuration (RFC 0010 §5).
#[derive(Clone, Debug)]
pub struct RelayV1Config {
    /// Maximum concurrent reservations.
    pub max_reservations: usize,
    /// Maximum reservation duration in seconds.
    pub max_duration_secs: u64,
    /// Maximum concurrent relayed connections.
    pub max_connections: usize,
    /// Relay's multiaddr (returned in reserve responses).
    pub relay_addr: String,
}

impl Default for RelayV1Config {
    fn default() -> Self {
        Self {
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            relay_addr: "quic://0.0.0.0:4433".to_string(),
        }
    }
}

/// Relay service: manages reservations and relayed connections (RFC 0010).
pub struct RelayV1Service {
    config: RelayV1Config,
    /// Active reservations: reservation_id → Reservation
    reservations: HashMap<u64, Reservation>,
    /// Map agent_id → reservation_id for lookup
    agent_reservations: HashMap<AgentId, u64>,
    /// Active relayed connections: connection_id → RelayedConnection
    connections: HashMap<u64, RelayedConnection>,
    /// Next reservation ID
    next_reservation_id: u64,
    /// Next connection ID
    next_connection_id: u64,
}

impl RelayV1Service {
    /// Create a new relay service.
    pub fn new(config: RelayV1Config) -> Self {
        Self {
            config,
            reservations: HashMap::new(),
            agent_reservations: HashMap::new(),
            connections: HashMap::new(),
            next_reservation_id: 1,
            next_connection_id: 1,
        }
    }

    /// Create with default config.
    pub fn with_defaults() -> Self {
        Self::new(RelayV1Config::default())
    }

    /// Handle a reserve request (RFC 0010 §3.1).
    pub fn handle_reserve(
        &mut self,
        caller_id: &AgentId,
        params: &ReserveParams,
    ) -> Result<ReserveResult, RelayV1Error> {
        // Check duration
        if params.duration_secs > self.config.max_duration_secs {
            return Err(RelayV1Error::DurationExceeded);
        }

        // Evict expired reservations first
        self.evict_expired();

        // Check capacity
        if self.reservations.len() >= self.config.max_reservations {
            return Err(RelayV1Error::AtCapacity);
        }

        // If agent already has a reservation, remove the old one
        if let Some(old_id) = self.agent_reservations.remove(caller_id) {
            self.reservations.remove(&old_id);
        }

        // Create new reservation
        let id = self.next_reservation_id;
        self.next_reservation_id += 1;
        let now = Instant::now();
        let expires = now + Duration::from_secs(params.duration_secs);

        let reservation = Reservation {
            id,
            agent_id: *caller_id,
            created: now,
            expires,
        };

        self.reservations.insert(id, reservation);
        self.agent_reservations.insert(*caller_id, id);

        // Compute expires_at as Unix timestamp (use a base of 0 for testing)
        // In production, this would use SystemTime
        let expires_at = params.duration_secs;

        Ok(ReserveResult::new(
            id,
            expires_at,
            self.config.relay_addr.clone(),
        ))
    }

    /// Handle a renew request (RFC 0010 §3.2).
    pub fn handle_renew(
        &mut self,
        caller_id: &AgentId,
        params: &RenewParams,
    ) -> Result<ReserveResult, RelayV1Error> {
        // Check duration
        if params.duration_secs > self.config.max_duration_secs {
            return Err(RelayV1Error::DurationExceeded);
        }

        // Find reservation
        let reservation = self
            .reservations
            .get_mut(&params.reservation_id)
            .ok_or(RelayV1Error::ReservationNotFound)?;

        // Verify ownership
        if &reservation.agent_id != caller_id {
            return Err(RelayV1Error::NotAuthorized);
        }

        // Extend TTL
        let now = Instant::now();
        reservation.expires = now + Duration::from_secs(params.duration_secs);

        let expires_at = params.duration_secs;
        Ok(ReserveResult::new(
            params.reservation_id,
            expires_at,
            self.config.relay_addr.clone(),
        ))
    }

    /// Handle a cancel request (RFC 0010 §3.3).
    pub fn handle_cancel(
        &mut self,
        caller_id: &AgentId,
        params: &CancelParams,
    ) -> Result<(), RelayV1Error> {
        // Find reservation
        let reservation = self
            .reservations
            .get(&params.reservation_id)
            .ok_or(RelayV1Error::ReservationNotFound)?;

        // Verify ownership
        if &reservation.agent_id != caller_id {
            return Err(RelayV1Error::NotAuthorized);
        }

        // Remove
        self.agent_reservations.remove(&reservation.agent_id);
        self.reservations.remove(&params.reservation_id);
        Ok(())
    }

    /// Handle a connect request (RFC 0010 §4.1).
    pub fn handle_connect(
        &mut self,
        caller_id: &AgentId,
        params: &ConnectParams,
    ) -> Result<ConnectResult, RelayV1Error> {
        // Evict expired
        self.evict_expired();

        // Check target has active reservation
        let target_reservation_id = self
            .agent_reservations
            .get(&params.target)
            .ok_or(RelayV1Error::NoReservation)?;

        if !self
            .reservations
            .get(target_reservation_id)
            .map(|r| !r.is_expired())
            .unwrap_or(false)
        {
            return Err(RelayV1Error::NoReservation);
        }

        // Check connection capacity
        if self.connections.len() >= self.config.max_connections {
            return Err(RelayV1Error::AtCapacity);
        }

        // Create relayed connection
        let id = self.next_connection_id;
        self.next_connection_id += 1;
        let conn = RelayedConnection {
            id,
            source: *caller_id,
            target: params.target,
            created: Instant::now(),
            bytes_forwarded: 0,
        };
        self.connections.insert(id, conn);

        Ok(ConnectResult::new(id))
    }

    /// Evict expired reservations (RFC 0010 §3.4).
    pub fn evict_expired(&mut self) {
        let expired_ids: Vec<u64> = self
            .reservations
            .iter()
            .filter(|(_, r)| r.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in expired_ids {
            if let Some(reservation) = self.reservations.remove(&id) {
                self.agent_reservations.remove(&reservation.agent_id);
            }
        }
    }

    /// Get the number of active reservations.
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Get the number of active relayed connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get a reservation by ID.
    pub fn get_reservation(&self, id: u64) -> Option<&Reservation> {
        self.reservations.get(&id)
    }

    /// Get a relayed connection by ID.
    pub fn get_connection(&self, id: u64) -> Option<&RelayedConnection> {
        self.connections.get(&id)
    }

    /// Remove a relayed connection.
    pub fn remove_connection(&mut self, id: u64) {
        self.connections.remove(&id);
    }

    /// Check if an agent has an active reservation.
    pub fn has_reservation(&self, agent_id: &AgentId) -> bool {
        self.agent_reservations
            .get(agent_id)
            .and_then(|id| self.reservations.get(id))
            .map(|r| !r.is_expired())
            .unwrap_or(false)
    }
}

/// Server-side handler for relay RPC requests (RFC 0010 §2).
pub struct RelayV1RpcHandler {
    service: Arc<Mutex<RelayV1Service>>,
}

impl RelayV1RpcHandler {
    /// Create a new handler wrapping the given relay service.
    pub fn new(service: Arc<Mutex<RelayV1Service>>) -> Self {
        Self { service }
    }

    /// Create with a fresh service.
    pub fn with_defaults() -> Self {
        Self::new(Arc::new(Mutex::new(RelayV1Service::with_defaults())))
    }

    /// Handle an incoming RPC request.
    ///
    /// Returns the CBOR-encoded RPC response result value.
    pub fn handle_request(
        &self,
        method: &str,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, RelayV1Error> {
        match method {
            METHOD_RESERVE => {
                let p = ReserveParams::from_cbor(params)?;
                let mut service = self.service.lock().unwrap();
                let result = service.handle_reserve(caller_id, &p)?;
                Ok(result.to_cbor())
            }
            METHOD_RENEW => {
                let p = RenewParams::from_cbor(params)?;
                let mut service = self.service.lock().unwrap();
                let result = service.handle_renew(caller_id, &p)?;
                Ok(result.to_cbor())
            }
            METHOD_CANCEL => {
                let p = CancelParams::from_cbor(params)?;
                let mut service = self.service.lock().unwrap();
                service.handle_cancel(caller_id, &p)?;
                Ok(int_map(vec![]))
            }
            METHOD_CONNECT => {
                let p = ConnectParams::from_cbor(params)?;
                let mut service = self.service.lock().unwrap();
                let result = service.handle_connect(caller_id, &p)?;
                Ok(result.to_cbor())
            }
            _ => Err(RelayV1Error::Cbor(cbor_err(format!(
                "unknown method: {method}"
            )))),
        }
    }

    /// Get a reference to the underlying service.
    pub fn service(&self) -> &Arc<Mutex<RelayV1Service>> {
        &self.service
    }
}

/// Client-side relay RPC helper.
///
/// Provides convenience methods for encoding relay RPC requests
/// and decoding responses. The actual transport is handled by the caller.
pub struct RelayV1Client;

impl RelayV1Client {
    /// Encode a reserve request payload.
    pub fn encode_reserve_request(
        correlation_id: u64,
        duration_secs: u64,
    ) -> Result<Vec<u8>, RelayV1Error> {
        let request = aafp_messaging::RpcRequest {
            id: correlation_id,
            method: METHOD_RESERVE.to_string(),
            params: ReserveParams::new(duration_secs).to_cbor(),
        };
        aafp_cbor::encode(&request.to_cbor()).map_err(RelayV1Error::Cbor)
    }

    /// Encode a renew request payload.
    pub fn encode_renew_request(
        correlation_id: u64,
        reservation_id: u64,
        duration_secs: u64,
    ) -> Result<Vec<u8>, RelayV1Error> {
        let request = aafp_messaging::RpcRequest {
            id: correlation_id,
            method: METHOD_RENEW.to_string(),
            params: RenewParams::new(reservation_id, duration_secs).to_cbor(),
        };
        aafp_cbor::encode(&request.to_cbor()).map_err(RelayV1Error::Cbor)
    }

    /// Encode a cancel request payload.
    pub fn encode_cancel_request(
        correlation_id: u64,
        reservation_id: u64,
    ) -> Result<Vec<u8>, RelayV1Error> {
        let request = aafp_messaging::RpcRequest {
            id: correlation_id,
            method: METHOD_CANCEL.to_string(),
            params: CancelParams::new(reservation_id).to_cbor(),
        };
        aafp_cbor::encode(&request.to_cbor()).map_err(RelayV1Error::Cbor)
    }

    /// Encode a connect request payload.
    pub fn encode_connect_request(
        correlation_id: u64,
        target: AgentId,
    ) -> Result<Vec<u8>, RelayV1Error> {
        let request = aafp_messaging::RpcRequest {
            id: correlation_id,
            method: METHOD_CONNECT.to_string(),
            params: ConnectParams::new(target).to_cbor(),
        };
        aafp_cbor::encode(&request.to_cbor()).map_err(RelayV1Error::Cbor)
    }

    /// Decode a reserve response.
    pub fn decode_reserve_response(data: &[u8]) -> Result<ReserveResult, RelayV1Error> {
        let response = aafp_messaging::RpcResponse::decode(data)
            .map_err(|e| RelayV1Error::Cbor(cbor_err(e.to_string())))?;
        if let Some(err) = response.error {
            return Err(RelayV1Error::Cbor(cbor_err(err.message)));
        }
        let result_val = response
            .result
            .ok_or(RelayV1Error::Cbor(cbor_err("missing result")))?;
        ReserveResult::from_cbor(&result_val)
    }

    /// Decode a connect response.
    pub fn decode_connect_response(data: &[u8]) -> Result<ConnectResult, RelayV1Error> {
        let response = aafp_messaging::RpcResponse::decode(data)
            .map_err(|e| RelayV1Error::Cbor(cbor_err(e.to_string())))?;
        if let Some(err) = response.error {
            return Err(RelayV1Error::Cbor(cbor_err(err.message)));
        }
        let result_val = response
            .result
            .ok_or(RelayV1Error::Cbor(cbor_err("missing result")))?;
        ConnectResult::from_cbor(&result_val)
    }
}

/// AutoNAT: automatic NAT detection (RFC 0010 §6).
#[derive(Clone, Debug)]
pub struct AutoNatV1 {
    status: NatStatusV1,
    observed_addresses: Vec<String>,
}

/// NAT status (RFC 0010 §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatStatusV1 {
    Unknown,
    NotBehindNat,
    BehindNat,
}

impl AutoNatV1 {
    /// Create a new AutoNAT instance.
    pub fn new() -> Self {
        Self {
            status: NatStatusV1::Unknown,
            observed_addresses: Vec::new(),
        }
    }

    /// Report an observed address from a peer.
    pub fn report_observed(&mut self, addr: String, local_addr: &str) {
        if addr != local_addr {
            self.status = NatStatusV1::BehindNat;
        } else if self.status == NatStatusV1::Unknown {
            self.status = NatStatusV1::NotBehindNat;
        }
        self.observed_addresses.push(addr);
    }

    /// Get the current NAT status.
    pub fn status(&self) -> &NatStatusV1 {
        &self.status
    }

    /// Get all observed addresses.
    pub fn observed_addresses(&self) -> &[String] {
        &self.observed_addresses
    }

    /// Check if behind NAT.
    pub fn is_behind_nat(&self) -> bool {
        self.status == NatStatusV1::BehindNat
    }
}

impl Default for AutoNatV1 {
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
    fn test_reserve_and_connect() {
        let mut service = RelayV1Service::with_defaults();
        let agent_a = make_agent_id(1);
        let agent_b = make_agent_id(2);

        // Agent A reserves
        let result = service
            .handle_reserve(&agent_a, &ReserveParams::new(3600))
            .unwrap();
        assert_eq!(result.reservation_id, 1);
        assert!(service.has_reservation(&agent_a));

        // Agent B connects to A through relay
        let connect_result = service
            .handle_connect(&agent_b, &ConnectParams::new(agent_a))
            .unwrap();
        assert_eq!(connect_result.connection_id, 1);
        assert_eq!(service.connection_count(), 1);
    }

    #[test]
    fn test_reserve_at_capacity() {
        let config = RelayV1Config {
            max_reservations: 2,
            ..Default::default()
        };
        let mut service = RelayV1Service::new(config);

        service
            .handle_reserve(&make_agent_id(1), &ReserveParams::new(60))
            .unwrap();
        service
            .handle_reserve(&make_agent_id(2), &ReserveParams::new(60))
            .unwrap();

        // Third reservation fails
        let result = service.handle_reserve(&make_agent_id(3), &ReserveParams::new(60));
        assert!(matches!(result, Err(RelayV1Error::AtCapacity)));
    }

    #[test]
    fn test_reserve_duration_exceeded() {
        let config = RelayV1Config {
            max_duration_secs: 100,
            ..Default::default()
        };
        let mut service = RelayV1Service::new(config);

        let result = service.handle_reserve(&make_agent_id(1), &ReserveParams::new(200));
        assert!(matches!(result, Err(RelayV1Error::DurationExceeded)));
    }

    #[test]
    fn test_renew_reservation() {
        let mut service = RelayV1Service::with_defaults();
        let agent = make_agent_id(1);

        let result = service
            .handle_reserve(&agent, &ReserveParams::new(60))
            .unwrap();

        // Renew
        let renew_result = service
            .handle_renew(&agent, &RenewParams::new(result.reservation_id, 120))
            .unwrap();
        assert_eq!(renew_result.reservation_id, result.reservation_id);
    }

    #[test]
    fn test_renew_not_authorized() {
        let mut service = RelayV1Service::with_defaults();
        let agent_a = make_agent_id(1);
        let agent_b = make_agent_id(2);

        let result = service
            .handle_reserve(&agent_a, &ReserveParams::new(60))
            .unwrap();

        // Agent B tries to renew A's reservation
        let renew_result =
            service.handle_renew(&agent_b, &RenewParams::new(result.reservation_id, 120));
        assert!(matches!(renew_result, Err(RelayV1Error::NotAuthorized)));
    }

    #[test]
    fn test_cancel_reservation() {
        let mut service = RelayV1Service::with_defaults();
        let agent = make_agent_id(1);

        let result = service
            .handle_reserve(&agent, &ReserveParams::new(60))
            .unwrap();
        assert!(service.has_reservation(&agent));

        service
            .handle_cancel(&agent, &CancelParams::new(result.reservation_id))
            .unwrap();
        assert!(!service.has_reservation(&agent));
    }

    #[test]
    fn test_cancel_not_authorized() {
        let mut service = RelayV1Service::with_defaults();
        let agent_a = make_agent_id(1);
        let agent_b = make_agent_id(2);

        let result = service
            .handle_reserve(&agent_a, &ReserveParams::new(60))
            .unwrap();

        let cancel_result =
            service.handle_cancel(&agent_b, &CancelParams::new(result.reservation_id));
        assert!(matches!(cancel_result, Err(RelayV1Error::NotAuthorized)));
    }

    #[test]
    fn test_connect_no_reservation() {
        let mut service = RelayV1Service::with_defaults();
        let agent_b = make_agent_id(2);

        // No agent has a reservation
        let result = service.handle_connect(&agent_b, &ConnectParams::new(make_agent_id(1)));
        assert!(matches!(result, Err(RelayV1Error::NoReservation)));
    }

    #[test]
    fn test_reservation_replacement() {
        let mut service = RelayV1Service::with_defaults();
        let agent = make_agent_id(1);

        // First reservation
        let r1 = service
            .handle_reserve(&agent, &ReserveParams::new(60))
            .unwrap();

        // Second reservation replaces the first
        let r2 = service
            .handle_reserve(&agent, &ReserveParams::new(60))
            .unwrap();

        assert_ne!(r1.reservation_id, r2.reservation_id);
        assert_eq!(service.reservation_count(), 1);
    }

    #[test]
    fn test_reserve_params_cbor_roundtrip() {
        let params = ReserveParams::new(3600);
        let cbor = params.to_cbor();
        let decoded = ReserveParams::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.duration_secs, 3600);
    }

    #[test]
    fn test_reserve_result_cbor_roundtrip() {
        let result = ReserveResult::new(42, 999, "quic://relay:4433".to_string());
        let cbor = result.to_cbor();
        let decoded = ReserveResult::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.reservation_id, 42);
        assert_eq!(decoded.expires_at, 999);
        assert_eq!(decoded.relay_addr, "quic://relay:4433");
    }

    #[test]
    fn test_connect_params_cbor_roundtrip() {
        let target = make_agent_id(5);
        let params = ConnectParams::new(target);
        let cbor = params.to_cbor();
        let decoded = ConnectParams::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.target, target);
    }

    #[test]
    fn test_rpc_handler_reserve() {
        let handler = RelayV1RpcHandler::with_defaults();
        let caller = make_agent_id(1);
        let params = ReserveParams::new(3600).to_cbor();

        let result = handler
            .handle_request(METHOD_RESERVE, &params, &caller)
            .unwrap();
        let decoded = ReserveResult::from_cbor(&result).unwrap();
        assert_eq!(decoded.reservation_id, 1);
    }

    #[test]
    fn test_rpc_handler_connect() {
        let handler = RelayV1RpcHandler::with_defaults();
        let agent_a = make_agent_id(1);
        let agent_b = make_agent_id(2);

        // Reserve first
        let params = ReserveParams::new(3600).to_cbor();
        handler
            .handle_request(METHOD_RESERVE, &params, &agent_a)
            .unwrap();

        // Connect
        let params = ConnectParams::new(agent_a).to_cbor();
        let result = handler
            .handle_request(METHOD_CONNECT, &params, &agent_b)
            .unwrap();
        let decoded = ConnectResult::from_cbor(&result).unwrap();
        assert_eq!(decoded.connection_id, 1);
    }

    #[test]
    fn test_rpc_handler_unknown_method() {
        let handler = RelayV1RpcHandler::with_defaults();
        let caller = make_agent_id(1);
        let result = handler.handle_request("aafp.unknown", &int_map(vec![]), &caller);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_encode_reserve_request() {
        let encoded = RelayV1Client::encode_reserve_request(1, 3600).unwrap();
        assert!(!encoded.is_empty());

        let request = aafp_messaging::RpcRequest::decode(&encoded).unwrap();
        assert_eq!(request.id, 1);
        assert_eq!(request.method, METHOD_RESERVE);
    }

    #[test]
    fn test_client_encode_connect_request() {
        let target = make_agent_id(3);
        let encoded = RelayV1Client::encode_connect_request(2, target).unwrap();
        let request = aafp_messaging::RpcRequest::decode(&encoded).unwrap();
        assert_eq!(request.id, 2);
        assert_eq!(request.method, METHOD_CONNECT);
    }

    #[test]
    fn test_client_decode_reserve_response() {
        let handler = RelayV1RpcHandler::with_defaults();
        let caller = make_agent_id(1);
        let params = ReserveParams::new(3600).to_cbor();
        let result_val = handler
            .handle_request(METHOD_RESERVE, &params, &caller)
            .unwrap();

        let response = aafp_messaging::RpcResponse {
            id: 1,
            result: Some(result_val),
            error: None,
        };
        let encoded = response.encode().unwrap();
        let decoded = RelayV1Client::decode_reserve_response(&encoded).unwrap();
        assert_eq!(decoded.reservation_id, 1);
    }

    #[test]
    fn test_autonat_detects_nat() {
        let mut autonat = AutoNatV1::new();
        assert_eq!(autonat.status(), &NatStatusV1::Unknown);

        // Peer reports different address → behind NAT
        autonat.report_observed("203.0.113.1:4433".to_string(), "127.0.0.1:4433");
        assert_eq!(autonat.status(), &NatStatusV1::BehindNat);
        assert!(autonat.is_behind_nat());
    }

    #[test]
    fn test_autonat_no_nat() {
        let mut autonat = AutoNatV1::new();
        autonat.report_observed("1.2.3.4:4433".to_string(), "1.2.3.4:4433");
        assert_eq!(autonat.status(), &NatStatusV1::NotBehindNat);
        assert!(!autonat.is_behind_nat());
    }
}
