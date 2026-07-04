//! AAFP NAT traversal: relay, AutoNAT, and DCuTR (direct connection upgrade).
//!
//! ## Design (from AAFP_Architecture_Deliverable.md Phase 2.5)
//! - **Relay**: relay nodes forward traffic for agents behind NAT.
//! - **AutoNAT**: automatically detects if an agent is behind NAT by
//!   requesting dial-back checks from peers.
//! - **DCuTR**: attempts to upgrade relayed connections to direct connections
//!   using hole punching (for NAT types that support it).
//!
//! For MVP, these are stubs that track NAT status and relay assignments.
//! A production version would implement the full libp2p circuit relay v2
//! protocol and DCuTR hole-punching over QUIC.

pub mod auto_nat;
/// AutoNAT v1: dial-back based NAT detection (RFC 0010 §6).
pub mod auto_nat_v1;
pub mod dcutr;
/// DCuTR v1: Direct Connection Upgrade through Relay (RFC 0010 §7).
pub mod dcutr_v1;
pub mod relay;
/// Relay data forwarding: bidirectional QUIC stream forwarding (RFC 0010 §4.2).
pub mod relay_forwarding;
/// Circuit relay protocol v1 (RFC 0010).
pub mod relay_v1;

pub use auto_nat::{AutoNat, NatStatus};
pub use auto_nat_v1::{
    AutoNatClient, AutoNatV1DialBack, DialBackResult, DEFAULT_CONFIRMATION_THRESHOLD,
    DEFAULT_DIALBACK_TIMEOUT_SECS, METHOD_DIALBACK_REQUEST, METHOD_OBSERVE,
};
pub use dcutr::Dcutr;
pub use dcutr_v1::{
    CoordinateMessage, DcutrCoordinator, DcutrV1, DcutrV1Error, HolePunchResult, NatType,
    DEFAULT_HOLE_PUNCH_TIMEOUT_SECS, DEFAULT_SYNC_DELAY_MS,
};
pub use relay::{RelayConfig, RelayNode, RelayService};
pub use relay_forwarding::{
    RelayV1CallerHelper, RelayV1Server, RelayV1TargetHandler, DATA_STREAM_HEADER_LEN,
    DATA_STREAM_MAGIC, INCOMING_STREAM_MAGIC,
};
pub use relay_v1::{
    AutoNatV1, CancelParams, ConnectParams, ConnectResult, NatStatusV1, RelayV1Client,
    RelayV1Config, RelayV1Error, RelayV1RpcHandler, RelayV1Service, RenewParams, ReserveParams,
    ReserveResult, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_DURATION_SECS, DEFAULT_MAX_RESERVATIONS,
    METHOD_CANCEL, METHOD_CONNECT, METHOD_RENEW, METHOD_RESERVE,
};
