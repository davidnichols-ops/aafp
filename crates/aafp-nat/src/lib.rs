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
pub mod dcutr;
pub mod relay;

pub use auto_nat::{AutoNat, NatStatus};
pub use dcutr::Dcutr;
pub use relay::{RelayConfig, RelayNode, RelayService};
