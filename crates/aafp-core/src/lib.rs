//! AAFP core traits: Transport, Connection, Stream, Swarm, NetworkBehaviour.
//!
//! These are simplified, forked versions of libp2p-core's trait abstractions,
//! adapted to use `AgentId` instead of `PeerId`. The SDK drives connections
//! directly for MVP; the full Swarm/NetworkBehaviour model is available for
//! future protocol implementations.

pub mod connection;
pub mod error;
pub mod swarm;
pub mod transport;

pub use connection::{ConnectionHandler, FromBehaviour, ToBehaviour};
pub use error::{codes, Error, ErrorCategory, ProtocolError, is_always_fatal};
pub use swarm::{NetworkBehaviour, Swarm, SwarmEvent};
pub use transport::{Connection, Multiaddr, Stream, Transport, TransportEvent};
