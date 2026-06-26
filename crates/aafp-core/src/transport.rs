//! Transport trait (forked and simplified from libp2p-core).
//!
//! Replaces libp2p's `PeerId` with AAFP's `AgentId`.

use crate::error::Error;
use aafp_identity::AgentId;
use std::task::{Context, Poll};

/// A simplified multiaddress (e.g., "quic://1.2.3.4:4433").
pub type Multiaddr = String;

/// Events emitted by a [`Transport`].
#[derive(Debug)]
pub enum TransportEvent {
    /// A new incoming connection attempt.
    Incoming { local_addr: Multiaddr, remote_addr: Multiaddr },
    /// A connection was established with a peer.
    ConnectionEstablished { peer: AgentId, remote_addr: Multiaddr },
    /// A connection was closed.
    ConnectionClosed { peer: AgentId },
    /// A transport-level error.
    Error(Error),
}

/// A transport abstraction for establishing connections to peers.
///
/// This is a simplified, synchronous-poll version of libp2p's `Transport`
/// trait. Implementations include [`aafp_transport_quic::QuicTransport`].
pub trait Transport: Send {
    /// Start listening on the given multiaddress.
    fn listen_on(&mut self, addr: &Multiaddr) -> Result<(), Error>;

    /// Initiate a connection to the given multiaddress.
    fn dial(&mut self, addr: &Multiaddr) -> Result<(), Error>;

    /// Poll for transport events.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<TransportEvent>;
}

/// A connection to a peer.
pub trait Connection: Send {
    /// The peer's AgentId.
    fn peer_id(&self) -> AgentId;

    /// The remote address.
    fn remote_addr(&self) -> Multiaddr;

    /// Close the connection.
    fn close(&mut self);
}

/// A bidirectional stream within a connection.
pub trait Stream: Send {
    /// Unique stream ID within the connection.
    fn id(&self) -> u64;
}
