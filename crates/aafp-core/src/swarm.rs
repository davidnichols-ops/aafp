//! Swarm and NetworkBehaviour traits (simplified from libp2p).
//!
//! For MVP, the SDK drives the transport and connections directly. The
//! `NetworkBehaviour` trait is defined for future protocol implementations
//! (gossipsub, Kademlia, etc.) but is not required for the MVP.

use crate::connection::ConnectionHandler;
use crate::error::Error;
use crate::transport::{Multiaddr, Transport, TransportEvent};
use aafp_identity::AgentId;
use std::task::{Context, Poll};

/// A network behaviour (e.g., discovery, messaging, NAT traversal).
pub trait NetworkBehaviour: Send {
    /// Events emitted by this behaviour.
    type Event: Send;
    /// The connection handler for this behaviour.
    type ConnectionHandler: ConnectionHandler;

    /// Called when a transport event occurs.
    fn on_transport_event(&mut self, event: TransportEvent);

    /// Poll for behaviour events.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Self::Event>;

    /// Create a new connection handler for a peer.
    fn new_handler(&self) -> Self::ConnectionHandler;
}

/// Events emitted by the Swarm.
#[derive(Debug)]
pub enum SwarmEvent<B: NetworkBehaviour> {
    /// An event from the network behaviour.
    Behaviour(B::Event),
    /// A new connection was established.
    ConnectionEstablished { peer: AgentId },
    /// A connection was closed.
    ConnectionClosed { peer: AgentId },
    /// A new incoming connection.
    IncomingConnection { remote_addr: Multiaddr },
    /// An error.
    Error(Error),
}

/// Drives a [`Transport`] and one or more [`NetworkBehaviour`]s.
pub struct Swarm<T: Transport, B: NetworkBehaviour> {
    transport: T,
    behaviour: B,
}

impl<T: Transport, B: NetworkBehaviour> Swarm<T, B> {
    /// Create a new swarm.
    pub fn new(transport: T, behaviour: B) -> Self {
        Self {
            transport,
            behaviour,
        }
    }

    /// Start listening.
    pub fn listen_on(&mut self, addr: &Multiaddr) -> Result<(), Error> {
        self.transport.listen_on(addr)
    }

    /// Dial a peer.
    pub fn dial(&mut self, addr: &Multiaddr) -> Result<(), Error> {
        self.transport.dial(addr)
    }

    /// Poll the swarm for events.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SwarmEvent<B>> {
        // Poll transport for events.
        match self.transport.poll(cx) {
            Poll::Ready(TransportEvent::ConnectionEstablished { peer, .. }) => {
                self.behaviour
                    .on_transport_event(TransportEvent::ConnectionEstablished {
                        peer,
                        remote_addr: String::new(),
                    });
                return Poll::Ready(SwarmEvent::ConnectionEstablished { peer });
            }
            Poll::Ready(TransportEvent::ConnectionClosed { peer }) => {
                self.behaviour
                    .on_transport_event(TransportEvent::ConnectionClosed { peer });
                return Poll::Ready(SwarmEvent::ConnectionClosed { peer });
            }
            Poll::Ready(TransportEvent::Incoming { remote_addr, .. }) => {
                return Poll::Ready(SwarmEvent::IncomingConnection { remote_addr });
            }
            Poll::Ready(TransportEvent::Error(e)) => {
                return Poll::Ready(SwarmEvent::Error(e));
            }
            Poll::Pending => {}
        }

        // Poll behaviour for events.
        match self.behaviour.poll(cx) {
            Poll::Ready(event) => return Poll::Ready(SwarmEvent::Behaviour(event)),
            Poll::Pending => {}
        }

        Poll::Pending
    }
}
