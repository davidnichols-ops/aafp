//! AAFP core traits: Transport, Connection, Stream, Swarm, NetworkBehaviour.
//!
//! These are simplified, forked versions of libp2p-core's trait abstractions,
//! adapted to use `AgentId` instead of `PeerId`. The SDK drives connections
//! directly for MVP; the full Swarm/NetworkBehaviour model is available for
//! future protocol implementations.

pub mod connection;
pub mod error;
pub mod handshake_state;
pub mod session;
pub mod swarm;
pub mod transport;

pub use connection::{ConnectionHandler, FromBehaviour, ToBehaviour};
pub use error::{codes, is_always_fatal, Error, ErrorCategory, ProtocolError};
pub use handshake_state::{
    ClientHandshakeMachine, ClientHandshakeState, DuplicateHandshakeMessageError, FrameDisposition,
    HandshakeRole, HandshakeStateError, HandshakeTimeoutError, ServerHandshakeMachine,
    ServerHandshakeState, UnexpectedFrameError, DEFAULT_CLOSE_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT,
    MIN_CLOSE_TIMEOUT, MIN_HANDSHAKE_TIMEOUT,
};
pub use session::{
    AuthorizationContext, AuthorizationError, AuthorizationProvider, NegotiatedFeatures, Session,
    SessionId, SessionState, SessionStateError, TestingAuthProvider, TestingCapabilityProvider,
    TestingDenyProvider, TransportHandle, SESSION_ID_SIZE,
};
pub use swarm::{NetworkBehaviour, Swarm, SwarmEvent};
pub use transport::{Connection, Multiaddr, Stream, Transport, TransportEvent};
