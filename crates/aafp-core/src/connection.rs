//! Connection handler traits (simplified from libp2p's ConnectionHandler).
//!
//! For MVP, the SDK drives connections directly rather than through the full
//! NetworkBehaviour/ConnectionHandler event model. These traits are defined
//! for future use but not required for the MVP transport.

use std::task::{Context, Poll};

/// Events sent from a behaviour to a connection handler.
pub trait FromBehaviour: Send {}
/// Events sent from a connection handler to a behaviour.
pub trait ToBehaviour: Send {}

/// Handles protocol-level events on a connection.
pub trait ConnectionHandler: Send {
    /// Events from the behaviour to this handler.
    type FromBehaviour: FromBehaviour;
    /// Events from this handler to the behaviour.
    type ToBehaviour: ToBehaviour;

    /// Called when the behaviour sends an event.
    fn on_behaviour_event(&mut self, event: Self::FromBehaviour);

    /// Poll for handler events to send to the behaviour.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Self::ToBehaviour>;
}
