//! `SubscriptionStream` — async stream of PubSub `Event`s.
//!
//! Created by `ConnectedAgent::subscribe()`. Wraps a `tokio::sync::mpsc::Receiver`
//! that is fed by the event listener task. Implements async stream semantics
//! matching `ResponseStream` (in `simple.rs`).
//!
//! See `PS_P1_P2_API_PROPAGATION.md` Task 2 for the full design.

use crate::SdkError;
use tokio::sync::mpsc;

use super::event::Event;

/// A stream of PubSub events for a topic subscription.
///
/// Created by `ConnectedAgent::subscribe()`. Call `.next().await` to receive
/// each `Event`. The stream closes when the subscription is dropped or the
/// connection is lost.
///
/// Mirrors `ResponseStream` (in `simple.rs`) but yields `Event` instead of
/// `Response`.
///
/// # Design note
///
/// Uses `mpsc::Receiver` (not `broadcast::Receiver`) for the client-facing
/// stream because each subscription has exactly one consumer. The internal
/// `NetworkedPubSub` uses `broadcast` for fan-out to multiple local
/// subscribers; the bridge converts `broadcast::Receiver<TopicMessage>` →
/// `mpsc::Sender<Result<Event, SdkError>>` via a spawned forwarder task.
pub struct SubscriptionStream {
    /// The underlying mpsc receiver fed by the event listener task.
    inner: mpsc::Receiver<Result<Event, SdkError>>,
}

impl SubscriptionStream {
    /// Create a new `SubscriptionStream` wrapping an mpsc receiver.
    ///
    /// Typically called by `ConnectedAgent::subscribe()` after spawning
    /// the forwarder task that converts `broadcast::Receiver<TopicMessage>`
    /// into `mpsc::Sender<Result<Event, SdkError>>`.
    pub fn new(inner: mpsc::Receiver<Result<Event, SdkError>>) -> Self {
        Self { inner }
    }

    /// Receive the next event from the subscription.
    ///
    /// Returns `None` when the subscription is closed (connection lost or
    /// unsubscribed). Returns `Some(Err(...))` on a decode/transport error.
    ///
    /// # Example
    /// ```no_run
    /// # use aafp_sdk::pubsub::{Event, SubscriptionStream};
    /// # async fn consume(mut stream: SubscriptionStream) {
    /// while let Some(result) = stream.next().await {
    ///     match result {
    ///         Ok(event) => println!("event: {}", event.body()),
    ///         Err(e) => eprintln!("subscription error: {e}"),
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn next(&mut self) -> Option<Result<Event, SdkError>> {
        self.inner.recv().await
    }
}

// NOTE: We do NOT implement `futures::Stream` here to avoid adding a
// `futures` dependency. The `.next()` async method is sufficient for
// P1/P2 and mirrors `ResponseStream::next()`. If `Stream` trait
// integration is needed later, a wrapper can be added without changing
// the public API.
