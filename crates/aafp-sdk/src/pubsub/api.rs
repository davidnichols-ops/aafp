//! Simple API extension stubs for PubSub (P1/P2).
//!
//! These are **extension trait stubs** that add PubSub methods to
//! `ServeBuilder` and `ConnectedAgent`. They are defined as separate traits
//! so that `simple.rs` does not need to be modified in this scaffolding
//! phase — the traits can be imported and used once `pub mod pubsub;` is
//! added to `lib.rs`.
//!
//! See `PS_P1_P2_API_PROPAGATION.md` Tasks 3, 5 for the full design.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use aafp_identity::AgentId;

use super::event::Event;
use super::subscription::SubscriptionStream;
use crate::SdkError;

// ─── OnPublishHandler type alias ───────────────────────────────

/// Handler invoked when a PubSub event is received on a subscribed topic.
///
/// Sugar for `subscribe()` + a spawned consumer task. The handler receives
/// the topic name and the decoded `Event`.
///
/// This mirrors the `CapabilityHandler` / `HandlerFnV2` pattern in `simple.rs`:
/// a boxed async closure stored in an `Arc` for sharing across tasks.
pub type OnPublishHandler = Arc<
    dyn Fn(&str, Event) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

// ─── ServeBuilderPubSubExt ─────────────────────────────────────

/// Extension trait adding PubSub methods to `ServeBuilder`.
///
/// **STUB**: These methods are defined as a separate trait so that
/// `simple.rs` does not need modification in this scaffolding phase.
/// In the final integration, the methods will be moved directly onto
/// `ServeBuilder` (or `ServeBuilder` will gain `pubsub_topics` and
/// `pubsub_on_publish` fields and these trait impls will delegate to them).
///
/// See `PS_P1_P2_API_PROPAGATION.md` Task 3.
pub trait ServeBuilderPubSubExt: Sized {
    /// Declare a PubSub topic this agent publishes to.
    ///
    /// Registers the topic in the internal `NetworkedPubSub` so that
    /// `publish()` calls succeed. The topic is also advertised so remote
    /// peers can subscribe to it. Multiple `.topic()` calls register
    /// multiple topics.
    ///
    /// # Example
    /// ```no_run
    /// # use aafp_sdk::simple::Agent;
    /// # use aafp_sdk::pubsub::ServeBuilderPubSubExt;
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// Agent::serve()
    ///     .topic("translate.events")
    ///     .start()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    fn topic(self, name: impl Into<String>) -> Self;

    /// Subscribe to a PubSub topic and invoke `handler` for each event.
    ///
    /// This is sugar for `subscribe()` + a spawned consumer task. The handler
    /// runs in a background task for the lifetime of the `ServingAgent`.
    /// Multiple `.on_publish()` calls register handlers for different topics.
    ///
    /// # Example
    /// ```no_run
    /// # use aafp_sdk::simple::Agent;
    /// # use aafp_sdk::pubsub::{Event, ServeBuilderPubSubExt};
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// Agent::serve()
    ///     .on_publish("commands", |_topic, ev: Event| async move {
    ///         if ev.body() == "shutdown" {
    ///             // react to a published command
    ///         }
    ///     })
    ///     .start()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    fn on_publish<F, Fut>(self, topic: impl Into<String>, handler: F) -> Self
    where
        F: Fn(&str, Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static;
}

// NOTE: The impl block for `ServeBuilderPubSubExt` is intentionally
// omitted here. It will be implemented in `simple.rs` during the
// integration phase, once `ServeBuilder` gains the `pubsub_topics`
// and `pubsub_on_publish` fields. The trait definition here serves
// as the contract / API surface stub.

// ─── ConnectedAgentPubSubExt ───────────────────────────────────

/// Extension trait adding PubSub methods to `ConnectedAgent`.
///
/// **STUB**: These methods are defined as a separate trait so that
/// `simple.rs` does not need modification in this scaffolding phase.
/// In the final integration, the methods will be moved directly onto
/// `ConnectedAgent` (or `ConnectedAgent` will gain a `local_pubsub`
/// field and these trait impls will delegate to it).
///
/// See `PS_P1_P2_API_PROPAGATION.md` Task 5.
pub trait ConnectedAgentPubSubExt {
    /// Subscribe to a PubSub topic on a remote agent.
    ///
    /// Sends an `aafp.pubsub.subscribe` RPC request and returns a
    /// [`SubscriptionStream`] that yields [`Event`]s as they are published.
    ///
    /// For v1 (Option A, design doc §7.2), the client opens a bi-stream,
    /// sends the subscribe request, and keeps the stream open. The server
    /// forwards published messages as `aafp.pubsub.publish` RPC requests
    /// back to the client.
    ///
    /// # Example
    /// ```no_run
    /// # use aafp_sdk::simple::Agent;
    /// # use aafp_sdk::pubsub::ConnectedAgentPubSubExt;
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let agent = Agent::connect().connect().await?;
    /// let mut events = agent.subscribe("translate.events").await?;
    /// while let Some(event) = events.next().await {
    ///     println!("event: {}", event?.body());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn subscribe(
        &self,
        topic: &str,
    ) -> Pin<Box<dyn Future<Output = Result<SubscriptionStream, SdkError>> + Send + '_>>;

    /// Publish an event to a PubSub topic (fire-and-forget).
    ///
    /// Sends an `aafp.pubsub.publish` RPC request to the remote peer.
    /// The peer's propagation driver forwards the message to all remote
    /// subscribers (floodsub, RFC-0009 §3.2).
    ///
    /// # Example
    /// ```no_run
    /// # use aafp_sdk::simple::Agent;
    /// # use aafp_sdk::pubsub::{Event, ConnectedAgentPubSubExt};
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let agent = Agent::connect().connect().await?;
    /// agent.publish("commands", Event::text("shutdown")).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn publish(
        &self,
        topic: &str,
        event: Event,
    ) -> Pin<Box<dyn Future<Output = Result<(), SdkError>> + Send + '_>>;

    /// Publish to a topic on a specific peer (by address).
    ///
    /// If `addr` is `None`, publishes locally (P1) or to the first pooled peer.
    /// If `addr` is `Some(addr)`, sends the publish RPC to that peer via
    /// `ConnectionPool::get_or_connect()`.
    fn publish_to(
        &self,
        topic: &str,
        event: Event,
        addr: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), SdkError>> + Send + '_>>;
}

// NOTE: The impl blocks for `ConnectedAgentPubSubExt` are intentionally
// omitted here. They will be implemented in `simple.rs` during the
// integration phase, once `ConnectedAgent` gains the `local_pubsub`
// field. The trait definition here serves as the contract / API surface
// stub.

// ─── Helper: compute seen list for a publish ───────────────────

/// Compute the initial `seen` list for a publish (includes our_id + from).
///
/// This is a trivial helper used by the propagation driver. It lives here
/// rather than in `bridge.rs` because it is a pure function with no
/// dependencies on `NetworkedPubSub` or `ConnectionPool`.
pub fn compute_seen_list(our_id: AgentId, from: AgentId) -> Vec<AgentId> {
    vec![our_id, from]
}
