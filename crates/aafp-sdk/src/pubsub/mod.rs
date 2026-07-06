//! PubSub module — scaffolding for RFC-0009 PubSub integration.
//!
//! This module is **not** yet wired into `lib.rs` (no `pub mod pubsub;`).
//! It provides stub types and method signatures that will be integrated
//! into `simple.rs` in a subsequent build phase.
//!
//! ## Phase layout
//!
//! | Phase | Modules | Purpose |
//! |-------|---------|---------|
//! | P1-P2 | [`event`], [`subscription`], [`api`], [`bridge`], [`handler`] | Simple API surface + propagation driver |
//! | P3 | [`backchannel`] | Back-channel topic naming (RFC-0006 extension) |
//! | P4 | [`topic`], [`topic_matcher`] | MQTT-style hierarchical topics + wildcards |
//! | P5 | [`acl`], [`limits`], [`errors`] | UCAN ACLs, per-connection limits, error codes |
//! | P6 | [`gossipsub`] | GossipSub v1.1 router (replaces floodsub) |
//!
//! See `builder-prompts/PS_P1_P2_API_PROPAGATION.md` for the P1/P2 design.

// ── P1/P2: Simple API surface + propagation driver ──
pub mod api;
pub mod bridge;
pub mod event;
pub mod handler;
pub mod subscription;

// ── P3: back-channeling ──
pub mod backchannel;

// ── P4: hierarchical topic routing ──
pub mod topic;
pub mod topic_matcher;

// ── P5: security / UCAN + limits + error codes ──
pub mod acl;
pub mod errors;
pub mod limits;

// ── P6: GossipSub upgrade ──
pub mod gossipsub;

// Re-export the primary P1/P2 public types so that, once wired into `lib.rs`,
// consumers can access them as `aafp_sdk::pubsub::Event`, etc.
pub use api::{ConnectedAgentPubSubExt, OnPublishHandler, ServeBuilderPubSubExt};
pub use backchannel::{
    backchannel_topic, extract_backchannel_topic, frame_with_backchannel,
    generate_request_id, is_backchannel_topic, parse_backchannel_topic, EXT_BACKCHANNEL_TOPIC,
};
pub use bridge::PubSubBridge;
pub use event::Event;
pub use handler::PubSubRpcHandler;
pub use subscription::SubscriptionStream;
pub use topic::{
    check_reserved_prefix, split_topic, topic_matches, validate_filter, validate_publish_topic,
    MAX_TOPIC_DEPTH, MAX_TOPIC_LENGTH,
};
pub use topic_matcher::TopicMatcher;
