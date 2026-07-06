//! UCAN-based ACLs for PubSub topics (Phase P5).
//!
//! A PubSub UCAN capability is encoded as a CBOR text string in the
//! `Capability.resource` field, with `action` set to `"pubsub"`:
//!
//! ```text
//! "pubsub/<topic_filter>/<action>"
//! ```
//!
//! Where `<action>` is `publish` or `subscribe`, and `<topic_filter>` uses
//! MQTT-style wildcard syntax (`+` single-level, `#` multi-level).

use aafp_core::session::{AuthorizationContext, AuthorizationError, AuthorizationProvider};
use aafp_identity::agent_id::AgentId;
use aafp_identity::ucan::{Capability, UcanToken};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Action permitted on a topic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TopicAction {
    Publish,
    Subscribe,
}

impl TopicAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
        }
    }
}

/// Parsed pubsub capability: `pubsub/<filter>/<action>`.
#[derive(Clone, Debug)]
pub struct PubSubCapability {
    /// MQTT-style topic filter (e.g. `tasks.*`, `agents.A.inbox`, `rpc.A.#`).
    pub topic_filter: String,
    /// Whether this capability grants publish or subscribe.
    pub action: TopicAction,
}

impl PubSubCapability {
    /// Parse a capability resource string like `"pubsub/tasks.*/subscribe"`.
    ///
    /// Returns `None` if the string is not a valid pubsub capability.
    pub fn parse(resource: &str) -> Option<Self> {
        let rest = resource.strip_prefix("pubsub/")?;
        let last_slash = rest.rfind('/')?;
        let (filter, action_str) = rest.split_at(last_slash);
        let action_str = &action_str[1..]; // skip the '/'
        let action = match action_str {
            "publish" => TopicAction::Publish,
            "subscribe" => TopicAction::Subscribe,
            _ => return None,
        };
        Some(Self {
            topic_filter: filter.to_string(),
            action,
        })
    }

    /// Encode this capability back into the `pubsub/<filter>/<action>` form.
    pub fn encode(&self) -> String {
        format!("pubsub/{}/{}", self.topic_filter, self.action.as_str())
    }
}

/// UCAN-backed ACL for PubSub topics.
///
/// Stores verified UCAN tokens per agent. `check()` walks the agent's
/// capability chain and matches the requested `(topic, action)` against
/// any granted capability whose filter matches the topic.
pub struct TopicAcl {
    /// agent_id -> verified UCAN tokens (chain leaf tokens).
    grants: HashMap<AgentId, Vec<UcanToken>>,
}

impl TopicAcl {
    /// Create an empty ACL.
    pub fn new() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }

    /// Register a verified UCAN token granting pubsub capabilities to its
    /// audience.
    pub fn grant(&mut self, token: UcanToken) {
        if let Ok(aud_id) = aafp_identity::agent_id::agent_id_from_hex(&token.payload.aud) {
            self.grants.entry(aud_id).or_default().push(token);
        }
    }

    /// Check whether `caller` is authorized for `(topic, action)`.
    pub fn check(&self, caller: &AgentId, topic: &str, action: TopicAction) -> bool {
        let Some(tokens) = self.grants.get(caller) else {
            return false;
        };
        tokens.iter().any(|token| {
            token
                .payload
                .cap
                .iter()
                .any(|cap| Self::cap_matches(cap, topic, action))
        })
    }

    fn cap_matches(cap: &Capability, topic: &str, action: TopicAction) -> bool {
        let Some(psc) = PubSubCapability::parse(&cap.resource) else {
            return false;
        };
        psc.action == action && topic_matches(&psc.topic_filter, topic)
    }
}

impl Default for TopicAcl {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether a topic filter matches a concrete topic.
///
/// Supports MQTT-style wildcards: `+` (single level) and `#` (multi-level).
/// Delegates to `crate::pubsub::topic::topic_matches`.
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    crate::pubsub::topic::topic_matches(filter, topic)
}

/// Authorization context backed by the PubSub ACL.
pub struct AclAuthContext {
    caller: AgentId,
    acl: Arc<RwLock<TopicAcl>>,
}

impl AuthorizationContext for AclAuthContext {
    fn is_authorized(&self, capability: &str) -> bool {
        // capability is "pubsub/<topic>/<action>" or "pubsub.<topic>.<action>"
        let parsed = capability
            .strip_prefix("pubsub/")
            .or_else(|| capability.strip_prefix("pubsub."));
        let Some(rest) = parsed else {
            return false; // unknown capability prefix — default deny
        };
        let last_sep = rest.rfind(['/', '.']);
        let Some(idx) = last_sep else {
            return false; // no action separator — default deny
        };
        let (topic, action_str) = rest.split_at(idx);
        let action_str = &action_str[1..];
        let action = match action_str {
            "publish" => TopicAction::Publish,
            "subscribe" => TopicAction::Subscribe,
            _ => return false, // unknown action — default deny
        };
        let acl = self.acl.read().expect("acl lock poisoned");
        acl.check(&self.caller, topic, action)
    }
}

/// `AuthorizationProvider` implementation backed by `TopicAcl`.
///
/// Default policy when no ACL entry exists: `true` = allow (backward compat
/// with RFC-0009 §5), `false` = deny. Use [`with_default_deny`][Self::with_default_deny]
/// to switch to deny-by-default.
pub struct AclAuthorizationProvider {
    acl: Arc<RwLock<TopicAcl>>,
    /// Default policy when no ACL entry exists.
    default_allow: bool,
}

impl AclAuthorizationProvider {
    /// Create a new provider wrapping the given ACL (default-allow).
    pub fn new(acl: TopicAcl) -> Self {
        Self {
            acl: Arc::new(RwLock::new(acl)),
            default_allow: true,
        }
    }

    /// Switch to deny-by-default policy.
    pub fn with_default_deny(mut self) -> Self {
        self.default_allow = false;
        self
    }
}

#[async_trait::async_trait]
impl AuthorizationProvider for AclAuthorizationProvider {
    async fn authorize(
        &self,
        peer_agent_id: &AgentId,
        _peer_public_key: &[u8],
    ) -> Result<Box<dyn AuthorizationContext>, AuthorizationError> {
        Ok(Box::new(AclAuthContext {
            caller: *peer_agent_id,
            acl: Arc::clone(&self.acl),
        }))
    }
}

/// Authorize a publish request against the ACL provider.
///
/// Returns `Ok(())` if authorized, or `Err(())` if denied (caller maps to
/// `PubSubError::PublishDenied` / error code 9007).
pub async fn authorize_publish(
    acl: &AclAuthorizationProvider,
    caller: &AgentId,
    topic: &str,
) -> Result<(), ()> {
    let ctx = acl
        .authorize(caller, &[])
        .await
        .map_err(|_| ())?;
    if ctx.is_authorized(&format!("pubsub/{topic}/publish")) {
        Ok(())
    } else {
        Err(())
    }
}

/// Authorize a subscribe request against the ACL provider.
///
/// Returns `Ok(())` if authorized, or `Err(())` if denied (caller maps to
/// `PubSubError::SubscribeDenied` / error code 9008).
pub async fn authorize_subscribe(
    acl: &AclAuthorizationProvider,
    caller: &AgentId,
    topic: &str,
) -> Result<(), ()> {
    let ctx = acl
        .authorize(caller, &[])
        .await
        .map_err(|_| ())?;
    if ctx.is_authorized(&format!("pubsub/{topic}/subscribe")) {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubsub_capability_parse_publish() {
        let cap = PubSubCapability::parse("pubsub/tasks.*/publish").unwrap();
        assert_eq!(cap.topic_filter, "tasks.*");
        assert_eq!(cap.action, TopicAction::Publish);
    }

    #[test]
    fn test_pubsub_capability_parse_subscribe() {
        let cap = PubSubCapability::parse("pubsub/agents.A.inbox/subscribe").unwrap();
        assert_eq!(cap.topic_filter, "agents.A.inbox");
        assert_eq!(cap.action, TopicAction::Subscribe);
    }

    #[test]
    fn test_pubsub_capability_parse_invalid() {
        assert!(PubSubCapability::parse("not_pubsub").is_none());
        assert!(PubSubCapability::parse("pubsub/topic").is_none());
        assert!(PubSubCapability::parse("pubsub/topic/delete").is_none());
    }

    #[test]
    fn test_pubsub_capability_encode() {
        let cap = PubSubCapability::parse("pubsub/tasks.*/publish").unwrap();
        assert_eq!(cap.encode(), "pubsub/tasks.*/publish");
    }

    #[test]
    fn test_topic_acl_check_no_grants() {
        let acl = TopicAcl::new();
        let caller = [1u8; 32];
        assert!(!acl.check(&caller, "tasks/123", TopicAction::Publish));
    }

    #[test]
    fn test_topic_matches_exact() {
        assert!(topic_matches("tasks/123", "tasks/123"));
        assert!(!topic_matches("tasks/123", "tasks/456"));
    }

    #[test]
    fn test_topic_matches_wildcard() {
        assert!(topic_matches("tasks/+", "tasks/123"));
        assert!(topic_matches("agents/+/status", "agents/A/status"));
        assert!(!topic_matches("agents/+/status", "agents/A/inbox"));
    }
}
