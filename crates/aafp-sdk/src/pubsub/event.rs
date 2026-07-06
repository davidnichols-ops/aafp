//! `Event` type — ergonomic PubSub event wrapper.
//!
//! Mirrors `Request`/`Response` ergonomics and wraps `aafp_messaging::TopicMessage`.
//! Carries the topic name, publisher AgentId, timestamp, and payload (text or binary).
//!
//! See `PS_P1_P2_API_PROPAGATION.md` Task 1 for the full design.

use std::time::SystemTime;

use aafp_identity::AgentId;

/// A PubSub event delivered to a subscriber.
///
/// Wraps `aafp_messaging::TopicMessage` with ergonomic accessors matching
/// the `Request`/`Response` pattern. Carries the topic name, the publisher's
/// AgentId, a timestamp, and the payload (text or binary).
///
/// # Example
/// ```
/// use aafp_sdk::pubsub::Event;
///
/// let ev = Event::text("hello");
/// assert_eq!(ev.body(), "hello");
/// assert_eq!(ev.payload(), None);
/// ```
#[derive(Debug, Clone)]
pub struct Event {
    /// The topic this event was published to.
    topic: String,
    /// The AgentId of the publisher.
    from: AgentId,
    /// Unix timestamp (seconds) when the event was created/published.
    timestamp: u64,
    /// Optional text body (human-readable events).
    text: String,
    /// Optional binary payload (structured CBOR, raw bytes).
    data: Option<Vec<u8>>,
}

impl Event {
    /// Create a text event (v1 compat, like `Request::text`).
    ///
    /// The `topic` and `from` fields are left empty/zero and should be
    /// set via [`Event::with_topic`] / [`Event::with_from`] when constructing
    /// from a wire message.
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            topic: String::new(),
            from: [0u8; 32],
            timestamp: now_unix(),
            text: s.into(),
            data: None,
        }
    }

    /// Create a binary data event.
    ///
    /// The `topic` and `from` fields are left empty/zero and should be
    /// set via [`Event::with_topic`] / [`Event::with_from`] when constructing
    /// from a wire message.
    pub fn data(d: Vec<u8>) -> Self {
        Self {
            topic: String::new(),
            from: [0u8; 32],
            timestamp: now_unix(),
            text: String::new(),
            data: Some(d),
        }
    }

    /// Set the topic (used internally when constructing from a `TopicMessage`).
    pub fn with_topic(mut self, topic: impl Into<String>) -> Self {
        self.topic = topic.into();
        self
    }

    /// Set the publisher AgentId (used internally).
    pub fn with_from(mut self, from: AgentId) -> Self {
        self.from = from;
        self
    }

    /// Get the topic this event was published to.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Get the publisher's AgentId.
    pub fn from(&self) -> AgentId {
        self.from
    }

    /// Get the Unix timestamp (seconds).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the text body (v1 compat).
    pub fn body(&self) -> &str {
        &self.text
    }

    /// Get the binary payload, if any.
    pub fn payload(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Encode the event to bytes for publishing (prefers text, falls back to data).
    ///
    /// This is the inverse of [`Event::from_topic_message`]: the returned
    /// bytes become the `data` field of a `PublishParams` / `TopicMessage`.
    pub fn encode_payload(&self) -> Vec<u8> {
        if let Some(data) = &self.data {
            data.clone()
        } else {
            self.text.as_bytes().to_vec()
        }
    }

    /// Decode an event from a `TopicMessage` (received from the wire or locally).
    ///
    /// Heuristic: try to interpret the payload as UTF-8 text; if it fails,
    /// treat it as binary. This matches how `simple.rs` decodes RPC params
    /// (`TextString` vs `ByteString`). For P1/P2 this is sufficient;
    /// structured CBOR payloads are a future extension (design doc §4.2).
    ///
    /// **STUB**: The full implementation will extract `topic` and `from`
    /// from the `TopicMessage` and apply the text/binary heuristic to `data`.
    /// The `timestamp` is set to the current time (the wire format does not
    /// carry a timestamp — it is inferred at receive time).
    pub fn from_topic_message(msg: &aafp_messaging::pubsub_v1::TopicMessage) -> Self {
        // Heuristic: try to interpret as UTF-8 text; if it fails, treat as binary.
        let text = String::from_utf8(msg.data.clone()).unwrap_or_default();
        let data = if String::from_utf8(msg.data.clone()).is_ok() {
            None
        } else {
            Some(msg.data.clone())
        };
        Self {
            topic: msg.topic.clone(),
            from: msg.from,
            timestamp: now_unix(),
            text,
            data,
        }
    }
}

/// Helper: current Unix timestamp in seconds.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_text() {
        let ev = Event::text("hello");
        assert_eq!(ev.body(), "hello");
        assert_eq!(ev.payload(), None);
        assert_eq!(ev.encode_payload(), b"hello".to_vec());
    }

    #[test]
    fn test_event_data() {
        let ev = Event::data(vec![1, 2, 3]);
        assert_eq!(ev.payload(), Some(&[1u8, 2, 3][..]));
        assert_eq!(ev.encode_payload(), vec![1, 2, 3]);
    }

    #[test]
    fn test_event_with_topic_and_from() {
        let ev = Event::text("hi")
            .with_topic("test.topic")
            .with_from([42u8; 32]);
        assert_eq!(ev.topic(), "test.topic");
        assert_eq!(ev.from(), [42u8; 32]);
    }

    #[test]
    fn test_event_from_topic_message_text() {
        let msg = aafp_messaging::pubsub_v1::TopicMessage {
            topic: "test.topic".to_string(),
            from: [42u8; 32],
            data: b"hello world".to_vec(),
        };
        let ev = Event::from_topic_message(&msg);
        assert_eq!(ev.topic(), "test.topic");
        assert_eq!(ev.from(), [42u8; 32]);
        assert_eq!(ev.body(), "hello world");
        assert_eq!(ev.payload(), None);
    }

    #[test]
    fn test_event_from_topic_message_binary() {
        let msg = aafp_messaging::pubsub_v1::TopicMessage {
            topic: "bin.topic".to_string(),
            from: [7u8; 32],
            data: vec![0xff, 0xfe, 0x00],
        };
        let ev = Event::from_topic_message(&msg);
        assert_eq!(ev.topic(), "bin.topic");
        assert_eq!(ev.from(), [7u8; 32]);
        assert_eq!(ev.payload(), Some(&[0xff, 0xfe, 0x00][..]));
    }
}
