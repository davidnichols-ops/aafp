//! Pubsub: topic-based publish/subscribe (stub for MVP).
//!
//! For MVP, this is a local in-memory pubsub. A production version would
//! implement gossipsub over QUIC streams.

use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PubSubError {
    #[error("topic not found")]
    TopicNotFound,
    #[error("broadcast error: {0}")]
    Broadcast(String),
}

/// A pubsub topic name.
pub type Topic = String;

/// A message published to a topic.
#[derive(Clone, Debug)]
pub struct TopicMessage {
    pub topic: Topic,
    pub from: AgentId,
    pub data: Vec<u8>,
}

/// In-memory pubsub system.
pub struct PubSub {
    topics: HashMap<Topic, broadcast::Sender<TopicMessage>>,
    /// Buffer size for each topic channel.
    buffer_size: usize,
}

impl PubSub {
    /// Create a new pubsub system.
    pub fn new() -> Self {
        Self {
            topics: HashMap::new(),
            buffer_size: 256,
        }
    }

    /// Create with a custom buffer size.
    pub fn with_buffer_size(buffer_size: usize) -> Self {
        Self {
            topics: HashMap::new(),
            buffer_size,
        }
    }

    /// Subscribe to a topic. Returns a receiver for messages.
    pub fn subscribe(&mut self, topic: &str) -> broadcast::Receiver<TopicMessage> {
        let buffer_size = self.buffer_size;
        let sender = self
            .topics
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(buffer_size).0);
        sender.subscribe()
    }

    /// Publish a message to a topic.
    pub fn publish(&self, topic: &str, from: AgentId, data: Vec<u8>) -> Result<(), PubSubError> {
        let sender = self
            .topics
            .get(topic)
            .ok_or(PubSubError::TopicNotFound)?;
        let msg = TopicMessage {
            topic: topic.to_string(),
            from,
            data,
        };
        sender
            .send(msg)
            .map(|_| ())
            .map_err(|e| PubSubError::Broadcast(e.to_string()))
    }

    /// Unsubscribe from a topic (by dropping the receiver).
    pub fn drop_topic(&mut self, topic: &str) {
        self.topics.remove(topic);
    }

    /// List all active topics.
    pub fn topics(&self) -> Vec<&str> {
        self.topics.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of subscribers for a topic.
    pub fn subscriber_count(&self, topic: &str) -> usize {
        self.topics
            .get(topic)
            .map(|s| s.receiver_count())
            .unwrap_or(0)
    }
}

impl Default for PubSub {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;
    use std::time::Duration;

    #[tokio::test]
    async fn subscribe_and_publish() {
        let mut pubsub = PubSub::new();
        let mut rx = pubsub.subscribe("test-topic");
        let from = [1u8; 32];

        pubsub.publish("test-topic", from, b"hello".to_vec()).unwrap();

        let msg = timeout(Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
        assert_eq!(msg.topic, "test-topic");
        assert_eq!(msg.from, from);
        assert_eq!(msg.data, b"hello");
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let mut pubsub = PubSub::new();
        let mut rx1 = pubsub.subscribe("topic");
        let mut rx2 = pubsub.subscribe("topic");
        let from = [1u8; 32];

        pubsub.publish("topic", from, b"msg".to_vec()).unwrap();

        let msg1 = timeout(Duration::from_secs(1), rx1.recv()).await.unwrap().unwrap();
        let msg2 = timeout(Duration::from_secs(1), rx2.recv()).await.unwrap().unwrap();
        assert_eq!(msg1.data, b"msg");
        assert_eq!(msg2.data, b"msg");
        assert_eq!(pubsub.subscriber_count("topic"), 2);
    }

    #[tokio::test]
    async fn publish_nonexistent_topic() {
        let pubsub = PubSub::new();
        assert!(pubsub.publish("no-topic", [1u8; 32], vec![]).is_err());
    }

    #[tokio::test]
    async fn drop_topic() {
        let mut pubsub = PubSub::new();
        pubsub.subscribe("topic");
        assert_eq!(pubsub.topics().len(), 1);
        pubsub.drop_topic("topic");
        assert_eq!(pubsub.topics().len(), 0);
    }

    #[tokio::test]
    async fn multiple_topics() {
        let mut pubsub = PubSub::new();
        let mut rx1 = pubsub.subscribe("topic1");
        let mut rx2 = pubsub.subscribe("topic2");
        let from = [1u8; 32];

        pubsub.publish("topic1", from, b"a".to_vec()).unwrap();
        pubsub.publish("topic2", from, b"b".to_vec()).unwrap();

        let msg1 = timeout(Duration::from_secs(1), rx1.recv()).await.unwrap().unwrap();
        let msg2 = timeout(Duration::from_secs(1), rx2.recv()).await.unwrap().unwrap();
        assert_eq!(msg1.data, b"a");
        assert_eq!(msg2.data, b"b");
    }
}
