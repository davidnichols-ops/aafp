//! Per-connection resource limits for PubSub (Phase P5).
//!
//! Enforces bounded resource usage per connection: maximum simultaneous
//! subscriptions, publish rate, and message size. These prevent a single
//! misbehaving or noisy peer from exhausting server resources.

use crate::pubsub::errors::PubSubError;
use aafp_identity::agent_id::AgentId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-connection resource limits for PubSub.
#[derive(Clone, Debug)]
pub struct ConnectionLimits {
    /// Maximum simultaneous subscriptions per connection (default 1024).
    pub max_subscriptions: usize,
    /// Maximum publish RPC calls per second per connection (default 100).
    pub max_publish_rate: u32,
    /// Maximum message payload size in bytes (default 1 MiB).
    pub max_message_size: usize,
    /// Maximum topic string length (default 256).
    pub max_topic_length: usize,
    /// Maximum topic hierarchy depth (default 16).
    pub max_topic_depth: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_subscriptions: 1024,
            max_publish_rate: 100,
            max_message_size: 1024 * 1024, // 1 MiB
            max_topic_length: 256,
            max_topic_depth: 16,
        }
    }
}

/// Tracks per-connection PubSub state for limit enforcement.
pub struct ConnectionState {
    /// Topics this connection is currently subscribed to.
    pub subscriptions: HashSet<String>,
    /// Rolling window of publish timestamps (for rate limiting).
    pub publish_timestamps: VecDeque<Instant>,
}

impl ConnectionState {
    /// Create empty per-connection state.
    pub fn new() -> Self {
        Self {
            subscriptions: HashSet::new(),
            publish_timestamps: VecDeque::new(),
        }
    }

    /// Check and record a publish; returns `Err(RateLimited)` if the
    /// per-second rate limit is exceeded.
    pub fn check_publish_rate(&mut self, limit: u32) -> Result<(), PubSubError> {
        let now = Instant::now();
        let window = Duration::from_secs(1);
        // Evict timestamps older than 1 second.
        while let Some(front) = self.publish_timestamps.front() {
            if now.duration_since(*front) > window {
                self.publish_timestamps.pop_front();
            } else {
                break;
            }
        }
        if self.publish_timestamps.len() >= limit as usize {
            return Err(PubSubError::RateLimited);
        }
        self.publish_timestamps.push_back(now);
        Ok(())
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Check that a message payload is within the configured size limit.
///
/// Returns `Err(MessageTooLarge)` (9010) if the payload exceeds
/// `max_message_size`.
pub fn check_message_size(data: &[u8], limits: &ConnectionLimits) -> Result<(), PubSubError> {
    if data.len() > limits.max_message_size {
        return Err(PubSubError::MessageTooLarge);
    }
    Ok(())
}

/// Map of peer `AgentId` -> `ConnectionState`, guarded by a `Mutex`.
pub type ConnectionStates = Arc<Mutex<HashMap<AgentId, ConnectionState>>>;
