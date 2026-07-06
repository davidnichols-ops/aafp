//! PubSub-specific error codes (RFC-0005 extension, Phase P5).
//!
//! These error codes extend the base RPC error space (RFC-0005) for the
//! PubSub back-channel (RFC-0009). They are returned in `RpcResponse` error
//! frames via `RpcResponse::error(code, message)`.

/// PubSub-specific error codes (RFC-0005 extension).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PubSubError {
    /// 9006: Topic does not exist or is malformed.
    TopicNotFound,
    /// 9007: Caller lacks `pubsub/<topic>/publish` capability.
    PublishDenied,
    /// 9008: Caller lacks `pubsub/<topic>/subscribe` capability or sub limit hit.
    SubscribeDenied,
    /// 9009: Publish rate limit exceeded for this connection.
    RateLimited,
    /// 9010: Message payload exceeds `max_message_size`.
    MessageTooLarge,
}

impl PubSubError {
    /// Numeric error code (RFC-0005 extension range 9006-9010).
    pub fn code(&self) -> u32 {
        match self {
            Self::TopicNotFound => 9006,
            Self::PublishDenied => 9007,
            Self::SubscribeDenied => 9008,
            Self::RateLimited => 9009,
            Self::MessageTooLarge => 9010,
        }
    }

    /// Human-readable error message.
    pub fn message(&self) -> &'static str {
        match self {
            Self::TopicNotFound => "topic not found or malformed",
            Self::PublishDenied => "publish denied: insufficient UCAN capability",
            Self::SubscribeDenied => "subscribe denied: insufficient capability or limit exceeded",
            Self::RateLimited => "publish rate limit exceeded",
            Self::MessageTooLarge => "message payload exceeds maximum size",
        }
    }
}

impl std::fmt::Display for PubSubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for PubSubError {}
