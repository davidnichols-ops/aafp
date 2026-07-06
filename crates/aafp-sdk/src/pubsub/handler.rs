//! `PubSubRpcHandler` dispatch stub for `aafp.pubsub.*` methods.
//!
//! This module provides a thin wrapper around `aafp_messaging::PubSubRpcHandler`
//! that is suitable for integration into the `ServingAgent` handler dispatch
//! loop in `simple.rs`.
//!
//! The existing `aafp_messaging::PubSubRpcHandler` already dispatches
//! `aafp.pubsub.subscribe`, `aafp.pubsub.unsubscribe`, and
//! `aafp.pubsub.publish`. This module adds:
//!
//! 1. A [`PubSubRpcHandler`] newtype that holds an `Arc<NetworkedPubSub>`
//!    and provides a `dispatch()` method with a signature matching the
//!    `ServingAgent` handler loop's expectations.
//! 2. A [`dispatch_pubsub_rpc`] free function that can be called from the
//!    handler loop to intercept `aafp.pubsub.*` methods before the
//!    capability lookup.
//!
//! See `PS_P1_P2_API_PROPAGATION.md` Task 4 for the full design.

use std::sync::Arc;

use aafp_cbor::Value;
use aafp_identity::AgentId;
use aafp_messaging::{
    NetworkedPubSub, PubSubRpcHandler as MessagingPubSubRpcHandler, PubSubV1Error as PubSubError,
    METHOD_PUBLISH, METHOD_SUBSCRIBE, METHOD_UNSUBSCRIBE,
};

/// Prefix for all PubSub RPC methods.
pub const PUBSUB_METHOD_PREFIX: &str = "aafp.pubsub.";

/// Check whether an RPC method is a PubSub method (`aafp.pubsub.*`).
///
/// Used by the `ServingAgent` handler loop to decide whether to dispatch
/// to the PubSub handler before the capability lookup.
pub fn is_pubsub_method(method: &str) -> bool {
    method.starts_with(PUBSUB_METHOD_PREFIX)
}

/// Server-side handler for PubSub RPC requests (RFC-0009 §2).
///
/// Thin wrapper around `aafp_messaging::PubSubRpcHandler` that provides
/// a `dispatch()` method with a signature convenient for the
/// `ServingAgent` handler loop.
///
/// Created once (shared across connections) and used in the dispatch arm
/// for `aafp.pubsub.*` methods.
pub struct PubSubRpcHandler {
    /// The underlying messaging-layer handler.
    inner: Arc<MessagingPubSubRpcHandler>,
}

impl PubSubRpcHandler {
    /// Create a new handler wrapping the given PubSub instance.
    pub fn new(pubsub: Arc<NetworkedPubSub>) -> Self {
        Self {
            inner: Arc::new(MessagingPubSubRpcHandler::new(pubsub)),
        }
    }

    /// Create from an existing messaging-layer handler (for sharing).
    pub fn from_messaging(handler: Arc<MessagingPubSubRpcHandler>) -> Self {
        Self { inner: handler }
    }

    /// Get a reference to the underlying messaging-layer handler.
    pub fn inner(&self) -> &Arc<MessagingPubSubRpcHandler> {
        &self.inner
    }

    /// Dispatch an incoming PubSub RPC request.
    ///
    /// This is the main entry point called by the `ServingAgent` handler
    /// loop when `is_pubsub_method(rpc_req.method)` is true.
    ///
    /// # Arguments
    /// - `method`: The RPC method name (e.g. `aafp.pubsub.publish`).
    /// - `params`: The CBOR params value from the RPC request.
    /// - `caller_id`: The verified peer AgentId from the session.
    ///   (RFC-0009 §5: `from` is verified against the connection peer.)
    ///
    /// # Returns
    /// - `Ok(Value)`: The CBOR result value to send back as the RPC response.
    /// - `Err(PubSubError)`: An error to encode as an RPC error response.
    pub fn dispatch(
        &self,
        method: &str,
        params: &Value,
        caller_id: &AgentId,
    ) -> Result<Value, PubSubError> {
        self.inner.handle_request(method, params, caller_id)
    }
}

/// Free-function dispatch for `aafp.pubsub.*` RPC methods.
///
/// This is a convenience function that the `ServingAgent` handler loop can
/// call directly (without constructing a `PubSubRpcHandler` wrapper) when
/// it needs to handle a PubSub method inline.
///
/// **STUB**: The full integration in `simple.rs` will call this (or
/// `PubSubRpcHandler::dispatch`) from the handler loop, after decoding
/// the `RpcRequest` and before the capability lookup. See
/// `PS_P1_P2_API_PROPAGATION.md` Task 4 for the exact insertion point.
///
/// # Arguments
/// - `handler`: The PubSub RPC handler (wrapping `NetworkedPubSub`).
/// - `method`: The RPC method name.
/// - `params`: The CBOR params value.
/// - `caller_id`: The verified peer AgentId.
///
/// # Returns
/// - `Ok(Value)`: The CBOR result value for the RPC response.
/// - `Err(PubSubError)`: Error to encode as an RPC error response.
pub fn dispatch_pubsub_rpc(
    handler: &PubSubRpcHandler,
    method: &str,
    params: &Value,
    caller_id: &AgentId,
) -> Result<Value, PubSubError> {
    handler.dispatch(method, params, caller_id)
}

/// Check if a publish should be re-forwarded (TTL > 0).
///
/// After `PubSubRpcHandler::dispatch()` returns `Ok(value)` for
/// `METHOD_PUBLISH`, the handler loop should call this to determine
/// whether to notify the propagation driver for re-forwarding.
///
/// This decodes the `PublishParams` from the RPC params to check the TTL.
/// If TTL > 0, the message should be re-forwarded to other remote
/// subscribers (floodsub, RFC-0009 §3.2).
///
/// **STUB**: Returns `false` for now. The full implementation will
/// decode `PublishParams::from_cbor(params)` and return `params.ttl > 0`.
pub fn should_reforward_publish(params: &Value) -> bool {
    use aafp_messaging::PublishParams;
    match PublishParams::from_cbor(params) {
        Ok(pp) => pp.ttl > 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pubsub_method() {
        assert!(is_pubsub_method(METHOD_SUBSCRIBE));
        assert!(is_pubsub_method(METHOD_UNSUBSCRIBE));
        assert!(is_pubsub_method(METHOD_PUBLISH));
        assert!(!is_pubsub_method("translate"));
        assert!(!is_pubsub_method("aafp.call"));
    }

    #[test]
    fn test_handler_dispatch_subscribe() {
        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let handler = PubSubRpcHandler::new(Arc::clone(&pubsub));

        let params = aafp_cbor::int_map(vec![(1, aafp_cbor::Value::TextString("test".to_string()))]);
        let result = handler.dispatch(METHOD_SUBSCRIBE, &params, &[2u8; 32]);
        assert!(result.is_ok());

        // The remote subscriber should be tracked
        let subs = pubsub.remote_subscribers("test");
        assert_eq!(subs.len(), 1);
        assert!(subs.contains(&[2u8; 32]));
    }

    #[test]
    fn test_handler_dispatch_unknown_method() {
        let pubsub = Arc::new(NetworkedPubSub::new([1u8; 32]));
        let handler = PubSubRpcHandler::new(pubsub);

        let params = aafp_cbor::int_map(vec![]);
        let result = handler.dispatch("aafp.pubsub.bogus", &params, &[2u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_should_reforward_publish_ttl_positive() {
        use aafp_messaging::PublishParams;
        let params = PublishParams {
            topic: "test".to_string(),
            data: b"hello".to_vec(),
            ttl: 3,
            seen: vec![],
        };
        assert!(should_reforward_publish(&params.to_cbor()));
    }

    #[test]
    fn test_should_reforward_publish_ttl_zero() {
        use aafp_messaging::PublishParams;
        let params = PublishParams {
            topic: "test".to_string(),
            data: b"hello".to_vec(),
            ttl: 0,
            seen: vec![],
        };
        assert!(!should_reforward_publish(&params.to_cbor()));
    }
}
