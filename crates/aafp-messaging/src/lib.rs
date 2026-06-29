//! AAFP messaging layer: framing, stream multiplexing, RPC, and pubsub.
//!
//! ## Frame Format (RFC-0002 §3-4)
//! - **Framing**: 28-byte header + extensions + payload over QUIC streams.
//! - **Stream multiplexing**: each logical stream gets its own QUIC stream.
//! - **RPC**: request/response pattern with correlation IDs (integer CBOR keys).
//! - **Pubsub**: gossip-based topic subscription (stub for MVP).

pub mod extensions;
pub mod framing;
pub mod pubsub;
pub mod rpc;
pub mod rpc_v1;
pub mod stream;

pub use extensions::{decode_extensions, encode_extensions, Extension, ExtensionError};
pub use framing::{
    decode_frame, encode_frame, Frame, FrameCodec, FrameError, FrameType, AAFP_VERSION,
    FRAME_HEADER_SIZE, MAX_EXTENSION_SIZE, MAX_PAYLOAD_SIZE,
};
pub use pubsub::{PubSub, Topic, TopicMessage};
// v1 RFC-compliant types are the primary exports (integer keys, canonical CBOR).
// Legacy MVP types (rpc module) use serde with string keys and are NOT
// RFC-compliant. They are kept for backward compatibility but should not
// be used for wire serialization.
pub use rpc_v1::{
    CloseMessage, ErrorMessage, RpcError, RpcErrorObject, RpcRequest, RpcResponse,
};
// Legacy MVP types — NOT RFC-compliant. Use the v1 types above for wire format.
pub use rpc::{
    RpcClient as LegacyRpcClient, RpcRequest as LegacyRpcRequest,
    RpcResponse as LegacyRpcResponse, RpcServer as LegacyRpcServer,
};
pub use stream::{MessageStream, StreamId, StreamManager};
