//! AAFP messaging layer: framing, stream multiplexing, RPC, and pubsub.
//!
//! ## Frame Format (RFC-0002 §3-4)
//! - **Framing**: 24-byte header + extensions + payload over QUIC streams.
//! - **Stream multiplexing**: each logical stream gets its own QUIC stream.
//! - **RPC**: request/response pattern with correlation IDs (integer CBOR keys).
//! - **Pubsub**: gossip-based topic subscription (stub for MVP).

pub mod extensions;
pub mod framing;
pub mod pubsub;
pub mod rpc;
pub mod stream;

pub use extensions::{decode_extensions, encode_extensions, Extension, ExtensionError};
pub use framing::{
    decode_frame, encode_frame, Frame, FrameCodec, FrameError, FrameType, AAFP_VERSION,
    FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};
pub use pubsub::{PubSub, Topic, TopicMessage};
pub use rpc::{RpcClient, RpcRequest, RpcResponse, RpcServer};
pub use stream::{MessageStream, StreamId, StreamManager};
