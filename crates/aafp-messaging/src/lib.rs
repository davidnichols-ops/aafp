//! AAFP messaging layer: framing, stream multiplexing, RPC, and pubsub.
//!
//! ## Frame Format (RFC-0002 §3-4)
//! - **Framing**: 28-byte header + extensions + payload over QUIC streams.
//! - **Stream multiplexing**: each logical stream gets its own QUIC stream.
//! - **RPC**: request/response pattern with correlation IDs (integer CBOR keys).
//! - **Pubsub**: gossip-based topic subscription (stub for MVP).

pub mod close_manager;
pub mod extensions;
pub mod framing;
pub mod keepalive;
pub mod pipeline;
pub mod pubsub;
/// Legacy MVP RPC module. Uses serde with string keys — NOT RFC-compliant.
/// Use [`rpc_v1`] instead for wire serialization.
#[deprecated = "Use rpc_v1 instead. Legacy rpc uses serde/string keys, not RFC-compliant."]
#[allow(deprecated)]
pub mod rpc;
pub mod rpc_v1;
pub mod stream;

pub use close_manager::{
    CloseAction, CloseFrameDisposition, CloseManager, CloseManagerError, CloseState,
    DEFAULT_CLOSE_TIMEOUT, MAX_CLOSE_MESSAGE_LEN, MIN_CLOSE_TIMEOUT,
};
pub use extensions::{decode_extensions, encode_extensions, Extension, ExtensionError};
pub use framing::{
    decode_frame, encode_frame, Frame, FrameCodec, FrameError, FrameType, AAFP_VERSION,
    FRAME_HEADER_SIZE, MAX_EXTENSION_SIZE, MAX_PAYLOAD_SIZE,
};
pub use keepalive::{KeepAliveConfig, PingTracker};
pub use pipeline::{
    ExtensionCallback, FrameProcessingPipeline, PipelineContext, PipelineError, PipelinePhase,
    ProcessedFrame, TestingContext,
};
pub use pubsub::{PubSub, Topic, TopicMessage};
pub use rpc_v1::{CloseMessage, ErrorMessage, RpcError, RpcErrorObject, RpcRequest, RpcResponse};
pub use stream::{MessageStream, StreamId, StreamManager};
