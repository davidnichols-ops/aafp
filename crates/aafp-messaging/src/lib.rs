//! AAFP messaging layer: stream multiplexing, RPC, framing, and pubsub.
//!
//! ## Design (from AAFP_Architecture_Deliverable.md Phase 2.6)
//! - **Framing**: length-prefixed CBOR messages over QUIC streams.
//! - **Stream multiplexing**: each logical stream gets its own QUIC stream.
//! - **RPC**: request/response pattern with correlation IDs.
//! - **Pubsub**: gossip-based topic subscription (stub for MVP).

pub mod framing;
pub mod pubsub;
pub mod rpc;
pub mod stream;

pub use framing::{deserialize_frame, serialize_frame, Frame, FrameCodec, FrameError};
pub use pubsub::{PubSub, Topic, TopicMessage};
pub use rpc::{RpcClient, RpcRequest, RpcResponse, RpcServer};
pub use stream::{MessageStream, StreamId, StreamManager};
