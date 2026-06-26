//! Error types for the AAFP core layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("dial error: {0}")]
    Dial(String),
    #[error("listen error: {0}")]
    Listen(String),
    #[error("not connected to peer")]
    NotConnected,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
