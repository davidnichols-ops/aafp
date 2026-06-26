//! Stream multiplexing: each logical stream maps to a QUIC bidirectional stream.

use crate::framing::{Frame, FrameCodec, FrameError};
use aafp_crypto::Aead;
use aafp_identity::AgentId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::codec::Framed;

/// Unique stream identifier.
pub type StreamId = u64;

/// A message stream wrapping a QUIC bidirectional stream with AEAD encryption.
pub struct MessageStream {
    pub id: StreamId,
    pub peer: AgentId,
    aead: Aead,
}

impl MessageStream {
    /// Create a new message stream with the given AEAD key.
    pub fn new(id: StreamId, peer: AgentId, aead: Aead) -> Self {
        Self { id, peer, aead }
    }

    /// Encrypt a plaintext message for sending.
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.aead.encrypt(nonce, aad, plaintext)
    }

    /// Decrypt a received ciphertext.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aafp_crypto::CryptoError> {
        self.aead.decrypt(nonce, aad, ciphertext)
    }

    /// Get the stream ID.
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get the peer's AgentId.
    pub fn peer(&self) -> &AgentId {
        &self.peer
    }
}

/// Manages active message streams for a connection.
pub struct StreamManager {
    streams: HashMap<StreamId, MessageStream>,
    next_id: StreamId,
}

impl StreamManager {
    /// Create a new stream manager.
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            next_id: 1,
        }
    }

    /// Register a new stream.
    pub fn add(&mut self, stream: MessageStream) {
        self.streams.insert(stream.id, stream);
    }

    /// Create and register a new stream.
    pub fn create(&mut self, peer: AgentId, aead: Aead) -> &MessageStream {
        let id = self.next_id;
        self.next_id += 1;
        let stream = MessageStream::new(id, peer, aead);
        self.streams.insert(id, stream);
        self.streams.get(&id).unwrap()
    }

    /// Get a stream by ID.
    pub fn get(&self, id: &StreamId) -> Option<&MessageStream> {
        self.streams.get(id)
    }

    /// Get a mutable stream by ID.
    pub fn get_mut(&mut self, id: &StreamId) -> Option<&mut MessageStream> {
        self.streams.get_mut(id)
    }

    /// Remove a stream.
    pub fn remove(&mut self, id: &StreamId) -> Option<MessageStream> {
        self.streams.remove(id)
    }

    /// Get the number of active streams.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Get all active stream IDs.
    pub fn active_ids(&self) -> Vec<StreamId> {
        self.streams.keys().copied().collect()
    }
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_crypto::{Aead, AeadAlgorithm};

    fn make_aead() -> Aead {
        Aead::new([0x42u8; 32], AeadAlgorithm::ChaCha20Poly1305)
    }

    #[test]
    fn create_and_get() {
        let mut mgr = StreamManager::new();
        let peer = [1u8; 32];
        let stream = mgr.create(peer, make_aead());
        assert_eq!(stream.id(), 1);
        assert!(mgr.get(&1).is_some());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn multiple_streams() {
        let mut mgr = StreamManager::new();
        let peer = [1u8; 32];
        mgr.create(peer, make_aead());
        mgr.create(peer, make_aead());
        mgr.create(peer, make_aead());
        assert_eq!(mgr.len(), 3);
        let mut ids = mgr.active_ids();
        ids.sort();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn remove_stream() {
        let mut mgr = StreamManager::new();
        let peer = [1u8; 32];
        mgr.create(peer, make_aead());
        assert_eq!(mgr.len(), 1);
        mgr.remove(&1);
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let peer = [1u8; 32];
        let stream = MessageStream::new(1, peer, make_aead());
        let nonce = [0u8; 12];
        let aad = b"stream-1";
        let pt = b"secret message";
        let ct = stream.encrypt(&nonce, aad, pt);
        let decrypted = stream.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }
}
