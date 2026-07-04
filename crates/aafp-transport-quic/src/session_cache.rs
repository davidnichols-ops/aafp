//! TLS session ticket cache for connection resumption (Track I1).
//!
//! Provides a shared, thread-safe TLS session ticket store that persists
//! across multiple `dial()` calls on the same `QuicTransport`. This enables
//! TLS 1.3 session resumption: the first connection to a server performs a
//! full TLS handshake, and subsequent connections to the same server can
//! reuse the cached session ticket, skipping the expensive key exchange.
//!
//! ## How it works
//!
//! 1. The server sends TLS 1.3 NewSessionTicket messages after a successful
//!    handshake (rustls default: 2 tickets per connection).
//! 2. The client stores these tickets in the `SessionCache` (keyed by SNI).
//! 3. On the next `dial()` to the same server, the client presents the
//!    cached ticket, allowing the server to resume the session without a
//!    full key exchange.
//! 4. The AAFP application-layer handshake still runs after TLS resumption
//!    — only the TLS KEX is skipped. Identity verification (ML-DSA-65) is
//!    not affected.
//!
//! ## Security
//!
//! - Session tickets are encrypted by the server's ticket encryption key.
//! - Tickets are single-use (TLS 1.3 spec) — each ticket can resume one
//!   session. The server sends multiple tickets to allow multiple resumptions.
//! - 0-RTT early data is NOT enabled (replay attack risk). The client still
//!   waits for the server's response before sending application data.
//! - The AAFP handshake (ML-DSA-65 identity verification) runs after TLS
//!   resumption, so agent identity is still authenticated.
//!
//! ## Memory
//!
//! The cache uses rustls's built-in `ClientSessionMemoryCache` with LRU
//! eviction. Default size: 1024 entries (~200KB max). Configurable.

use rustls::client::ClientSessionStore;
use std::sync::Arc;

/// Default cache size (number of server entries).
///
/// Each entry stores up to `MAX_TLS13_TICKETS_PER_SERVER` (4) TLS 1.3
/// tickets. 1024 entries × ~200 bytes = ~200KB max memory.
pub const DEFAULT_SESSION_CACHE_SIZE: usize = 1024;

/// A TLS session ticket cache for clients (Track I1).
///
/// Wraps rustls's built-in `ClientSessionMemoryCache` with a configurable
/// size. The cache is shared across all `dial()` calls on the same
/// `QuicTransport`, enabling TLS 1.3 session resumption.
///
/// Created via [`SessionCache::new()`] or [`SessionCache::with_size()`],
/// and passed to [`QuicConfig::build_client_config_with_resumption()`].
///
/// [`QuicConfig::build_client_config_with_resumption()`]: crate::config::QuicConfig::build_client_config_with_resumption
#[derive(Debug, Clone)]
pub struct SessionCache {
    store: Arc<dyn ClientSessionStore>,
    size: usize,
}

impl SessionCache {
    /// Create a new session cache with the default size (1024 entries).
    pub fn new() -> Self {
        Self::with_size(DEFAULT_SESSION_CACHE_SIZE)
    }

    /// Create a new session cache with a custom size.
    ///
    /// `size` is the maximum number of server entries. Each entry can hold
    /// multiple TLS 1.3 tickets (up to 4 per server).
    pub fn with_size(size: usize) -> Self {
        let store = rustls::client::ClientSessionMemoryCache::new(size);
        Self {
            store: Arc::new(store),
            size,
        }
    }

    /// Get the underlying session store (for use with rustls `Resumption`).
    pub fn store(&self) -> Arc<dyn ClientSessionStore> {
        self.store.clone()
    }

    /// Get the configured cache size.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cache_default_size() {
        let cache = SessionCache::new();
        assert_eq!(cache.size(), DEFAULT_SESSION_CACHE_SIZE);
    }

    #[test]
    fn session_cache_custom_size() {
        let cache = SessionCache::with_size(256);
        assert_eq!(cache.size(), 256);
    }

    #[test]
    fn session_cache_store_is_clonable() {
        let cache = SessionCache::new();
        let store1 = cache.store();
        let store2 = cache.store();
        // Both should point to the same underlying store (Arc clone).
        assert!(Arc::ptr_eq(&store1, &store2));
    }

    #[test]
    fn session_cache_clone_shares_store() {
        let cache1 = SessionCache::new();
        let cache2 = cache1.clone();
        // Cloned SessionCache should share the same underlying store.
        assert!(Arc::ptr_eq(&cache1.store, &cache2.store));
    }
}
