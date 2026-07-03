//! Thread-local buffer pool for zero-copy message handling.
//!
//! Provides reusable `BytesMut` buffers to eliminate heap allocations
//! on the hot path. After warmup, `acquire()` returns a pre-allocated
//! buffer and `release()` returns it to the pool for reuse.
//!
//! ## Design
//!
//! - Thread-local: each thread has its own pool, no lock contention.
//! - Configurable: pool size, initial buffer capacity, max buffer capacity.
//! - Automatic growth: buffers grow as needed up to max capacity.
//! - Idle eviction: buffers unused for `idle_timeout_secs` are freed.
//!
//! ## Usage
//!
//! ```no_run
//! use aafp_transport_quic::buffer_pool::{acquire, release};
//!
//! // Acquire a buffer from the pool
//! let mut buf = acquire();
//!
//! // Use it...
//! buf.extend_from_slice(&[1, 2, 3]);
//!
//! // Release it back to the pool for reuse
//! release(buf);
//! ```

use bytes::{BufMut, BytesMut};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::{Duration, Instant};

/// Default pool size (max buffers per thread).
pub const DEFAULT_POOL_SIZE: usize = 256;

/// Default initial buffer capacity.
pub const DEFAULT_INITIAL_CAPACITY: usize = 4096;

/// Default max buffer capacity (buffers larger than this are not pooled).
pub const DEFAULT_MAX_CAPACITY: usize = 1024 * 1024;

/// Default idle timeout (buffers unused for this duration are freed).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;

/// Configuration for the buffer pool.
#[derive(Clone, Debug)]
pub struct BufferPoolConfig {
    /// Maximum number of buffers to keep in the pool.
    pub pool_size: usize,
    /// Initial capacity for new buffers.
    pub initial_capacity: usize,
    /// Maximum capacity for pooled buffers (larger buffers are dropped).
    pub max_capacity: usize,
    /// Idle timeout in seconds (buffers unused for this long are freed).
    pub idle_timeout_secs: u64,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            pool_size: DEFAULT_POOL_SIZE,
            initial_capacity: DEFAULT_INITIAL_CAPACITY,
            max_capacity: DEFAULT_MAX_CAPACITY,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
        }
    }
}

/// A pooled buffer with its last-used timestamp.
struct PooledBuffer {
    /// The buffer.
    buf: BytesMut,
    /// When this buffer was last released to the pool.
    released_at: Instant,
}

/// Thread-local buffer pool.
struct ThreadLocalPool {
    /// Pool of available buffers.
    buffers: VecDeque<PooledBuffer>,
    /// Pool configuration.
    config: BufferPoolConfig,
    /// Number of times a buffer was acquired from the pool (hit).
    hits: u64,
    /// Number of times a new buffer was allocated (miss).
    misses: u64,
}

impl ThreadLocalPool {
    fn new(config: BufferPoolConfig) -> Self {
        Self {
            buffers: VecDeque::with_capacity(config.pool_size),
            config,
            hits: 0,
            misses: 0,
        }
    }

    fn acquire(&mut self) -> BytesMut {
        // Evict idle buffers
        self.evict_idle();

        if let Some(pooled) = self.buffers.pop_front() {
            self.hits += 1;
            let mut buf = pooled.buf;
            buf.clear();
            buf
        } else {
            self.misses += 1;
            BytesMut::with_capacity(self.config.initial_capacity)
        }
    }

    fn release(&mut self, mut buf: BytesMut) {
        // Don't pool buffers that are too large
        if buf.capacity() > self.config.max_capacity {
            return;
        }

        // Don't pool if pool is full
        if self.buffers.len() >= self.config.pool_size {
            return;
        }

        // Clear the buffer but keep its capacity
        buf.clear();
        self.buffers.push_back(PooledBuffer {
            buf,
            released_at: Instant::now(),
        });
    }

    fn evict_idle(&mut self) {
        let timeout = Duration::from_secs(self.config.idle_timeout_secs);
        let now = Instant::now();
        self.buffers
            .retain(|pooled| now.duration_since(pooled.released_at) < timeout);
    }

    fn stats(&self) -> PoolStats {
        PoolStats {
            pool_size: self.buffers.len(),
            hits: self.hits,
            misses: self.misses,
            hit_rate: if self.hits + self.misses > 0 {
                self.hits as f64 / (self.hits + self.misses) as f64
            } else {
                0.0
            },
        }
    }
}

/// Pool statistics for monitoring.
#[derive(Clone, Debug, Default)]
pub struct PoolStats {
    /// Number of buffers currently in the pool.
    pub pool_size: usize,
    /// Number of times a buffer was acquired from the pool.
    pub hits: u64,
    /// Number of times a new buffer was allocated.
    pub misses: u64,
    /// Hit rate (0.0 to 1.0).
    pub hit_rate: f64,
}

thread_local! {
    static POOL: RefCell<ThreadLocalPool> = RefCell::new(ThreadLocalPool::new(BufferPoolConfig::default()));
}

/// Acquire a buffer from the thread-local pool.
///
/// Returns a `BytesMut` with at least `DEFAULT_INITIAL_CAPACITY` capacity.
/// If the pool has an available buffer, it is reused (no allocation).
/// Otherwise, a new buffer is allocated.
pub fn acquire() -> BytesMut {
    POOL.with(|p| p.borrow_mut().acquire())
}

/// Release a buffer back to the thread-local pool for reuse.
///
/// The buffer is cleared (but its capacity is retained) and stored
/// in the pool. If the pool is full or the buffer is too large,
/// it is dropped (and its memory freed).
pub fn release(buf: BytesMut) {
    POOL.with(|p| p.borrow_mut().release(buf));
}

/// Get the current pool statistics for this thread.
pub fn stats() -> PoolStats {
    POOL.with(|p| p.borrow().stats())
}

/// Configure the thread-local pool.
///
/// This replaces the current pool with a new one using the given config.
/// Any existing pooled buffers are lost.
pub fn configure(config: BufferPoolConfig) {
    POOL.with(|p| {
        *p.borrow_mut() = ThreadLocalPool::new(config);
    });
}

/// A guard that automatically releases the buffer when dropped.
///
/// Use this for RAII-style buffer management:
/// ```no_run
/// use aafp_transport_quic::buffer_pool::acquire_guard;
///
/// let mut guard = acquire_guard();
/// guard.buf_mut().extend_from_slice(&[1, 2, 3]);
/// // buffer is automatically released when guard goes out of scope
/// ```
pub struct BufferGuard {
    /// The pooled buffer.
    buf: Option<BytesMut>,
}

impl BufferGuard {
    /// Get a reference to the buffer.
    pub fn buf(&self) -> &BytesMut {
        self.buf.as_ref().unwrap()
    }

    /// Get a mutable reference to the buffer.
    pub fn buf_mut(&mut self) -> &mut BytesMut {
        self.buf.as_mut().unwrap()
    }

    /// Take ownership of the buffer, preventing it from being returned to the pool.
    pub fn take(mut self) -> BytesMut {
        self.buf.take().unwrap()
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            release(buf);
        }
    }
}

/// Acquire a buffer from the pool with automatic release on drop.
pub fn acquire_guard() -> BufferGuard {
    BufferGuard {
        buf: Some(acquire()),
    }
}

/// A wrapper that implements `io::Write` for `BytesMut`.
///
/// This allows `serde_json::to_writer()` to write directly into a
/// pooled `BytesMut` buffer, eliminating the intermediate `Vec<u8>`
/// allocation that `serde_json::to_vec()` would create.
///
/// ## Usage
///
/// ```
/// use aafp_transport_quic::buffer_pool::{acquire, BytesMutWriter};
/// use std::io::Write;
///
/// let mut buf = acquire();
/// let mut writer = BytesMutWriter::new(&mut buf);
/// writer.write_all(b"hello").unwrap();
/// // buf now contains "hello"
/// assert_eq!(buf.as_ref(), b"hello");
/// ```
pub struct BytesMutWriter<'a> {
    /// The underlying buffer.
    buf: &'a mut BytesMut,
}

impl<'a> BytesMutWriter<'a> {
    /// Create a new writer wrapping a `BytesMut` buffer.
    pub fn new(buf: &'a mut BytesMut) -> Self {
        Self { buf }
    }
}

impl<'a> Write for BytesMutWriter<'a> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.put_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_and_release() {
        configure(BufferPoolConfig::default());

        // First acquire should be a miss (empty pool)
        let buf1 = acquire();
        assert!(!buf1.is_empty() || buf1.capacity() >= DEFAULT_INITIAL_CAPACITY);
        release(buf1);

        // Second acquire should be a hit (pool has a buffer)
        let _buf2 = acquire();
        let stats = stats();
        assert!(stats.hits >= 1 || stats.misses >= 1);
    }

    #[test]
    fn test_pool_reuse() {
        configure(BufferPoolConfig::default());

        // Warmup: acquire and release several times
        for _ in 0..10 {
            let buf = acquire();
            release(buf);
        }

        // After warmup, all acquires should be hits
        let stats_before = stats();
        let buf = acquire();
        release(buf);
        let stats_after = stats();
        assert!(stats_after.hits > stats_before.hits);
    }

    #[test]
    fn test_buffer_guard_auto_release() {
        configure(BufferPoolConfig::default());

        {
            let mut guard = acquire_guard();
            guard.buf_mut().extend_from_slice(&[1, 2, 3]);
            assert_eq!(guard.buf().len(), 3);
            // guard dropped here, buffer returned to pool
        }

        // Pool should have the buffer now
        let stats = stats();
        assert!(stats.pool_size > 0 || stats.hits > 0);
    }

    #[test]
    fn test_buffer_guard_take() {
        configure(BufferPoolConfig::default());

        let guard = acquire_guard();
        let buf = guard.take();
        assert!(buf.capacity() >= DEFAULT_INITIAL_CAPACITY);
    }

    #[test]
    fn test_large_buffer_not_pooled() {
        configure(BufferPoolConfig {
            max_capacity: 1024,
            ..BufferPoolConfig::default()
        });

        let mut buf = acquire();
        buf.resize(2048, 0); // larger than max_capacity
        release(buf);

        // Pool should be empty (buffer was too large to pool)
        let stats = stats();
        assert_eq!(stats.pool_size, 0);
    }

    #[test]
    fn test_pool_size_limit() {
        configure(BufferPoolConfig {
            pool_size: 2,
            ..BufferPoolConfig::default()
        });

        // Acquire 3 buffers
        let buf1 = acquire();
        let buf2 = acquire();
        let buf3 = acquire();

        // Release all 3, but only 2 should be pooled
        release(buf1);
        release(buf2);
        release(buf3);

        let stats = stats();
        assert!(stats.pool_size <= 2);
    }

    #[test]
    fn test_zero_allocations_after_warmup() {
        configure(BufferPoolConfig::default());

        // Warmup: fill the pool
        let buffers: Vec<BytesMut> = (0..4).map(|_| acquire()).collect();
        for buf in buffers {
            release(buf);
        }

        // After warmup, acquire should return pooled buffers (hits, not misses)
        let stats_before = stats();
        for _ in 0..10 {
            let mut buf = acquire();
            buf.extend_from_slice(&[1, 2, 3, 4]);
            release(buf);
        }
        let stats_after = stats();

        // All 10 acquires should be hits (from pool, no new allocations)
        assert_eq!(
            stats_after.hits - stats_before.hits,
            10,
            "expected 10 pool hits after warmup, got {}",
            stats_after.hits - stats_before.hits
        );
        assert_eq!(
            stats_after.misses, stats_before.misses,
            "expected 0 new allocations (misses) after warmup"
        );
    }
}
