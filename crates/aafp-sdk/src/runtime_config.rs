//! Tokio runtime configuration (Track L5).
//!
//! Allows choosing between `current_thread` and `multi_thread` Tokio runtimes.
//! For localhost RPC, `current_thread` eliminates cross-core scheduling overhead
//! (pthread_cond_signal/cvwait), which L1 profiling showed accounts for 84%
//! of time in the multi-thread runtime.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use aafp_sdk::RuntimeConfig;
//!
//! // Low-latency preset (single-thread, minimal stack)
//! let config = RuntimeConfig::low_latency();
//!
//! // High-throughput preset (multi-thread, default worker count)
//! let config = RuntimeConfig::high_throughput();
//!
//! // Custom
//! let config = RuntimeConfig {
//!     flavor: RuntimeFlavor::CurrentThread,
//!     worker_threads: 1,
//!     thread_stack_size: 2 * 1024 * 1024, // 2MB
//!     max_blocking_threads: 512,
//! };
//! ```

use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

/// Tokio runtime flavor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuntimeFlavor {
    /// Single-thread runtime — no cross-core scheduling.
    /// Best for localhost RPC (eliminates condvar signal/wait overhead).
    CurrentThread,
    /// Multi-thread runtime — work-stealing across cores.
    /// Best for production servers with concurrent connections.
    #[default]
    MultiThread,
}

/// Configuration for the Tokio runtime.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Runtime flavor (current_thread vs multi_thread).
    pub flavor: RuntimeFlavor,
    /// Number of worker threads (multi_thread only).
    /// 0 = use physical core count.
    pub worker_threads: usize,
    /// Thread stack size in bytes (default: 2MB instead of Tokio's 8MB).
    /// Smaller stack = better cache utilization.
    pub thread_stack_size: usize,
    /// Maximum blocking thread pool size.
    pub max_blocking_threads: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            flavor: RuntimeFlavor::MultiThread,
            worker_threads: 0, // 0 = auto-detect (physical core count)
            thread_stack_size: 2 * 1024 * 1024, // 2MB (down from Tokio's 8MB default)
            max_blocking_threads: 512,
        }
    }
}

impl RuntimeConfig {
    /// Low-latency preset for agent-to-agent RPC (Track L5).
    ///
    /// Uses `current_thread` runtime — eliminates cross-core scheduling
    /// overhead (pthread_cond_signal/cvwait). L1 profiling showed 84%
    /// of time was spent in condvar wait with the multi-thread runtime.
    ///
    /// Reduces stack size to 2MB (from 8MB default) for better cache.
    pub fn low_latency() -> Self {
        Self {
            flavor: RuntimeFlavor::CurrentThread,
            worker_threads: 1,
            thread_stack_size: 2 * 1024 * 1024, // 2MB
            max_blocking_threads: 512,
        }
    }

    /// High-throughput preset for production servers.
    ///
    /// Uses `multi_thread` runtime with auto-detected worker count.
    /// Best for servers handling many concurrent connections.
    pub fn high_throughput() -> Self {
        Self::default()
    }

    /// Build a Tokio `Runtime` from this configuration.
    pub fn build(&self) -> std::io::Result<Runtime> {
        let mut builder = match self.flavor {
            RuntimeFlavor::CurrentThread => Builder::new_current_thread(),
            RuntimeFlavor::MultiThread => {
                let mut b = Builder::new_multi_thread();
                if self.worker_threads > 0 {
                    b.worker_threads(self.worker_threads);
                }
                b
            }
        };

        builder
            .enable_all()
            .thread_stack_size(self.thread_stack_size)
            .max_blocking_threads(self.max_blocking_threads);

        builder.build()
    }

    /// Build an Arc<Runtime> for sharing across the application.
    pub fn build_shared(&self) -> std::io::Result<Arc<Runtime>> {
        self.build().map(Arc::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_multi_thread() {
        let config = RuntimeConfig::default();
        assert_eq!(config.flavor, RuntimeFlavor::MultiThread);
    }

    #[test]
    fn low_latency_is_current_thread() {
        let config = RuntimeConfig::low_latency();
        assert_eq!(config.flavor, RuntimeFlavor::CurrentThread);
        assert_eq!(config.worker_threads, 1);
        assert_eq!(config.thread_stack_size, 2 * 1024 * 1024);
    }

    #[test]
    fn build_current_thread_runtime() {
        let config = RuntimeConfig::low_latency();
        let runtime = config.build().unwrap();
        runtime.block_on(async { /* works */ });
    }

    #[test]
    fn build_multi_thread_runtime() {
        let config = RuntimeConfig::high_throughput();
        let runtime = config.build().unwrap();
        runtime.block_on(async { /* works */ });
    }

    #[test]
    fn build_shared_runtime() {
        let config = RuntimeConfig::low_latency();
        let runtime = config.build_shared().unwrap();
        runtime.block_on(async { /* works */ });
    }

    #[test]
    fn custom_worker_count() {
        let config = RuntimeConfig {
            flavor: RuntimeFlavor::MultiThread,
            worker_threads: 4,
            ..Default::default()
        };
        let runtime = config.build().unwrap();
        runtime.block_on(async { /* works */ });
    }
}
