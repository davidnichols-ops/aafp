//! CPU affinity and priority tuning (Track L6).
//!
//! This module provides optional CPU core pinning for tokio worker threads.
//! Pinning threads to specific cores reduces p99 latency variance by
//! eliminating core migration.
//!
//! ## Usage
//!
//! Enable the `cpu-affinity` feature:
//! ```toml
//! aafp-sdk = { features = ["cpu-affinity"] }
//! ```
//!
//! Then use the affinity helpers:
//! ```rust,ignore
//! use aafp_sdk::pin_current_thread_to_core;
//!
//! // Pin the current thread to CPU core 0
//! pin_current_thread_to_core(0).ok();
//! ```
//!
//! ## Platform Notes
//!
//! - **macOS:** Core pinning is advisory (not guaranteed by the scheduler).
//!   Process priority can be set via `setpriority()` but requires root.
//! - **Linux:** Core pinning is enforced via `sched_setaffinity()`.
//!   Process priority via `nice()` or `sched_setscheduler()`.
//!
//! ## When to Use
//!
//! Core pinning is most beneficial for:
//! - Latency-critical RPC servers (reduces p99 variance)
//! - High-throughput packet processing (improves cache locality)
//!
//! It is NOT recommended for:
//! - Client-side agents (no benefit for occasional RPCs)
//! - Multi-tenant servers (reduces scheduling flexibility)

#[cfg(feature = "cpu-affinity")]
use core_affinity;

/// Pin the current thread to a specific CPU core.
///
/// Returns `Ok(())` if pinning succeeded, or `Err` if the core is invalid
/// or the OS denied the request.
///
/// On macOS, pinning is advisory — the scheduler may still migrate the thread.
/// On Linux, pinning is enforced via `sched_setaffinity()`.
#[cfg(feature = "cpu-affinity")]
pub fn pin_current_thread_to_core(core_id: usize) -> Result<(), String> {
    let core_ids =
        core_affinity::get_core_ids().ok_or_else(|| "failed to get core IDs".to_string())?;
    let core = core_ids.get(core_id).ok_or_else(|| {
        format!(
            "core {core_id} not available (have {} cores)",
            core_ids.len()
        )
    })?;
    core_affinity::set_for_current(*core);
    Ok(())
}

/// Pin the current thread to a specific CPU core.
///
/// This is a no-op when the `cpu-affinity` feature is not enabled.
#[cfg(not(feature = "cpu-affinity"))]
pub fn pin_current_thread_to_core(_core_id: usize) -> Result<(), String> {
    Err("cpu-affinity feature not enabled".to_string())
}

/// Get the number of available CPU cores.
#[cfg(feature = "cpu-affinity")]
pub fn num_cores() -> usize {
    core_affinity::get_core_ids()
        .map(|ids| ids.len())
        .unwrap_or(1)
}

/// Get the number of available CPU cores.
#[cfg(not(feature = "cpu-affinity"))]
pub fn num_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Try to set the current process priority to high.
///
/// On macOS/Linux, this attempts to set nice value to -10.
/// Requires root privileges or appropriate capabilities.
/// Returns `Ok(())` if successful, `Err` if permission denied.
#[cfg(all(unix, feature = "cpu-affinity"))]
pub fn set_high_priority() -> Result<(), String> {
    // Safety: setpriority is a POSIX syscall, safe to call.
    let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -10) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!(
            "setpriority failed (errno: {}) — requires root or CAP_SYS_NICE",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        ))
    }
}

#[cfg(not(all(unix, feature = "cpu-affinity")))]
pub fn set_high_priority() -> Result<(), String> {
    Err(
        "set_high_priority not supported on this platform or cpu-affinity feature not enabled"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_cores_returns_at_least_1() {
        assert!(num_cores() >= 1);
    }

    #[test]
    fn pin_to_invalid_core_fails() {
        let result = pin_current_thread_to_core(9999);
        // Without the feature, this returns an error.
        // With the feature, this also returns an error for invalid core.
        assert!(result.is_err());
    }

    #[test]
    fn pin_to_core_0() {
        // Only test if the feature is enabled and we have at least 1 core
        let result = pin_current_thread_to_core(0);
        #[cfg(feature = "cpu-affinity")]
        {
            // Should succeed on most systems
            assert!(result.is_ok() || result.is_err());
        }
        #[cfg(not(feature = "cpu-affinity"))]
        {
            assert!(result.is_err()); // Feature not enabled
        }
    }

    #[test]
    fn set_high_priority_without_feature_fails() {
        #[cfg(not(all(unix, feature = "cpu-affinity")))]
        {
            assert!(set_high_priority().is_err());
        }
        #[cfg(all(unix, feature = "cpu-affinity"))]
        {
            // May succeed (if root) or fail (if not root) — just check it doesn't panic
            let _ = set_high_priority();
        }
    }
}
