//! Allocation tracking for benchmarks.
//!
//! Provides a global allocator wrapper that counts allocations and
//! deallocations, enabling per-benchmark allocation profiling.
//!
//! ## Usage
//!
//! In your benchmark or test binary, set the global allocator:
//!
//! ```no_run
//! use aafp_benchmark::alloc_tracker::CountingAllocator;
//! #[global_allocator]
//! static ALLOC: CountingAllocator = CountingAllocator;
//!
//! use aafp_benchmark::alloc_tracker::track_allocs;
//!
//! let report = track_allocs(|| {
//!     let v = vec![0u8; 1024];
//!     v
//! });
//! assert!(report.alloc_count >= 1);
//! assert!(report.bytes_allocated >= 1024);
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Global allocation counter.
///
/// Wraps the system allocator and atomically counts all allocations
/// and deallocations. Use `reset()` before a measurement and
/// `snapshot()` after to get the delta.
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BYTES_DEALLOCATED: AtomicUsize = AtomicUsize::new(0);
static TRACKING_ENABLED: AtomicUsize = AtomicUsize::new(0);

/// Mutex to serialize tracking operations (prevents test interference).
static TRACKING_MUTEX: Mutex<()> = Mutex::new(());

/// Counting allocator wrapper.
///
/// Set this as your `#[global_allocator]` to enable allocation tracking.
pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING_ENABLED.load(Ordering::Relaxed) == 1 {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            BYTES_ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACKING_ENABLED.load(Ordering::Relaxed) == 1 {
            DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            BYTES_DEALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        System.dealloc(ptr, layout);
    }
}

/// Set the global allocator to the counting allocator.
///
/// Call this at the start of your benchmark binary (or use `#[global_allocator]`).
/// This macro expands to a `#[global_allocator]` declaration.
#[macro_export]
macro_rules! setup_counting_allocator {
    () => {
        #[global_allocator]
        static GLOBAL_ALLOC: $crate::alloc_tracker::CountingAllocator =
            $crate::alloc_tracker::CountingAllocator;
    };
}

/// Snapshot of allocation counters at a point in time.
#[derive(Clone, Debug, Default)]
pub struct AllocSnapshot {
    /// Number of allocations.
    pub alloc_count: usize,
    /// Number of deallocations.
    pub dealloc_count: usize,
    /// Total bytes allocated.
    pub bytes_allocated: usize,
    /// Total bytes deallocated.
    pub bytes_deallocated: usize,
}

/// Report of allocations during a tracked operation.
#[derive(Clone, Debug, Default)]
pub struct AllocReport {
    /// Number of allocations made during the tracked operation.
    pub alloc_count: usize,
    /// Number of deallocations made during the tracked operation.
    pub dealloc_count: usize,
    /// Total bytes allocated during the tracked operation.
    pub bytes_allocated: usize,
    /// Total bytes deallocated during the tracked operation.
    pub bytes_deallocated: usize,
}

/// Reset all allocation counters to zero.
pub fn reset() {
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    DEALLOC_COUNT.store(0, Ordering::Relaxed);
    BYTES_ALLOCATED.store(0, Ordering::Relaxed);
    BYTES_DEALLOCATED.store(0, Ordering::Relaxed);
}

/// Take a snapshot of current allocation counters.
pub fn snapshot() -> AllocSnapshot {
    AllocSnapshot {
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        bytes_allocated: BYTES_ALLOCATED.load(Ordering::Relaxed),
        bytes_deallocated: BYTES_DEALLOCATED.load(Ordering::Relaxed),
    }
}

/// Enable allocation tracking.
pub fn enable() {
    TRACKING_ENABLED.store(1, Ordering::Relaxed);
}

/// Disable allocation tracking.
pub fn disable() {
    TRACKING_ENABLED.store(0, Ordering::Relaxed);
}

/// Track allocations during a closure.
///
/// Enables counting, resets counters, runs `f`, disables counting,
/// and returns the allocation report. Thread-safe via internal mutex.
pub fn track_allocs<F, O>(f: F) -> AllocReport
where
    F: FnOnce() -> O,
{
    let _guard = TRACKING_MUTEX.lock().unwrap();
    reset();
    enable();
    let _result = f();
    disable();

    AllocReport {
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        bytes_allocated: BYTES_ALLOCATED.load(Ordering::Relaxed),
        bytes_deallocated: BYTES_DEALLOCATED.load(Ordering::Relaxed),
    }
}

/// Track allocations during a closure, returning both the result and the report.
///
/// Like `track_allocs` but also returns the closure's output. Thread-safe
/// via internal mutex.
pub fn track_allocs_with_result<F, O>(f: F) -> (O, AllocReport)
where
    F: FnOnce() -> O,
{
    let _guard = TRACKING_MUTEX.lock().unwrap();
    reset();
    enable();
    let result = f();
    disable();

    let report = AllocReport {
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        bytes_allocated: BYTES_ALLOCATED.load(Ordering::Relaxed),
        bytes_deallocated: BYTES_DEALLOCATED.load(Ordering::Relaxed),
    };
    (result, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Set the counting allocator as the global allocator for tests.
    #[global_allocator]
    static TEST_ALLOC: CountingAllocator = CountingAllocator;

    #[test]
    fn test_track_allocs_vec() {
        let report = track_allocs(|| {
            let v = vec![0u8; 1024];
            std::hint::black_box(&v);
        });
        assert!(report.alloc_count >= 1);
        assert!(report.bytes_allocated >= 1024);
    }

    #[test]
    fn test_track_allocs_no_alloc() {
        let report = track_allocs(|| {
            let x = 42u64;
            std::hint::black_box(x);
        });
        assert_eq!(report.alloc_count, 0);
        assert_eq!(report.bytes_allocated, 0);
    }

    #[test]
    fn test_track_allocs_with_result() {
        let (result, report) = track_allocs_with_result(|| {
            let v = vec![1u8; 512];
            v.len()
        });
        assert_eq!(result, 512);
        assert!(report.alloc_count >= 1);
        assert!(report.bytes_allocated >= 512);
    }

    #[test]
    fn test_track_allocs_string() {
        let report = track_allocs(|| {
            let s = String::from("hello world");
            std::hint::black_box(&s);
        });
        assert!(report.alloc_count >= 1);
        assert!(report.bytes_allocated >= 11);
    }

    #[test]
    fn test_reset_and_snapshot() {
        let _guard = TRACKING_MUTEX.lock().unwrap();
        // Reset, do some allocs, snapshot
        reset();
        enable();
        let _v = vec![0u8; 256];
        let snap = snapshot();
        disable();
        assert!(snap.alloc_count >= 1);
        assert!(snap.bytes_allocated >= 256);
    }
}
