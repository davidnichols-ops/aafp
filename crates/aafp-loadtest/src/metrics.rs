//! Metrics collection for load tests (Track S1).
//!
//! `LoadTestMetrics` captures throughput, latency distribution, error rate,
//! and resource usage for a completed load test run.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Latency distribution percentiles (in microseconds).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Minimum observed latency.
    pub min_us: f64,
    /// 50th percentile (median).
    pub p50_us: f64,
    /// 90th percentile.
    pub p90_us: f64,
    /// 99th percentile.
    pub p99_us: f64,
    /// 99.9th percentile.
    pub p999_us: f64,
    /// Maximum observed latency.
    pub max_us: f64,
    /// Mean (average) latency.
    pub mean_us: f64,
}

impl LatencyStats {
    /// Compute latency statistics from a sorted list of latencies (in microseconds).
    ///
    /// The input MUST be sorted in ascending order.
    pub fn from_sorted(mut latencies: Vec<f64>) -> Self {
        if latencies.is_empty() {
            return Self::default();
        }
        // Ensure sorted (caller should sort, but double-check)
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = latencies.len();
        let percentile = |p: f64| -> f64 {
            if n == 1 {
                return latencies[0];
            }
            let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
            latencies[idx.min(n - 1)]
        };

        let sum: f64 = latencies.iter().sum();
        let mean = sum / n as f64;

        Self {
            min_us: latencies[0],
            p50_us: percentile(50.0),
            p90_us: percentile(90.0),
            p99_us: percentile(99.0),
            p999_us: percentile(99.9),
            max_us: latencies[n - 1],
            mean_us: mean,
        }
    }
}

/// Resource usage snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Process RSS memory in bytes (best-effort, platform-dependent).
    pub memory_bytes: u64,
    /// Number of file descriptors (best-effort, platform-dependent).
    pub file_descriptors: u64,
}

/// Complete metrics from a load test run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LoadTestMetrics {
    /// Test configuration summary.
    pub config_summary: ConfigSummary,
    /// Total messages sent (attempted).
    pub messages_sent: u64,
    /// Total messages received (successfully echoed).
    pub messages_received: u64,
    /// Total messages that failed (send error, timeout, etc.).
    pub messages_failed: u64,
    /// Aggregate throughput in messages/second.
    pub throughput_msgps: f64,
    /// Aggregate throughput in bytes/second.
    pub throughput_bps: f64,
    /// Round-trip latency statistics.
    pub latency: LatencyStats,
    /// Error rate (failed / sent), 0.0 to 1.0.
    pub error_rate: f64,
    /// Number of connections established.
    pub connections_established: u64,
    /// Number of connections that failed.
    pub connections_failed: u64,
    /// Wall-clock duration of the test.
    pub duration_secs: f64,
    /// Resource usage at end of test.
    pub resources: ResourceUsage,
}

/// A serializable summary of the test config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub num_agents: usize,
    pub messages_per_agent: usize,
    pub message_size: usize,
    pub topology: String,
    pub num_edges: usize,
}

impl LoadTestMetrics {
    /// Compute derived metrics (throughput, error rate) from raw counters.
    pub fn finalize(&mut self) {
        if self.duration_secs > 0.0 {
            self.throughput_msgps = self.messages_received as f64 / self.duration_secs;
            self.throughput_bps = self.throughput_msgps * self.config_summary.message_size as f64;
        }
        if self.messages_sent > 0 {
            self.error_rate = self.messages_failed as f64 / self.messages_sent as f64;
        }
    }

    /// Serialize to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Print a human-readable summary to stdout.
    pub fn print_summary(&self) {
        println!("═══════════════════════════════════════════════════════════");
        println!("  AAFP Load Test Results");
        println!("═══════════════════════════════════════════════════════════");
        println!("  Agents:          {}", self.config_summary.num_agents);
        println!("  Topology:        {}", self.config_summary.topology);
        println!("  Edges:           {}", self.config_summary.num_edges);
        println!(
            "  Message size:    {} bytes",
            self.config_summary.message_size
        );
        println!(
            "  Messages/agent:  {}",
            self.config_summary.messages_per_agent
        );
        println!("───────────────────────────────────────────────────────────");
        println!("  Messages sent:     {}", self.messages_sent);
        println!("  Messages received: {}", self.messages_received);
        println!("  Messages failed:   {}", self.messages_failed);
        println!("  Error rate:        {:.4}%", self.error_rate * 100.0);
        println!("───────────────────────────────────────────────────────────");
        println!("  Throughput:        {:.0} msg/s", self.throughput_msgps);
        println!(
            "  Throughput:        {:.2} MB/s",
            self.throughput_bps / 1_000_000.0
        );
        println!("  Duration:          {:.3}s", self.duration_secs);
        println!("───────────────────────────────────────────────────────────");
        println!("  Latency (round-trip):");
        println!("    min:   {:>10.1} µs", self.latency.min_us);
        println!("    p50:   {:>10.1} µs", self.latency.p50_us);
        println!("    p90:   {:>10.1} µs", self.latency.p90_us);
        println!("    p99:   {:>10.1} µs", self.latency.p99_us);
        println!("    p99.9: {:>10.1} µs", self.latency.p999_us);
        println!("    max:   {:>10.1} µs", self.latency.max_us);
        println!("    mean:  {:>10.1} µs", self.latency.mean_us);
        println!("───────────────────────────────────────────────────────────");
        println!(
            "  Connections:       {} established, {} failed",
            self.connections_established, self.connections_failed
        );
        if self.resources.memory_bytes > 0 {
            println!(
                "  Memory (RSS):      {:.1} MB",
                self.resources.memory_bytes as f64 / 1_000_000.0
            );
        }
        if self.resources.file_descriptors > 0 {
            println!("  File descriptors:  {}", self.resources.file_descriptors);
        }
        println!("═══════════════════════════════════════════════════════════");
    }
}

/// Collect per-message results from worker tasks.
#[derive(Clone, Debug, Default)]
pub struct MessageResult {
    /// Latency in microseconds (round-trip).
    pub latency_us: f64,
    /// Whether the message succeeded.
    pub success: bool,
}

/// A thread-safe accumulator for message results.
pub struct ResultsAccumulator {
    pub latencies: std::sync::Mutex<Vec<f64>>,
    pub sent: std::sync::atomic::AtomicU64,
    pub received: std::sync::atomic::AtomicU64,
    pub failed: std::sync::atomic::AtomicU64,
    pub connections_established: std::sync::atomic::AtomicU64,
    pub connections_failed: std::sync::atomic::AtomicU64,
}

impl ResultsAccumulator {
    pub fn new() -> Self {
        Self {
            latencies: std::sync::Mutex::new(Vec::new()),
            sent: std::sync::atomic::AtomicU64::new(0),
            received: std::sync::atomic::AtomicU64::new(0),
            failed: std::sync::atomic::AtomicU64::new(0),
            connections_established: std::sync::atomic::AtomicU64::new(0),
            connections_failed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a successful message with its round-trip latency.
    pub fn record_success(&self, latency_us: f64) {
        self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.latencies.lock().unwrap().push(latency_us);
    }

    /// Record a failed message.
    pub fn record_failure(&self) {
        self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a successful connection.
    pub fn record_connection(&self) {
        self.connections_established
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a failed connection.
    pub fn record_connection_failure(&self) {
        self.connections_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Build the final `LoadTestMetrics` from accumulated data.
    pub fn into_metrics(
        self,
        config_summary: ConfigSummary,
        duration: Duration,
    ) -> LoadTestMetrics {
        let latencies = self.latencies.into_inner().unwrap();
        let latency = LatencyStats::from_sorted(latencies);

        let mut metrics = LoadTestMetrics {
            config_summary,
            messages_sent: self.sent.load(std::sync::atomic::Ordering::Relaxed),
            messages_received: self.received.load(std::sync::atomic::Ordering::Relaxed),
            messages_failed: self.failed.load(std::sync::atomic::Ordering::Relaxed),
            latency,
            connections_established: self
                .connections_established
                .load(std::sync::atomic::Ordering::Relaxed),
            connections_failed: self
                .connections_failed
                .load(std::sync::atomic::Ordering::Relaxed),
            duration_secs: duration.as_secs_f64(),
            resources: collect_resource_usage(),
            ..Default::default()
        };
        metrics.finalize();
        metrics
    }
}

impl Default for ResultsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Best-effort resource usage collection (platform-dependent).
fn collect_resource_usage() -> ResourceUsage {
    let mut usage = ResourceUsage::default();

    // Memory: try /proc/self/status (Linux) or mach_task_info (macOS).
    // For portability, we use a simple approach that works on Linux.
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(kb_str) = rest.trim().split_whitespace().next() {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            usage.memory_bytes = kb * 1024;
                        }
                    }
                }
            }
        }
        // File descriptors
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            usage.file_descriptors = entries.count() as u64;
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: use mach_task_basic_info via libc::task_info.
        // The `mach` crate would be cleaner, but we avoid the extra dependency.
        // On macOS, libc exposes mach_task_self() and KERN_SUCCESS, but
        // task_basic_info_data_t is in the mach crate. We use a raw FFI
        // call with the known struct layout instead.
        //
        // task_basic_info_data_t layout (from mach/task_info.h):
        //   natural_t suspend_count;  // 4 bytes
        //   vm_size_t virtual_size;   // 8 bytes (uint64_t on 64-bit)
        //   vm_size_t resident_size;  // 8 bytes
        //   integer_t user_time;      // 4 bytes
        //   integer_t system_time;    // 4 bytes
        //   policy_t policy;          // 4 bytes
        #[repr(C)]
        struct TaskBasicInfo {
            suspend_count: u32,
            _pad: u32, // alignment for 64-bit
            virtual_size: u64,
            resident_size: u64,
            user_time: i32,
            system_time: i32,
            policy: i32,
        }

        const TASK_BASIC_INFO: u32 = 5; // from mach/task_info.h
        type MachMsgTypeNumber = u32;
        type KernReturn = i32;

        extern "C" {
            fn task_info(
                target: u32,
                flavor: u32,
                info: *mut TaskBasicInfo,
                count: *mut MachMsgTypeNumber,
            ) -> KernReturn;
        }

        unsafe {
            #[allow(deprecated)] // libc::mach_task_self is deprecated but works
            let task = libc::mach_task_self();
            let mut info: TaskBasicInfo = std::mem::zeroed();
            let mut count =
                (std::mem::size_of::<TaskBasicInfo>() / std::mem::size_of::<u32>()) as u32;
            let kr = task_info(task, TASK_BASIC_INFO, &mut info, &mut count);
            if kr == libc::KERN_SUCCESS {
                usage.memory_bytes = info.resident_size;
            }
        }
    }

    usage
}
