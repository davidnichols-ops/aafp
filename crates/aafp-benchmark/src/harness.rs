//! Automated benchmark harness.
//!
//! Provides a lightweight, criterion-free benchmark runner that records
//! per-iteration wall-clock times and computes percentile statistics
//! (p50, p90, p99, p99.9), mean, and standard deviation. Results can be
//! serialized to JSON and compared against a baseline via [`compare_results`].
//!
//! Usage:
//! ```ignore
//! use aafp_benchmark::harness::BenchmarkRunner;
//!
//! let mut runner = BenchmarkRunner::new("my_bench");
//! runner.measure(1000, || {
//!     // code to benchmark
//!     42
//! });
//! let result = runner.finish();
//! println!("{}", result.to_json());
//! ```

use std::time::{Duration, Instant};

/// Result of a benchmark run, containing percentile and summary statistics.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Name of the benchmark.
    pub name: String,
    /// 50th percentile (median) latency in nanoseconds.
    pub p50_ns: u64,
    /// 90th percentile latency in nanoseconds.
    pub p90_ns: u64,
    /// 99th percentile latency in nanoseconds.
    pub p99_ns: u64,
    /// 99.9th percentile latency in nanoseconds.
    pub p99_9_ns: u64,
    /// Arithmetic mean latency in nanoseconds.
    pub mean_ns: u64,
    /// Standard deviation of latency in nanoseconds.
    pub stddev_ns: u64,
    /// Number of recorded samples (excluding warmup).
    pub samples: usize,
    /// Total wall-clock duration of the measurement phase in seconds.
    pub duration_secs: f64,
}

impl BenchmarkResult {
    /// Serialize this result to a JSON string using `serde_json`.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "name": self.name,
            "p50_ns": self.p50_ns,
            "p90_ns": self.p90_ns,
            "p99_ns": self.p99_ns,
            "p99_9_ns": self.p99_9_ns,
            "mean_ns": self.mean_ns,
            "stddev_ns": self.stddev_ns,
            "samples": self.samples,
            "duration_secs": self.duration_secs,
        })
        .to_string()
    }
}

/// Report produced by comparing two [`BenchmarkResult`] values.
#[derive(Debug, Clone)]
pub struct ComparisonReport {
    /// Name of the benchmark being compared.
    pub name: String,
    /// Baseline p50 latency in nanoseconds.
    pub baseline_p50_ns: u64,
    /// Current p50 latency in nanoseconds.
    pub current_p50_ns: u64,
    /// Ratio of baseline p50 to current p50 (>1.0 means current is faster).
    pub improvement_factor: f64,
    /// `true` if the current result is slower than the baseline.
    pub is_regression: bool,
    /// `true` if the difference exceeds a 5% threshold.
    pub is_significant: bool,
}

impl ComparisonReport {
    /// Serialize this report to a JSON string using `serde_json`.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "name": self.name,
            "baseline_p50_ns": self.baseline_p50_ns,
            "current_p50_ns": self.current_p50_ns,
            "improvement_factor": self.improvement_factor,
            "is_regression": self.is_regression,
            "is_significant": self.is_significant,
        })
        .to_string()
    }
}

/// Compare a baseline result against a current result and produce a report.
///
/// The improvement factor is computed as `baseline_p50 / current_p50`, so a
/// value greater than `1.0` indicates the current run is faster. A difference
/// is considered significant when the relative change exceeds 5%.
#[allow(clippy::module_name_repetitions)]
pub fn compare_results(baseline: &BenchmarkResult, current: &BenchmarkResult) -> ComparisonReport {
    let baseline_p50 = f64::max(baseline.p50_ns as f64, 1.0);
    let current_p50 = f64::max(current.p50_ns as f64, 1.0);
    let improvement_factor = baseline_p50 / current_p50;
    let relative_change = (baseline_p50 - current_p50).abs() / baseline_p50;
    let is_regression = current_p50 > baseline_p50;
    let is_significant = relative_change > 0.05;
    ComparisonReport {
        name: current.name.clone(),
        baseline_p50_ns: baseline.p50_ns,
        current_p50_ns: current.p50_ns,
        improvement_factor,
        is_regression,
        is_significant,
    }
}

/// Automated benchmark runner that records per-iteration wall-clock times.
pub struct BenchmarkRunner {
    /// Benchmark name.
    name: String,
    /// Recorded per-iteration durations (including warmup).
    times: Vec<Duration>,
}

impl BenchmarkRunner {
    /// Create a new runner with the given benchmark name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            times: Vec::new(),
        }
    }

    /// Run `f` `iterations` times, recording each iteration's wall-clock time.
    ///
    /// The first iteration is treated as warmup and excluded from statistics
    /// by [`BenchmarkRunner::finish`].
    pub fn measure<F: Fn() -> O, O>(&mut self, iterations: usize, f: F) {
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = f();
            let elapsed = start.elapsed();
            self.times.push(elapsed);
        }
    }

    /// Consume the runner and compute percentile/summary statistics.
    ///
    /// The first recorded iteration (warmup) is skipped. Returns a
    /// [`BenchmarkResult`] with p50, p90, p99, p99.9, mean, and stddev.
    pub fn finish(self) -> BenchmarkResult {
        let total = self.times.len();
        let warmup = usize::min(1, total);
        let mut sample_durations: Vec<Duration> = self.times.into_iter().skip(warmup).collect();
        sample_durations.sort_unstable();

        let samples = sample_durations.len();
        let duration_secs: f64 = if samples == 0 {
            0.0
        } else {
            sample_durations
                .iter()
                .map(|d| d.as_secs_f64())
                .sum::<f64>()
        };

        if samples == 0 {
            return BenchmarkResult {
                name: self.name,
                p50_ns: 0,
                p90_ns: 0,
                p99_ns: 0,
                p99_9_ns: 0,
                mean_ns: 0,
                stddev_ns: 0,
                samples,
                duration_secs,
            };
        }

        let ns: Vec<u64> = sample_durations
            .iter()
            .map(|d| d.as_nanos() as u64)
            .collect();

        let p50 = percentile(&ns, 50.0);
        let p90 = percentile(&ns, 90.0);
        let p99 = percentile(&ns, 99.0);
        let p99_9 = percentile(&ns, 99.9);

        let sum: u128 = ns.iter().map(|&v| v as u128).sum();
        let mean = (sum / samples as u128) as u64;

        let mean_f = mean as f64;
        let variance: f64 = ns
            .iter()
            .map(|&v| {
                let diff = v as f64 - mean_f;
                diff * diff
            })
            .sum::<f64>()
            / samples as f64;
        let stddev = variance.sqrt() as u64;

        BenchmarkResult {
            name: self.name,
            p50_ns: p50,
            p90_ns: p90,
            p99_ns: p99,
            p99_9_ns: p99_9,
            mean_ns: mean,
            stddev_ns: stddev,
            samples,
            duration_secs,
        }
    }
}

/// Compute the `p`-th percentile from a sorted (ascending) slice of values.
///
/// Uses nearest-rank interpolation. `p` must be in `[0.0, 100.0]`.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * (n as f64 - 1.0);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let frac = rank - lower as f64;
        let lo = sorted[lower] as f64;
        let hi = sorted[upper] as f64;
        (lo + (hi - lo) * frac) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_runner_basic() {
        let mut runner = BenchmarkRunner::new("basic");
        runner.measure(100, || {
            // A small amount of work so timings are nonzero.
            let mut acc: u64 = 0;
            for i in 0..100_u64 {
                acc = acc.wrapping_add(i);
            }
            acc
        });
        let result = runner.finish();
        assert_eq!(result.name, "basic");
        assert_eq!(result.samples, 99, "warmup iteration should be skipped");
        assert!(result.p50_ns > 0, "p50 should be positive");
        assert!(result.mean_ns > 0, "mean should be positive");
        assert!(result.p90_ns >= result.p50_ns, "p90 >= p50");
        assert!(result.p99_ns >= result.p90_ns, "p99 >= p90");
        assert!(result.p99_9_ns >= result.p99_ns, "p99.9 >= p99");
        assert!(result.duration_secs > 0.0, "duration should be positive");
    }

    #[test]
    fn test_compare_results() {
        let baseline = BenchmarkResult {
            name: "bench".to_string(),
            p50_ns: 1000,
            p90_ns: 1200,
            p99_ns: 1500,
            p99_9_ns: 2000,
            mean_ns: 1000,
            stddev_ns: 100,
            samples: 500,
            duration_secs: 1.0,
        };
        let current = BenchmarkResult {
            name: "bench".to_string(),
            p50_ns: 500,
            p90_ns: 600,
            p99_ns: 700,
            p99_9_ns: 800,
            mean_ns: 500,
            stddev_ns: 50,
            samples: 500,
            duration_secs: 0.5,
        };
        let report = compare_results(&baseline, &current);
        assert_eq!(report.name, "bench");
        assert_eq!(report.baseline_p50_ns, 1000);
        assert_eq!(report.current_p50_ns, 500);
        assert!(
            report.improvement_factor > 1.0,
            "current is faster, factor should exceed 1.0"
        );
        assert!(
            (report.improvement_factor - 2.0).abs() < 0.01,
            "improvement factor should be ~2.0"
        );
        assert!(!report.is_regression, "faster current is not a regression");
        assert!(report.is_significant, "50% improvement is significant");
    }

    #[test]
    fn test_to_json() {
        let result = BenchmarkResult {
            name: "json_bench".to_string(),
            p50_ns: 100,
            p90_ns: 200,
            p99_ns: 300,
            p99_9_ns: 400,
            mean_ns: 150,
            stddev_ns: 50,
            samples: 1000,
            duration_secs: 2.5,
        };
        let json = result.to_json();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"p50_ns\""));
        assert!(json.contains("\"p90_ns\""));
        assert!(json.contains("\"p99_ns\""));
        assert!(json.contains("\"p99_9_ns\""));
        assert!(json.contains("\"mean_ns\""));
        assert!(json.contains("\"stddev_ns\""));
        assert!(json.contains("\"samples\""));
        assert!(json.contains("\"duration_secs\""));
        assert!(json.contains("json_bench"));

        let report = ComparisonReport {
            name: "cmp".to_string(),
            baseline_p50_ns: 1000,
            current_p50_ns: 800,
            improvement_factor: 1.25,
            is_regression: false,
            is_significant: true,
        };
        let rjson = report.to_json();
        assert!(rjson.contains("\"name\""));
        assert!(rjson.contains("\"baseline_p50_ns\""));
        assert!(rjson.contains("\"current_p50_ns\""));
        assert!(rjson.contains("\"improvement_factor\""));
        assert!(rjson.contains("\"is_regression\""));
        assert!(rjson.contains("\"is_significant\""));
    }
}
