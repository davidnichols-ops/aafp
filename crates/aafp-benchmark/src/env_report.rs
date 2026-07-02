//! Benchmark environment reporting.
//!
//! Every benchmark prints a structured environment summary at startup so
//! that results are reproducible by another developer. This module collects
//! CPU model, OS, Rust version, compiler profile, and transport configuration.
//!
//! Usage:
//! ```ignore
//! use aafp_benchmark::env_report;
//! env_report::print_env_summary("mcp_transport");
//! ```

use std::fmt::Write;

/// Configuration parameters that affect benchmark results.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Benchmark name (e.g., "mcp_transport").
    pub benchmark_name: &'static str,
    /// Network topology: "localhost", "lan", or "wan".
    pub topology: &'static str,
    /// Number of QUIC streams used.
    pub stream_count: u32,
    /// Message size in bytes (0 = variable / protocol-defined).
    pub message_size: usize,
    /// Build profile: "release" or "debug".
    pub profile: &'static str,
    /// Whether post-quantum TLS is enabled.
    pub pq_tls_enabled: bool,
    /// Transport configuration description.
    pub transport_config: &'static str,
}

impl BenchmarkConfig {
    /// Default config for MCP transport benchmarks.
    pub fn mcp_transport_default() -> Self {
        Self {
            benchmark_name: "mcp_transport",
            topology: "localhost",
            stream_count: 1,
            message_size: 0, // MCP ping is variable-size JSON-RPC
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            pq_tls_enabled: true,
            transport_config: "AAFP v1 over QUIC (quinn + rustls, X25519MLKEM768)",
        }
    }
}

/// Collect system information for reproducibility.
pub struct SystemInfo {
    pub os: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub rust_version: String,
    pub host_arch: String,
}

impl SystemInfo {
    /// Collect system information. Falls back to "unknown" for fields
    /// that cannot be determined.
    pub fn collect() -> Self {
        Self {
            os: collect_os(),
            cpu_model: collect_cpu_model(),
            cpu_cores: collect_cpu_cores(),
            rust_version: collect_rust_version(),
            host_arch: collect_arch(),
        }
    }
}

fn collect_os() -> String {
    let mut parts = Vec::new();
    if let Ok(name) = std::env::var("OSTYPE") {
        parts.push(name);
    } else {
        #[cfg(target_os = "linux")]
        parts.push("linux".to_string());
        #[cfg(target_os = "macos")]
        parts.push("macos".to_string());
        #[cfg(target_os = "windows")]
        parts.push("windows".to_string());
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        parts.push("unknown".to_string());
    }
    parts.join(" ")
}

fn collect_cpu_model() -> String {
    // Try /proc/cpuinfo on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("model name") {
                    if let Some(idx) = line.find(':') {
                        return line[idx + 1..].trim().to_string();
                    }
                }
            }
        }
    }

    // Try sysctl on macOS
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
        {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }

    // Fallback: use the target triple's architecture
    format!("unknown ({})", std::env::consts::ARCH)
}

fn collect_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn collect_rust_version() -> String {
    if let Ok(output) = std::process::Command::new("rustc")
        .arg("--version")
        .output()
    {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    "unknown".to_string()
}

fn collect_arch() -> String {
    std::env::consts::ARCH.to_string()
}

/// Print a structured environment summary to stderr.
///
/// This is printed at benchmark startup so it appears in the benchmark
/// output before any criterion measurements.
pub fn print_env_summary(config: &BenchmarkConfig) {
    let sys = SystemInfo::collect();
    let summary = format_summary(config, &sys);
    eprintln!("{summary}");
}

fn format_summary(config: &BenchmarkConfig, sys: &SystemInfo) -> String {
    let mut s = String::new();
    writeln!(
        s,
        "═══════════════════════════════════════════════════════════════"
    )
    .unwrap();
    writeln!(s, "  BENCHMARK ENVIRONMENT SUMMARY").unwrap();
    writeln!(
        s,
        "═══════════════════════════════════════════════════════════════"
    )
    .unwrap();
    writeln!(s, "  Benchmark:        {}", config.benchmark_name).unwrap();
    writeln!(
        s,
        "  ───────────────────────────────────────────────────────────"
    )
    .unwrap();
    writeln!(s, "  SYSTEM").unwrap();
    writeln!(s, "    OS:              {}", sys.os).unwrap();
    writeln!(s, "    CPU model:       {}", sys.cpu_model).unwrap();
    writeln!(s, "    CPU cores:       {}", sys.cpu_cores).unwrap();
    writeln!(s, "    Architecture:    {}", sys.host_arch).unwrap();
    writeln!(s, "    Rust version:    {}", sys.rust_version).unwrap();
    writeln!(
        s,
        "  ───────────────────────────────────────────────────────────"
    )
    .unwrap();
    writeln!(s, "  BUILD").unwrap();
    writeln!(s, "    Profile:         {}", config.profile).unwrap();
    writeln!(
        s,
        "    PQ TLS:          {}",
        if config.pq_tls_enabled {
            "enabled (X25519MLKEM768)"
        } else {
            "disabled"
        }
    )
    .unwrap();
    writeln!(
        s,
        "  ───────────────────────────────────────────────────────────"
    )
    .unwrap();
    writeln!(s, "  TRANSPORT").unwrap();
    writeln!(s, "    Topology:        {}", config.topology).unwrap();
    writeln!(s, "    Stream count:    {}", config.stream_count).unwrap();
    let message_size_str = if config.message_size == 0 {
        "variable (protocol-defined)".to_string()
    } else {
        format!("{} bytes", config.message_size)
    };
    writeln!(s, "    Message size:    {}", message_size_str).unwrap();
    writeln!(s, "    Config:          {}", config.transport_config).unwrap();
    writeln!(
        s,
        "  ───────────────────────────────────────────────────────────"
    )
    .unwrap();
    writeln!(s, "  METHODOLOGY").unwrap();
    writeln!(s, "    Framework:       criterion").unwrap();
    writeln!(
        s,
        "    Warmup:          configured by criterion (default 3s)"
    )
    .unwrap();
    writeln!(
        s,
        "    Measurement:     configured by criterion (default 5s)"
    )
    .unwrap();
    writeln!(
        s,
        "    Samples:         configured by criterion (default 100)"
    )
    .unwrap();
    writeln!(
        s,
        "  ───────────────────────────────────────────────────────────"
    )
    .unwrap();
    writeln!(s, "  REPRODUCTION").unwrap();
    writeln!(
        s,
        "    Command:         cargo bench --bench {} -- --warm-up-time 3 --measurement-time 5",
        config.benchmark_name
    )
    .unwrap();
    writeln!(
        s,
        "    Note:            Results vary by hardware. Compare only"
    )
    .unwrap();
    writeln!(s, "                     within the same environment.").unwrap();
    writeln!(
        s,
        "═══════════════════════════════════════════════════════════════"
    )
    .unwrap();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_summary_contains_key_fields() {
        let config = BenchmarkConfig::mcp_transport_default();
        let sys = SystemInfo {
            os: "linux".to_string(),
            cpu_model: "AMD Ryzen 9 7950X".to_string(),
            cpu_cores: 16,
            rust_version: "rustc 1.96.0".to_string(),
            host_arch: "x86_64".to_string(),
        };
        let summary = format_summary(&config, &sys);
        assert!(summary.contains("AMD Ryzen 9 7950X"));
        assert!(summary.contains("mcp_transport"));
        assert!(summary.contains("localhost"));
        assert!(summary.contains("X25519MLKEM768"));
        assert!(summary.contains("cargo bench"));
    }
}
