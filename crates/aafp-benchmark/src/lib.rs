//! AAFP benchmark framework.
//!
//! Provides Criterion benchmarks for crypto, framing, transport, and session
//! operations. Every benchmark reports CPU, OS, Rust version, and methodology.

/// Allocation tracking for benchmarks.
pub mod alloc_tracker;
pub mod env_report;
pub mod harness;
