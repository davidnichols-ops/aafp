//! Congestion control configuration (Track J1).
//!
//! Quinn provides three congestion controllers:
//! - **Cubic** (default): Good for bulk transfer, TCP-friendly
//! - **NewReno**: Simple, standard, conservative
//! - **BBR** (experimental): Better for low-latency RPC — estimates bandwidth
//!   and RTT, doesn't rely on packet loss
//!
//! For AAFP agent-to-agent RPC, BBR is preferred because:
//! 1. It doesn't wait for packet loss to reduce the window
//! 2. It estimates the bottleneck bandwidth, allowing faster ramp-up
//! 3. It's better for low-latency, small-message workloads
//!
//! ## Usage
//!
//! ```rust
//! use aafp_transport_quic::{QuicConfig, CongestionController};
//!
//! // Low-latency preset (BBR + tuned RTT + small buffers)
//! let config = QuicConfig::low_latency();
//!
//! // Bulk transfer preset (Cubic + larger buffers)
//! let config = QuicConfig::bulk_transfer();
//!
//! // Custom: pick a specific controller
//! let mut config = QuicConfig::default();
//! config.congestion = CongestionController::Bbr;
//! ```

use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn::TransportConfig;
use std::sync::Arc;

/// The congestion controller to use for QUIC connections.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CongestionController {
    /// Cubic (quinn default) — good for bulk transfer, TCP-friendly.
    #[default]
    Cubic,
    /// NewReno — simple, standard, conservative.
    NewReno,
    /// BBR (experimental) — better for low-latency RPC.
    /// Estimates bandwidth and RTT, doesn't rely on packet loss.
    Bbr,
}

impl CongestionController {
    /// Apply this congestion controller to a `TransportConfig`.
    pub fn apply_to_transport_config(&self, transport: &mut TransportConfig) {
        match self {
            Self::Cubic => {
                transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
            }
            Self::NewReno => {
                transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
            }
            Self::Bbr => {
                transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_cubic() {
        assert_eq!(CongestionController::default(), CongestionController::Cubic);
    }

    #[test]
    fn apply_cubic_to_transport() {
        let mut transport = TransportConfig::default();
        CongestionController::Cubic.apply_to_transport_config(&mut transport);
        // Should not panic — just sets the factory
    }

    #[test]
    fn apply_newreno_to_transport() {
        let mut transport = TransportConfig::default();
        CongestionController::NewReno.apply_to_transport_config(&mut transport);
    }

    #[test]
    fn apply_bbr_to_transport() {
        let mut transport = TransportConfig::default();
        CongestionController::Bbr.apply_to_transport_config(&mut transport);
    }
}
