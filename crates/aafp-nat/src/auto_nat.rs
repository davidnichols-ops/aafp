//! AutoNAT: automatic NAT status detection.
//!
//! An agent requests dial-back checks from peers to determine if it is
//! reachable from the public internet. If peers can dial the agent's
//! advertised address, the agent is NOT behind NAT. If all dial-backs fail,
//! the agent IS behind NAT and should use a relay.

use aafp_identity::AgentId;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors returned by AutoNAT operations.
#[derive(Debug, Error)]
pub enum AutoNatError {
    /// No peers were available to perform a dial-back probe.
    #[error("no peers available for dial-back")]
    NoPeers,
    /// A dial-back probe timed out before completing.
    #[error("dial-back timeout")]
    Timeout,
}

/// NAT status of an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatStatus {
    /// Agent is publicly reachable (not behind NAT).
    Public,
    /// Agent is behind NAT and needs a relay.
    Private,
    /// NAT status unknown (not yet probed).
    Unknown,
}

impl NatStatus {
    /// Returns `true` if the agent is behind NAT and needs a relay.
    pub fn is_behind_nat(&self) -> bool {
        matches!(self, NatStatus::Private)
    }
}

impl std::fmt::Display for NatStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatStatus::Public => write!(f, "public"),
            NatStatus::Private => write!(f, "private"),
            NatStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of a single dial-back probe.
#[derive(Debug, Clone)]
pub struct DialBackResult {
    /// The peer that performed the dial-back.
    pub peer: AgentId,
    /// Whether the dial-back succeeded.
    pub success: bool,
    /// The address the peer dialed.
    pub dialed_addr: String,
    /// Time of the probe.
    pub timestamp: Instant,
}

/// AutoNAT driver.
pub struct AutoNat {
    /// Current NAT status.
    status: NatStatus,
    /// Results of recent dial-back probes.
    probes: Vec<DialBackResult>,
    /// Minimum number of successful probes to be considered public.
    min_successes: usize,
    /// Minimum number of probes to attempt before concluding.
    min_probes: usize,
    /// Time of last status update.
    last_updated: Option<Instant>,
    /// Re-probe interval.
    probe_interval: Duration,
}

impl AutoNat {
    /// Create a new AutoNAT driver.
    pub fn new() -> Self {
        Self {
            status: NatStatus::Unknown,
            probes: Vec::new(),
            min_successes: 2,
            min_probes: 3,
            last_updated: None,
            probe_interval: Duration::from_secs(60),
        }
    }

    /// Record a dial-back probe result.
    pub fn record_probe(&mut self, result: DialBackResult) {
        self.probes.push(result);
        // Keep only recent probes (last 10).
        if self.probes.len() > 10 {
            self.probes.remove(0);
        }
        self.update_status();
    }

    /// Update NAT status based on probe results.
    fn update_status(&mut self) {
        if self.probes.len() < self.min_probes {
            return;
        }
        let successes = self.probes.iter().filter(|p| p.success).count();
        if successes >= self.min_successes {
            self.status = NatStatus::Public;
        } else {
            self.status = NatStatus::Private;
        }
        self.last_updated = Some(Instant::now());
    }

    /// Get the current NAT status.
    pub fn status(&self) -> NatStatus {
        self.status
    }

    /// Check if a re-probe is needed.
    pub fn needs_probe(&self) -> bool {
        match self.last_updated {
            None => true,
            Some(t) => t.elapsed() >= self.probe_interval,
        }
    }

    /// Get recent probe results.
    pub fn probes(&self) -> &[DialBackResult] {
        &self.probes
    }

    /// Get the success rate of recent probes.
    pub fn success_rate(&self) -> f64 {
        if self.probes.is_empty() {
            return 0.0;
        }
        let successes = self.probes.iter().filter(|p| p.success).count();
        successes as f64 / self.probes.len() as f64
    }

    /// Reset all probe data.
    pub fn reset(&mut self) {
        self.probes.clear();
        self.status = NatStatus::Unknown;
        self.last_updated = None;
    }
}

impl Default for AutoNat {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_probe(success: bool) -> DialBackResult {
        DialBackResult {
            peer: [0u8; 32],
            success,
            dialed_addr: "quic://1.2.3.4:4433".into(),
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn initial_status_unknown() {
        let auto_nat = AutoNat::new();
        assert_eq!(auto_nat.status(), NatStatus::Unknown);
        assert!(auto_nat.needs_probe());
    }

    #[test]
    fn public_after_enough_successes() {
        let mut auto_nat = AutoNat::new();
        // Record 3 successful probes.
        for _ in 0..3 {
            auto_nat.record_probe(make_probe(true));
        }
        assert_eq!(auto_nat.status(), NatStatus::Public);
    }

    #[test]
    fn private_after_enough_failures() {
        let mut auto_nat = AutoNat::new();
        for _ in 0..3 {
            auto_nat.record_probe(make_probe(false));
        }
        assert_eq!(auto_nat.status(), NatStatus::Private);
    }

    #[test]
    fn mixed_results() {
        let mut auto_nat = AutoNat::new();
        auto_nat.record_probe(make_probe(true));
        auto_nat.record_probe(make_probe(false));
        auto_nat.record_probe(make_probe(false));
        // 1 success out of 3, min_successes=2 → private
        assert_eq!(auto_nat.status(), NatStatus::Private);
    }

    #[test]
    fn success_rate() {
        let mut auto_nat = AutoNat::new();
        auto_nat.record_probe(make_probe(true));
        auto_nat.record_probe(make_probe(false));
        auto_nat.record_probe(make_probe(true));
        assert_eq!(auto_nat.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn reset() {
        let mut auto_nat = AutoNat::new();
        for _ in 0..3 {
            auto_nat.record_probe(make_probe(true));
        }
        assert_eq!(auto_nat.status(), NatStatus::Public);
        auto_nat.reset();
        assert_eq!(auto_nat.status(), NatStatus::Unknown);
        assert!(auto_nat.probes().is_empty());
    }
}
