//! DCuTR (Direct Connection Upgrade through Relay): hole punching.
//!
//! Attempts to upgrade relayed connections to direct connections using
//! simultaneous open (hole punching). For MVP, this is a stub that tracks
//! upgrade attempts. A production version would implement the libp2p
//! DCuTR protocol over QUIC.

use aafp_core::Multiaddr;
use aafp_identity::AgentId;
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DcutrError {
    #[error("not relayed, cannot upgrade")]
    NotRelayed,
    #[error("hole punch failed: {0}")]
    HolePunchFailed(String),
    #[error("peer does not support DCuTR")]
    NotSupported,
}

/// Result of a DCuTR upgrade attempt.
#[derive(Debug, Clone)]
pub struct UpgradeResult {
    /// The peer we upgraded with.
    pub peer: AgentId,
    /// Whether the upgrade succeeded.
    pub success: bool,
    /// The direct address if successful.
    pub direct_addr: Option<Multiaddr>,
    /// Time of the attempt.
    pub timestamp: Instant,
    /// Error message if failed.
    pub error: Option<String>,
}

/// DCuTR driver.
pub struct Dcutr {
    /// History of upgrade attempts.
    attempts: Vec<UpgradeResult>,
    /// Whether DCuTR is enabled.
    enabled: bool,
}

impl Dcutr {
    /// Create a new DCuTR driver.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
            enabled: true,
        }
    }

    /// Record an upgrade attempt.
    pub fn record_attempt(&mut self, result: UpgradeResult) {
        self.attempts.push(result);
        // Keep only last 20 attempts.
        if self.attempts.len() > 20 {
            self.attempts.remove(0);
        }
    }

    /// Get all upgrade attempts.
    pub fn attempts(&self) -> &[UpgradeResult] {
        &self.attempts
    }

    /// Get successful upgrades.
    pub fn successful_upgrades(&self) -> Vec<&UpgradeResult> {
        self.attempts.iter().filter(|a| a.success).collect()
    }

    /// Get the success rate.
    pub fn success_rate(&self) -> f64 {
        if self.attempts.is_empty() {
            return 0.0;
        }
        let successes = self.attempts.iter().filter(|a| a.success).count();
        successes as f64 / self.attempts.len() as f64
    }

    /// Check if DCuTR is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable DCuTR.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the last attempt for a specific peer.
    pub fn last_attempt_for(&self, peer: &AgentId) -> Option<&UpgradeResult> {
        self.attempts.iter().rev().find(|a| &a.peer == peer)
    }
}

impl Default for Dcutr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(peer: u8, success: bool) -> UpgradeResult {
        UpgradeResult {
            peer: [peer; 32],
            success,
            direct_addr: if success {
                Some(format!("quic://1.2.{}.{}:4433", peer, peer))
            } else {
                None
            },
            timestamp: Instant::now(),
            error: if success {
                None
            } else {
                Some("hole punch timeout".into())
            },
        }
    }

    #[test]
    fn record_and_query() {
        let mut dcutr = Dcutr::new();
        dcutr.record_attempt(make_result(1, true));
        dcutr.record_attempt(make_result(2, false));
        dcutr.record_attempt(make_result(3, true));
        assert_eq!(dcutr.attempts().len(), 3);
        assert_eq!(dcutr.successful_upgrades().len(), 2);
        assert_eq!(dcutr.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn last_attempt_for() {
        let mut dcutr = Dcutr::new();
        dcutr.record_attempt(make_result(1, false));
        dcutr.record_attempt(make_result(2, true));
        dcutr.record_attempt(make_result(1, true));
        let last = dcutr.last_attempt_for(&[1; 32]).unwrap();
        assert!(last.success);
    }

    #[test]
    fn enable_disable() {
        let mut dcutr = Dcutr::new();
        assert!(dcutr.is_enabled());
        dcutr.set_enabled(false);
        assert!(!dcutr.is_enabled());
    }
}
