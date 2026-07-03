//! PING/PONG keep-alive (RFC-0002 §4.7-4.8).
//!
//! Provides application-layer liveness checks for AAFP connections.
//! Periodic PING frames are sent on stream 0; PONG responses are
//! expected within a configurable timeout. Missed PONGs trigger
//! connection close.
//!
//! ## Frame Types
//! - PING (0x07): application-layer keepalive probe
//! - PONG (0x08): response to PING, MUST be sent on same stream
//!
//! ## Configuration
//! - `interval`: time between PING frames (default: 30s)
//! - `timeout`: max wait for PONG response (default: 10s)
//! - `max_missed`: consecutive missed PONGs before close (default: 3)

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for keep-alive behavior.
#[derive(Clone, Debug)]
pub struct KeepAliveConfig {
    /// Interval between PING frames (default: 30 seconds).
    pub interval: Duration,
    /// Timeout for PONG response (default: 10 seconds).
    pub timeout: Duration,
    /// Maximum consecutive missed PONGs before closing (default: 3).
    pub max_missed: u32,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            max_missed: 3,
        }
    }
}

impl KeepAliveConfig {
    /// Disable keep-alive entirely (infinite interval).
    pub fn disabled() -> Self {
        Self {
            interval: Duration::MAX,
            timeout: Duration::MAX,
            max_missed: u32::MAX,
        }
    }

    /// Check if keep-alive is enabled.
    pub fn is_enabled(&self) -> bool {
        self.interval != Duration::MAX
    }
}

/// Tracks outstanding PING frames for a connection.
///
/// Each connection has its own `PingTracker`. The tracker records when PINGs
/// are sent, matches PONGs to outstanding PINGs, and detects timeouts.
#[derive(Debug)]
pub struct PingTracker {
    config: KeepAliveConfig,
    /// Outstanding PINGs: ping_id → sent timestamp
    outstanding: HashMap<u64, Instant>,
    /// Consecutive missed PONGs
    missed_count: u32,
    /// Next ping ID to use
    next_id: u64,
    /// Timestamp of the last PING sent
    last_ping_sent: Option<Instant>,
}

impl PingTracker {
    /// Create a new tracker with the given configuration.
    pub fn new(config: KeepAliveConfig) -> Self {
        Self {
            config,
            outstanding: HashMap::new(),
            missed_count: 0,
            next_id: 1,
            last_ping_sent: None,
        }
    }

    /// Record a sent PING. Returns the ping ID to include in the frame payload.
    pub fn record_ping(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.outstanding.insert(id, Instant::now());
        self.last_ping_sent = Some(Instant::now());
        id
    }

    /// Record a received PONG. Returns true if the PONG matched an outstanding PING.
    pub fn record_pong(&mut self, ping_id: u64) -> bool {
        if self.outstanding.remove(&ping_id).is_some() {
            self.missed_count = 0;
            true
        } else {
            false
        }
    }

    /// Check for timed-out PINGs. Returns true if the connection should be closed.
    pub fn check_timeouts(&mut self) -> bool {
        let now = Instant::now();
        let timed_out: Vec<u64> = self
            .outstanding
            .iter()
            .filter(|(_, sent)| now.duration_since(**sent) > self.config.timeout)
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            self.outstanding.remove(&id);
            self.missed_count += 1;
        }

        self.missed_count >= self.config.max_missed
    }

    /// Check if it's time to send the next PING.
    pub fn should_ping(&self) -> bool {
        if !self.config.is_enabled() {
            return false;
        }
        match self.last_ping_sent {
            None => true,
            Some(last) => Instant::now().duration_since(last) >= self.config.interval,
        }
    }

    /// Get the number of outstanding PINGs.
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Get the consecutive missed PONG count.
    pub fn missed_count(&self) -> u32 {
        self.missed_count
    }

    /// Get the keep-alive configuration.
    pub fn config(&self) -> &KeepAliveConfig {
        &self.config
    }
}

impl Default for PingTracker {
    fn default() -> Self {
        Self::new(KeepAliveConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_pong_cycle() {
        let mut tracker = PingTracker::new(KeepAliveConfig::default());
        let id = tracker.record_ping();
        assert_eq!(tracker.outstanding_count(), 1);
        assert!(tracker.record_pong(id));
        assert_eq!(tracker.outstanding_count(), 0);
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_timeout_detection() {
        let config = KeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 2,
            ..Default::default()
        };
        let mut tracker = PingTracker::new(config);
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        assert!(!tracker.check_timeouts()); // 1 missed, not enough
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        assert!(tracker.check_timeouts()); // 2 missed, close
    }

    #[test]
    fn test_unsolicited_pong() {
        let mut tracker = PingTracker::new(KeepAliveConfig::default());
        assert!(!tracker.record_pong(999)); // no matching ping
    }

    #[test]
    fn test_missed_count_resets_on_pong() {
        let config = KeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 5,
            ..Default::default()
        };
        let mut tracker = PingTracker::new(config);
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        tracker.check_timeouts();
        assert_eq!(tracker.missed_count(), 1);

        // Send another ping and get a pong — missed count should reset
        let id = tracker.record_ping();
        assert!(tracker.record_pong(id));
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_should_ping_initially() {
        let mut tracker = PingTracker::new(KeepAliveConfig::default());
        assert!(tracker.should_ping()); // no ping sent yet
        tracker.record_ping();
        assert!(!tracker.should_ping()); // just sent one
    }

    #[test]
    fn test_should_ping_after_interval() {
        let config = KeepAliveConfig {
            interval: Duration::from_millis(10),
            ..Default::default()
        };
        let mut tracker = PingTracker::new(config);
        tracker.record_ping();
        assert!(!tracker.should_ping());
        std::thread::sleep(Duration::from_millis(15));
        assert!(tracker.should_ping());
    }

    #[test]
    fn test_disabled_config() {
        let config = KeepAliveConfig::disabled();
        assert!(!config.is_enabled());
        let mut tracker = PingTracker::new(config);
        assert!(!tracker.should_ping());
    }

    #[test]
    fn test_multiple_outstanding_pings() {
        let mut tracker = PingTracker::new(KeepAliveConfig::default());
        let id1 = tracker.record_ping();
        let id2 = tracker.record_ping();
        let id3 = tracker.record_ping();
        assert_eq!(tracker.outstanding_count(), 3);

        // Pong for id2
        assert!(tracker.record_pong(id2));
        assert_eq!(tracker.outstanding_count(), 2);

        // Pong for id1
        assert!(tracker.record_pong(id1));
        assert_eq!(tracker.outstanding_count(), 1);

        // Pong for id3
        assert!(tracker.record_pong(id3));
        assert_eq!(tracker.outstanding_count(), 0);
    }

    #[test]
    fn test_ping_ids_are_unique_and_incrementing() {
        let mut tracker = PingTracker::new(KeepAliveConfig::default());
        let id1 = tracker.record_ping();
        let id2 = tracker.record_ping();
        let id3 = tracker.record_ping();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }
}
