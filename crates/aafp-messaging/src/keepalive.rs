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
//!
//! ## Adaptive Keep-Alive (Track I7)
//!
//! The [`AdaptivePingTracker`] adjusts the PING interval based on
//! connection stability:
//! - Default: 30s
//! - After 3 consecutive PONGs: increase to 60s (connection is stable)
//! - After a missed PONG: decrease to 10s (connection may be unstable)
//! - After 3 missed PONGs: close connection (peer is gone)

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

/// Configuration for adaptive keep-alive (Track I7).
///
/// The adaptive keep-alive adjusts the PING interval based on
/// connection stability, reducing overhead for stable connections
/// and increasing responsiveness for unstable ones.
#[derive(Clone, Debug)]
pub struct AdaptiveKeepAliveConfig {
    /// Base (default) interval between PING frames.
    pub base_interval: Duration,
    /// Interval for stable connections (after `stable_threshold` consecutive PONGs).
    pub stable_interval: Duration,
    /// Interval for unstable connections (after a missed PONG).
    pub unstable_interval: Duration,
    /// Timeout for PONG response.
    pub timeout: Duration,
    /// Consecutive PONGs required to transition to stable interval.
    pub stable_threshold: u32,
    /// Maximum consecutive missed PONGs before closing.
    pub max_missed: u32,
}

impl Default for AdaptiveKeepAliveConfig {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_secs(30),
            stable_interval: Duration::from_secs(60),
            unstable_interval: Duration::from_secs(10),
            timeout: Duration::from_secs(10),
            stable_threshold: 3,
            max_missed: 3,
        }
    }
}

/// The current adaptive keep-alive state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepAliveState {
    /// Default interval (base_interval).
    Normal,
    /// Connection is stable — using stable_interval (longer).
    Stable,
    /// Connection may be unstable — using unstable_interval (shorter).
    Unstable,
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

/// Adaptive PING tracker that adjusts the interval based on stability (Track I7).
///
/// The tracker starts in `Normal` state with `base_interval`. After
/// `stable_threshold` consecutive PONGs, it transitions to `Stable`
/// state with `stable_interval` (longer, less overhead). After a
/// missed PONG, it transitions to `Unstable` state with
/// `unstable_interval` (shorter, faster detection). After `max_missed`
/// consecutive missed PONGs, the connection should be closed.
///
/// # State Transitions
///
/// ```text
/// Normal ──(3 PONGs)──> Stable
///   │                     │
///   │  (missed PONG)      │  (missed PONG)
///   v                     v
/// Unstable <──────────────┘
///   │
///   │  (PONG received)
///   v
/// Normal
///   │
///   │  (max_missed reached)
///   v
/// CLOSE CONNECTION
/// ```
pub struct AdaptivePingTracker {
    config: AdaptiveKeepAliveConfig,
    /// Outstanding PINGs: ping_id → sent timestamp
    outstanding: HashMap<u64, Instant>,
    /// Consecutive missed PONGs
    missed_count: u32,
    /// Consecutive successful PONGs (resets on miss)
    consecutive_pongs: u32,
    /// Current adaptive state
    state: KeepAliveState,
    /// Next ping ID to use
    next_id: u64,
    /// Timestamp of the last PING sent
    last_ping_sent: Option<Instant>,
}

impl std::fmt::Debug for AdaptivePingTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptivePingTracker")
            .field("state", &self.state)
            .field("missed_count", &self.missed_count)
            .field("consecutive_pongs", &self.consecutive_pongs)
            .field("outstanding", &self.outstanding.len())
            .finish()
    }
}

impl AdaptivePingTracker {
    /// Create a new adaptive tracker with the default configuration.
    pub fn new() -> Self {
        Self::with_config(AdaptiveKeepAliveConfig::default())
    }

    /// Create a new adaptive tracker with custom configuration.
    pub fn with_config(config: AdaptiveKeepAliveConfig) -> Self {
        Self {
            config,
            outstanding: HashMap::new(),
            missed_count: 0,
            consecutive_pongs: 0,
            state: KeepAliveState::Normal,
            next_id: 1,
            last_ping_sent: None,
        }
    }

    /// Get the current effective interval based on the adaptive state.
    pub fn current_interval(&self) -> Duration {
        match self.state {
            KeepAliveState::Normal => self.config.base_interval,
            KeepAliveState::Stable => self.config.stable_interval,
            KeepAliveState::Unstable => self.config.unstable_interval,
        }
    }

    /// Get the current adaptive state.
    pub fn state(&self) -> KeepAliveState {
        self.state
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
    ///
    /// On successful PONG:
    /// - `missed_count` resets to 0
    /// - `consecutive_pongs` increments
    /// - If `consecutive_pongs >= stable_threshold`, transition to `Stable`
    /// - If in `Unstable` state, transition back to `Normal`
    pub fn record_pong(&mut self, ping_id: u64) -> bool {
        if self.outstanding.remove(&ping_id).is_some() {
            self.missed_count = 0;
            self.consecutive_pongs += 1;

            // State transition: Unstable → Normal on first PONG
            if self.state == KeepAliveState::Unstable {
                self.state = KeepAliveState::Normal;
            }

            // State transition: Normal → Stable after threshold consecutive PONGs
            if self.state == KeepAliveState::Normal
                && self.consecutive_pongs >= self.config.stable_threshold
            {
                self.state = KeepAliveState::Stable;
            }

            true
        } else {
            false
        }
    }

    /// Check for timed-out PINGs. Returns true if the connection should be closed.
    ///
    /// On timeout:
    /// - `missed_count` increments
    /// - `consecutive_pongs` resets to 0
    /// - Transition to `Unstable` state (shorter interval)
    /// - If `missed_count >= max_missed`, return true (close connection)
    pub fn check_timeouts(&mut self) -> bool {
        let now = Instant::now();
        let timed_out: Vec<u64> = self
            .outstanding
            .iter()
            .filter(|(_, sent)| now.duration_since(**sent) > self.config.timeout)
            .map(|(id, _)| *id)
            .collect();

        let any_timed_out = !timed_out.is_empty();

        for id in timed_out {
            self.outstanding.remove(&id);
            self.missed_count += 1;
        }

        if any_timed_out {
            // Reset consecutive PONGs and transition to Unstable
            self.consecutive_pongs = 0;
            self.state = KeepAliveState::Unstable;
        }

        self.missed_count >= self.config.max_missed
    }

    /// Check if it's time to send the next PING (using adaptive interval).
    pub fn should_ping(&self) -> bool {
        match self.last_ping_sent {
            None => true,
            Some(last) => Instant::now().duration_since(last) >= self.current_interval(),
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

    /// Get the consecutive successful PONG count.
    pub fn consecutive_pongs(&self) -> u32 {
        self.consecutive_pongs
    }

    /// Get the adaptive keep-alive configuration.
    pub fn config(&self) -> &AdaptiveKeepAliveConfig {
        &self.config
    }
}

impl Default for AdaptivePingTracker {
    fn default() -> Self {
        Self::new()
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

    // ----- AdaptivePingTracker tests (Track I7) -----

    #[test]
    fn test_adaptive_starts_in_normal_state() {
        let tracker = AdaptivePingTracker::new();
        assert_eq!(tracker.state(), KeepAliveState::Normal);
        assert_eq!(tracker.current_interval(), Duration::from_secs(30));
    }

    #[test]
    fn test_adaptive_transitions_to_stable_after_threshold_pongs() {
        let mut tracker = AdaptivePingTracker::new();
        assert_eq!(tracker.state(), KeepAliveState::Normal);

        // Send 3 PINGs and get 3 PONGs
        for _ in 0..3 {
            let id = tracker.record_ping();
            assert!(tracker.record_pong(id));
        }

        assert_eq!(tracker.consecutive_pongs(), 3);
        assert_eq!(tracker.state(), KeepAliveState::Stable);
        assert_eq!(tracker.current_interval(), Duration::from_secs(60));
    }

    #[test]
    fn test_adaptive_stays_normal_below_threshold() {
        let mut tracker = AdaptivePingTracker::new();

        // Only 2 PONGs (below threshold of 3)
        for _ in 0..2 {
            let id = tracker.record_ping();
            assert!(tracker.record_pong(id));
        }

        assert_eq!(tracker.state(), KeepAliveState::Normal);
        assert_eq!(tracker.current_interval(), Duration::from_secs(30));
    }

    #[test]
    fn test_adaptive_transitions_to_unstable_on_missed_pong() {
        let config = AdaptiveKeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 3,
            ..Default::default()
        };
        let mut tracker = AdaptivePingTracker::with_config(config);

        // First, get to Stable state
        for _ in 0..3 {
            let id = tracker.record_ping();
            assert!(tracker.record_pong(id));
        }
        assert_eq!(tracker.state(), KeepAliveState::Stable);

        // Send a PING and let it time out
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        let should_close = tracker.check_timeouts();

        assert!(!should_close); // Only 1 missed, not enough to close
        assert_eq!(tracker.state(), KeepAliveState::Unstable);
        assert_eq!(tracker.current_interval(), Duration::from_secs(10));
        assert_eq!(tracker.consecutive_pongs(), 0);
    }

    #[test]
    fn test_adaptive_unstable_to_normal_on_pong() {
        let config = AdaptiveKeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 3,
            ..Default::default()
        };
        let mut tracker = AdaptivePingTracker::with_config(config);

        // Get to Unstable state
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        tracker.check_timeouts();
        assert_eq!(tracker.state(), KeepAliveState::Unstable);

        // Receive a PONG
        let id = tracker.record_ping();
        assert!(tracker.record_pong(id));

        assert_eq!(tracker.state(), KeepAliveState::Normal);
        assert_eq!(tracker.current_interval(), Duration::from_secs(30));
    }

    #[test]
    fn test_adaptive_closes_after_max_missed() {
        let config = AdaptiveKeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 3,
            ..Default::default()
        };
        let mut tracker = AdaptivePingTracker::with_config(config);

        // Miss 3 PONGs
        for _ in 0..3 {
            tracker.record_ping();
            std::thread::sleep(Duration::from_millis(10));
        }

        let should_close = tracker.check_timeouts();
        assert!(should_close); // 3 missed, should close
        assert_eq!(tracker.missed_count(), 3);
    }

    #[test]
    fn test_adaptive_stable_to_unstable_directly() {
        let config = AdaptiveKeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 3,
            ..Default::default()
        };
        let mut tracker = AdaptivePingTracker::with_config(config);

        // Get to Stable
        for _ in 0..3 {
            let id = tracker.record_ping();
            assert!(tracker.record_pong(id));
        }
        assert_eq!(tracker.state(), KeepAliveState::Stable);

        // Miss a PONG
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        tracker.check_timeouts();

        // Should go directly to Unstable (not Normal)
        assert_eq!(tracker.state(), KeepAliveState::Unstable);
    }

    #[test]
    fn test_adaptive_should_ping_uses_current_interval() {
        let config = AdaptiveKeepAliveConfig {
            base_interval: Duration::from_millis(10),
            stable_interval: Duration::from_millis(50),
            unstable_interval: Duration::from_millis(5),
            timeout: Duration::from_secs(10),
            stable_threshold: 2,
            max_missed: 3,
        };
        let mut tracker = AdaptivePingTracker::with_config(config);

        // Initially should ping (no ping sent yet)
        assert!(tracker.should_ping());

        // Send a ping — should not ping immediately after
        tracker.record_ping();
        assert!(!tracker.should_ping());

        // Wait 10ms (base interval) — should ping
        std::thread::sleep(Duration::from_millis(15));
        assert!(tracker.should_ping());

        // Get to stable state (2 PONGs)
        let id = tracker.record_ping();
        assert!(tracker.record_pong(id));
        let id = tracker.record_ping();
        assert!(tracker.record_pong(id));
        assert_eq!(tracker.state(), KeepAliveState::Stable);

        // Now interval is 50ms — should not ping after 20ms
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(20));
        assert!(!tracker.should_ping());

        // But should ping after 50ms
        std::thread::sleep(Duration::from_millis(35));
        assert!(tracker.should_ping());
    }

    #[test]
    fn test_adaptive_config_defaults() {
        let config = AdaptiveKeepAliveConfig::default();
        assert_eq!(config.base_interval, Duration::from_secs(30));
        assert_eq!(config.stable_interval, Duration::from_secs(60));
        assert_eq!(config.unstable_interval, Duration::from_secs(10));
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.stable_threshold, 3);
        assert_eq!(config.max_missed, 3);
    }

    #[test]
    fn test_adaptive_missed_count_resets_on_pong() {
        let config = AdaptiveKeepAliveConfig {
            timeout: Duration::from_millis(1),
            max_missed: 5,
            ..Default::default()
        };
        let mut tracker = AdaptivePingTracker::with_config(config);

        // Miss a PONG
        tracker.record_ping();
        std::thread::sleep(Duration::from_millis(10));
        tracker.check_timeouts();
        assert_eq!(tracker.missed_count(), 1);

        // Receive a PONG
        let id = tracker.record_ping();
        assert!(tracker.record_pong(id));
        assert_eq!(tracker.missed_count(), 0);
    }
}
