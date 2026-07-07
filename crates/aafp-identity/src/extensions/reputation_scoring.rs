//! Reputation score engine (Track W7).
//!
//! Calculates reputation scores from performance history using a weighted
//! average of: success rate, latency, cost, availability, and attestation
//! count. Older interactions are weighted less via exponential time decay.
//!
//! This engine is distinct from [`crate::extensions::reputation`], which
//! only carries a self-claimed score and attestation references. The engine
//! here *computes* a score from observed performance history and optional
//! third-party attestations, then can write the result back into a
//! [`ReputationExtension`] on an [`AgentRecord`].

use super::performance::PerformanceExtension;
use super::reputation::ReputationExtension;
use super::Attestation;
use crate::identity_v1::{AgentId, AgentRecord};
use std::collections::VecDeque;

/// Default weights and tuning parameters for the score engine.
pub const DEFAULT_SUCCESS_WEIGHT: f64 = 0.3;
pub const DEFAULT_LATENCY_WEIGHT: f64 = 0.2;
pub const DEFAULT_COST_WEIGHT: f64 = 0.15;
pub const DEFAULT_AVAILABILITY_WEIGHT: f64 = 0.2;
pub const DEFAULT_ATTESTATION_WEIGHT: f64 = 0.15;
pub const DEFAULT_HISTORY_WINDOW: usize = 100;
pub const DEFAULT_DECAY_FACTOR: f64 = 0.95;

/// Neutral sub-score returned when there is no interaction history.
pub const NEUTRAL_SCORE: u8 = 50;

/// Configuration for [`ReputationScoreEngine`].
#[derive(Clone, Debug)]
pub struct ReputationConfig {
    /// Weight for success rate (0.0-1.0).
    pub success_weight: f64,
    /// Weight for latency (0.0-1.0).
    pub latency_weight: f64,
    /// Weight for cost (0.0-1.0).
    pub cost_weight: f64,
    /// Weight for availability (0.0-1.0).
    pub availability_weight: f64,
    /// Weight for attestation count (0.0-1.0).
    pub attestation_weight: f64,
    /// History window (maximum number of interactions considered).
    pub history_window: usize,
    /// Decay factor for old interactions (per-index exponential decay).
    /// A value of 0.95 means each step back in history is weighted 95% as
    /// much as the next-newer one.
    pub decay_factor: f64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            success_weight: DEFAULT_SUCCESS_WEIGHT,
            latency_weight: DEFAULT_LATENCY_WEIGHT,
            cost_weight: DEFAULT_COST_WEIGHT,
            availability_weight: DEFAULT_AVAILABILITY_WEIGHT,
            attestation_weight: DEFAULT_ATTESTATION_WEIGHT,
            history_window: DEFAULT_HISTORY_WINDOW,
            decay_factor: DEFAULT_DECAY_FACTOR,
        }
    }
}

impl ReputationConfig {
    /// Normalize weights so they sum to 1.0.
    ///
    /// If the sum is zero, NaN, or infinite, equal weights are used instead.
    fn normalized_weights(&self) -> (f64, f64, f64, f64, f64) {
        let sum = self.success_weight
            + self.latency_weight
            + self.cost_weight
            + self.availability_weight
            + self.attestation_weight;
        if !sum.is_finite() || sum <= 0.0 {
            // Fall back to equal weights (1/5 each).
            let w = 0.2_f64;
            return (w, w, w, w, w);
        }
        (
            self.success_weight / sum,
            self.latency_weight / sum,
            self.cost_weight / sum,
            self.availability_weight / sum,
            self.attestation_weight / sum,
        )
    }
}

/// Calculates reputation scores from performance history.
///
/// Uses a weighted average of: success rate, latency, cost, availability,
/// and attestation count. Older interactions contribute less via exponential
/// time decay (see [`ReputationConfig::decay_factor`]).
pub struct ReputationScoreEngine {
    config: ReputationConfig,
}

impl ReputationScoreEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: ReputationConfig) -> Self {
        Self { config }
    }

    /// Create a new engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ReputationConfig::default())
    }

    /// Return a reference to the engine's configuration.
    pub fn config(&self) -> &ReputationConfig {
        &self.config
    }

    /// Calculate reputation score for an agent from its performance history
    /// and a slice of third-party attestations.
    pub fn score(
        &self,
        history: &PerformanceHistory,
        attestations: &[Attestation],
    ) -> ReputationScore {
        // Confidence is a function of interaction count.
        let count = history.interactions.len();
        let confidence = if count == 0 {
            0.0
        } else {
            let raw = count as f64 / 10.0;
            if raw.is_finite() {
                raw.min(1.0)
            } else {
                1.0
            }
        };

        // Empty history: neutral sub-scores, zero confidence.
        if count == 0 {
            return ReputationScore {
                overall: NEUTRAL_SCORE,
                success_score: NEUTRAL_SCORE,
                latency_score: NEUTRAL_SCORE,
                cost_score: NEUTRAL_SCORE,
                availability_score: NEUTRAL_SCORE,
                attestation_score: self.attestation_score(attestations),
                confidence: 0.0,
            };
        }

        // Apply the history window: only the most recent `history_window`
        // interactions are considered. "Most recent" = highest timestamp.
        let windowed = self.window_interactions(&history.interactions);

        // Compute decay weights for the windowed slice (newest first).
        let decay_weights = self.decay_weights(windowed.len());

        let success_score = self.success_score(&windowed, &decay_weights);
        let latency_score = self.latency_score(&windowed, &decay_weights);
        let cost_score = self.cost_score(&windowed, &decay_weights);
        let availability_score = self.availability_score(&windowed, &decay_weights);
        let attestation_score = self.attestation_score(attestations);

        let overall = self.weighted_overall(
            success_score,
            latency_score,
            cost_score,
            availability_score,
            attestation_score,
        );

        ReputationScore {
            overall,
            success_score,
            latency_score,
            cost_score,
            availability_score,
            attestation_score,
            confidence,
        }
    }

    /// Calculate a score from an [`AgentRecord`]'s extensions.
    ///
    /// If a [`PerformanceExtension`] is present, its self-reported metrics
    /// are used to synthesize a minimal [`PerformanceHistory`]. Otherwise an
    /// empty history is used (yielding neutral sub-scores). Attestations are
    /// not stored on the record, so an empty slice is used.
    pub fn score_from_record(&self, record: &AgentRecord) -> ReputationScore {
        let perf: Option<PerformanceExtension> = record.get_extension();
        let history = match perf {
            Some(p) => synthesize_history(&record.agent_id, &p),
            None => PerformanceHistory {
                agent_id: record.agent_id,
                interactions: VecDeque::new(),
            },
        };
        self.score(&history, &[])
    }

    /// Update the [`ReputationExtension`] on an [`AgentRecord`] with a
    /// freshly computed score.
    ///
    /// Computes the score from the given history and attestations, then sets
    /// `self_claimed_score` on the record's reputation extension (creating
    /// one if absent). The record must be re-signed before publishing.
    pub fn update_record(
        &self,
        record: &mut AgentRecord,
        history: &PerformanceHistory,
        attestations: &[Attestation],
    ) {
        let score = self.score(history, attestations);
        let mut rep: ReputationExtension = record.get_extension().unwrap_or_default();
        rep.self_claimed_score = Some(score.overall);
        record.set_extension(rep);
    }

    // ----- internal helpers -------------------------------------------------

    /// Select the most recent `history_window` interactions, sorted newest
    /// first. Interactions with equal timestamps keep their relative order.
    fn window_interactions(&self, interactions: &VecDeque<Interaction>) -> Vec<Interaction> {
        let mut all: Vec<Interaction> = interactions.iter().cloned().collect();
        // Sort by timestamp descending (newest first). Stable sort preserves
        // insertion order for equal timestamps.
        all.sort_by_key(|a| std::cmp::Reverse(a.timestamp));
        let window = self.config.history_window.min(all.len());
        all.truncate(window);
        all
    }

    /// Compute per-interaction decay weights for a slice of length `n`,
    /// ordered newest-first. The newest interaction has weight 1.0, the next
    /// `decay_factor`, then `decay_factor^2`, etc.
    fn decay_weights(&self, n: usize) -> Vec<f64> {
        let mut weights = Vec::with_capacity(n);
        let mut w = 1.0_f64;
        for _ in 0..n {
            if !w.is_finite() {
                w = 0.0;
            }
            weights.push(w);
            w *= self.config.decay_factor;
        }
        weights
    }

    /// Weighted success rate as a 0-100 score.
    fn success_score(&self, windowed: &[Interaction], weights: &[f64]) -> u8 {
        let mut weighted_sum = 0.0_f64;
        let mut total_weight = 0.0_f64;
        for (inter, w) in windowed.iter().zip(weights.iter()) {
            let w = if w.is_finite() { *w } else { 0.0 };
            let val = if inter.success { 1.0_f64 } else { 0.0 };
            weighted_sum += w * val;
            total_weight += w;
        }
        if !total_weight.is_finite() || total_weight <= 0.0 {
            return NEUTRAL_SCORE;
        }
        let ratio = weighted_sum / total_weight;
        let ratio = sanitize_f64(ratio);
        let scaled = ratio * 100.0;
        clamp_to_u8(scaled)
    }

    /// Weighted latency score: 0ms -> 100, 1000ms -> 0.
    fn latency_score(&self, windowed: &[Interaction], weights: &[f64]) -> u8 {
        let mut weighted_sum = 0.0_f64;
        let mut total_weight = 0.0_f64;
        for (inter, w) in windowed.iter().zip(weights.iter()) {
            let w = if w.is_finite() { *w } else { 0.0 };
            let lat = inter.latency_ms as f64;
            weighted_sum += w * lat;
            total_weight += w;
        }
        if !total_weight.is_finite() || total_weight <= 0.0 {
            return NEUTRAL_SCORE;
        }
        let avg = sanitize_f64(weighted_sum / total_weight);
        // 0ms -> 100, 1000ms -> 0
        let raw = 100.0 - (avg / 10.0);
        clamp_to_u8(raw)
    }

    /// Weighted cost score: 0 cost -> 100, 10000 cost -> 0.
    fn cost_score(&self, windowed: &[Interaction], weights: &[f64]) -> u8 {
        let mut weighted_sum = 0.0_f64;
        let mut total_weight = 0.0_f64;
        for (inter, w) in windowed.iter().zip(weights.iter()) {
            let w = if w.is_finite() { *w } else { 0.0 };
            let cost = inter.cost as f64;
            weighted_sum += w * cost;
            total_weight += w;
        }
        if !total_weight.is_finite() || total_weight <= 0.0 {
            return NEUTRAL_SCORE;
        }
        let avg = sanitize_f64(weighted_sum / total_weight);
        // 0 cost -> 100, 10000 cost -> 0
        let raw = 100.0 - (avg / 100.0);
        clamp_to_u8(raw)
    }

    /// Availability score derived from success rate (no uptime field on
    /// interactions). This mirrors the spec's fallback: "based on uptime
    /// from PerformanceExtension if available, else derived from success
    /// rate". Since interactions carry no uptime, we derive from success.
    fn availability_score(&self, windowed: &[Interaction], weights: &[f64]) -> u8 {
        // Reuse the success computation: availability ~= success rate.
        self.success_score(windowed, weights)
    }

    /// Attestation score: `min(100, count * 20)` — 5 attestations = 100.
    fn attestation_score(&self, attestations: &[Attestation]) -> u8 {
        let count = attestations.len();
        let raw = count.saturating_mul(20);
        raw.min(100) as u8
    }

    /// Weighted average of all sub-scores, normalized to 0-100.
    fn weighted_overall(
        &self,
        success: u8,
        latency: u8,
        cost: u8,
        availability: u8,
        attestation: u8,
    ) -> u8 {
        let (ws, wl, wc, wa, wt) = self.config.normalized_weights();
        let s = success as f64;
        let l = latency as f64;
        let c = cost as f64;
        let a = availability as f64;
        let t = attestation as f64;
        let raw = ws * s + wl * l + wc * c + wa * a + wt * t;
        let raw = sanitize_f64(raw);
        clamp_to_u8(raw)
    }
}

/// A single observed interaction with an agent.
#[derive(Clone, Debug)]
pub struct Interaction {
    /// Unix-seconds timestamp of the interaction.
    pub timestamp: u64,
    /// Whether the interaction succeeded.
    pub success: bool,
    /// Observed latency in milliseconds.
    pub latency_ms: u64,
    /// Observed cost (arbitrary units).
    pub cost: u64,
    /// Capability that was invoked.
    pub capability: String,
}

/// Performance history for a single agent, stored as a window of
/// interactions.
#[derive(Clone, Debug)]
pub struct PerformanceHistory {
    /// The agent this history pertains to.
    pub agent_id: AgentId,
    /// Window of recent interactions (order is preserved; the engine sorts
    /// by timestamp when scoring).
    pub interactions: VecDeque<Interaction>,
}

impl PerformanceHistory {
    /// Create an empty history for the given agent.
    pub fn new(agent_id: AgentId) -> Self {
        Self {
            agent_id,
            interactions: VecDeque::new(),
        }
    }

    /// Push a new interaction, evicting the oldest if the window exceeds
    /// `max_len`. This keeps the deque bounded.
    pub fn push(&mut self, interaction: Interaction, max_len: usize) {
        self.interactions.push_back(interaction);
        while self.interactions.len() > max_len {
            self.interactions.pop_front();
        }
    }
}

/// A computed reputation score with per-component breakdown.
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationScore {
    /// Overall weighted score (0-100).
    pub overall: u8,
    /// Success-rate component (0-100).
    pub success_score: u8,
    /// Latency component (0-100).
    pub latency_score: u8,
    /// Cost component (0-100).
    pub cost_score: u8,
    /// Availability component (0-100).
    pub availability_score: u8,
    /// Attestation-count component (0-100).
    pub attestation_score: u8,
    /// Confidence in the score (0.0-1.0), based on interaction count.
    pub confidence: f64,
}

// ----- free functions -------------------------------------------------------

/// Replace NaN/infinite floats with 0.0.
fn sanitize_f64(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

/// Clamp a float to [0, 100] and cast to `u8`, guarding against NaN/inf.
fn clamp_to_u8(v: f64) -> u8 {
    if !v.is_finite() {
        return 0;
    }
    if v <= 0.0 {
        return 0;
    }
    if v >= 100.0 {
        return 100;
    }
    // v is finite and in (0, 100).
    v.round() as u8
}

/// Synthesize a minimal [`PerformanceHistory`] from a [`PerformanceExtension`].
///
/// The extension's self-reported metrics are translated into a single
/// representative interaction so the engine can score records that carry
/// only a perf extension (no raw interaction log).
fn synthesize_history(agent_id: &AgentId, perf: &PerformanceExtension) -> PerformanceHistory {
    let mut interactions = VecDeque::new();
    let success = perf.uptime_bps.map(|bps| bps >= 5000).unwrap_or(true);
    let latency_ms = perf.avg_latency_ms.map(|l| l as u64).unwrap_or(0);
    // No cost field on the perf extension; assume 0.
    let cost = 0u64;
    interactions.push_back(Interaction {
        timestamp: perf.updated_at,
        success,
        latency_ms,
        cost,
        capability: String::new(),
    });
    PerformanceHistory {
        agent_id: *agent_id,
        interactions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::attestation::AttestationData;
    use crate::identity_v1::{AgentId, AgentRecord, CapabilityDescriptor};

    fn agent_id(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn interaction(timestamp: u64, success: bool, latency_ms: u64, cost: u64) -> Interaction {
        Interaction {
            timestamp,
            success,
            latency_ms,
            cost,
            capability: "test".into(),
        }
    }

    fn perfect_history() -> PerformanceHistory {
        let mut interactions = VecDeque::new();
        for i in 0..10 {
            interactions.push_back(interaction(1000 + i, true, 0, 0));
        }
        PerformanceHistory {
            agent_id: agent_id(1),
            interactions,
        }
    }

    fn make_attestations(count: usize) -> Vec<Attestation> {
        (0..count)
            .map(|i| Attestation {
                record_type: "aafp-attestation-v1".into(),
                subject_agent_id: agent_id(1),
                attester_agent_id: agent_id(i as u8 + 10),
                attester_public_key: vec![0u8; 1952],
                attested_at: 1000,
                expires_at: 2000,
                data: AttestationData::default(),
                signature: vec![],
            })
            .collect()
    }

    // 1. Perfect agent (all 100s)
    #[test]
    fn test_perfect_agent() {
        let engine = ReputationScoreEngine::with_defaults();
        let history = perfect_history();
        let attestations = make_attestations(5);
        let score = engine.score(&history, &attestations);
        assert_eq!(score.success_score, 100);
        assert_eq!(score.latency_score, 100);
        assert_eq!(score.cost_score, 100);
        assert_eq!(score.availability_score, 100);
        assert_eq!(score.attestation_score, 100);
        assert_eq!(score.overall, 100);
        assert!((score.confidence - 1.0).abs() < 1e-9);
    }

    // 2. Poor agent (low scores)
    #[test]
    fn test_poor_agent() {
        let engine = ReputationScoreEngine::with_defaults();
        let mut interactions = VecDeque::new();
        for i in 0..10 {
            interactions.push_back(interaction(1000 + i, false, 2000, 20000));
        }
        let history = PerformanceHistory {
            agent_id: agent_id(2),
            interactions,
        };
        let score = engine.score(&history, &[]);
        assert_eq!(score.success_score, 0);
        assert_eq!(score.latency_score, 0);
        assert_eq!(score.cost_score, 0);
        assert_eq!(score.availability_score, 0);
        assert_eq!(score.overall, 0);
    }

    // 3. Mixed performance
    #[test]
    fn test_mixed_performance() {
        let engine = ReputationScoreEngine::with_defaults();
        let mut interactions = VecDeque::new();
        // 5 success, 5 failure; moderate latency and cost
        for i in 0..10 {
            interactions.push_back(interaction(
                1000 + i,
                i % 2 == 0,
                500,  // -> 100 - 50 = 50
                5000, // -> 100 - 50 = 50
            ));
        }
        let history = PerformanceHistory {
            agent_id: agent_id(3),
            interactions,
        };
        let score = engine.score(&history, &[]);
        // With time decay (decay_factor=0.95), earlier interactions have
        // slightly less weight, so the weighted success rate is not exactly
        // 50%. The success/latency/cost scores are close to 50 but may differ
        // by ±1 due to rounding.
        assert!((score.success_score as i32 - 50).abs() <= 1);
        assert!((score.latency_score as i32 - 50).abs() <= 1);
        assert!((score.cost_score as i32 - 50).abs() <= 1);
        // overall = weighted avg with default weights, no attestations
        // attestation_score=0 pulls overall down.
        assert!(score.overall < 50);
    }

    // 4. Time decay (old interactions weighted less)
    #[test]
    fn test_time_decay() {
        let engine = ReputationScoreEngine::with_defaults();
        // One old failure, many recent successes.
        let mut interactions = VecDeque::new();
        interactions.push_back(interaction(1, false, 0, 0)); // old failure
        for i in 0..10 {
            interactions.push_back(interaction(1000 + i, true, 0, 0));
        }
        let history = PerformanceHistory {
            agent_id: agent_id(4),
            interactions,
        };
        let score = engine.score(&history, &[]);
        // With decay, the single old failure is heavily discounted, so the
        // success score should be very high (close to 100) but not exactly
        // 100 because the old failure still contributes a tiny amount.
        assert!(score.success_score > 90);
        assert!(score.success_score <= 100);
    }

    // 5. Confidence increases with more interactions
    #[test]
    fn test_confidence_increases() {
        let engine = ReputationScoreEngine::with_defaults();
        // 1 interaction -> confidence 0.1
        let h1 = PerformanceHistory {
            agent_id: agent_id(5),
            interactions: {
                let mut d = VecDeque::new();
                d.push_back(interaction(1, true, 0, 0));
                d
            },
        };
        let s1 = engine.score(&h1, &[]);
        assert!((s1.confidence - 0.1).abs() < 1e-9);

        // 5 interactions -> confidence 0.5
        let h5 = PerformanceHistory {
            agent_id: agent_id(5),
            interactions: {
                let mut d = VecDeque::new();
                for i in 0..5 {
                    d.push_back(interaction(i, true, 0, 0));
                }
                d
            },
        };
        let s5 = engine.score(&h5, &[]);
        assert!((s5.confidence - 0.5).abs() < 1e-9);

        // 10 interactions -> confidence 1.0
        let h10 = perfect_history();
        let s10 = engine.score(&h10, &[]);
        assert!((s10.confidence - 1.0).abs() < 1e-9);
    }

    // 6. Weight configuration (custom weights)
    #[test]
    fn test_custom_weights() {
        let config = ReputationConfig {
            success_weight: 1.0,
            latency_weight: 0.0,
            cost_weight: 0.0,
            availability_weight: 0.0,
            attestation_weight: 0.0,
            history_window: 100,
            decay_factor: 0.95,
        };
        let engine = ReputationScoreEngine::new(config);
        let mut interactions = VecDeque::new();
        for i in 0..10 {
            interactions.push_back(interaction(1000 + i, i % 2 == 0, 2000, 20000));
        }
        let history = PerformanceHistory {
            agent_id: agent_id(6),
            interactions,
        };
        let score = engine.score(&history, &[]);
        // Only success matters; ~50% success with time decay.
        assert!((score.overall as i32 - 50).abs() <= 1);
    }

    // 7. Score from AgentRecord (with PerformanceExtension)
    #[test]
    fn test_score_from_record_with_perf() {
        let engine = ReputationScoreEngine::with_defaults();
        let pk = vec![0u8; 1952];
        let mut record = AgentRecord::new(
            &pk,
            vec![CapabilityDescriptor::new("test")],
            vec!["/ip4/127.0.0.1/tcp/4001".into()],
            1000,
            2000,
            1,
        );
        let perf = PerformanceExtension {
            version: 1,
            avg_latency_ms: Some(0),
            uptime_bps: Some(10000),
            updated_at: 1500,
            ..Default::default()
        };
        record.set_extension(perf);
        let score = engine.score_from_record(&record);
        // Synthesized history: 1 interaction, success=true (uptime>=5000),
        // latency=0, cost=0. Sub-scores should be 100 for success/latency/cost.
        assert_eq!(score.success_score, 100);
        assert_eq!(score.latency_score, 100);
        assert_eq!(score.cost_score, 100);
        assert_eq!(score.attestation_score, 0);
    }

    // 8. Update AgentRecord with new score
    #[test]
    fn test_update_record() {
        let engine = ReputationScoreEngine::with_defaults();
        let pk = vec![0u8; 1952];
        let mut record = AgentRecord::new(
            &pk,
            vec![CapabilityDescriptor::new("test")],
            vec!["/ip4/127.0.0.1/tcp/4001".into()],
            1000,
            2000,
            1,
        );
        let history = perfect_history();
        engine.update_record(&mut record, &history, &make_attestations(5));
        let rep: ReputationExtension = record
            .get_extension()
            .expect("reputation extension should be set");
        assert_eq!(rep.self_claimed_score, Some(100));
    }

    // 9. Empty history (default neutral score, 0.0 confidence)
    #[test]
    fn test_empty_history() {
        let engine = ReputationScoreEngine::with_defaults();
        let history = PerformanceHistory::new(agent_id(9));
        let score = engine.score(&history, &[]);
        assert_eq!(score.success_score, NEUTRAL_SCORE);
        assert_eq!(score.latency_score, NEUTRAL_SCORE);
        assert_eq!(score.cost_score, NEUTRAL_SCORE);
        assert_eq!(score.availability_score, NEUTRAL_SCORE);
        assert_eq!(score.attestation_score, 0); // no attestations
        assert_eq!(score.confidence, 0.0);
        // Empty history returns NEUTRAL_SCORE (50) for overall, not the
        // weighted average (which would be lower due to attestation_score=0).
        assert_eq!(score.overall, NEUTRAL_SCORE);
    }

    // 10. Single interaction
    #[test]
    fn test_single_interaction() {
        let engine = ReputationScoreEngine::with_defaults();
        let history = PerformanceHistory {
            agent_id: agent_id(10),
            interactions: {
                let mut d = VecDeque::new();
                d.push_back(interaction(1, true, 100, 1000));
                d
            },
        };
        let score = engine.score(&history, &[]);
        assert_eq!(score.success_score, 100);
        // latency 100ms -> 100 - 10 = 90
        assert_eq!(score.latency_score, 90);
        // cost 1000 -> 100 - 10 = 90
        assert_eq!(score.cost_score, 90);
        assert!((score.confidence - 0.1).abs() < 1e-9);
    }

    // 11. Attestation boost (more attestations = higher score)
    #[test]
    fn test_attestation_boost() {
        let engine = ReputationScoreEngine::with_defaults();
        let history = perfect_history();
        let mk_att = |n: u8| Attestation {
            record_type: "aafp-attestation-v1".into(),
            subject_agent_id: agent_id(1),
            attester_agent_id: agent_id(n),
            attester_public_key: vec![0u8; 1952],
            attested_at: 1000,
            expires_at: 2000,
            data: Default::default(),
            signature: vec![],
        };
        let score0 = engine.score(&history, &[]);
        let score1 = engine.score(&history, &[mk_att(2)]);
        let score5 = engine.score(
            &history,
            &[mk_att(2), mk_att(3), mk_att(4), mk_att(5), mk_att(6)],
        );
        assert_eq!(score0.attestation_score, 0);
        assert_eq!(score1.attestation_score, 20);
        assert_eq!(score5.attestation_score, 100);
        assert!(score5.overall >= score1.overall);
        assert!(score1.overall >= score0.overall);
    }

    // 12. No attestations (attestation_score = 0)
    #[test]
    fn test_no_attestations() {
        let engine = ReputationScoreEngine::with_defaults();
        let history = perfect_history();
        let score = engine.score(&history, &[]);
        assert_eq!(score.attestation_score, 0);
    }

    // 13. NaN/infinity guards (feed NaN/inf via config, verify no panic)
    #[test]
    fn test_nan_inf_guards() {
        let config = ReputationConfig {
            success_weight: f64::NAN,
            latency_weight: f64::INFINITY,
            cost_weight: f64::NEG_INFINITY,
            availability_weight: -1.0,
            attestation_weight: 0.0,
            history_window: 100,
            decay_factor: f64::NAN,
        };
        let engine = ReputationScoreEngine::new(config);
        let history = perfect_history();
        // Should not panic; should produce a finite, bounded score.
        let score = engine.score(&history, &[]);
        assert!(score.overall <= 100);
        assert!(score.confidence.is_finite());
        // With all-non-finite weights, equal weights (0.2 each) are used.
        // success=100, latency=100, cost=100, avail=100, att=0
        // overall = 0.2*100*4 + 0.2*0 = 80
        assert_eq!(score.overall, 80);
    }

    // 14. Score bounds (0-100, never exceeds or goes below)
    #[test]
    fn test_score_bounds() {
        let engine = ReputationScoreEngine::with_defaults();
        // Extreme latency and cost -> should clamp to 0, not underflow.
        let mut interactions = VecDeque::new();
        interactions.push_back(interaction(1, false, u64::MAX, u64::MAX));
        let history = PerformanceHistory {
            agent_id: agent_id(14),
            interactions,
        };
        let score = engine.score(&history, &[]);
        assert_eq!(score.success_score, 0);
        assert_eq!(score.latency_score, 0);
        assert_eq!(score.cost_score, 0);
        assert_eq!(score.overall, 0);

        // Perfect -> 100, not above. (Need attestations for overall=100.)
        let perfect = perfect_history();
        let s2 = engine.score(&perfect, &make_attestations(5));
        assert_eq!(s2.overall, 100);
        assert!((s2.confidence - 1.0).abs() < 1e-9);
    }

    // 15. Weighted average correctness (overall = weighted sum)
    #[test]
    fn test_weighted_average_correctness() {
        let engine = ReputationScoreEngine::with_defaults();
        let mut interactions = VecDeque::new();
        for i in 0..10 {
            interactions.push_back(interaction(1000 + i, true, 500, 5000));
        }
        let history = PerformanceHistory {
            agent_id: agent_id(15),
            interactions,
        };
        let score = engine.score(&history, &[]);
        // All sub-scores: success=100, latency=50, cost=50, avail=100, att=0
        assert_eq!(score.success_score, 100);
        assert_eq!(score.latency_score, 50);
        assert_eq!(score.cost_score, 50);
        assert_eq!(score.availability_score, 100);
        assert_eq!(score.attestation_score, 0);
        // Default weights sum to 1.0.
        // overall = 0.3*100 + 0.2*50 + 0.15*50 + 0.2*100 + 0.15*0
        //         = 30 + 10 + 7.5 + 20 + 0 = 67.5 -> 68
        let expected: f64 = 0.3 * 100.0 + 0.2 * 50.0 + 0.15 * 50.0 + 0.2 * 100.0 + 0.15 * 0.0;
        assert_eq!(score.overall, expected.round() as u8);
        assert_eq!(score.overall, 68);
    }

    // 16. History window truncation (extra interactions ignored)
    #[test]
    fn test_history_window_truncation() {
        let config = ReputationConfig {
            history_window: 5,
            ..Default::default()
        };
        let engine = ReputationScoreEngine::new(config);
        // 20 interactions: 10 old failures, 10 recent successes.
        let mut interactions = VecDeque::new();
        for i in 0..10 {
            interactions.push_back(interaction(i, false, 0, 0)); // old failures
        }
        for i in 100..110 {
            interactions.push_back(interaction(i, true, 0, 0)); // recent successes
        }
        let history = PerformanceHistory {
            agent_id: agent_id(16),
            interactions,
        };
        let score = engine.score(&history, &[]);
        // Only the 5 most recent (successes) are considered.
        assert_eq!(score.success_score, 100);
    }

    // 17. PerformanceHistory::push evicts oldest beyond max_len
    #[test]
    fn test_history_push_eviction() {
        let mut hist = PerformanceHistory::new(agent_id(17));
        for i in 0..5 {
            hist.push(interaction(i, true, 0, 0), 3);
        }
        assert_eq!(hist.interactions.len(), 3);
        // Oldest two (timestamps 0, 1) should have been evicted.
        assert_eq!(hist.interactions.front().unwrap().timestamp, 2);
    }

    // 18. Default config values
    #[test]
    fn test_default_config_values() {
        let cfg = ReputationConfig::default();
        assert_eq!(cfg.success_weight, DEFAULT_SUCCESS_WEIGHT);
        assert_eq!(cfg.latency_weight, DEFAULT_LATENCY_WEIGHT);
        assert_eq!(cfg.cost_weight, DEFAULT_COST_WEIGHT);
        assert_eq!(cfg.availability_weight, DEFAULT_AVAILABILITY_WEIGHT);
        assert_eq!(cfg.attestation_weight, DEFAULT_ATTESTATION_WEIGHT);
        assert_eq!(cfg.history_window, DEFAULT_HISTORY_WINDOW);
        assert_eq!(cfg.decay_factor, DEFAULT_DECAY_FACTOR);
    }

    // 19. score_from_record without PerformanceExtension -> neutral sub-scores
    #[test]
    fn test_score_from_record_no_perf() {
        let engine = ReputationScoreEngine::with_defaults();
        let pk = vec![0u8; 1952];
        let record = AgentRecord::new(
            &pk,
            vec![CapabilityDescriptor::new("test")],
            vec!["/ip4/127.0.0.1/tcp/4001".into()],
            1000,
            2000,
            1,
        );
        let score = engine.score_from_record(&record);
        assert_eq!(score.success_score, NEUTRAL_SCORE);
        assert_eq!(score.latency_score, NEUTRAL_SCORE);
        assert_eq!(score.cost_score, NEUTRAL_SCORE);
        assert_eq!(score.confidence, 0.0);
    }

    // 20. update_record preserves existing attestation refs on the extension
    #[test]
    fn test_update_record_preserves_refs() {
        let engine = ReputationScoreEngine::with_defaults();
        let pk = vec![0u8; 1952];
        let mut record = AgentRecord::new(
            &pk,
            vec![CapabilityDescriptor::new("test")],
            vec!["/ip4/127.0.0.1/tcp/4001".into()],
            1000,
            2000,
            1,
        );
        let mut rep = ReputationExtension::default();
        rep.attestation_refs = vec!["abc".into(), "def".into()];
        rep.sources = vec!["dht://key".into()];
        record.set_extension(rep);

        let history = perfect_history();
        engine.update_record(&mut record, &history, &make_attestations(5));

        let rep2: ReputationExtension = record
            .get_extension()
            .expect("reputation extension present");
        assert_eq!(rep2.self_claimed_score, Some(100));
        assert_eq!(
            rep2.attestation_refs,
            vec!["abc".to_string(), "def".to_string()]
        );
        assert_eq!(rep2.sources, vec!["dht://key".to_string()]);
    }
}
