//! Track T8 — Temporal Prediction Engine.
//!
//! Predicts *future* agent performance based on historical metrics.
//! "Who will be fastest 200ms from now?" not "Who is fastest now?"
//!
//! Each agent gets a [`PredictionModel`] that maintains:
//! - A linear-regression latency trend (slope + intercept) over recent samples.
//! - EWMA-smoothed latency, success rate, and load.
//! - A confidence score derived from sample count and variance.
//!
//! The engine answers questions like:
//! - What latency do we expect from agent X in `horizon_ms`?
//! - Which candidate is predicted to be fastest?
//! - How confident are we in agent X's prediction?

use aafp_identity::identity_v1::AgentId;
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

/// EWMA smoothing factor used for latency/success/load updates.
const EWMA_ALPHA: f64 = 0.3;

/// Predicts future agent performance based on historical metrics.
///
/// "Who will be fastest 200ms from now?" not "Who is fastest now?"
pub struct TemporalPredictionEngine {
    /// Agent ID -> prediction model.
    models: RwLock<HashMap<AgentId, PredictionModel>>,
    config: PredictionConfig,
}

/// Configuration for the [`TemporalPredictionEngine`].
#[derive(Clone, Debug)]
pub struct PredictionConfig {
    /// History window size (number of samples retained per agent).
    pub window_size: usize,
    /// Prediction horizon (ms) — how far ahead to predict by default.
    pub horizon_ms: u64,
    /// Model update interval (ms) — how often `update_models` should run.
    pub update_interval_ms: u64,
    /// Confidence threshold (0.0-1.0) below which predictions are discarded.
    pub confidence_threshold: f64,
}

impl Default for PredictionConfig {
    fn default() -> Self {
        Self {
            window_size: 50,
            horizon_ms: 200,
            update_interval_ms: 1000,
            confidence_threshold: 0.5,
        }
    }
}

/// A per-agent prediction model.
///
/// Combines a linear-regression latency trend with EWMA-smoothed
/// latency, success, and load signals, plus a confidence score.
#[derive(Clone, Debug)]
pub struct PredictionModel {
    /// The agent this model describes.
    pub agent_id: AgentId,
    /// Linear regression: `latency = slope * t + intercept`.
    pub latency_slope: f64,
    /// Linear regression intercept.
    pub latency_intercept: f64,
    /// EWMA of latency (ms).
    pub latency_ewma: f64,
    /// EWMA of success rate (0.0-1.0).
    pub success_ewma: f64,
    /// EWMA of load (0.0-1.0).
    pub load_ewma: f64,
    /// Prediction confidence (0.0-1.0).
    pub confidence: f64,
    /// Last N samples: `(timestamp_ms, latency_ms, success, load)`.
    pub samples: VecDeque<(u64, f64, bool, f64)>,
}

impl PredictionModel {
    /// Create a fresh, empty model for `agent_id`.
    fn new(agent_id: AgentId) -> Self {
        Self {
            agent_id,
            latency_slope: 0.0,
            latency_intercept: 0.0,
            latency_ewma: 0.0,
            success_ewma: 0.0,
            load_ewma: 0.0,
            confidence: 0.0,
            samples: VecDeque::new(),
        }
    }

    /// Returns true if the model has at least one sample.
    fn has_samples(&self) -> bool {
        !self.samples.is_empty()
    }
}

impl TemporalPredictionEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: PredictionConfig) -> Self {
        Self {
            models: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create a new engine with the default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PredictionConfig::default())
    }

    /// Borrow the engine's configuration.
    pub fn config(&self) -> &PredictionConfig {
        &self.config
    }

    /// Record a new sample for an agent.
    ///
    /// Non-finite (`NaN`/`inf`) latency or load values are silently skipped
    /// to avoid corrupting the model.
    pub fn record(
        &self,
        agent: &AgentId,
        timestamp: u64,
        latency_ms: f64,
        success: bool,
        load: f64,
    ) {
        // Guard against NaN/infinity in float inputs.
        if !latency_ms.is_finite() || !load.is_finite() {
            return;
        }

        let mut models = self
            .models
            .write()
            .expect("prediction models lock poisoned");

        let model = models
            .entry(*agent)
            .or_insert_with(|| PredictionModel::new(*agent));

        // Track whether this is the first sample so we can initialize EWMA.
        let was_empty = !model.has_samples();

        // Push the new sample, evicting the oldest once we exceed the window.
        model
            .samples
            .push_back((timestamp, latency_ms, success, load));
        while model.samples.len() > self.config.window_size {
            model.samples.pop_front();
        }

        // Update EWMA signals incrementally so callers see fresh state
        // without waiting for `update_models`.
        if was_empty {
            // First sample — initialize EWMA to it.
            model.latency_ewma = latency_ms;
            model.success_ewma = if success { 1.0 } else { 0.0 };
            model.load_ewma = load;
        } else {
            model.latency_ewma = ewma_update(model.latency_ewma, latency_ms);
            let success_val = if success { 1.0 } else { 0.0 };
            model.success_ewma = ewma_update(model.success_ewma, success_val);
            model.load_ewma = ewma_update(model.load_ewma, load);
        }

        // Recompute the trend + confidence from the (possibly trimmed) window.
        recompute_trend(model);
        recompute_confidence(model, self.config.window_size);
    }

    /// Predict the latency of an agent `horizon_ms` from now.
    ///
    /// Returns `None` if the agent is unknown, has no samples, or the
    /// computed prediction is not finite.
    pub fn predict_latency(&self, agent: &AgentId, horizon_ms: u64) -> Option<f64> {
        let models = self.models.read().expect("prediction models lock poisoned");
        let model = models.get(agent)?;

        if !model.has_samples() {
            return None;
        }

        // latency_ewma + slope * horizon
        let predicted = model.latency_ewma + model.latency_slope * horizon_ms as f64;

        if predicted.is_finite() && predicted >= 0.0 {
            Some(predicted)
        } else {
            None
        }
    }

    /// Predict the success probability of an agent (0.0-1.0).
    ///
    /// Returns `None` if the agent is unknown or has no samples.
    pub fn predict_success(&self, agent: &AgentId) -> Option<f64> {
        let models = self.models.read().expect("prediction models lock poisoned");
        let model = models.get(agent)?;

        if !model.has_samples() {
            return None;
        }

        // success_ewma is already in [0,1]; guard just in case.
        let s = model.success_ewma;
        if s.is_finite() {
            Some(s.clamp(0.0, 1.0))
        } else {
            None
        }
    }

    /// Get the predicted-best agent from `candidates` for a given horizon.
    ///
    /// Candidates whose confidence falls below the configured threshold are
    /// skipped. Among the remaining candidates, the one with the lowest
    /// predicted latency is returned. Returns `None` if no candidate is
    /// viable.
    pub fn predict_best(&self, candidates: &[AgentId], horizon_ms: u64) -> Option<AgentId> {
        let models = self.models.read().expect("prediction models lock poisoned");

        let mut best: Option<(AgentId, f64)> = None;

        for candidate in candidates {
            let model = match models.get(candidate) {
                Some(m) => m,
                None => continue,
            };

            if !model.has_samples() {
                continue;
            }

            if model.confidence < self.config.confidence_threshold {
                continue;
            }

            let predicted = model.latency_ewma + model.latency_slope * horizon_ms as f64;
            if !predicted.is_finite() || predicted < 0.0 {
                continue;
            }

            match &best {
                None => best = Some((*candidate, predicted)),
                Some((_, best_lat)) if predicted < *best_lat => {
                    best = Some((*candidate, predicted));
                }
                _ => {}
            }
        }

        best.map(|(id, _)| id)
    }

    /// Get prediction confidence for an agent.
    ///
    /// Returns `0.0` for unknown agents or agents with no samples.
    pub fn confidence(&self, agent: &AgentId) -> f64 {
        let models = self.models.read().expect("prediction models lock poisoned");
        match models.get(agent) {
            Some(m) if m.has_samples() => m.confidence,
            _ => 0.0,
        }
    }

    /// Update all models (called periodically).
    ///
    /// Recomputes slope, intercept, EWMA, and confidence for every model
    /// from its retained samples. This is useful when samples have been
    /// recorded incrementally and a full refresh is desired.
    pub fn update_models(&self) {
        let mut models = self
            .models
            .write()
            .expect("prediction models lock poisoned");
        let window_size = self.config.window_size;

        for model in models.values_mut() {
            if !model.has_samples() {
                model.latency_slope = 0.0;
                model.latency_intercept = 0.0;
                model.latency_ewma = 0.0;
                model.success_ewma = 0.0;
                model.load_ewma = 0.0;
                model.confidence = 0.0;
                continue;
            }

            // Recompute EWMA from scratch over the window.
            recompute_ewma(model);
            recompute_trend(model);
            recompute_confidence(model, window_size);
        }
    }

    /// Snapshot a clone of the model for an agent (for inspection/testing).
    pub fn model(&self, agent: &AgentId) -> Option<PredictionModel> {
        let models = self.models.read().expect("prediction models lock poisoned");
        models.get(agent).cloned()
    }
}

impl Default for TemporalPredictionEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ──────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────

/// One EWMA update step: `alpha * new + (1 - alpha) * old`.
fn ewma_update(old: f64, new: f64) -> f64 {
    let result = EWMA_ALPHA * new + (1.0 - EWMA_ALPHA) * old;
    if result.is_finite() {
        result
    } else {
        old
    }
}

/// Recompute the latency trend (slope + intercept) via least-squares linear
/// regression over the model's samples.
///
/// `slope = (n*sum(xy) - sum(x)*sum(y)) / (n*sum(x^2) - sum(x)^2)`
/// `intercept = (sum(y) - slope*sum(x)) / n`
///
/// If the denominator is zero (all timestamps identical), slope is set to 0
/// and intercept to the mean latency.
fn recompute_trend(model: &mut PredictionModel) {
    let n = model.samples.len();
    if n == 0 {
        model.latency_slope = 0.0;
        model.latency_intercept = 0.0;
        return;
    }

    let mut sum_x: f64 = 0.0;
    let mut sum_y: f64 = 0.0;
    let mut sum_xy: f64 = 0.0;
    let mut sum_x2: f64 = 0.0;
    let mut count: f64 = 0.0;

    for (t, lat, _, _) in &model.samples {
        // Skip non-finite samples defensively.
        if !lat.is_finite() {
            continue;
        }
        let x = *t as f64;
        let y = *lat;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
        count += 1.0;
    }

    if count == 0.0 {
        model.latency_slope = 0.0;
        model.latency_intercept = 0.0;
        return;
    }

    let denominator = count * sum_x2 - sum_x * sum_x;
    if denominator.abs() < f64::EPSILON || !denominator.is_finite() {
        // Degenerate case (e.g. single sample or identical timestamps):
        // slope = 0, intercept = mean latency.
        let mean = sum_y / count;
        model.latency_slope = 0.0;
        model.latency_intercept = if mean.is_finite() { mean } else { 0.0 };
        return;
    }

    let slope = (count * sum_xy - sum_x * sum_y) / denominator;
    let intercept = (sum_y - slope * sum_x) / count;

    model.latency_slope = if slope.is_finite() { slope } else { 0.0 };
    model.latency_intercept = if intercept.is_finite() {
        intercept
    } else {
        0.0
    };
}

/// Recompute EWMA latency/success/load from scratch over the window.
fn recompute_ewma(model: &mut PredictionModel) {
    let mut lat_ewma = 0.0;
    let mut succ_ewma = 0.0;
    let mut load_ewma = 0.0;
    let mut initialized = false;

    for (_, lat, succ, load) in &model.samples {
        if !lat.is_finite() || !load.is_finite() {
            continue;
        }
        let succ_val = if *succ { 1.0 } else { 0.0 };
        if !initialized {
            lat_ewma = *lat;
            succ_ewma = succ_val;
            load_ewma = *load;
            initialized = true;
        } else {
            lat_ewma = ewma_update(lat_ewma, *lat);
            succ_ewma = ewma_update(succ_ewma, succ_val);
            load_ewma = ewma_update(load_ewma, *load);
        }
    }

    model.latency_ewma = lat_ewma;
    model.success_ewma = succ_ewma;
    model.load_ewma = load_ewma;
}

/// Recompute the confidence score.
///
/// `confidence = min(1.0, sample_count / window_size) * (1.0 - normalized_variance)`
/// where `normalized_variance = min(1.0, variance / mean^2)` if `mean > 0`,
/// else `0`. More samples + lower variance = higher confidence.
fn recompute_confidence(model: &mut PredictionModel, window_size: usize) {
    let n = model.samples.len();
    if n == 0 || window_size == 0 {
        model.confidence = 0.0;
        return;
    }

    // Collect finite latencies.
    let mut sum: f64 = 0.0;
    let mut count: usize = 0;
    for (_, lat, _, _) in &model.samples {
        if lat.is_finite() {
            sum += *lat;
            count = count.saturating_add(1);
        }
    }

    if count == 0 {
        model.confidence = 0.0;
        return;
    }

    let mean = sum / count as f64;
    if !mean.is_finite() {
        model.confidence = 0.0;
        return;
    }

    // Variance over finite latencies.
    let mut sq_sum: f64 = 0.0;
    for (_, lat, _, _) in &model.samples {
        if lat.is_finite() {
            let diff = *lat - mean;
            sq_sum += diff * diff;
        }
    }
    let variance = sq_sum / count as f64;
    if !variance.is_finite() {
        model.confidence = 0.0;
        return;
    }

    let normalized_variance = if mean.abs() > f64::EPSILON {
        let ratio = variance / (mean * mean);
        if ratio.is_finite() {
            ratio.min(1.0)
        } else {
            1.0
        }
    } else {
        0.0
    };

    let sample_factor = (count as f64 / window_size as f64).min(1.0);
    let confidence = sample_factor * (1.0 - normalized_variance);

    model.confidence = if confidence.is_finite() {
        confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> AgentId {
        AgentId([byte; 32])
    }

    // 1. Single sample prediction ------------------------------------------------
    #[test]
    fn test_single_sample_prediction() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(1);
        engine.record(&a, 1000, 50.0, true, 0.2);

        let pred = engine.predict_latency(&a, 200).expect("should predict");
        // With a single sample slope is 0, so prediction == ewma == 50.
        assert!((pred - 50.0).abs() < 0.001);

        let succ = engine.predict_success(&a).expect("should predict success");
        assert!((succ - 1.0).abs() < 0.001);
    }

    // 2. Multi-sample prediction with trend -------------------------------------
    #[test]
    fn test_multi_sample_prediction_with_trend() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(2);
        // Latency grows linearly: 10ms per timestamp unit.
        for i in 0..10u64 {
            let t = 1000 + i * 10;
            let lat = 50.0 + i as f64 * 10.0;
            engine.record(&a, t, lat, true, 0.1);
        }

        let model = engine.model(&a).expect("model should exist");
        // Slope should be ~1.0 (10ms latency per 10ms time = 1 ms/ms).
        assert!(
            model.latency_slope > 0.5,
            "slope should be positive: {}",
            model.latency_slope
        );

        let pred_now = engine.predict_latency(&a, 0).expect("should predict");
        let pred_future = engine.predict_latency(&a, 100).expect("should predict");
        assert!(pred_future > pred_now, "future latency should be higher");
    }

    // 3. Predicted latency increases with upward trend --------------------------
    #[test]
    fn test_predicted_latency_increases_with_upward_trend() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(3);
        for i in 0..20u64 {
            let t = i * 100;
            let lat = 100.0 + i as f64 * 5.0;
            engine.record(&a, t, lat, true, 0.3);
        }
        let p0 = engine.predict_latency(&a, 0).expect("predict");
        let p200 = engine.predict_latency(&a, 200).expect("predict");
        assert!(p200 > p0, "upward trend: p200={} > p0={}", p200, p0);
    }

    // 4. Predicted latency decreases with downward trend ------------------------
    #[test]
    fn test_predicted_latency_decreases_with_downward_trend() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(4);
        for i in 0..20u64 {
            let t = i * 100;
            let lat = 200.0 - i as f64 * 5.0;
            engine.record(&a, t, lat, true, 0.3);
        }
        let p0 = engine.predict_latency(&a, 0).expect("predict");
        let p200 = engine.predict_latency(&a, 200).expect("predict");
        assert!(p200 < p0, "downward trend: p200={} < p0={}", p200, p0);
    }

    // 5. Confidence increases with more samples ---------------------------------
    #[test]
    fn test_confidence_increases_with_more_samples() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(5);
        // Low variance, increasing sample count.
        engine.record(&a, 0, 100.0, true, 0.1);
        let c1 = engine.confidence(&a);

        for i in 1..20u64 {
            engine.record(&a, i * 10, 100.0, true, 0.1);
        }
        let c20 = engine.confidence(&a);

        assert!(
            c20 > c1,
            "confidence should increase: c1={} c20={}",
            c1,
            c20
        );
    }

    // 6. Confidence decreases with high variance --------------------------------
    #[test]
    fn test_confidence_decreases_with_high_variance() {
        let engine = TemporalPredictionEngine::with_defaults();

        let low = id(6);
        let high = id(7);

        // Low variance agent.
        for i in 0..20u64 {
            engine.record(&low, i * 10, 100.0, true, 0.1);
        }
        // High variance agent (same sample count).
        for i in 0..20u64 {
            let lat = if i % 2 == 0 { 50.0 } else { 200.0 };
            engine.record(&high, i * 10, lat, true, 0.1);
        }

        let c_low = engine.confidence(&low);
        let c_high = engine.confidence(&high);
        assert!(
            c_low > c_high,
            "low-variance confidence {} should exceed high-variance {}",
            c_low,
            c_high
        );
    }

    // 7. predict_best selects lowest predicted latency --------------------------
    #[test]
    fn test_predict_best_selects_lowest_latency() {
        let engine = TemporalPredictionEngine::with_defaults();
        let slow = id(10);
        let fast = id(11);

        // Both get enough samples to clear the confidence threshold.
        for i in 0..30u64 {
            engine.record(&slow, i * 10, 200.0, true, 0.2);
            engine.record(&fast, i * 10, 50.0, true, 0.2);
        }

        let best = engine
            .predict_best(&[slow, fast], 100)
            .expect("should pick one");
        assert_eq!(best, fast, "should pick the faster agent");
    }

    // 8. predict_best respects confidence threshold -----------------------------
    #[test]
    fn test_predict_best_respects_confidence_threshold() {
        let engine = TemporalPredictionEngine::with_defaults();
        // Very high threshold so a low-sample agent is skipped.
        let cfg = PredictionConfig {
            confidence_threshold: 0.99,
            ..PredictionConfig::default()
        };
        let engine = TemporalPredictionEngine::new(cfg);

        let low_conf = id(12);
        let high_conf = id(13);

        // Only one sample -> low confidence.
        engine.record(&low_conf, 0, 10.0, true, 0.1);
        // Many samples -> high confidence.
        for i in 0..50u64 {
            engine.record(&high_conf, i * 10, 200.0, true, 0.1);
        }

        // low_conf has lower latency but is below threshold.
        let best = engine
            .predict_best(&[low_conf, high_conf], 100)
            .expect("should pick one");
        assert_eq!(best, high_conf, "should skip low-confidence agent");
    }

    // 9. EWMA smoothing ----------------------------------------------------------
    #[test]
    fn test_ewma_smoothing() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(14);
        // First sample initializes EWMA to 100.
        engine.record(&a, 0, 100.0, true, 0.1);
        // Second sample 50: ewma = 0.3*50 + 0.7*100 = 85.
        engine.record(&a, 10, 50.0, true, 0.1);
        let model = engine.model(&a).expect("model");
        assert!(
            (model.latency_ewma - 85.0).abs() < 0.001,
            "ewma should be 85, got {}",
            model.latency_ewma
        );
    }

    // 10. NaN/infinity guards ----------------------------------------------------
    #[test]
    fn test_nan_infinity_guards() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(15);

        // Feed NaN and inf latency/load — should be skipped, no panic.
        engine.record(&a, 0, f64::NAN, true, 0.1);
        engine.record(&a, 10, f64::INFINITY, true, f64::NAN);
        engine.record(&a, 20, f64::NEG_INFINITY, true, 0.1);

        // No valid samples recorded.
        assert_eq!(engine.confidence(&a), 0.0);
        assert!(engine.predict_latency(&a, 100).is_none());

        // Now record a valid sample — engine should still work.
        engine.record(&a, 30, 100.0, true, 0.1);
        let pred = engine
            .predict_latency(&a, 100)
            .expect("should predict after valid sample");
        assert!((pred - 100.0).abs() < 0.001);
    }

    // 11. Empty model ------------------------------------------------------------
    #[test]
    fn test_empty_model() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(16);
        // Never recorded.
        assert_eq!(engine.confidence(&a), 0.0);
        assert!(engine.predict_latency(&a, 100).is_none());
        assert!(engine.predict_success(&a).is_none());
    }

    // 12. Single agent prediction ------------------------------------------------
    #[test]
    fn test_single_agent_prediction() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(17);
        // Record enough samples to exceed the confidence threshold (0.5).
        // confidence = min(1.0, count/window_size) * (1 - normalized_variance)
        // With window_size=50 and flat latency (variance=0), we need >= 25 samples.
        for i in 0..30u64 {
            engine.record(&a, i * 100, 80.0, true, 0.2);
        }
        let pred = engine.predict_latency(&a, 200).expect("should predict");
        // Flat latency -> prediction == ewma == 80.
        assert!((pred - 80.0).abs() < 0.001);
        let best = engine.predict_best(&[a], 200);
        assert_eq!(best, Some(a));
    }

    // 13. Multi-agent comparison -------------------------------------------------
    #[test]
    fn test_multi_agent_comparison() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(18);
        let b = id(19);
        let c = id(20);

        for i in 0..40u64 {
            engine.record(&a, i * 10, 120.0, true, 0.2);
            engine.record(&b, i * 10, 80.0, true, 0.2);
            engine.record(&c, i * 10, 150.0, true, 0.2);
        }

        let best = engine
            .predict_best(&[a, b, c], 100)
            .expect("should pick one");
        assert_eq!(best, b, "agent b (80ms) should be predicted best");
    }

    // 14. Horizon effect ---------------------------------------------------------
    #[test]
    fn test_horizon_effect() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(21);
        // Upward trend: +2ms per 10ms timestamp.
        for i in 0..20u64 {
            let t = i * 10;
            let lat = 100.0 + i as f64 * 2.0;
            engine.record(&a, t, lat, true, 0.2);
        }

        let p0 = engine.predict_latency(&a, 0).expect("predict");
        let p100 = engine.predict_latency(&a, 100).expect("predict");
        let p500 = engine.predict_latency(&a, 500).expect("predict");

        // Upward trend => longer horizon => higher predicted latency.
        assert!(p100 > p0, "p100={} > p0={}", p100, p0);
        assert!(p500 > p100, "p500={} > p100={}", p500, p100);
    }

    // 15. Model update interval --------------------------------------------------
    #[test]
    fn test_update_models_recomputes() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(22);

        // Record samples with an upward trend.
        for i in 0..20u64 {
            let t = i * 100;
            let lat = 50.0 + i as f64 * 3.0;
            engine.record(&a, t, lat, true, 0.2);
        }

        let before = engine.model(&a).expect("model");
        assert!(before.latency_slope > 0.0);

        // update_models should recompute and keep consistent values.
        engine.update_models();
        let after = engine.model(&a).expect("model");

        // Slope/intercept/ewma/confidence should be recomputed from samples
        // and remain finite & consistent.
        assert!(after.latency_slope.is_finite());
        assert!(after.latency_intercept.is_finite());
        assert!(after.latency_ewma.is_finite());
        assert!(after.success_ewma.is_finite());
        assert!(after.load_ewma.is_finite());
        assert!(after.confidence >= 0.0 && after.confidence <= 1.0);

        // Slope should still reflect the upward trend.
        assert!(
            after.latency_slope > 0.0,
            "slope should remain positive after update"
        );

        // EWMA recomputed from scratch should match the incremental value
        // (both use the same alpha and the same sample order).
        assert!(
            (after.latency_ewma - before.latency_ewma).abs() < 1.0,
            "recomputed ewma should be close to incremental: {} vs {}",
            after.latency_ewma,
            before.latency_ewma
        );
    }

    // 16. predict_best with no viable candidates --------------------------------
    #[test]
    fn test_predict_best_no_viable_candidates() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(23);
        let b = id(24);
        // No samples recorded for either.
        assert!(engine.predict_best(&[a, b], 100).is_none());
    }

    // 17. predict_success reflects failure rate ---------------------------------
    #[test]
    fn test_predict_success_reflects_failures() {
        let engine = TemporalPredictionEngine::with_defaults();
        let a = id(25);
        // 8 successes, 2 failures -> ewma converges near 0.8-ish (with alpha 0.3).
        let outcomes = [true, true, true, true, false, true, true, true, true, false];
        for (i, &succ) in outcomes.iter().enumerate() {
            engine.record(&a, i as u64 * 10, 50.0, succ, 0.1);
        }
        let s = engine.predict_success(&a).expect("should predict success");
        assert!(
            s > 0.5 && s < 1.0,
            "success ewma should be between 0.5 and 1.0, got {}",
            s
        );
    }

    // 18. Window eviction keeps size bounded ------------------------------------
    #[test]
    fn test_window_eviction() {
        let cfg = PredictionConfig {
            window_size: 5,
            ..PredictionConfig::default()
        };
        let engine = TemporalPredictionEngine::new(cfg);
        let a = id(26);
        for i in 0..20u64 {
            engine.record(&a, i * 10, 100.0, true, 0.1);
        }
        let model = engine.model(&a).expect("model");
        assert_eq!(model.samples.len(), 5, "window should be capped at 5");
    }

    // 19. Default config values --------------------------------------------------
    #[test]
    fn test_default_config() {
        let cfg = PredictionConfig::default();
        assert_eq!(cfg.window_size, 50);
        assert_eq!(cfg.horizon_ms, 200);
        assert_eq!(cfg.update_interval_ms, 1000);
        assert!((cfg.confidence_threshold - 0.5).abs() < f64::EPSILON);
    }

    // 20. predict_best with empty candidate slice -------------------------------
    #[test]
    fn test_predict_best_empty_candidates() {
        let engine = TemporalPredictionEngine::with_defaults();
        assert!(engine.predict_best(&[], 100).is_none());
    }
}
