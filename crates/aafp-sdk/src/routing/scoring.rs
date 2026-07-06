//! Composite scoring function for the adaptive routing plane.

use crate::routing::circuit::CircuitState;
use crate::routing::metrics::{HealthProbeResult, PeerMetrics, PeerMetricsRegistry};

#[cfg(test)]
use crate::routing::metrics::Ewma;
use aafp_identity::identity_v1::AgentId;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct DynamicScoreConfig {
    pub weight_latency: f64,
    pub weight_success: f64,
    pub weight_load: f64,
    pub weight_availability: f64,
    pub weight_cost: f64,
    pub latency_ref_ms: f64,
    pub cost_ref_micro_usd: f64,
}

impl Default for DynamicScoreConfig {
    fn default() -> Self {
        Self {
            weight_latency: 0.35,
            weight_success: 0.30,
            weight_load: 0.15,
            weight_availability: 0.15,
            weight_cost: 0.05,
            latency_ref_ms: 50.0,
            cost_ref_micro_usd: 100.0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    pub agent_id: AgentId,
    pub total_score: f64,
    pub static_score: f64,
    pub dynamic_score: f64,
}

pub fn dynamic_score(
    metrics: &PeerMetrics,
    config: &DynamicScoreConfig,
    now: Instant,
    staleness_threshold: Duration,
) -> f64 {
    match metrics.circuit {
        CircuitState::Open => return 0.0,
        CircuitState::HalfOpen => return 0.1,
        CircuitState::Closed => {}
    }
    if now.duration_since(metrics.last_seen) >= staleness_threshold {
        return 0.5;
    }

    let latency_score = if metrics.latency_ewma_ms.is_initialized() {
        (1.0 - (metrics.latency_ewma_ms.value() / (5.0 * config.latency_ref_ms))).max(0.0)
    } else {
        0.5
    };

    let success_score = metrics.success_window.success_rate();
    let queue = metrics.queue_depth.unwrap_or(0) as f64;
    let load_score = 1.0 / (1.0 + metrics.in_flight as f64 + queue);
    let availability_score = match metrics.last_health {
        Some(HealthProbeResult::Healthy) => 1.0,
        Some(HealthProbeResult::Degraded) => 0.5,
        Some(HealthProbeResult::Unhealthy) => 0.1,
        Some(HealthProbeResult::Unreachable) => 0.0,
        None => 0.7,
    };
    let cost_score = match metrics.cost_micro_usd {
        Some(cost) => (1.0 - (cost as f64 / (5.0 * config.cost_ref_micro_usd))).max(0.0),
        None => 0.8,
    };

    let total_weight = config.weight_latency
        + config.weight_success
        + config.weight_load
        + config.weight_availability
        + config.weight_cost;
    if total_weight <= 0.0 {
        return 0.0;
    }

    let weighted = config.weight_latency * latency_score
        + config.weight_success * success_score
        + config.weight_load * load_score
        + config.weight_availability * availability_score
        + config.weight_cost * cost_score;
    (weighted / total_weight).clamp(0.0, 1.0)
}

pub fn score_candidates(
    candidates: &[aafp_identity::agent_record::AgentRecord],
    registry: &PeerMetricsRegistry,
    static_scores: &[f64],
    dyn_config: &DynamicScoreConfig,
    static_weight: f64,
    dynamic_weight: f64,
) -> Vec<(AgentId, f64)> {
    let now = Instant::now();
    candidates
        .iter()
        .zip(static_scores.iter())
        .filter_map(|(record, &static_score)| {
            let agent_id = AgentId(record.agent_id);
            let circuit = registry.check_circuit(&agent_id);
            if circuit == CircuitState::Open {
                return None;
            }
            let metrics = registry.get_or_create(&agent_id);
            let dyn_score = dynamic_score(&metrics, dyn_config, now, registry.staleness_threshold);
            let total = static_weight * static_score + dynamic_weight * dyn_score;
            Some((agent_id, total))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_metrics() -> PeerMetrics {
        PeerMetrics::new(AgentId([1u8; 32]))
    }

    #[test]
    fn test_dynamic_score_circuit_open_is_zero() {
        let mut m = make_test_metrics();
        m.circuit = CircuitState::Open;
        assert_eq!(
            dynamic_score(
                &m,
                &DynamicScoreConfig::default(),
                Instant::now(),
                Duration::from_secs(60)
            ),
            0.0
        );
    }

    #[test]
    fn test_dynamic_score_circuit_half_open_is_low() {
        let mut m = make_test_metrics();
        m.circuit = CircuitState::HalfOpen;
        assert_eq!(
            dynamic_score(
                &m,
                &DynamicScoreConfig::default(),
                Instant::now(),
                Duration::from_secs(60)
            ),
            0.1
        );
    }

    #[test]
    fn test_dynamic_score_stale_returns_neutral() {
        let mut m = make_test_metrics();
        m.last_seen = Instant::now() - Duration::from_secs(120);
        assert_eq!(
            dynamic_score(
                &m,
                &DynamicScoreConfig::default(),
                Instant::now(),
                Duration::from_secs(60)
            ),
            0.5
        );
    }

    #[test]
    fn test_dynamic_score_healthy_peer() {
        let mut m = make_test_metrics();
        m.last_seen = Instant::now();
        m.latency_ewma_ms = Ewma::new(0.1);
        m.latency_ewma_ms.update(10.0);
        for _ in 0..20 {
            m.success_window.record(true);
        }
        m.last_health = Some(HealthProbeResult::Healthy);
        let score = dynamic_score(
            &m,
            &DynamicScoreConfig::default(),
            Instant::now(),
            Duration::from_secs(60),
        );
        assert!(score > 0.8, "healthy peer should score > 0.8, got {score}");
    }

    #[test]
    fn test_dynamic_score_high_latency_penalized() {
        let mut m = make_test_metrics();
        m.latency_ewma_ms = Ewma::new(0.1);
        m.latency_ewma_ms.update(250.0);
        for _ in 0..20 {
            m.success_window.record(true);
        }
        m.last_health = Some(HealthProbeResult::Healthy);
        let score = dynamic_score(
            &m,
            &DynamicScoreConfig::default(),
            Instant::now(),
            Duration::from_secs(60),
        );
        assert!(score < 0.8, "high latency should reduce score, got {score}");
    }

    #[test]
    fn test_dynamic_score_no_latency_data() {
        let mut m = make_test_metrics();
        for _ in 0..10 {
            m.success_window.record(true);
        }
        m.last_health = Some(HealthProbeResult::Healthy);
        let score = dynamic_score(
            &m,
            &DynamicScoreConfig::default(),
            Instant::now(),
            Duration::from_secs(60),
        );
        assert!(score > 0.5 && score < 0.9);
    }

    #[test]
    fn test_dynamic_score_clamped_to_unit_range() {
        let config = DynamicScoreConfig {
            weight_latency: 1.0,
            weight_success: 0.0,
            weight_load: 0.0,
            weight_availability: 0.0,
            weight_cost: 0.0,
            latency_ref_ms: 1.0,
            cost_ref_micro_usd: 1.0,
        };
        let mut m = make_test_metrics();
        m.latency_ewma_ms = Ewma::new(0.1);
        m.latency_ewma_ms.update(0.1);
        let score = dynamic_score(&m, &config, Instant::now(), Duration::from_secs(60));
        assert!(score <= 1.0 && score >= 0.0);
    }

    #[test]
    fn test_score_candidates_filters_open_circuits() {
        use aafp_identity::agent_record::AgentRecord;
        let registry = PeerMetricsRegistry::new();
        let id1 = AgentId([1u8; 32]);
        let id2 = AgentId([2u8; 32]);
        for _ in 0..5 {
            registry.record_outcome(&id1, 100.0, false);
        }
        let make_record = |id: AgentId| AgentRecord {
            agent_id: id.0,
            public_key: vec![0u8; 1952],
            capabilities: vec!["test".to_string()],
            endpoints: vec!["127.0.0.1:0".to_string()],
            version: 1,
            timestamp: 0,
            signature: vec![],
        };
        let candidates = vec![make_record(id1), make_record(id2)];
        let scored = score_candidates(
            &candidates,
            &registry,
            &[1.0, 1.0],
            &DynamicScoreConfig::default(),
            0.5,
            0.5,
        );
        assert_eq!(scored.len(), 1);
        assert_eq!(scored[0].0, id2);
    }
}
