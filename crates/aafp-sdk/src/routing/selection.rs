//! Selection strategies for the adaptive routing plane.

use aafp_identity::identity_v1::AgentId;
use rand::Rng;

#[derive(Clone, Debug)]
pub struct SelectionCandidate {
    pub agent_id: AgentId,
    pub score: f64,
    pub in_flight: u32,
    pub latency_ewma_ms: f64,
    pub latency_initialized: bool,
    pub success_rate: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RoutingStrategy {
    P2C,
    WeightedRandom,
    LeastConnections,
    LowestLatency,
    EpsilonGreedy { epsilon: f64 },
}

impl RoutingStrategy {
    pub fn select(&self, candidates: &[SelectionCandidate], rng: &mut impl Rng) -> Option<AgentId> {
        match self {
            RoutingStrategy::P2C => select_power_of_two(candidates, rng),
            RoutingStrategy::WeightedRandom => select_weighted_random(candidates, rng),
            RoutingStrategy::LeastConnections => select_least_connections(candidates),
            RoutingStrategy::LowestLatency => select_lowest_latency(candidates),
            RoutingStrategy::EpsilonGreedy { epsilon } => {
                select_epsilon_greedy(candidates, *epsilon, rng)
            }
        }
    }
}

pub fn select_power_of_two(
    candidates: &[SelectionCandidate],
    rng: &mut impl Rng,
) -> Option<AgentId> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(candidates[0].agent_id);
    }
    if candidates.len() < 4 {
        return select_weighted_random(candidates, rng);
    }
    let i = rng.gen_range(0..candidates.len());
    let mut j = rng.gen_range(0..candidates.len());
    if j == i {
        j = (j + 1) % candidates.len();
    }
    let (a, b) = (&candidates[i], &candidates[j]);
    if a.score >= b.score {
        Some(a.agent_id)
    } else {
        Some(b.agent_id)
    }
}

pub fn select_weighted_random(
    candidates: &[SelectionCandidate],
    rng: &mut impl Rng,
) -> Option<AgentId> {
    if candidates.is_empty() {
        return None;
    }
    let total: f64 = candidates.iter().map(|c| c.score).sum();
    if total <= 0.0 {
        let idx = rng.gen_range(0..candidates.len());
        return Some(candidates[idx].agent_id);
    }
    let mut r = rng.gen_range(0.0..total);
    for c in candidates {
        r -= c.score;
        if r <= 0.0 {
            return Some(c.agent_id);
        }
    }
    Some(candidates.last().unwrap().agent_id)
}

pub fn select_least_connections(candidates: &[SelectionCandidate]) -> Option<AgentId> {
    candidates
        .iter()
        .min_by(|a, b| {
            a.in_flight.cmp(&b.in_flight).then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        })
        .map(|c| c.agent_id)
}

pub fn select_lowest_latency(candidates: &[SelectionCandidate]) -> Option<AgentId> {
    candidates
        .iter()
        .filter(|c| c.latency_initialized)
        .min_by(|a, b| {
            a.latency_ewma_ms
                .partial_cmp(&b.latency_ewma_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    b.success_rate
                        .partial_cmp(&a.success_rate)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
        })
        .map(|c| c.agent_id)
        .or_else(|| {
            candidates
                .iter()
                .max_by(|a, b| {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|c| c.agent_id)
        })
}

pub fn select_epsilon_greedy(
    candidates: &[SelectionCandidate],
    epsilon: f64,
    rng: &mut impl Rng,
) -> Option<AgentId> {
    if candidates.is_empty() {
        return None;
    }
    if rng.gen_bool(epsilon) {
        let idx = rng.gen_range(0..candidates.len());
        Some(candidates[idx].agent_id)
    } else {
        candidates
            .iter()
            .max_by(|a, b| {
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|c| c.agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_candidates() -> Vec<SelectionCandidate> {
        vec![
            SelectionCandidate {
                agent_id: AgentId([1u8; 32]),
                score: 0.9,
                in_flight: 2,
                latency_ewma_ms: 10.0,
                latency_initialized: true,
                success_rate: 0.99,
            },
            SelectionCandidate {
                agent_id: AgentId([2u8; 32]),
                score: 0.5,
                in_flight: 10,
                latency_ewma_ms: 80.0,
                latency_initialized: true,
                success_rate: 0.80,
            },
            SelectionCandidate {
                agent_id: AgentId([3u8; 32]),
                score: 0.3,
                in_flight: 0,
                latency_ewma_ms: 200.0,
                latency_initialized: true,
                success_rate: 0.60,
            },
        ]
    }

    #[test]
    fn test_p2c_returns_valid_candidate() {
        let cands = make_candidates();
        let mut rng = StdRng::seed_from_u64(42);
        let selected = select_power_of_two(&cands, &mut rng);
        assert!(selected.is_some());
        let id = selected.unwrap();
        assert!(cands.iter().any(|c| c.agent_id == id));
    }

    #[test]
    fn test_p2c_single_candidate() {
        let cands = vec![make_candidates()[0].clone()];
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(
            select_power_of_two(&cands, &mut rng),
            Some(cands[0].agent_id)
        );
    }

    #[test]
    fn test_p2c_empty_returns_none() {
        let cands: Vec<SelectionCandidate> = vec![];
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(select_power_of_two(&cands, &mut rng), None);
    }

    #[test]
    fn test_weighted_random_favors_high_score() {
        let cands = make_candidates();
        let mut rng = StdRng::seed_from_u64(42);
        let mut counts = [0u32; 3];
        for _ in 0..10000 {
            let id = select_weighted_random(&cands, &mut rng).unwrap();
            for (i, c) in cands.iter().enumerate() {
                if c.agent_id == id {
                    counts[i] += 1;
                }
            }
        }
        assert!(
            counts[0] > counts[1],
            "score 0.9 should beat 0.5: {:?}",
            counts
        );
        assert!(
            counts[1] > counts[2],
            "score 0.5 should beat 0.3: {:?}",
            counts
        );
    }

    #[test]
    fn test_weighted_random_all_zero_falls_back_uniform() {
        let mut cands = make_candidates();
        for c in &mut cands {
            c.score = 0.0;
        }
        let mut rng = StdRng::seed_from_u64(42);
        assert!(select_weighted_random(&cands, &mut rng).is_some());
    }

    #[test]
    fn test_least_connections_picks_lowest_inflight() {
        let cands = make_candidates();
        assert_eq!(select_least_connections(&cands), Some(cands[2].agent_id));
    }

    #[test]
    fn test_lowest_latency_picks_fastest() {
        let cands = make_candidates();
        assert_eq!(select_lowest_latency(&cands), Some(cands[0].agent_id));
    }

    #[test]
    fn test_lowest_latency_no_initialized_falls_back_to_score() {
        let mut cands = make_candidates();
        for c in &mut cands {
            c.latency_initialized = false;
        }
        assert_eq!(select_lowest_latency(&cands), Some(cands[0].agent_id));
    }

    #[test]
    fn test_epsilon_greedy_explores() {
        let cands = make_candidates();
        let mut rng = StdRng::seed_from_u64(42);
        let mut non_best = 0;
        for _ in 0..1000 {
            let id = select_epsilon_greedy(&cands, 0.3, &mut rng).unwrap();
            if id != cands[0].agent_id {
                non_best += 1;
            }
        }
        assert!(
            non_best > 100,
            "expected exploration, got {non_best} non-best out of 1000"
        );
    }

    #[test]
    fn test_epsilon_greedy_zero_always_exploits() {
        let cands = make_candidates();
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            assert_eq!(
                select_epsilon_greedy(&cands, 0.0, &mut rng).unwrap(),
                cands[0].agent_id
            );
        }
    }

    #[test]
    fn test_selection_empty_returns_none() {
        let cands: Vec<SelectionCandidate> = vec![];
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(select_weighted_random(&cands, &mut rng), None);
        assert_eq!(select_least_connections(&cands), None);
        assert_eq!(select_lowest_latency(&cands), None);
    }
}
