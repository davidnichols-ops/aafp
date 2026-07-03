//! Regional discovery: group agents by geographic region for latency optimization.
//!
//! Regions are determined by latency probes (ping) rather than geographic

#![allow(deprecated)]
//! coordinates. For MVP, regions are assigned manually or by latency buckets.

use aafp_identity::agent_record::AgentRecord;
use aafp_identity::AgentId;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Errors returned by regional discovery operations.
#[derive(Debug, Error)]
pub enum RegionalError {
    /// The requested agent was not found in the regional store.
    #[error("agent not found")]
    AgentNotFound,
    /// No agents are registered in the requested region.
    #[error("no agents in region")]
    NoAgentsInRegion,
}

/// A geographic region identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Region {
    /// US East / North America East
    UsEast,
    /// US West / North America West
    UsWest,
    /// Europe
    Europe,
    /// Asia Pacific
    AsiaPacific,
    /// South America
    SouthAmerica,
    /// Africa
    Africa,
    /// Oceania
    Oceania,
    /// Unknown / unassigned
    Unknown,
}

impl Region {
    /// Get a string label for the region.
    pub fn label(&self) -> &'static str {
        match self {
            Region::UsEast => "us-east",
            Region::UsWest => "us-west",
            Region::Europe => "europe",
            Region::AsiaPacific => "asia-pacific",
            Region::SouthAmerica => "south-america",
            Region::Africa => "africa",
            Region::Oceania => "oceania",
            Region::Unknown => "unknown",
        }
    }

    /// Determine region from latency (rough heuristic for MVP).
    pub fn from_latency(latency: Duration) -> Self {
        match latency.as_millis() {
            0..=50 => Region::UsEast,         // Very close
            51..=100 => Region::UsWest,       // Same continent
            101..=150 => Region::Europe,      // Cross-Atlantic
            151..=200 => Region::AsiaPacific, // Cross-continent
            201..=300 => Region::Oceania,     // Far
            _ => Region::Unknown,             // Very far
        }
    }
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

use serde::{Deserialize, Serialize};

/// Regional discovery: tracks agents by region.
pub struct RegionalDiscovery {
    /// Map: AgentId → (Region, AgentRecord).
    agents: HashMap<AgentId, (Region, AgentRecord)>,
    /// Map: Region → `Vec<AgentId>`.
    by_region: HashMap<Region, Vec<AgentId>>,
}

impl RegionalDiscovery {
    /// Create a new regional discovery store.
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            by_region: HashMap::new(),
        }
    }

    /// Add or update an agent's region assignment.
    pub fn add(&mut self, agent_id: AgentId, region: Region, record: AgentRecord) {
        // Remove from old region if present.
        if let Some((old_region, _)) = self.agents.get(&agent_id) {
            if let Some(list) = self.by_region.get_mut(old_region) {
                list.retain(|id| *id != agent_id);
            }
        }
        // Add to new region.
        self.by_region.entry(region).or_default().push(agent_id);
        self.agents.insert(agent_id, (region, record));
    }

    /// Get an agent's region.
    pub fn region_of(&self, agent_id: &AgentId) -> Option<Region> {
        self.agents.get(agent_id).map(|(r, _)| *r)
    }

    /// Get all agents in a region.
    pub fn agents_in_region(&self, region: Region) -> Vec<&AgentRecord> {
        self.by_region
            .get(&region)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.agents.get(id).map(|(_, r)| r))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all agent IDs in a region.
    pub fn agent_ids_in_region(&self, region: Region) -> Vec<AgentId> {
        self.by_region.get(&region).cloned().unwrap_or_default()
    }

    /// Find the closest agents (same region first, then adjacent).
    pub fn find_closest(&self, target_region: Region, limit: usize) -> Vec<&AgentRecord> {
        let mut result: Vec<&AgentRecord> = self.agents_in_region(target_region);

        if result.len() < limit {
            // Fill from other regions.
            for region in [
                Region::UsEast,
                Region::UsWest,
                Region::Europe,
                Region::AsiaPacific,
                Region::SouthAmerica,
                Region::Africa,
                Region::Oceania,
                Region::Unknown,
            ] {
                if region == target_region {
                    continue;
                }
                for record in self.agents_in_region(region) {
                    if result.len() >= limit {
                        break;
                    }
                    result.push(record);
                }
                if result.len() >= limit {
                    break;
                }
            }
        }

        result.truncate(limit);
        result
    }

    /// Remove an agent.
    pub fn remove(&mut self, agent_id: &AgentId) {
        if let Some((region, _)) = self.agents.remove(agent_id) {
            if let Some(list) = self.by_region.get_mut(&region) {
                list.retain(|id| *id != *agent_id);
            }
        }
    }

    /// Total number of agents tracked.
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Get all regions that have agents.
    pub fn active_regions(&self) -> Vec<Region> {
        self.by_region
            .iter()
            .filter_map(|(region, ids)| if !ids.is_empty() { Some(*region) } else { None })
            .collect()
    }
}

impl Default for RegionalDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_identity::{derive_agent_id, AgentKeypair};

    fn make_record() -> (AgentId, AgentRecord) {
        let kp = AgentKeypair::generate();
        let id = derive_agent_id(&kp.public_key);
        let record = AgentRecord::new(&kp, vec!["inference".into()], vec![]);
        (id, record)
    }

    #[test]
    fn add_and_lookup() {
        let mut rd = RegionalDiscovery::new();
        let (id, record) = make_record();
        rd.add(id, Region::UsEast, record);
        assert_eq!(rd.region_of(&id), Some(Region::UsEast));
        assert_eq!(rd.agents_in_region(Region::UsEast).len(), 1);
        assert_eq!(rd.len(), 1);
    }

    #[test]
    fn move_between_regions() {
        let mut rd = RegionalDiscovery::new();
        let (id, record) = make_record();
        rd.add(id, Region::UsEast, record.clone());
        rd.add(id, Region::Europe, record);
        assert_eq!(rd.region_of(&id), Some(Region::Europe));
        assert_eq!(rd.agents_in_region(Region::UsEast).len(), 0);
        assert_eq!(rd.agents_in_region(Region::Europe).len(), 1);
    }

    #[test]
    fn find_closest() {
        let mut rd = RegionalDiscovery::new();
        for _ in 0..3 {
            let (id, record) = make_record();
            rd.add(id, Region::UsEast, record);
        }
        for _ in 0..2 {
            let (id, record) = make_record();
            rd.add(id, Region::Europe, record);
        }
        let closest = rd.find_closest(Region::UsEast, 5);
        assert_eq!(closest.len(), 5);
        // First 3 should be from UsEast.
    }

    #[test]
    fn remove_agent() {
        let mut rd = RegionalDiscovery::new();
        let (id, record) = make_record();
        rd.add(id, Region::UsEast, record);
        assert_eq!(rd.len(), 1);
        rd.remove(&id);
        assert_eq!(rd.len(), 0);
        assert_eq!(rd.agents_in_region(Region::UsEast).len(), 0);
    }

    #[test]
    fn from_latency() {
        assert_eq!(
            Region::from_latency(Duration::from_millis(10)),
            Region::UsEast
        );
        assert_eq!(
            Region::from_latency(Duration::from_millis(75)),
            Region::UsWest
        );
        assert_eq!(
            Region::from_latency(Duration::from_millis(120)),
            Region::Europe
        );
        assert_eq!(
            Region::from_latency(Duration::from_millis(500)),
            Region::Unknown
        );
    }

    #[test]
    fn active_regions() {
        let mut rd = RegionalDiscovery::new();
        let (id1, r1) = make_record();
        rd.add(id1, Region::UsEast, r1);
        let (id2, r2) = make_record();
        rd.add(id2, Region::Europe, r2);
        let active = rd.active_regions();
        assert_eq!(active.len(), 2);
    }
}
