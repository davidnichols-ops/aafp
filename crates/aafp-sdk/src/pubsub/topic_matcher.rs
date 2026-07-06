//! `TopicMatcher<T>` — exact + wildcard subscription index (PubSub P4, §6.3).
//!
//! Stores exact subscriptions in a `HashMap` for O(1) lookup, and wildcard
//! subscriptions in a `Vec` scanned on each publish (O(wildcards × depth)).
//! A trie index is a future optimization for large wildcard counts (§12.4).
//!
//! This module is a pre-build scaffold; method bodies are `todo!()` stubs
//! to be implemented in the P4 build pass.

#![allow(dead_code)]

use std::collections::HashMap;

use super::topic::topic_matches;

/// A matcher that indexes subscriptions by filter and resolves which
/// subscribers receive a given published topic.
///
/// Stores exact subscriptions in a `HashMap` for O(1) lookup, and wildcard
/// subscriptions in a `Vec` scanned on each publish (O(wildcards × depth)).
/// A trie index is a future optimization for large wildcard counts (§12.4).
pub struct TopicMatcher<T: Clone> {
    /// Exact topic -> subscribers.
    exact: HashMap<String, Vec<T>>,
    /// Wildcard filters -> subscribers.
    wildcard: Vec<(String, Vec<T>)>,
}

impl<T: Clone> TopicMatcher<T> {
    /// Create an empty `TopicMatcher`.
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard: Vec::new(),
        }
    }

    /// Register a subscriber for a filter.
    ///
    /// If the filter contains no wildcards (`+` / `#`), it goes in the exact
    /// map; otherwise in the wildcard vec. Subscribers for an existing
    /// wildcard filter are appended to that filter's entry.
    pub fn subscribe(&mut self, filter: &str, sub: T) {
        todo!("if filter contains + or # -> wildcard vec (find or push), else exact map")
    }

    /// Remove a subscriber from a filter.
    ///
    /// Returns `true` if a subscriber was removed from either the exact map
    /// or the wildcard vec.
    pub fn unsubscribe(&mut self, filter: &str, sub: &T) -> bool
    where
        T: PartialEq,
    {
        todo!("retain in exact[filter] and wildcard entry; return true if any removed")
    }

    /// Find all subscribers whose filter matches the given published topic.
    ///
    /// Returns a `Vec` of cloned subscriber references. Exact matches are
    /// O(1); wildcard matches are O(wildcards × depth) via `topic_matches`.
    pub fn matches(&self, topic: &str) -> Vec<T> {
        let _ = topic_matches; // referenced for stub wiring
        todo!("extend from exact.get(topic) + wildcard entries where topic_matches")
    }

    /// Number of distinct filters (exact + wildcard).
    pub fn filter_count(&self) -> usize {
        todo!("self.exact.len() + self.wildcard.len()")
    }

    /// Total subscriber count across all filters.
    pub fn subscriber_count(&self) -> usize {
        todo!("sum exact.values().len() + sum wildcard entry len()")
    }
}

impl<T: Clone> Default for TopicMatcher<T> {
    fn default() -> Self {
        Self::new()
    }
}
