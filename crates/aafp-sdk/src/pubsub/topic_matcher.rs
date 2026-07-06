//! `TopicMatcher<T>` — exact + wildcard subscription index (PubSub P4, §6.3).
//!
//! Stores exact subscriptions in a `HashMap` for O(1) lookup, and wildcard
//! subscriptions in a `Vec` scanned on each publish (O(wildcards × depth)).
//! A trie index is a future optimization for large wildcard counts (§12.4).

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
        if filter.contains('+') || filter.contains('#') {
            if let Some(entry) = self.wildcard.iter_mut().find(|(f, _)| *f == filter) {
                entry.1.push(sub);
            } else {
                self.wildcard.push((filter.to_string(), vec![sub]));
            }
        } else {
            self.exact.entry(filter.to_string()).or_default().push(sub);
        }
    }

    /// Remove a subscriber from a filter.
    ///
    /// Returns `true` if a subscriber was removed from either the exact map
    /// or the wildcard vec.
    pub fn unsubscribe(&mut self, filter: &str, sub: &T) -> bool
    where
        T: PartialEq,
    {
        let removed_from_exact = self.exact.get_mut(filter).is_some_and(|v| {
            let before = v.len();
            v.retain(|s| s != sub);
            v.len() < before
        });
        let removed_from_wild = self
            .wildcard
            .iter_mut()
            .find(|(f, _)| *f == filter)
            .is_some_and(|(_, v)| {
                let before = v.len();
                v.retain(|s| s != sub);
                v.len() < before
            });
        removed_from_exact || removed_from_wild
    }

    /// Find all subscribers whose filter matches the given published topic.
    ///
    /// Returns a `Vec` of cloned subscriber references. Exact matches are
    /// O(1); wildcard matches are O(wildcards × depth) via `topic_matches`.
    pub fn matches(&self, topic: &str) -> Vec<T> {
        let mut out = Vec::new();
        // Exact match: O(1).
        if let Some(subs) = self.exact.get(topic) {
            out.extend_from_slice(subs);
        }
        // Wildcard match: O(wildcards × depth).
        for (filter, subs) in &self.wildcard {
            if topic_matches(filter, topic) {
                out.extend_from_slice(subs);
            }
        }
        out
    }

    /// Number of distinct filters (exact + wildcard).
    pub fn filter_count(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Total subscriber count across all filters.
    pub fn subscriber_count(&self) -> usize {
        self.exact.values().map(|v| v.len()).sum::<usize>()
            + self.wildcard.iter().map(|(_, v)| v.len()).sum::<usize>()
    }
}

impl<T: Clone> Default for TopicMatcher<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_exact_only() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("a/b/c", "sub1");
        assert_eq!(m.matches("a/b/c"), vec!["sub1"]);
        assert!(m.matches("a/b/d").is_empty());
    }

    #[test]
    fn matcher_single_wildcard() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("agents/+/status", "sub1");
        assert_eq!(m.matches("agents/A/status"), vec!["sub1"]);
        assert_eq!(m.matches("agents/B/status"), vec!["sub1"]);
        assert!(m.matches("agents/A/inbox").is_empty());
    }

    #[test]
    fn matcher_multi_wildcard() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("tasks/#", "sub1");
        assert_eq!(m.matches("tasks"), vec!["sub1"]);
        assert_eq!(m.matches("tasks/123"), vec!["sub1"]);
        assert_eq!(m.matches("tasks/123/events"), vec!["sub1"]);
        assert!(m.matches("agents/A/status").is_empty());
    }

    #[test]
    fn matcher_multiple_filters_same_topic() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("a/b/c", "exact");
        m.subscribe("a/+/c", "single");
        m.subscribe("a/#", "multi");
        let mut matches = m.matches("a/b/c");
        matches.sort();
        assert_eq!(matches, vec!["exact", "multi", "single"]);
    }

    #[test]
    fn matcher_unsubscribe() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("a/b", "sub1");
        m.subscribe("a/b", "sub2");
        assert_eq!(m.matches("a/b").len(), 2);
        assert!(m.unsubscribe("a/b", &"sub1"));
        assert_eq!(m.matches("a/b"), vec!["sub2"]);
        assert!(!m.unsubscribe("a/b", &"sub1")); // already removed
    }

    #[test]
    fn matcher_unsubscribe_wildcard() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("a/+/c", "sub1");
        m.subscribe("a/+/c", "sub2");
        assert!(m.unsubscribe("a/+/c", &"sub1"));
        assert_eq!(m.matches("a/b/c"), vec!["sub2"]);
    }

    #[test]
    fn matcher_counts() {
        let mut m: TopicMatcher<&str> = TopicMatcher::new();
        m.subscribe("a/b", "s1");
        m.subscribe("a/+/c", "s2");
        m.subscribe("a/#", "s3");
        assert_eq!(m.filter_count(), 3);
        assert_eq!(m.subscriber_count(), 3);
    }
}
