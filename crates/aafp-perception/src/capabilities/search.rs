//! Search capability (Track Y2).
//!
//! Provides federated search across pluggable [`SearchProvider`]s with
//! per-agent rate limiting and result deduplication.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use aafp_identity::AgentId;

use super::Clock;
use crate::PerceptionError;

/// A pluggable search backend.
#[async_trait]
pub trait SearchProvider: Send + Sync {
    /// Execute a search request.
    async fn search(&self, query: &SearchRequest) -> Result<SearchResponse, PerceptionError>;
}

/// A time-range filter for search results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeRange {
    /// Results from the past day.
    PastDay,
    /// Results from the past week.
    PastWeek,
    /// Results from the past month.
    PastMonth,
    /// Results from the past year.
    PastYear,
}

/// A search request.
#[derive(Clone, Debug)]
pub struct SearchRequest {
    /// The search query string.
    pub query: String,
    /// Maximum number of results to return.
    pub num_results: u32,
    /// Preferred sources (provider-specific identifiers).
    pub sources: Vec<String>,
    /// Optional time-range filter.
    pub time_range: Option<TimeRange>,
    /// Whether to fetch full content for each result.
    pub fetch_content: bool,
}

impl SearchRequest {
    /// Create a new search request with the given query.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            num_results: 10,
            sources: Vec::new(),
            time_range: None,
            fetch_content: false,
        }
    }
}

/// A single search result.
#[derive(Clone, Debug, PartialEq)]
pub struct SearchResult {
    /// Result title.
    pub title: String,
    /// Result URL.
    pub url: String,
    /// Short snippet/extract.
    pub snippet: String,
    /// Relevance score (higher is more relevant).
    pub score: f64,
    /// Source provider identifier.
    pub source: String,
}

/// A search response.
#[derive(Clone, Debug, PartialEq)]
pub struct SearchResponse {
    /// The returned results.
    pub results: Vec<SearchResult>,
    /// Total number of results available (may exceed `results.len()`).
    pub total: u32,
}

/// Configuration for the search capability.
#[derive(Clone, Debug)]
pub struct SearchConfig {
    /// Hard cap on the number of results returned per request.
    pub max_results: u32,
    /// Maximum requests allowed per agent per hour.
    pub rate_limit_per_hour: u32,
    /// Whether to federate queries across all providers.
    pub federation: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_results: 20,
            rate_limit_per_hour: 100,
            federation: true,
        }
    }
}

/// A per-agent rate-limit bucket (fixed window per hour).
struct RateBucket {
    /// Unix-millisecond timestamp of the start of the current window.
    window_start_ms: u64,
    /// Number of requests made in the current window.
    count: u32,
}

impl RateBucket {
    fn new(now_ms: u64) -> Self {
        Self {
            window_start_ms: now_ms,
            count: 0,
        }
    }
}

/// The search capability: federates across providers and rate-limits per agent.
pub struct SearchCapability {
    providers: Vec<Arc<dyn SearchProvider>>,
    config: SearchConfig,
    rate_limiter: RwLock<HashMap<AgentId, RateBucket>>,
    clock: Clock,
}

impl SearchCapability {
    /// Create a new search capability with the default system clock.
    pub fn new(providers: Vec<Arc<dyn SearchProvider>>, config: SearchConfig) -> Self {
        Self {
            providers,
            config,
            rate_limiter: RwLock::new(HashMap::new()),
            clock: super::default_clock(),
        }
    }

    /// Create a new search capability with an injected clock (for testing).
    pub fn with_clock(
        providers: Vec<Arc<dyn SearchProvider>>,
        config: SearchConfig,
        clock: Clock,
    ) -> Self {
        Self {
            providers,
            config,
            rate_limiter: RwLock::new(HashMap::new()),
            clock,
        }
    }

    /// Execute a search on behalf of an agent, applying rate limiting and
    /// (optionally) federation.
    pub async fn search(
        &self,
        request: &SearchRequest,
        agent_id: &AgentId,
    ) -> Result<SearchResponse, PerceptionError> {
        // Rate-limit check (per-agent fixed window).
        self.check_rate_limit(agent_id)?;

        if self.providers.is_empty() {
            return Err(PerceptionError::Provider(
                "no search providers configured".into(),
            ));
        }

        // Clamp the requested number of results to the configured maximum.
        let mut req = request.clone();
        if req.num_results == 0 || req.num_results > self.config.max_results {
            req.num_results = self.config.max_results;
        }

        let results = if self.config.federation && self.providers.len() > 1 {
            self.federated_search(&req).await?
        } else {
            // Non-federated: try providers in order, failover on error.
            self.failover_search(&req).await?
        };

        let total = results.len() as u32;
        Ok(SearchResponse { results, total })
    }

    /// Query all providers in parallel, merge and deduplicate results.
    async fn federated_search(
        &self,
        req: &SearchRequest,
    ) -> Result<Vec<SearchResult>, PerceptionError> {
        let mut handles = Vec::with_capacity(self.providers.len());
        for provider in &self.providers {
            let provider = Arc::clone(provider);
            let req = req.clone();
            handles.push(tokio::spawn(async move { provider.search(&req).await }));
        }

        let mut merged: HashMap<String, SearchResult> = HashMap::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(resp)) => {
                    for result in resp.results {
                        let entry = merged
                            .entry(result.url.clone())
                            .or_insert_with(|| result.clone());
                        // Keep the highest-scoring result for a given URL.
                        if result.score > entry.score {
                            *entry = result;
                        }
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    // A provider failing in federation does not abort the whole query.
                }
            }
        }

        let mut results: Vec<SearchResult> = merged.into_values().collect();
        sort_by_score(&mut results);
        truncate_results(&mut results, req.num_results);
        Ok(results)
    }

    /// Query providers sequentially, returning the first successful response.
    async fn failover_search(
        &self,
        req: &SearchRequest,
    ) -> Result<Vec<SearchResult>, PerceptionError> {
        let mut last_err: Option<PerceptionError> = None;
        for provider in &self.providers {
            match provider.search(req).await {
                Ok(resp) => {
                    let mut results = resp.results;
                    sort_by_score(&mut results);
                    truncate_results(&mut results, req.num_results);
                    return Ok(results);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| PerceptionError::Provider("all search providers failed".into())))
    }

    /// Check and increment the per-agent rate-limit bucket.
    fn check_rate_limit(&self, agent_id: &AgentId) -> Result<(), PerceptionError> {
        const HOUR_MS: u64 = 60 * 60 * 1000;

        let now_ms = (self.clock)();
        let mut buckets = self
            .rate_limiter
            .write()
            .expect("rate_limiter lock poisoned");

        let bucket = buckets
            .entry(*agent_id)
            .or_insert_with(|| RateBucket::new(now_ms));

        // Reset the window if an hour has elapsed.
        if now_ms.saturating_sub(bucket.window_start_ms) >= HOUR_MS {
            bucket.window_start_ms = now_ms;
            bucket.count = 0;
        }

        if bucket.count >= self.config.rate_limit_per_hour {
            return Err(PerceptionError::RateLimited);
        }

        bucket.count += 1;
        Ok(())
    }
}

/// Sort results by descending score (highest first).
fn sort_by_score(results: &mut [SearchResult]) {
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// Truncate the results vector to at most `n` entries.
fn truncate_results(results: &mut Vec<SearchResult>, n: u32) {
    if results.len() > n as usize {
        results.truncate(n as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn agent(n: u8) -> AgentId {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    fn mock_clock() -> (Clock, Arc<AtomicU64>) {
        let cell = Arc::new(AtomicU64::new(1_700_000_000_000));
        let cell2 = Arc::clone(&cell);
        let clock: Clock = Arc::new(move || cell2.load(Ordering::SeqCst));
        (clock, cell)
    }

    /// A mock provider returning canned results.
    struct MockProvider {
        name: &'static str,
        results: Vec<SearchResult>,
        fail: bool,
    }

    impl MockProvider {
        fn new(name: &'static str, results: Vec<SearchResult>) -> Self {
            Self {
                name,
                results,
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                name: "failing",
                results: vec![],
                fail: true,
            }
        }
    }

    #[async_trait]
    impl SearchProvider for MockProvider {
        async fn search(&self, _req: &SearchRequest) -> Result<SearchResponse, PerceptionError> {
            if self.fail {
                return Err(PerceptionError::Provider(format!("{} failed", self.name)));
            }
            Ok(SearchResponse {
                results: self.results.clone(),
                total: self.results.len() as u32,
            })
        }
    }

    fn result(title: &str, url: &str, score: f64, source: &str) -> SearchResult {
        SearchResult {
            title: title.into(),
            url: url.into(),
            snippet: format!("Snippet for {title}"),
            score,
            source: source.into(),
        }
    }

    #[tokio::test]
    async fn test_search_with_mock_provider() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "mock",
            vec![
                result("A", "https://a.com", 0.9, "mock"),
                result("B", "https://b.com", 0.5, "mock"),
            ],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: false,
            },
            clock,
        );
        let req = SearchRequest::new("test");
        let resp = cap.search(&req, &agent(1)).await.expect("search ok");
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].title, "A");
    }

    #[tokio::test]
    async fn test_search_federation_merges() {
        let p1: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "p1",
            vec![result("A", "https://a.com", 0.9, "p1")],
        ));
        let p2: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "p2",
            vec![result("B", "https://b.com", 0.8, "p2")],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![p1, p2],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: true,
            },
            clock,
        );
        let resp = cap
            .search(&SearchRequest::new("q"), &agent(1))
            .await
            .expect("ok");
        assert_eq!(resp.results.len(), 2);
        // Highest score first.
        assert_eq!(resp.results[0].url, "https://a.com");
    }

    #[tokio::test]
    async fn test_search_dedup_by_url() {
        // Both providers return the same URL with different scores.
        let p1: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "p1",
            vec![result("A", "https://a.com", 0.7, "p1")],
        ));
        let p2: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "p2",
            vec![result("A2", "https://a.com", 0.95, "p2")],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![p1, p2],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: true,
            },
            clock,
        );
        let resp = cap
            .search(&SearchRequest::new("q"), &agent(1))
            .await
            .expect("ok");
        assert_eq!(resp.results.len(), 1, "duplicate URL should be merged");
        // The higher-scoring result is kept.
        assert!((resp.results[0].score - 0.95).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_search_rate_limited() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new("mock", vec![]));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 2,
                federation: false,
            },
            clock,
        );
        let req = SearchRequest::new("q");
        let id = agent(1);
        assert!(cap.search(&req, &id).await.is_ok());
        assert!(cap.search(&req, &id).await.is_ok());
        let err = cap.search(&req, &id).await.unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
    }

    #[tokio::test]
    async fn test_search_empty_results() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new("mock", vec![]));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: false,
            },
            clock,
        );
        let resp = cap
            .search(&SearchRequest::new("q"), &agent(1))
            .await
            .expect("ok");
        assert!(resp.results.is_empty());
        assert_eq!(resp.total, 0);
    }

    #[tokio::test]
    async fn test_search_with_time_range() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "mock",
            vec![result("A", "https://a.com", 0.9, "mock")],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: false,
            },
            clock,
        );
        let mut req = SearchRequest::new("q");
        req.time_range = Some(TimeRange::PastWeek);
        let resp = cap.search(&req, &agent(1)).await.expect("ok");
        assert_eq!(resp.results.len(), 1);
    }

    #[tokio::test]
    async fn test_search_with_fetch_content() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "mock",
            vec![result("A", "https://a.com", 0.9, "mock")],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: false,
            },
            clock,
        );
        let mut req = SearchRequest::new("q");
        req.fetch_content = true;
        let resp = cap.search(&req, &agent(1)).await.expect("ok");
        assert_eq!(resp.results.len(), 1);
    }

    #[tokio::test]
    async fn test_search_failover() {
        // First provider fails, second succeeds.
        let p1: Arc<dyn SearchProvider> = Arc::new(MockProvider::failing());
        let p2: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "p2",
            vec![result("A", "https://a.com", 0.9, "p2")],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![p1, p2],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: false,
            },
            clock,
        );
        let resp = cap
            .search(&SearchRequest::new("q"), &agent(1))
            .await
            .expect("failover should succeed");
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].source, "p2");
    }

    #[tokio::test]
    async fn test_rate_limit_reset_after_window() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new("mock", vec![]));
        let (clock, cell) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 1,
                federation: false,
            },
            clock,
        );
        let req = SearchRequest::new("q");
        let id = agent(1);
        // First request succeeds, second is rate-limited.
        assert!(cap.search(&req, &id).await.is_ok());
        assert!(matches!(
            cap.search(&req, &id).await.unwrap_err(),
            PerceptionError::RateLimited
        ));
        // Advance the clock past one hour.
        cell.store(1_700_000_000_000 + 60 * 60 * 1000 + 1, Ordering::SeqCst);
        // After the window resets, the request succeeds again.
        assert!(cap.search(&req, &id).await.is_ok());
    }

    #[tokio::test]
    async fn test_search_result_scoring_order() {
        let provider: Arc<dyn SearchProvider> = Arc::new(MockProvider::new(
            "mock",
            vec![
                result("low", "https://low.com", 0.1, "mock"),
                result("high", "https://high.com", 0.99, "mock"),
                result("mid", "https://mid.com", 0.5, "mock"),
            ],
        ));
        let (clock, _) = mock_clock();
        let cap = SearchCapability::with_clock(
            vec![provider],
            SearchConfig {
                max_results: 10,
                rate_limit_per_hour: 100,
                federation: false,
            },
            clock,
        );
        let resp = cap
            .search(&SearchRequest::new("q"), &agent(1))
            .await
            .expect("ok");
        assert_eq!(resp.results[0].url, "https://high.com");
        assert_eq!(resp.results[1].url, "https://mid.com");
        assert_eq!(resp.results[2].url, "https://low.com");
    }
}
