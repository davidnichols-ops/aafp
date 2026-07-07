//! Web-browse capability (Track Y2).
//!
//! Provides agent-native browsing of web content via a pluggable
//! [`BrowseProvider`], with a TTL-based content cache and simple
//! robots.txt enforcement.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use super::Clock;
use crate::schema::WebContent;
use crate::PerceptionError;

#[cfg(test)]
use crate::schema::{
    ContentHash, ContentSection, InteractiveElement, NavigationState, PageMetadata,
};

/// A pluggable browse backend that fetches and parses web content.
#[async_trait]
pub trait BrowseProvider: Send + Sync {
    /// Browse the requested URL and return agent-native content.
    async fn browse(&self, request: &BrowseRequest) -> Result<WebContent, PerceptionError>;
}

/// Desired output format for a browse request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowseFormat {
    /// Structured agent-native CBOR content (default).
    AgentNative,
    /// Markdown text.
    Markdown,
    /// Raw HTML.
    Html,
    /// Accessibility tree.
    Accessibility,
}

/// A condition to wait for before returning content.
#[derive(Clone, Debug, PartialEq)]
pub enum WaitCondition {
    /// Wait until network is idle.
    NetworkIdle,
    /// Wait for the page load event.
    Load,
    /// Wait until the given CSS selector is present.
    Selector(String),
    /// Wait at most `ms` milliseconds.
    Timeout(u64),
}

/// A browse request.
#[derive(Clone, Debug)]
pub struct BrowseRequest {
    /// The URL to browse.
    pub url: String,
    /// Desired output format.
    pub format: BrowseFormat,
    /// Optional wait condition.
    pub wait_for: Option<WaitCondition>,
    /// Whether to capture a screenshot.
    pub screenshot: bool,
}

impl BrowseRequest {
    /// Create a new browse request for the given URL (agent-native format).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            format: BrowseFormat::AgentNative,
            wait_for: None,
            screenshot: false,
        }
    }
}

/// The content returned by a browse operation.
#[derive(Clone, Debug)]
pub enum BrowseContent {
    /// Agent-native structured content.
    AgentNative(Box<WebContent>),
    /// Markdown text.
    Markdown(String),
    /// Raw HTML text.
    Html(String),
}

/// A browse response.
#[derive(Clone, Debug)]
pub struct BrowseResponse {
    /// The browsed content.
    pub content: BrowseContent,
    /// Optional screenshot bytes (PNG).
    pub screenshot: Option<Vec<u8>>,
}

/// Configuration for the web-browse capability.
#[derive(Clone, Debug)]
pub struct BrowseConfig {
    /// Cache time-to-live in milliseconds.
    pub cache_ttl_ms: u64,
    /// Maximum number of cache entries before eviction.
    pub max_cache_entries: usize,
    /// Whether to respect robots.txt.
    pub respect_robots: bool,
    /// Browse timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for BrowseConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 15 * 60 * 1000, // 15 minutes
            max_cache_entries: 256,
            respect_robots: true,
            timeout_ms: 30_000,
        }
    }
}

/// A cached browse result.
struct CacheEntry {
    content: WebContent,
    /// Unix-millisecond timestamp when the entry was stored.
    timestamp: u64,
}

/// A parsed robots.txt rule set for a host.
struct RobotsRule {
    /// Disallowed path prefixes.
    disallowed: Vec<String>,
    /// Optional crawl-delay in milliseconds.
    #[allow(dead_code)]
    crawl_delay: Option<u64>,
}

/// The web-browse capability: caches content and enforces robots.txt.
pub struct WebBrowseCapability {
    provider: Arc<dyn BrowseProvider>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    robots: RwLock<HashMap<String, RobotsRule>>,
    config: BrowseConfig,
    clock: Clock,
}

impl WebBrowseCapability {
    /// Create a new web-browse capability with the default system clock.
    pub fn new(provider: Arc<dyn BrowseProvider>, config: BrowseConfig) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            robots: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
        }
    }

    /// Create a new web-browse capability with an injected clock (for testing).
    pub fn with_clock(
        provider: Arc<dyn BrowseProvider>,
        config: BrowseConfig,
        clock: Clock,
    ) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            robots: RwLock::new(HashMap::new()),
            config,
            clock,
        }
    }

    /// Browse a URL, consulting the cache and robots.txt first.
    pub async fn browse(&self, request: &BrowseRequest) -> Result<BrowseResponse, PerceptionError> {
        if request.url.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "url",
                message: "url must not be empty".into(),
            });
        }

        // Robots.txt enforcement (only for agent-native full fetches).
        if self.config.respect_robots {
            self.check_robots(&request.url)?;
        }

        // Cache lookup.
        if let Some(cached) = self.cache_get(&request.url) {
            return Ok(BrowseResponse {
                content: BrowseContent::AgentNative(Box::new(cached)),
                screenshot: None,
            });
        }

        // Fetch from the provider.
        let content = self.provider.browse(request).await?;

        // Store in cache (only agent-native content is cacheable here).
        self.cache_put(&request.url, content.clone());

        // The provider returns content only; screenshots are not produced
        // by the current provider contract.
        let screenshot = None;

        Ok(BrowseResponse {
            content: BrowseContent::AgentNative(Box::new(content)),
            screenshot,
        })
    }

    /// Check robots.txt for the given URL. Returns an error if disallowed.
    fn check_robots(&self, url: &str) -> Result<(), PerceptionError> {
        let host = match extract_host(url) {
            Some(h) => h,
            None => return Ok(()), // Cannot determine host; allow.
        };
        let path = extract_path(url);

        let robots = self.robots.read().expect("robots lock poisoned");
        if let Some(rule) = robots.get(&host) {
            for disallowed in &rule.disallowed {
                if path.starts_with(disallowed) {
                    return Err(PerceptionError::RobotsDisallowed(url.into()));
                }
            }
        }
        Ok(())
    }

    /// Insert a robots.txt rule set for a host (used for testing/extension).
    pub fn set_robots(&self, host: &str, disallowed: Vec<String>, crawl_delay: Option<u64>) {
        let mut robots = self.robots.write().expect("robots lock poisoned");
        robots.insert(
            host.to_string(),
            RobotsRule {
                disallowed,
                crawl_delay,
            },
        );
    }

    /// Look up a URL in the cache, returning a clone if present and fresh.
    fn cache_get(&self, url: &str) -> Option<WebContent> {
        let now_ms = (self.clock)();
        let cache = self.cache.read().expect("cache lock poisoned");
        let entry = cache.get(url)?;
        if now_ms.saturating_sub(entry.timestamp) >= self.config.cache_ttl_ms {
            // Expired.
            return None;
        }
        Some(entry.content.clone())
    }

    /// Store content in the cache, evicting expired entries if the cache
    /// is full.
    fn cache_put(&self, url: &str, content: WebContent) {
        let now_ms = (self.clock)();
        let mut cache = self.cache.write().expect("cache lock poisoned");

        // Evict expired entries first.
        evict_expired_locked(&mut cache, self.config.cache_ttl_ms, now_ms);

        // If still at capacity, evict the oldest entry.
        if cache.len() >= self.config.max_cache_entries {
            if let Some((oldest_key, _)) = cache
                .iter()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(k, v)| (k.clone(), v.timestamp))
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(
            url.to_string(),
            CacheEntry {
                content,
                timestamp: now_ms,
            },
        );
    }

    /// Remove all expired entries from the cache.
    pub fn evict_expired(&self) {
        let now_ms = (self.clock)();
        let mut cache = self.cache.write().expect("cache lock poisoned");
        evict_expired_locked(&mut cache, self.config.cache_ttl_ms, now_ms);
    }
}

/// Remove all expired entries from the cache (helper).
fn evict_expired_locked(cache: &mut HashMap<String, CacheEntry>, ttl: u64, now_ms: u64) {
    cache.retain(|_, entry| now_ms.saturating_sub(entry.timestamp) < ttl);
}

/// Extract the host portion of a URL (lowercased).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip port
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Extract the path portion of a URL (always starts with `/`).
fn extract_path(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    match after_scheme.find('/') {
        Some(idx) => after_scheme[idx..].to_string(),
        None => "/".to_string(),
    }
}

/// Build a minimal but valid `WebContent` for tests.
#[cfg(test)]
fn sample_web_content(url: &str) -> WebContent {
    WebContent {
        url: url.into(),
        title: "Sample".into(),
        metadata: PageMetadata {
            status_code: 200,
            content_type: "text/html".into(),
            charset: Some("utf-8".into()),
            language: Some("en".into()),
            title: Some("Sample".into()),
            description: None,
            fetched_at: 1_700_000_000_000,
        },
        nav: NavigationState {
            url: url.into(),
            title: "Sample".into(),
            can_go_back: false,
            can_go_forward: false,
        },
        sections: vec![ContentSection {
            id: "s0".into(),
            title: "Intro".into(),
            content: "Hello world".into(),
            level: 1,
            children: vec![],
        }],
        elements: vec![InteractiveElement {
            id: "e0".into(),
            element_type: "button".into(),
            ref_target: "#btn".into(),
            text: "Go".into(),
            action: crate::schema::Action {
                action_type: "click".into(),
                target: "e0".into(),
                value: None,
            },
            safety: crate::schema::ActionSafety::Safe,
            attributes: vec![],
        }],
        forms: vec![],
        media: vec![],
        links: vec![],
        structured: vec![],
        entities: vec![],
        hash: ContentHash::compute(b"sample"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn mock_clock() -> (Clock, Arc<AtomicU64>) {
        let cell = Arc::new(AtomicU64::new(1_700_000_000_000));
        let cell2 = Arc::clone(&cell);
        let clock: Clock = Arc::new(move || cell2.load(Ordering::SeqCst));
        (clock, cell)
    }

    struct MockBrowseProvider {
        content: WebContent,
        call_count: AtomicU64,
    }

    impl MockBrowseProvider {
        fn new(url: &str) -> Self {
            Self {
                content: sample_web_content(url),
                call_count: AtomicU64::new(0),
            }
        }

        fn calls(&self) -> u64 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BrowseProvider for MockBrowseProvider {
        async fn browse(&self, _req: &BrowseRequest) -> Result<WebContent, PerceptionError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.content.clone())
        }
    }

    fn config_no_robots() -> BrowseConfig {
        BrowseConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            respect_robots: false,
            timeout_ms: 5_000,
        }
    }

    #[tokio::test]
    async fn test_browse_agent_native() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(provider.clone(), config_no_robots(), clock);
        let resp = cap
            .browse(&BrowseRequest::new("https://example.com"))
            .await
            .expect("browse ok");
        match resp.content {
            BrowseContent::AgentNative(wc) => {
                assert_eq!(wc.url, "https://example.com");
            }
            _ => panic!("expected agent-native content"),
        }
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_browse_markdown_format() {
        // The mock provider returns agent-native content regardless of format,
        // but we verify the request is accepted with a markdown format.
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(provider, config_no_robots(), clock);
        let mut req = BrowseRequest::new("https://example.com");
        req.format = BrowseFormat::Markdown;
        let resp = cap.browse(&req).await.expect("browse ok");
        assert!(matches!(resp.content, BrowseContent::AgentNative(_)));
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(provider.clone(), config_no_robots(), clock);
        let req = BrowseRequest::new("https://example.com");
        let _ = cap.browse(&req).await.expect("first browse");
        // Second browse should be served from cache (no new provider call).
        let resp = cap.browse(&req).await.expect("second browse");
        assert!(matches!(resp.content, BrowseContent::AgentNative(_)));
        assert_eq!(provider.calls(), 1, "second browse should hit cache");
    }

    #[tokio::test]
    async fn test_cache_miss_fetches() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(provider.clone(), config_no_robots(), clock);
        // Different URL → cache miss.
        let req = BrowseRequest::new("https://other.com");
        let _ = cap.browse(&req).await.expect("browse");
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, cell) = mock_clock();
        let cap = WebBrowseCapability::with_clock(
            provider.clone(),
            BrowseConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                respect_robots: false,
                timeout_ms: 5_000,
            },
            clock,
        );
        let req = BrowseRequest::new("https://example.com");
        let _ = cap.browse(&req).await.expect("first");
        assert_eq!(provider.calls(), 1);
        // Advance past TTL.
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        let _ = cap.browse(&req).await.expect("second");
        assert_eq!(provider.calls(), 2, "expired entry should refetch");
    }

    #[tokio::test]
    async fn test_robots_disallow() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com/private"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(
            provider.clone(),
            BrowseConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                respect_robots: true,
                timeout_ms: 5_000,
            },
            clock,
        );
        cap.set_robots("example.com", vec!["/private".into()], None);
        let err = cap
            .browse(&BrowseRequest::new("https://example.com/private/page"))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::RobotsDisallowed(_)));
        assert_eq!(
            provider.calls(),
            0,
            "provider must not be called when disallowed"
        );
    }

    #[tokio::test]
    async fn test_robots_allows() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com/public"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(
            provider.clone(),
            BrowseConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                respect_robots: true,
                timeout_ms: 5_000,
            },
            clock,
        );
        cap.set_robots("example.com", vec!["/private".into()], None);
        let resp = cap
            .browse(&BrowseRequest::new("https://example.com/public"))
            .await
            .expect("allowed");
        assert!(matches!(resp.content, BrowseContent::AgentNative(_)));
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_empty_url_error() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(provider.clone(), config_no_robots(), clock);
        let err = cap.browse(&BrowseRequest::new("")).await.unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField { field: "url", .. }
        ));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn test_browse_screenshot_flag() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, _) = mock_clock();
        let cap = WebBrowseCapability::with_clock(provider.clone(), config_no_robots(), clock);
        let mut req = BrowseRequest::new("https://example.com");
        req.screenshot = true;
        let resp = cap.browse(&req).await.expect("browse ok");
        // The mock provider does not produce screenshots.
        assert!(resp.screenshot.is_none());
    }

    #[tokio::test]
    async fn test_cache_eviction_max_entries() {
        let provider = Arc::new(MockBrowseProvider::new("https://example.com"));
        let (clock, clock_cell) = mock_clock();
        let cap = WebBrowseCapability::with_clock(
            provider.clone(),
            BrowseConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 2,
                respect_robots: false,
                timeout_ms: 5_000,
            },
            clock,
        );
        // Fill cache to capacity, advancing the clock between requests so
        // entries have distinct timestamps (needed for deterministic eviction).
        let _ = cap.browse(&BrowseRequest::new("https://a.com")).await;
        clock_cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.browse(&BrowseRequest::new("https://b.com")).await;
        clock_cell.fetch_add(1000, Ordering::SeqCst);
        // Adding a third should evict the oldest (a.com).
        let _ = cap.browse(&BrowseRequest::new("https://c.com")).await;

        let cache = cap.cache.read().expect("cache lock poisoned");
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains_key("https://a.com"), "oldest entry evicted");
        assert!(cache.contains_key("https://b.com"));
        assert!(cache.contains_key("https://c.com"));
    }

    #[test]
    fn test_extract_host_and_path() {
        assert_eq!(
            extract_host("https://Example.com/foo/bar"),
            Some("example.com".into())
        );
        assert_eq!(extract_path("https://example.com/foo/bar"), "/foo/bar");
        assert_eq!(extract_path("https://example.com"), "/");
        assert_eq!(
            extract_host("https://example.com:8080/x"),
            Some("example.com".into())
        );
    }
}
