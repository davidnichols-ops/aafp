//! Document-read capability (Track Y3).
//!
//! Provides agent-native reading of documents (PDF, plain text, markdown,
//! HTML, structured JSON/XML) via a pluggable [`DocumentReadProvider`],
//! with a TTL-based content cache and per-agent rate limiting.
//!
//! The capability mirrors the patterns established by the web-browse
//! (Track Y2) and search (Track Y2) capabilities: an injectable
//! [`Clock`] drives both cache TTL expiry and the fixed-window rate
//! limiter, while a pluggable provider trait keeps the extraction
//! backend decoupled from the capability logic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use aafp_identity::AgentId;

use super::Clock;
use crate::schema::{ContentSection, DocumentContent};
use crate::PerceptionError;

#[cfg(test)]
use crate::schema::{ContentHash, DocumentPage, PageMetadata};

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// A pluggable document-read backend that fetches and parses documents.
#[async_trait]
pub trait DocumentReadProvider: Send + Sync {
    /// Read the requested document and return agent-native content.
    async fn read(&self, request: &DocumentReadRequest)
        -> Result<DocumentContent, PerceptionError>;
}

// ---------------------------------------------------------------------------
// Document format
// ---------------------------------------------------------------------------

/// The format of a document to be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentFormat {
    /// PDF document.
    Pdf,
    /// Plain text.
    PlainText,
    /// Markdown.
    Markdown,
    /// HTML document.
    Html,
    /// Structured JSON.
    Json,
    /// Structured XML.
    Xml,
}

impl DocumentFormat {
    /// Lowercase canonical name used in `doc_type` and cache keys.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::PlainText => "text",
            Self::Markdown => "markdown",
            Self::Html => "html",
            Self::Json => "json",
            Self::Xml => "xml",
        }
    }
}

/// Detect a document format from a source path/URL or content-type hint.
///
/// Detection is performed by file extension first, then by a leading
/// content-type prefix (`application/pdf`, `text/markdown`, etc.). Returns
/// `None` when the format cannot be determined.
pub fn detect_format(source: &str) -> Option<DocumentFormat> {
    // Try file extension first.
    let lower = source.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "pdf" => return Some(DocumentFormat::Pdf),
        "txt" => return Some(DocumentFormat::PlainText),
        "md" | "markdown" => return Some(DocumentFormat::Markdown),
        "html" | "htm" => return Some(DocumentFormat::Html),
        "json" => return Some(DocumentFormat::Json),
        "xml" => return Some(DocumentFormat::Xml),
        _ => {}
    }

    // Fall back to a content-type style prefix embedded in the source.
    if lower.starts_with("application/pdf") {
        return Some(DocumentFormat::Pdf);
    }
    if lower.starts_with("text/plain") {
        return Some(DocumentFormat::PlainText);
    }
    if lower.starts_with("text/markdown") {
        return Some(DocumentFormat::Markdown);
    }
    if lower.starts_with("text/html") || lower.starts_with("application/xhtml") {
        return Some(DocumentFormat::Html);
    }
    if lower.starts_with("application/json") || lower.starts_with("text/json") {
        return Some(DocumentFormat::Json);
    }
    if lower.starts_with("application/xml") || lower.starts_with("text/xml") {
        return Some(DocumentFormat::Xml);
    }
    None
}

// ---------------------------------------------------------------------------
// Page range
// ---------------------------------------------------------------------------

/// An inclusive page range to extract (1-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRange {
    /// First page to extract (1-based).
    pub start: u32,
    /// Last page to extract (inclusive).
    pub end: u32,
}

impl PageRange {
    /// Create a new page range spanning `[start, end]` (inclusive).
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Create a single-page range.
    pub fn single(page: u32) -> Self {
        Self {
            start: page,
            end: page,
        }
    }

    /// Returns `true` if the range is well-formed (start <= end, start >= 1).
    pub fn is_valid(&self) -> bool {
        self.start >= 1 && self.start <= self.end
    }

    /// Returns `true` if `page` falls within this range.
    pub fn contains(&self, page: u32) -> bool {
        page >= self.start && page <= self.end
    }
}

// ---------------------------------------------------------------------------
// Extraction options
// ---------------------------------------------------------------------------

/// Options controlling how a document is extracted.
#[derive(Clone, Debug)]
pub struct ExtractionOptions {
    /// Whether to include document metadata in the result.
    pub include_metadata: bool,
    /// Whether to extract tables.
    pub include_tables: bool,
    /// Whether to extract images (references only; bytes are not embedded).
    pub include_images: bool,
    /// Maximum number of pages to extract (0 means unlimited).
    pub max_pages: u32,
    /// Whether to fall back to OCR when text extraction yields no text.
    pub ocr_fallback: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            include_metadata: true,
            include_tables: true,
            include_images: false,
            max_pages: 0,
            ocr_fallback: false,
        }
    }
}

impl ExtractionOptions {
    /// Returns `true` if `page` exceeds the configured `max_pages` limit.
    ///
    /// `max_pages == 0` is treated as unlimited.
    pub fn exceeds_max_pages(&self, page: u32) -> bool {
        self.max_pages > 0 && page > self.max_pages
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A document-read request.
#[derive(Clone, Debug)]
pub struct DocumentReadRequest {
    /// The source: a local file path or a URL.
    pub source: String,
    /// Optional format hint. When `None`, the format is auto-detected.
    pub format: Option<DocumentFormat>,
    /// Optional page range (1-based, inclusive). `None` means all pages.
    pub page_range: Option<PageRange>,
    /// Extraction options.
    pub options: ExtractionOptions,
}

impl DocumentReadRequest {
    /// Create a new document-read request for the given source with
    /// default extraction options and auto-detected format.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            format: None,
            page_range: None,
            options: ExtractionOptions::default(),
        }
    }

    /// Resolve the effective format: the explicit hint, or the detected one.
    pub fn effective_format(&self) -> Option<DocumentFormat> {
        self.format.or_else(|| detect_format(&self.source))
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the document-read capability.
#[derive(Clone, Debug)]
pub struct DocumentReadConfig {
    /// Cache time-to-live in milliseconds.
    pub cache_ttl_ms: u64,
    /// Maximum number of cache entries before eviction.
    pub max_cache_entries: usize,
    /// Maximum read requests allowed per agent per hour.
    pub rate_limit_per_hour: u32,
    /// Read timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for DocumentReadConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 30 * 60 * 1000, // 30 minutes
            max_cache_entries: 128,
            rate_limit_per_hour: 200,
            timeout_ms: 60_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// A cached document-read result.
struct CacheEntry {
    content: DocumentContent,
    /// Unix-millisecond timestamp when the entry was stored.
    timestamp: u64,
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

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// The document-read capability: caches content and rate-limits per agent.
pub struct DocumentReadCapability {
    provider: Arc<dyn DocumentReadProvider>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    rate_limiter: RwLock<HashMap<AgentId, RateBucket>>,
    config: DocumentReadConfig,
    clock: Clock,
}

impl DocumentReadCapability {
    /// Create a new document-read capability with the default system clock.
    pub fn new(provider: Arc<dyn DocumentReadProvider>, config: DocumentReadConfig) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
        }
    }

    /// Create a new document-read capability with an injected clock (for testing).
    pub fn with_clock(
        provider: Arc<dyn DocumentReadProvider>,
        config: DocumentReadConfig,
        clock: Clock,
    ) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock,
        }
    }

    /// Read a document on behalf of an agent, applying rate limiting and
    /// consulting the cache before delegating to the provider.
    pub async fn read(
        &self,
        request: &DocumentReadRequest,
        agent_id: &AgentId,
    ) -> Result<DocumentContent, PerceptionError> {
        if request.source.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "source",
                message: "source must not be empty".into(),
            });
        }

        if let Some(range) = request.page_range {
            if !range.is_valid() {
                return Err(PerceptionError::InvalidField {
                    field: "page_range",
                    message: format!(
                        "invalid page range: start={} end={} (need start>=1 and start<=end)",
                        range.start, range.end
                    ),
                });
            }
        }

        // Rate-limit check (per-agent fixed window).
        self.check_rate_limit(agent_id)?;

        // Cache lookup keyed by source + format + range.
        let cache_key = self.cache_key(request);
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        // Fetch from the provider.
        let content = self.provider.read(request).await?;

        // Store in cache.
        self.cache_put(&cache_key, content.clone());

        Ok(content)
    }

    /// Build a deterministic cache key from the request.
    fn cache_key(&self, request: &DocumentReadRequest) -> String {
        let format = request
            .effective_format()
            .map(DocumentFormat::as_str)
            .unwrap_or("auto");
        let range = match request.page_range {
            Some(r) => format!("{}-{}", r.start, r.end),
            None => "all".to_string(),
        };
        format!("{}|{}|{}", request.source, format, range)
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

    /// Look up a key in the cache, returning a clone if present and fresh.
    fn cache_get(&self, key: &str) -> Option<DocumentContent> {
        let now_ms = (self.clock)();
        let cache = self.cache.read().expect("cache lock poisoned");
        let entry = cache.get(key)?;
        if now_ms.saturating_sub(entry.timestamp) >= self.config.cache_ttl_ms {
            // Expired.
            return None;
        }
        Some(entry.content.clone())
    }

    /// Store content in the cache, evicting expired entries if the cache
    /// is full.
    fn cache_put(&self, key: &str, content: DocumentContent) {
        let now_ms = (self.clock)();
        let mut cache = self.cache.write().expect("cache lock poisoned");

        // Evict expired entries first.
        evict_expired_locked(&mut cache, self.config.cache_ttl_ms, now_ms);

        // If still at capacity, evict the oldest entry.
        if cache.len() >= self.config.max_cache_entries {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(
            key.to_string(),
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

// ---------------------------------------------------------------------------
// Text extraction helpers
// ---------------------------------------------------------------------------

/// Extract the full plain text of a [`DocumentContent`] by concatenating
/// the text of all pages in order.
pub fn extract_text(content: &DocumentContent) -> String {
    let mut out = String::new();
    for (i, page) in content.pages.iter().enumerate() {
        if i > 0 {
            out.push_str("\n\n");
        }
        out.push_str(&page.text);
    }
    out
}

/// Extract the text of a single page (1-based) from a [`DocumentContent`].
///
/// Returns `None` if the page number is out of range.
pub fn extract_page_text(content: &DocumentContent, page_num: u32) -> Option<String> {
    content
        .pages
        .iter()
        .find(|p| p.page_num == page_num)
        .map(|p| p.text.clone())
}

/// Extract all sections across all pages of a [`DocumentContent`].
pub fn extract_sections(content: &DocumentContent) -> Vec<&ContentSection> {
    content
        .pages
        .iter()
        .flat_map(|p| p.sections.iter())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    fn agent(n: u8) -> AgentId {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    fn sample_metadata() -> PageMetadata {
        PageMetadata {
            status_code: 200,
            content_type: "application/pdf".into(),
            charset: Some("utf-8".into()),
            language: Some("en".into()),
            title: Some("Sample Doc".into()),
            description: None,
            fetched_at: 1_700_000_000_000,
        }
    }

    fn sample_page(page_num: u32, text: &str) -> DocumentPage {
        DocumentPage {
            page_num,
            text: text.into(),
            sections: vec![ContentSection {
                id: format!("p{page_num}s0"),
                title: format!("Page {page_num}"),
                content: text.into(),
                level: 1,
                children: vec![],
            }],
        }
    }

    fn sample_document(source: &str, doc_type: &str, num_pages: u32) -> DocumentContent {
        let pages: Vec<DocumentPage> = (1..=num_pages)
            .map(|i| sample_page(i, &format!("Content of page {i}")))
            .collect();
        let text = pages
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        DocumentContent {
            source: source.into(),
            doc_type: doc_type.into(),
            title: Some("Sample Doc".into()),
            pages,
            tables: vec![],
            metadata: sample_metadata(),
            language: Some("en".into()),
            ocr_applied: false,
            hash: ContentHash::compute(text.as_bytes()),
        }
    }

    /// A mock provider returning a canned document, optionally failing.
    struct MockProvider {
        content: DocumentContent,
        call_count: AtomicU64,
        fail: bool,
    }

    impl MockProvider {
        fn new(content: DocumentContent) -> Self {
            Self {
                content,
                call_count: AtomicU64::new(0),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                content: sample_document("x", "pdf", 1),
                call_count: AtomicU64::new(0),
                fail: true,
            }
        }

        fn calls(&self) -> u64 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DocumentReadProvider for MockProvider {
        async fn read(
            &self,
            _req: &DocumentReadRequest,
        ) -> Result<DocumentContent, PerceptionError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(PerceptionError::Provider("mock read failed".into()));
            }
            Ok(self.content.clone())
        }
    }

    fn default_config() -> DocumentReadConfig {
        DocumentReadConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            rate_limit_per_hour: 100,
            timeout_ms: 5_000,
        }
    }

    // -----------------------------------------------------------------------
    // Format detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_format_pdf_extension() {
        assert_eq!(detect_format("report.pdf"), Some(DocumentFormat::Pdf));
    }

    #[test]
    fn test_detect_format_markdown_extension() {
        assert_eq!(detect_format("notes.md"), Some(DocumentFormat::Markdown));
        assert_eq!(
            detect_format("notes.markdown"),
            Some(DocumentFormat::Markdown)
        );
    }

    #[test]
    fn test_detect_format_html_extension() {
        assert_eq!(detect_format("page.html"), Some(DocumentFormat::Html));
        assert_eq!(detect_format("page.htm"), Some(DocumentFormat::Html));
    }

    #[test]
    fn test_detect_format_json_xml_extensions() {
        assert_eq!(detect_format("data.json"), Some(DocumentFormat::Json));
        assert_eq!(detect_format("data.xml"), Some(DocumentFormat::Xml));
    }

    #[test]
    fn test_detect_format_text_extension() {
        assert_eq!(detect_format("readme.txt"), Some(DocumentFormat::PlainText));
    }

    #[test]
    fn test_detect_format_content_type_fallback() {
        assert_eq!(detect_format("application/pdf"), Some(DocumentFormat::Pdf));
        assert_eq!(
            detect_format("text/markdown; charset=utf-8"),
            Some(DocumentFormat::Markdown)
        );
        assert_eq!(
            detect_format("application/json"),
            Some(DocumentFormat::Json)
        );
        assert_eq!(detect_format("application/xml"), Some(DocumentFormat::Xml));
    }

    #[test]
    fn test_detect_format_unknown_returns_none() {
        assert_eq!(detect_format("no_extension_here"), None);
        assert_eq!(detect_format("file.xyz"), None);
    }

    #[test]
    fn test_detect_format_case_insensitive() {
        assert_eq!(detect_format("REPORT.PDF"), Some(DocumentFormat::Pdf));
        assert_eq!(detect_format("Page.HTML"), Some(DocumentFormat::Html));
    }

    #[test]
    fn test_document_format_as_str() {
        assert_eq!(DocumentFormat::Pdf.as_str(), "pdf");
        assert_eq!(DocumentFormat::PlainText.as_str(), "text");
        assert_eq!(DocumentFormat::Markdown.as_str(), "markdown");
        assert_eq!(DocumentFormat::Html.as_str(), "html");
        assert_eq!(DocumentFormat::Json.as_str(), "json");
        assert_eq!(DocumentFormat::Xml.as_str(), "xml");
    }

    // -----------------------------------------------------------------------
    // Page range
    // -----------------------------------------------------------------------

    #[test]
    fn test_page_range_valid() {
        assert!(PageRange::new(1, 5).is_valid());
        assert!(PageRange::single(3).is_valid());
        assert!(!PageRange::new(0, 5).is_valid(), "start must be >= 1");
        assert!(!PageRange::new(5, 2).is_valid(), "start must be <= end");
    }

    #[test]
    fn test_page_range_contains() {
        let r = PageRange::new(3, 7);
        assert!(r.contains(3));
        assert!(r.contains(5));
        assert!(r.contains(7));
        assert!(!r.contains(2));
        assert!(!r.contains(8));
    }

    #[test]
    fn test_page_range_single() {
        let r = PageRange::single(4);
        assert_eq!(r.start, 4);
        assert_eq!(r.end, 4);
        assert!(r.contains(4));
        assert!(!r.contains(3));
    }

    // -----------------------------------------------------------------------
    // Extraction options
    // -----------------------------------------------------------------------

    #[test]
    fn test_extraction_options_default() {
        let opts = ExtractionOptions::default();
        assert!(opts.include_metadata);
        assert!(opts.include_tables);
        assert!(!opts.include_images);
        assert_eq!(opts.max_pages, 0);
        assert!(!opts.ocr_fallback);
    }

    #[test]
    fn test_extraction_options_max_pages() {
        let mut opts = ExtractionOptions::default();
        opts.max_pages = 10;
        assert!(!opts.exceeds_max_pages(10));
        assert!(opts.exceeds_max_pages(11));
        // max_pages == 0 means unlimited.
        opts.max_pages = 0;
        assert!(!opts.exceeds_max_pages(1_000_000));
    }

    // -----------------------------------------------------------------------
    // Request
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_effective_format_uses_hint() {
        let mut req = DocumentReadRequest::new("file.pdf");
        req.format = Some(DocumentFormat::PlainText);
        assert_eq!(req.effective_format(), Some(DocumentFormat::PlainText));
    }

    #[test]
    fn test_request_effective_format_auto_detects() {
        let req = DocumentReadRequest::new("file.pdf");
        assert_eq!(req.effective_format(), Some(DocumentFormat::Pdf));
    }

    #[test]
    fn test_request_effective_format_none_when_undetectable() {
        let req = DocumentReadRequest::new("noext");
        assert_eq!(req.effective_format(), None);
    }

    // -----------------------------------------------------------------------
    // Capability: basic read
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_read_basic() {
        let provider = Arc::new(MockProvider::new(sample_document("report.pdf", "pdf", 3)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let req = DocumentReadRequest::new("report.pdf");
        let content = cap.read(&req, &agent(1)).await.expect("read ok");
        assert_eq!(content.source, "report.pdf");
        assert_eq!(content.doc_type, "pdf");
        assert_eq!(content.pages.len(), 3);
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_read_with_format_hint() {
        let provider = Arc::new(MockProvider::new(sample_document("doc", "text", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider, default_config(), clock);
        let mut req = DocumentReadRequest::new("doc");
        req.format = Some(DocumentFormat::Markdown);
        let content = cap.read(&req, &agent(1)).await.expect("read ok");
        assert_eq!(content.pages.len(), 1);
    }

    #[tokio::test]
    async fn test_read_with_page_range() {
        let provider = Arc::new(MockProvider::new(sample_document("doc.pdf", "pdf", 5)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider, default_config(), clock);
        let mut req = DocumentReadRequest::new("doc.pdf");
        req.page_range = Some(PageRange::new(2, 4));
        let content = cap.read(&req, &agent(1)).await.expect("read ok");
        // The mock returns all pages regardless; we verify the request is accepted.
        assert_eq!(content.pages.len(), 5);
    }

    #[tokio::test]
    async fn test_read_empty_source_error() {
        let provider = Arc::new(MockProvider::new(sample_document("x", "pdf", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap
            .read(&DocumentReadRequest::new(""), &agent(1))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "source",
                ..
            }
        ));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn test_read_invalid_page_range_error() {
        let provider = Arc::new(MockProvider::new(sample_document("x.pdf", "pdf", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let mut req = DocumentReadRequest::new("x.pdf");
        req.page_range = Some(PageRange::new(5, 2));
        let err = cap.read(&req, &agent(1)).await.unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "page_range",
                ..
            }
        ));
        assert_eq!(provider.calls(), 0);
    }

    // -----------------------------------------------------------------------
    // Capability: caching
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_hit_avoids_provider() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 2)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let req = DocumentReadRequest::new("a.pdf");
        let _ = cap.read(&req, &agent(1)).await.expect("first read");
        let _ = cap.read(&req, &agent(1)).await.expect("second read");
        assert_eq!(provider.calls(), 1, "second read should hit cache");
    }

    #[tokio::test]
    async fn test_cache_miss_different_source() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let _ = cap
            .read(&DocumentReadRequest::new("a.pdf"), &agent(1))
            .await;
        let _ = cap
            .read(&DocumentReadRequest::new("b.pdf"), &agent(1))
            .await;
        assert_eq!(provider.calls(), 2, "different source should miss cache");
    }

    #[tokio::test]
    async fn test_cache_miss_different_page_range() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 5)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let mut r1 = DocumentReadRequest::new("a.pdf");
        r1.page_range = Some(PageRange::new(1, 2));
        let mut r2 = DocumentReadRequest::new("a.pdf");
        r2.page_range = Some(PageRange::new(3, 4));
        let _ = cap.read(&r1, &agent(1)).await;
        let _ = cap.read(&r2, &agent(1)).await;
        assert_eq!(
            provider.calls(),
            2,
            "different page range should miss cache"
        );
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, cell) = mock_clock();
        let cap = DocumentReadCapability::with_clock(
            provider.clone(),
            DocumentReadConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 100,
                timeout_ms: 5_000,
            },
            clock,
        );
        let req = DocumentReadRequest::new("a.pdf");
        let _ = cap.read(&req, &agent(1)).await.expect("first");
        assert_eq!(provider.calls(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        let _ = cap.read(&req, &agent(1)).await.expect("second");
        assert_eq!(provider.calls(), 2, "expired entry should refetch");
    }

    #[tokio::test]
    async fn test_cache_eviction_max_entries() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, cell) = mock_clock();
        let cap = DocumentReadCapability::with_clock(
            provider.clone(),
            DocumentReadConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 2,
                rate_limit_per_hour: 100,
                timeout_ms: 5_000,
            },
            clock,
        );
        let _ = cap
            .read(&DocumentReadRequest::new("a.pdf"), &agent(1))
            .await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap
            .read(&DocumentReadRequest::new("b.pdf"), &agent(1))
            .await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap
            .read(&DocumentReadRequest::new("c.pdf"), &agent(1))
            .await;

        let cache = cap.cache.read().expect("cache lock poisoned");
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains_key("a.pdf|pdf|all"), "oldest evicted");
    }

    #[tokio::test]
    async fn test_evict_expired_public() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, cell) = mock_clock();
        let cap = DocumentReadCapability::with_clock(
            provider,
            DocumentReadConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 100,
                timeout_ms: 5_000,
            },
            clock,
        );
        let _ = cap
            .read(&DocumentReadRequest::new("a.pdf"), &agent(1))
            .await;
        {
            let cache = cap.cache.read().expect("cache lock poisoned");
            assert_eq!(cache.len(), 1);
        }
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        cap.evict_expired();
        let cache = cap.cache.read().expect("cache lock poisoned");
        assert!(cache.is_empty(), "expired entry should be evicted");
    }

    // -----------------------------------------------------------------------
    // Capability: rate limiting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limited() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(
            provider,
            DocumentReadConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 2,
                timeout_ms: 5_000,
            },
            clock,
        );
        let req = DocumentReadRequest::new("a.pdf");
        let id = agent(1);
        assert!(cap.read(&req, &id).await.is_ok());
        // Second request hits cache (no rate-limit increment beyond first),
        // so use a distinct source to force a provider call.
        let req2 = DocumentReadRequest::new("b.pdf");
        assert!(cap.read(&req2, &id).await.is_ok());
        let req3 = DocumentReadRequest::new("c.pdf");
        let err = cap.read(&req3, &id).await.unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
    }

    #[tokio::test]
    async fn test_rate_limit_reset_after_window() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, cell) = mock_clock();
        let cap = DocumentReadCapability::with_clock(
            provider,
            DocumentReadConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 1,
                timeout_ms: 5_000,
            },
            clock,
        );
        let id = agent(1);
        assert!(cap
            .read(&DocumentReadRequest::new("a.pdf"), &id)
            .await
            .is_ok());
        let err = cap
            .read(&DocumentReadRequest::new("b.pdf"), &id)
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
        // Advance past one hour.
        cell.store(1_700_000_000_000 + 60 * 60 * 1000 + 1, Ordering::SeqCst);
        assert!(cap
            .read(&DocumentReadRequest::new("c.pdf"), &id)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_per_agent_isolated() {
        let provider = Arc::new(MockProvider::new(sample_document("a.pdf", "pdf", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(
            provider,
            DocumentReadConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 1,
                timeout_ms: 5_000,
            },
            clock,
        );
        // Agent 1 hits the limit.
        assert!(cap
            .read(&DocumentReadRequest::new("a.pdf"), &agent(1))
            .await
            .is_ok());
        assert!(cap
            .read(&DocumentReadRequest::new("b.pdf"), &agent(1))
            .await
            .is_err());
        // Agent 2 is unaffected.
        assert!(cap
            .read(&DocumentReadRequest::new("c.pdf"), &agent(2))
            .await
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // Capability: error handling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_provider_error_propagates() {
        let provider = Arc::new(MockProvider::failing());
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider, default_config(), clock);
        let err = cap
            .read(&DocumentReadRequest::new("a.pdf"), &agent(1))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    // -----------------------------------------------------------------------
    // Text extraction helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_text_concatenates_pages() {
        let doc = sample_document("a.pdf", "pdf", 3);
        let text = extract_text(&doc);
        assert!(text.contains("Content of page 1"));
        assert!(text.contains("Content of page 2"));
        assert!(text.contains("Content of page 3"));
        // Pages are separated by double newlines.
        assert!(text.contains("page 1\n\nContent of page 2"));
    }

    #[test]
    fn test_extract_text_single_page() {
        let doc = sample_document("a.pdf", "pdf", 1);
        let text = extract_text(&doc);
        assert_eq!(text, "Content of page 1");
    }

    #[test]
    fn test_extract_page_text_found() {
        let doc = sample_document("a.pdf", "pdf", 3);
        assert_eq!(
            extract_page_text(&doc, 2).as_deref(),
            Some("Content of page 2")
        );
    }

    #[test]
    fn test_extract_page_text_out_of_range() {
        let doc = sample_document("a.pdf", "pdf", 3);
        assert_eq!(extract_page_text(&doc, 99), None);
    }

    #[test]
    fn test_extract_sections_collects_all() {
        let doc = sample_document("a.pdf", "pdf", 2);
        let sections = extract_sections(&doc);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].id, "p1s0");
        assert_eq!(sections[1].id, "p2s0");
    }

    // -----------------------------------------------------------------------
    // Roundtrip (CBOR encode/decode of DocumentContent produced by read)
    // -----------------------------------------------------------------------

    #[test]
    fn test_document_content_cbor_roundtrip() {
        let doc = sample_document("report.pdf", "pdf", 3);
        let cbor = doc.to_cbor();
        let decoded = DocumentContent::from_cbor(&cbor).expect("decode ok");
        assert_eq!(doc, decoded);
    }

    #[test]
    fn test_cache_key_distinguishes_format() {
        let provider = Arc::new(MockProvider::new(sample_document("a", "text", 1)));
        let (clock, _) = mock_clock();
        let cap = DocumentReadCapability::with_clock(provider.clone(), default_config(), clock);
        let mut r1 = DocumentReadRequest::new("a");
        r1.format = Some(DocumentFormat::Pdf);
        let mut r2 = DocumentReadRequest::new("a");
        r2.format = Some(DocumentFormat::PlainText);
        let k1 = cap.cache_key(&r1);
        let k2 = cap.cache_key(&r2);
        assert_ne!(k1, k2, "different formats must have different cache keys");
    }
}
